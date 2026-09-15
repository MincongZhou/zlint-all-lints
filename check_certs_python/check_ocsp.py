#!/usr/bin/env python3
"""
check_ocsp.py —— 用 Python 联网查询证书的 OCSP 状态

依赖: cryptography (OCSP 模块 2.6+ 即可)

流程:
    1. 从证书 AIA 扩展提取 OCSP URL（及 CA Issuers 下载地址）
    2. 取得签发者证书（见下方"签发者来源"），并校验它确实匹配本证书
    3. 构造 OCSP 请求并发给 responder（POST）
    4. 解析响应，输出 GOOD / REVOKED / UNKNOWN

签发者来源（按优先级，命中即止）:
    1. --issuer / 第 2 个位置参数 —— 显式指定的签发者证书文件
    2. --issuer-dir（默认 <项目根>/issuers）—— 目录索引按证书 AKI 反查 SKI 自动匹配
       （证书缺 AKI 时退回 issuer DN → subject DN 比对）
    3. 证书 AIA 里的 CA Issuers 地址 —— 联网下载
    三者都不可用时才报错。注意很多 CA（如 CFCA Identity 体系）的 AIA 只给 OCSP 地址、
    不给 CA Issuers，此类证书必须靠来源 1 或 2 提供签发者。

用法:
    python3 check_ocsp.py <证书路径> [签发者证书路径] [--der] [--timeout 秒] [--respout 文件] [--sha256]
    python3 check_ocsp.py <证书路径> --issuer ca.pem --status   # 显式指定签发者
    python3 check_ocsp.py <证书路径> --issuer-dir ./mycas --status
    python3 check_ocsp.py <证书路径> --status        # 只输出状态，静默其他信息
    python3 check_ocsp.py                            # 无参数 → 交互模式

    --issuer <文件>:    签发者证书（等价于第 2 个位置参数）
    --issuer-dir <目录>: 签发者证书目录，可多次；指定后不再使用默认目录 <项目根>/issuers
    --respout <文件>: 把 responder 返回的原始 OCSP 响应(DER)保存到文件，
                      供 zlint 跑 OCSP 规则 (zlint -format der -longSummary <文件>)
    --sha256:  CertID 摘要用 SHA-256（默认 SHA-1，与 openssl ocsp 一致）。
               多数 responder（DigiCert / 微软等）只认 SHA-1，用 SHA-256 会返回
               MALFORMED_REQUEST；仅个别要求 SHA-256 的 responder 才需要此开关。
               注意 UNAUTHORIZED 与摘要算法无关——它表示 responder 不受理这个 CertID，
               常见于"传错签发者"或"该 CA 体系根本不提供 OCSP"。
    证书/签发者证书均为 PEM/DER 自动识别；--der 仅表示优先按 DER 解析，失败自动回退。

注意:
    - 拿到签发者后一律校验 AKI/SKI 是否匹配，不匹配立即报错。否则 CertID 算错，
      responder 会回 UNAUTHORIZED，把"传错签发者"掩盖成"服务端拒绝"
    - 本脚本只查询状态，不做 responder 响应签名验证
"""

import argparse
import glob
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

# 项目根（本文件在 <根>/check_certs_python/ 下）；签发者默认目录挂在根下
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_ISSUER_DIR = os.path.join(REPO_ROOT, "issuers")
# 签发者目录里认作证书的扩展名（与各脚本的证书扩展名口径一致）
ISSUER_EXTS = (".pem", ".crt", ".cer", ".der", ".cert")


def enable_utf8_output():
    """stdout/stderr 一旦被重定向（非真控制台），锁死按 UTF-8 写出。

    中文 Windows 上 Python 在"输出重定向到文件/管道"时默认按 GBK 写，
    上层若按 UTF-8 读就会把中文全变成 U+FFFD（表现为 "����"）。
    真控制台上 Python 本来就是 UTF-8（走 Windows 控制台 API），
    所以只对非 tty 的流做重配置，避免在控制台里双重编码。
    配套：run_ocsp_batch.py 已把子进程强制成 UTF-8，这里补齐父进程一侧。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            if not stream.isatty():
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def load_cert(data, prefer_der=False):
    """加载证书，自动识别 PEM / DER；prefer_der=True 时先按 DER 解析

    即使格式标错（如 PEM 文件被标成 DER）也会自动回退另一种，避免误报解析错误。
    """
    order = ([x509.load_der_x509_certificate, x509.load_pem_x509_certificate]
             if prefer_der else
             [x509.load_pem_x509_certificate, x509.load_der_x509_certificate])
    last_err = None
    for fn in order:
        try:
            return fn(data)
        except ValueError as e:
            last_err = e
    raise last_err


# ---------- 签发者识别、匹配与目录索引 ----------

def cert_ski(cert):
    """证书的 Subject Key Identifier（bytes）；无该扩展返回 None"""
    try:
        return cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier).value.digest
    except x509.ExtensionNotFound:
        return None


def cert_aki(cert):
    """证书 AKI 扩展里的 keyIdentifier（bytes）；无扩展或无该字段返回 None。

    RFC 5280 规定 AKI 的 keyIdentifier 就是签发者公钥的 SHA-1，
    因此可以直接拿它在签发者目录里反查 SKI。
    """
    try:
        return cert.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier).value.key_identifier
    except x509.ExtensionNotFound:
        return None


def is_correct_issuer(cert, issuer):
    """判断 issuer 是否真的是 cert 的签发者（只比对扩展/DN，不做签名运算）。
    返回 (ok, reason)；ok=False 时 reason 说明哪里不一致。"""
    aki, ski = cert_aki(cert), cert_ski(issuer)
    if aki is not None and ski is not None:
        if aki == ski:
            return True, ""
        return False, (f"AKI/SKI 不一致：证书 AKI={aki.hex(':').upper()}，"
                       f"签发者 SKI={ski.hex(':').upper()}")
    # 任一侧缺 AKI/SKI → 退回 DN 比对。强度弱，但足以挡住"传错证书文件"这类误操作
    if cert.issuer != issuer.subject:
        return False, (f"DN 不一致：证书 issuer={cert.issuer.rfc4514_string()}，"
                       f"签发者 subject={issuer.subject.rfc4514_string()}")
    return True, ""


def ensure_issuer_match(cert, issuer, source):
    """校验签发者与证书匹配，不匹配直接抛错。

    少了这一步，"传错签发者"会算出错误的 CertID，responder 回 UNAUTHORIZED，
    表现和"服务端拒绝服务"一模一样，极难排查。
    """
    ok, why = is_correct_issuer(cert, issuer)
    if not ok:
        raise RuntimeError(
            f"签发者与证书不匹配（来源: {source}）: {why}。"
            f"错误的签发者会算出错误的 CertID，responder 必然返回 UNAUTHORIZED")


_ISSUER_INDEX_CACHE = {}


def build_issuer_index(dirs, use_cache=True):
    """扫描签发者目录，建立索引 (by_ski, by_dn)：
        by_ski: {SKI 大写 hex: 文件路径}
        by_dn : {subject DN: 文件路径}
    dirs 为空/不存在 → 返回两个空 dict；同一进程内结果缓存。

    批量场景先建一次索引再逐张反查，避免每张证书重复扫目录。
    """
    key = tuple(sorted(os.path.expanduser(d) for d in (dirs or [])))
    if not key:
        return {}, {}
    if use_cache and key in _ISSUER_INDEX_CACHE:
        return _ISSUER_INDEX_CACHE[key]

    by_ski, by_dn = {}, {}
    for d in key:
        if not os.path.isdir(d):
            continue
        for p in sorted(glob.glob(os.path.join(d, "**", "*"), recursive=True)):
            if not os.path.isfile(p) or \
                    os.path.splitext(p)[1].lower() not in ISSUER_EXTS:
                continue
            try:
                with open(p, "rb") as f:
                    c = load_cert(f.read())
            except Exception:
                continue        # 目录里混入的非证书文件（说明/校验和等）静默跳过
            ski = cert_ski(c)
            if ski is not None:
                by_ski.setdefault(ski.hex().upper(), p)
            by_dn.setdefault(c.subject.rfc4514_string(), p)
    index = (by_ski, by_dn)
    if use_cache:
        _ISSUER_INDEX_CACHE[key] = index
    return index


def find_issuer(cert, index):
    """在已建好的索引里给 cert 找签发者，返回文件路径；未命中返回 None"""
    by_ski, by_dn = index
    aki = cert_aki(cert)
    if aki is not None:
        hit = by_ski.get(aki.hex().upper())
        if hit:
            return hit
    return by_dn.get(cert.issuer.rfc4514_string())


def find_issuer_in_dirs(cert, dirs):
    """便捷版：建索引 + 反查一步到位（单张查询用；批量请复用 build_issuer_index）"""
    if not dirs:
        return None
    return find_issuer(cert, build_issuer_index(dirs))


def get_aia_urls(cert):
    """从 AIA 扩展提取 (ocsp_url, ca_issuers_url)"""
    ocsp_url = ca_issuers_url = None
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return None, None
    for desc in aia:
        if desc.access_method == AuthorityInformationAccessOID.OCSP:
            ocsp_url = desc.access_location.value
        elif desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
            ca_issuers_url = desc.access_location.value
    return ocsp_url, ca_issuers_url


def fetch_url(url, timeout=15, retries=2, quiet=False):
    """带 User-Agent 下载；http 失败自动尝试 https；失败重试"""
    urls = [url]
    if url.startswith("http://"):
        urls.append("https://" + url[len("http://"):])

    last_err = None
    for attempt in range(retries + 1):
        for u in urls:
            try:
                req = urllib.request.Request(
                    u, headers={"User-Agent": "Mozilla/5.0 (check_ocsp.py)"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    data = r.read()
                if not data:
                    raise ValueError("空响应")
                if not quiet and u != url:
                    print(f"  {url} 失败，改用 {u} 成功")
                return data
            except (urllib.error.HTTPError, urllib.error.URLError,
                    ValueError, TimeoutError) as e:
                last_err = e
                if not quiet:
                    print(f"  下载失败 {u} ({type(e).__name__}: {e})")
        if attempt < retries:
            if not quiet:
                print(f"  重试 ({attempt + 1}/{retries})...")
            time.sleep(1)
    raise last_err


def load_issuer(issuer_path, cert, ca_issuers_url=None, quiet=False,
                issuer_dirs=None):
    """按优先级取得 cert 的签发者证书，并校验它确实匹配 cert：
        1. issuer_path       —— 显式指定的签发者文件（PEM/DER 自动识别）
        2. issuer_dirs       —— 签发者目录索引按 AKI→SKI 反查（默认 <项目根>/issuers）
        3. ca_issuers_url    —— 从证书 AIA 的 CA Issuers 地址下载
    三者都不可用时抛 RuntimeError。每一条来源都会做匹配校验，
    避免"传错签发者"被 responder 的 UNAUTHORIZED 掩盖。
    """
    if issuer_path:
        issuer_path = os.path.expanduser(issuer_path)
        with open(issuer_path, "rb") as f:
            issuer = load_cert(f.read())        # PEM/DER 自动识别
        ensure_issuer_match(cert, issuer, f"指定文件 {issuer_path}")
        return issuer

    dirs = default_issuer_dirs() if issuer_dirs is None else issuer_dirs
    found = find_issuer_in_dirs(cert, dirs)
    if found:
        with open(found, "rb") as f:
            issuer = load_cert(f.read())
        if not quiet:
            print(f"签发者目录命中: {found}")
        ensure_issuer_match(cert, issuer, f"目录匹配 {found}")
        return issuer

    if ca_issuers_url:
        if not quiet:
            print(f"从 CA Issuers 下载签发者证书: {ca_issuers_url}")
        data = fetch_url(ca_issuers_url, quiet=quiet)
        issuer = load_cert(data)
        ensure_issuer_match(cert, issuer, f"AIA 下载 {ca_issuers_url}")
        return issuer

    raise RuntimeError(
        "未提供签发者证书，且证书 AIA 中没有 CA Issuers 地址。"
        f"可用 --issuer 指定，或把签发者证书放进签发者目录（当前: "
        f"{', '.join(dirs) if dirs else '未配置'}）")


def default_issuer_dirs():
    """默认签发者目录（<项目根>/issuers）"""
    return [DEFAULT_ISSUER_DIR]


def query_ocsp(cert, issuer, ocsp_url, timeout=15, quiet=False, respout=None,
               hash_alg=hashes.SHA1()):
    """构造 OCSP 请求 → POST → 返回响应对象；http 失败自动试 https，失败重试
    hash_alg 是 CertID 摘要算法：默认 SHA-1（与 openssl ocsp 相同，兼容性最好，
    DigiCert / 微软等 responder 不接受 SHA-256 的 CertID）"""
    urls = [ocsp_url]
    if ocsp_url.startswith("http://"):
        urls.append("https://" + ocsp_url[len("http://"):])

    der = (ocsp.OCSPRequestBuilder()
           .add_certificate(cert, issuer, hash_alg)
           .build().public_bytes(serialization.Encoding.DER))

    last_err = None
    for attempt in range(3):  # 1 次尝试 + 2 次重试
        for u in urls:
            try:
                req = urllib.request.Request(
                    u, data=der,
                    headers={"Content-Type": "application/ocsp-request"},
                )
                # OCSP responder 的 https 端口常存在证书主机名不匹配问题，
                # 兜底请求不做证书校验（OCSP 响应本身是签名数据）
                ctx = ssl._create_unverified_context() if u.startswith("https://") else None
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                    resp_der = r.read()
                if not resp_der:
                    raise ValueError("空响应")
                if not quiet and u != ocsp_url:
                    print(f"  {ocsp_url} 失败，改用 {u} 成功")
                if respout:          # 保存 responder 返回的原始 DER（供 zlint 跑 OCSP 规则）
                    with open(respout, "wb") as f:
                        f.write(resp_der)
                    if not quiet:
                        print(f"原始 OCSP 响应已保存: {respout}")
                return ocsp.load_der_ocsp_response(resp_der)
            except (urllib.error.HTTPError, urllib.error.URLError,
                    ValueError, TimeoutError) as e:
                last_err = e
                if not quiet:
                    print(f"  OCSP 请求失败 {u} ({type(e).__name__}: {e})")
        if attempt < 2:
            if not quiet:
                print(f"  重试 ({attempt + 1}/2)...")
            time.sleep(1)
    raise last_err


def check_cert(cert_path, issuer_path=None, der=False, status_only=False, timeout=15,
               respout=None, hash_alg=hashes.SHA1(), issuer_dirs=None):
    """加载证书并查询 OCSP，输出结果；失败时按模式输出错误并退出

    issuer_dirs=None → 用默认签发者目录；传 [] 表示不查目录
    """
    cert_path = os.path.expanduser(cert_path)
    if issuer_path:
        issuer_path = os.path.expanduser(issuer_path)

    with open(cert_path, "rb") as f:
        data = f.read()
    cert = load_cert(data, der)

    ocsp_url, ca_issuers_url = get_aia_urls(cert)
    if not ocsp_url:
        if status_only:
            print("ERROR: 无 OCSP 地址", file=sys.stderr)
        else:
            print("该证书没有 AIA 扩展或其中没有 OCSP 地址，无法查询")
        sys.exit(1)

    if not status_only:
        print(f"证书: {cert.subject.rfc4514_string()}")
        print(f"OCSP responder: {ocsp_url}\n")

    try:
        issuer = load_issuer(issuer_path, cert, ca_issuers_url,
                             quiet=status_only, issuer_dirs=issuer_dirs)
    except Exception as e:
        if status_only:
            print(f"ERROR: 加载签发者证书失败: {e}", file=sys.stderr)
        else:
            print(f"\n加载签发者证书失败: {e}")
            print("替代方案①: 把签发者证书放进签发者目录（默认 <项目根>/issuers，"
                  "或用 --issuer-dir 指定）")
            print("替代方案②: 用 openssl 从 TLS 连接拉取证书链，取第 2 张（签发者）")
            print("  1) openssl s_client -connect baidu.com:443 -showcerts </dev/null 2>/dev/null | awk '/BEGIN CERTIFICATE/{n++} n==2' > issuer.pem")
            print("  2) python3 check_ocsp.py <证书> issuer.pem")
        sys.exit(1)

    try:
        response = query_ocsp(cert, issuer, ocsp_url, timeout, quiet=status_only,
                              respout=respout, hash_alg=hash_alg)
    except Exception as e:
        if status_only:
            print(f"ERROR: OCSP 查询失败: {e}", file=sys.stderr)
        else:
            print(f"\nOCSP 查询失败: {e}")
            print("可能原因: responder 网络不通或超时，可加大 --timeout")
        sys.exit(1)

    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        if status_only:
            print(f"ERROR: {response.response_status.name}", file=sys.stderr)
        else:
            print(f"OCSP 响应状态: {response.response_status.name}（非成功）")
        sys.exit(1)

    status = response.certificate_status
    if status_only:
        if status == ocsp.OCSPCertStatus.REVOKED:
            print(f"{status.name} {response.revocation_time_utc.isoformat()}")
        else:
            print(status.name)
        return

    print(f"SHA-256 指纹: {cert.fingerprint(hashes.SHA256()).hex(':').upper()}")
    print(f"序列号:  {response.serial_number}")
    print(f"状态:    {status.name}")
    if status == ocsp.OCSPCertStatus.REVOKED:
        print(f"吊销时间: {response.revocation_time_utc}")
        if response.revocation_reason is not None:
            print(f"吊销原因: {response.revocation_reason.name}")
    print(f"this_update:  {response.this_update_utc}")
    print(f"next_update:  {response.next_update_utc}")
    print(f"签发者:    {issuer.subject.rfc4514_string()}")


def interactive():
    """无参数时的交互式输入：证书路径必填，其余可回车跳过"""
    print("=== 交互模式（直接回车使用默认值，输入 q 退出）===")

    # 证书路径：必填，循环直到存在（支持 ~ 展开）
    cert_path = os.path.expanduser(input("证书路径: ").strip())
    while True:
        if cert_path.lower() in ("q", "quit"):
            sys.exit(0)
        if os.path.isfile(cert_path):
            break
        print(f"  !! 文件不存在: {cert_path}")
        cert_path = os.path.expanduser(input("请重新输入证书路径 (q 退出): ").strip())

    # 签发者证书：可选，回车则走签发者目录 / AIA 自动获取
    issuer_path = os.path.expanduser(
        input("签发者证书路径 (回车则自动查签发者目录 / CA Issuers): ").strip())
    if issuer_path.lower() in ("q", "quit"):
        sys.exit(0)
    if issuer_path and not os.path.isfile(issuer_path):
        print(f"  !! 文件不存在: {issuer_path}，改为自动查找")
        issuer_path = ""

    # DER 格式：可选，默认 PEM；PEM/DER 会自动识别，选错也会回退
    d = input("DER 格式 (y/N，回车自动识别): ").strip().lower()
    if d in ("q", "quit"):
        sys.exit(0)
    der = d in ("y", "yes")

    # 超时：可选，回车默认 15；输入非数字时容错
    t = input("超时秒数 (回车默认 15): ").strip()
    if t.lower() in ("q", "quit"):
        sys.exit(0)
    try:
        timeout = int(t) if t else 15
    except ValueError:
        print(f"  !! '{t}' 不是数字，按默认 15 处理")
        timeout = 15

    # 只输出状态：可选，默认详细输出
    s = input("只输出状态 (y/N): ").strip().lower()
    if s in ("q", "quit"):
        sys.exit(0)
    status_only = s in ("y", "yes")

    # 保存原始 OCSP 响应：可选，回车跳过
    rp = os.path.expanduser(input("保存原始 OCSP 响应到文件 (回车跳过): ").strip())
    if rp.lower() in ("q", "quit"):
        sys.exit(0)

    check_cert(cert_path, issuer_path or None, der, status_only, timeout, rp or None)


def build_parser():
    ap = argparse.ArgumentParser(
        prog="check_ocsp.py",
        description="查询证书的 OCSP 状态（GOOD / REVOKED / UNKNOWN）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  check_ocsp.py certs/a.cer --status\n"
               "  check_ocsp.py certs/a.cer --issuer ca.pem --status\n"
               "  check_ocsp.py certs/a.cer --issuer-dir ./mycas --status\n"
               "  check_ocsp.py certs/a.cer --respout resp.der\n"
               "\n签发者来源优先级: --issuer → --issuer-dir → AIA 的 CA Issuers")
    ap.add_argument("cert", nargs="?", help="证书路径（PEM/DER 自动识别）")
    ap.add_argument("issuer_pos", nargs="?", metavar="签发者证书",
                    help="签发者证书路径（等价于 --issuer，兼容旧的位置参数写法）")
    ap.add_argument("--issuer", metavar="文件", help="签发者证书路径")
    ap.add_argument("--issuer-dir", action="append", metavar="目录",
                    help="签发者证书目录（可多次）；按证书 AKI 反查 SKI 自动匹配。"
                         f"指定后不再使用默认目录 {DEFAULT_ISSUER_DIR}")
    ap.add_argument("--der", action="store_true", help="证书按 DER 优先解析")
    ap.add_argument("--status", action="store_true", help="只输出状态，静默其他信息")
    ap.add_argument("--timeout", type=int, default=15, metavar="秒",
                    help="联网超时秒数（默认 15）")
    ap.add_argument("--respout", metavar="文件",
                    help="把 responder 原始响应(DER)保存到文件，供 zlint 跑 OCSP 规则")
    ap.add_argument("--sha256", action="store_true",
                    help="CertID 摘要用 SHA-256（默认 SHA-1，兼容性最好）。"
                         "注意 UNAUTHORIZED 与摘要算法无关")
    return ap


def main():
    enable_utf8_output()
    if len(sys.argv) == 1:          # 没有任何参数 → 交互模式
        interactive()
        return

    ap = build_parser()
    a = ap.parse_args()
    if not a.cert:
        ap.print_help()
        sys.exit(1)

    check_cert(a.cert, a.issuer or a.issuer_pos, a.der, a.status,
               a.timeout, a.respout,
               hashes.SHA256() if a.sha256 else hashes.SHA1(),
               a.issuer_dir)


if __name__ == "__main__":
    main()
