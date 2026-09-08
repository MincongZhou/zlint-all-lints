#!/usr/bin/env python3
"""
find_cert_root.py —— 从任意一张证书出发，沿 issuer 一路追到根证书（root），
并把链顶与信任库（系统信任库 / 指定 bundle）做 SHA-256 指纹比对，
判断它是否构成当前环境的"信任锚"。

典型场景（审计核对"某证书的 root 是谁 / 是否被信任"）:
    1. 只有一张叶子证书：打印 issuer DN -> 到证书池 / AIA 里找签发者；
    2. 重复 issuer 匹配直到 subject == issuer（自签）-> 找到候选根；
    3. 自签不等于信任锚：拿链顶去信任库找同名根证书比对指纹；
    4. （可选）链完整时用 `openssl verify` 做整链终裁。

用法:
    python3 find_cert_root.py <证书路径|目录> [更多...] [选项]
    python3 find_cert_root.py                        # 单张证书 → 完整追链过程
    python3 find_cert_root.py certs/ --download      # 目录批量 → 逐张追链精简输出

选项:
    --pool DIR|FILE   证书池：目录会递归扫 *.pem/*.crt/*.cer/*.der，
                     单个文件则按 PEM bundle / 单张证书处理（把中间 CA / 根所在处指进来）
    --trust FILE      信任库 PEM bundle（默认自动找系统信任库）
    --download        允许联网：本地找不到上级时，从证书 AIA 的 CA Issuers 地址下载
    --no-openssl      跳过 openssl verify 整链终裁
    --csv 输出.csv    批量时输出汇总表（cert/root/trusted/openssl/chain_len/error）
    --detail          批量时保留每张的完整追链过程（默认每张一行结论）

批量说明:
    目录会递归收集 .pem/.crt/.cer/.der/.cert；证书池与信任库只加载一次，
    全部证书共用。退出码：全部处理成功 0，有加载失败 1
    （链中断 / 根不在信任库是审计结论，不算处理失败）。

示例:
    # 手里有中间 CA 文件，靠系统信任库确认根
    python3 find_cert_root.py baidu_new.pem --pool gsrsaovsslca2018.crt

    # 只有叶子，中间 CA 也从 AIA 下载（http 失败自动兜底 https）
    python3 find_cert_root.py certs/baidu.pem --download --trust cacert.pem

    # 指定一个证书池目录，目录里含中间 CA / 根证书
    python3 find_cert_root.py cert.pem --pool /path/to/ca_dir

    # 批量：一个目录里全部证书逐张追根，出汇总 CSV
    python3 find_cert_root.py certs/ --download --csv results/cert_roots.csv

依赖: pip install cryptography
"""

import argparse
import base64
import csv
import glob
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
import warnings

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import AuthorityInformationAccessOID

CERT_EXTS = (".pem", ".crt", ".cer", ".der", ".cert")

# ---------------- 解析 ----------------

def load_cert_bytes(data):
    """PEM / DER 自动识别加载单张证书（静音旧工具导出证书的噪音告警）"""
    for loader in (x509.load_pem_x509_certificate, x509.load_der_x509_certificate):
        try:
            with warnings.catch_warnings():
                # 信任库/样本里偶有负序列号等旧格式证书，cryptography 46 会告警；
                # 仅静音该类别噪音，不影响真实异常
                warnings.simplefilter("ignore", CryptographyDeprecationWarning)
                return loader(data)
        except ValueError:
            continue
    raise ValueError("无法解析：既不是合法 PEM 也不是 DER")


def load_cert(path):
    return load_cert_bytes(open(path, "rb").read())


def load_bundle(path):
    """加载 PEM bundle（容忍文件头注释行、多证书堆叠），返回证书列表"""
    text = open(path, encoding="utf-8", errors="replace").read()
    out = []
    for blob in re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                           text, re.S):
        raw = base64.b64decode("".join(blob.splitlines()[1:-1]))
        try:
            out.append(load_cert_bytes(raw))
        except ValueError:
            continue  # bundle 里偶有无法解析的块，跳过不致命
    return out


def collect_pool(spec):
    """证书池：单文件直接加载；目录则递归扫常见证书扩展名"""
    certs = []
    if os.path.isdir(spec):
        files = []
        for pat in ("*.pem", "*.crt", "*.cer", "*.der"):
            files += glob.glob(os.path.join(spec, "**", pat), recursive=True)
        for f in sorted(set(files)):
            try:
                if f.lower().endswith((".pem", ".crt", ".cer")):
                    certs += load_bundle(f)
                else:
                    certs.append(load_cert(f))
            except Exception as e:
                print(f"  (跳过 {f}: {e})")
    else:
        if spec.lower().endswith((".pem", ".crt", ".cer")):
            certs = load_bundle(spec)
        else:
            certs = [load_cert(spec)]
    return certs


def default_trust():
    """常见 Linux 系统信任库位置，找到即用"""
    for p in ("/etc/ssl/certs/ca-certificates.crt",
              "/etc/pki/tls/certs/ca-bundle.crt",
              "/etc/ssl/cert.pem"):
        if os.path.exists(p):
            print(f"使用系统信任库: {p}")
            return load_bundle(p)
    return []


def urlopen_any(url, timeout=15):
    """http 失败自动兜底 https"""
    urls = [url]
    if url.startswith("http://"):
        urls.append("https://" + url[len("http://"):])
    last = None
    for u in urls:
        try:
            with urllib.request.urlopen(u, timeout=timeout) as r:
                return r.read()
        except Exception as e:
            last = e
    raise last


# ---------------- 验签 ----------------

def signed_by(child, issuer_cert):
    """child 的签名能否被 issuer_cert 的公钥验证通过（支持 RSA PKCS1/PSS、ECDSA、Ed25519/Ed448）"""
    pub = issuer_cert.public_key()
    try:
        if child.signature_hash_algorithm is None:      # Ed25519 / Ed448
            if isinstance(pub, ed25519.Ed25519PublicKey):
                pub.verify(child.signature, child.tbs_certificate_bytes)
            elif isinstance(pub, ed448.Ed448PublicKey):
                pub.verify(child.signature, child.tbs_certificate_bytes)
            else:
                return False
        else:
            h = child.signature_hash_algorithm
            if isinstance(pub, rsa.RSAPublicKey):
                params = child.signature_algorithm_parameters
                if isinstance(params, padding.PSS):
                    # RSA-PSS：mgf / salt 长度尽量取签名参数里的，取不到则退化默认
                    mgf = getattr(params, "_mgf", padding.MGF1(h))
                    salt = getattr(params, "_salt_length", padding.PSS.MAX_LENGTH)
                    pub.verify(child.signature, child.tbs_certificate_bytes,
                               padding.PSS(mgf=mgf, salt_length=salt), h)
                else:
                    pub.verify(child.signature, child.tbs_certificate_bytes,
                               padding.PKCS1v15(), h)
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(h))
            else:
                return False
        return True
    except Exception:
        return False


# ---------------- 工具 ----------------

def fp_colon(cert):
    h = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def aia_ca_issuers(cert):
    """从 AIA 扩展提取 CA Issuers 下载地址"""
    try:
        aia = cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return []
    return [d.access_location.value for d in aia
            if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS]


def find_issuer(cert, pool):
    """在证书池里找 subject == cert.issuer 的上级证书，返回 (候选, 验签是否通过)"""
    cands = [c for c in pool if c.subject == cert.issuer]
    if not cands:
        return None, False
    for c in cands:
        if signed_by(cert, c):
            return c, True
    # DN 匹配但验签全部失败：同名不同钥，提示人工核对，仍返回第一张以便展示
    return cands[0], False


# ---------------- 主流程 ----------------

def expand_targets(paths):
    """展开输入：文件直接加入，目录递归收集常见证书扩展名。返回排序去重列表"""
    out = []
    for p in paths:
        p = os.path.expanduser(p)
        if os.path.isdir(p):
            out += [f for f in glob.glob(os.path.join(p, "**", "*"), recursive=True)
                    if os.path.isfile(f) and f.lower().endswith(CERT_EXTS)]
        elif os.path.isfile(p):
            out.append(p)
        else:
            print(f"错误: 路径不存在，跳过 -> {p}", file=sys.stderr)
    return sorted(set(out))


def trace_cert(cert_path, pool, trust, download=False, no_openssl=False,
               quiet=False):
    """从 cert_path 出发追链到根并与信任库比对（原单张主流程）。
    quiet=True 时不打印追链过程，仅返回结果 dict（批量精简模式用）。"""
    say = (lambda *a, **k: None) if quiet else print
    res = {"cert": cert_path, "root": "", "trusted": "", "openssl": "",
           "chain_len": 0, "error": ""}

    try:
        chain = [load_cert(cert_path)]
    except Exception as e:
        res["error"] = f"加载失败: {e}"
        return res
    say(f"起点: {chain[0].subject.rfc4514_string()}\n")

    seen = {chain[0].fingerprint(hashes.SHA256())}

    while True:
        cur = chain[-1]

        # 1) 到达候选根：subject == issuer 且自签验签通过
        if cur.subject == cur.issuer:
            if signed_by(cur, cur):
                say(f"[候选根] 自签验签通过: {cur.subject.rfc4514_string()}\n")
                break
            say(f"!! {cur.subject.rfc4514_string()} subject==issuer 但自签验签失败\n")

        # 2) 本地证书池里找上级
        nxt, verified = find_issuer(cur, pool)
        if nxt is not None:
            if not verified:
                say(f"!! DN 匹配但验签失败（同名不同钥？请人工核对）: "
                    f"{nxt.subject.rfc4514_string()}\n")
            else:
                say(f"[证书池] 验签通过: {nxt.subject.rfc4514_string()}\n")
            if nxt.fingerprint(hashes.SHA256()) in seen:
                say("!! 检测到证书链循环，停止追链\n")
                break
            seen.add(nxt.fingerprint(hashes.SHA256()))
            chain.append(nxt)
            continue

        # 3) 可选：从 AIA 下载第一跳
        if download:
            got = False
            stop_loop = False
            for url in aia_ca_issuers(cur):
                try:
                    data = urlopen_any(url)
                    cand = load_cert_bytes(data)
                    if cand.subject == cur.issuer and signed_by(cur, cand):
                        fp = cand.fingerprint(hashes.SHA256())
                        if fp in seen:
                            say(f"!! AIA 指向已在链中的证书，停止追链: {url}\n")
                            stop_loop = True
                            break
                        seen.add(fp)
                        say(f"[AIA 下载] {url}\n")
                        chain.append(cand)
                        got = True
                        break
                    say(f"  (下载内容 issuer 不匹配或验签失败: {url})")
                except Exception as e:
                    say(f"  (AIA 下载失败 {url}: {e})")
            if got and not stop_loop:
                continue
        break

    res["chain_len"] = len(chain)

    # ---- 输出整链 ----
    say("================ 追链结果（叶子 -> 根） ================")
    for i, c in enumerate(reversed(chain)):
        tag = "根(top)" if c.subject == c.issuer else ("叶子" if i == len(chain) - 1
                                                        else f"中间{i}")
        say(f"[{tag}] {c.subject.rfc4514_string()}")
        say(f"    issuer : {c.issuer.rfc4514_string()}")
        say(f"    SHA256 : {fp_colon(c)}")
    say("=======================================================")

    # ---- 链顶与信任库比对 -> 是否构成信任锚 ----
    top = chain[-1]
    if top.subject == top.issuer:
        res["root"] = top.subject.rfc4514_string()
        hits = [t for t in trust if t.subject == top.subject]
        if not hits:
            res["trusted"] = "否(不在信任库)"
            say(f"\n!! 信任库中没有同名根证书 —— 该根不是当前环境的信任锚")
        else:
            match = any(t.fingerprint(hashes.SHA256()) ==
                        top.fingerprint(hashes.SHA256()) for t in hits)
            res["trusted"] = "是" if match else "否(同名不同钥)"
            say(f"\n信任库命中 {len(hits)} 张同名根证书:")
            for t in hits:
                same = t.fingerprint(hashes.SHA256()) == top.fingerprint(hashes.SHA256())
                say(f"  信任库指纹: {fp_colon(t)}")
                say(f"  本地指纹:   {fp_colon(top)}")
                say(f"  一致: {'是 -> 该根就是信任锚' if same else '否（同名不同钥，勿信任）'}")
    else:
        res["trusted"] = "链中断"
        say(f"\n!! 链在 {top.subject.rfc4514_string()} 处中断，缺上级证书")
        say(f"   其 issuer = {top.issuer.rfc4514_string()}")
        if download:
            say("   已开 --download 仍中断：说明链顶证书的 AIA 里没有 CA Issuers 下载地址")
            say("   请把该上级 CA 的证书文件补进 --pool（或放信任库 bundle 里）")
        else:
            say("   可选：--pool 指向含上级 CA 的目录/文件，或加 --download 从 AIA 下载")

    # ---- openssl verify 整链终裁（锚为自签根时） ----
    if not no_openssl and top.subject == top.issuer and signed_by(top, top):
        with tempfile.TemporaryDirectory() as td:
            root_p = os.path.join(td, "root.pem")
            leaf_p = os.path.join(td, "leaf.pem")
            with open(root_p, "wb") as f:
                f.write(top.public_bytes(serialization.Encoding.PEM))
            with open(leaf_p, "wb") as f:
                f.write(chain[0].public_bytes(serialization.Encoding.PEM))
            cmd = ["openssl", "verify", "-CAfile", root_p]
            mids = chain[1:-1]
            if mids:
                untrusted_p = os.path.join(td, "untrusted.pem")
                with open(untrusted_p, "wb") as f:
                    f.write(b"".join(c.public_bytes(serialization.Encoding.PEM)
                                     for c in mids))
                cmd += ["-untrusted", untrusted_p]
            cmd.append(leaf_p)
            try:
                r = subprocess.run(cmd, capture_output=True, text=True)
                out = r.stdout.strip() or r.stderr.strip()
                res["openssl"] = "OK" if ": OK" in out else "FAIL"
                say(f"\nopenssl verify 终裁: {out}")
            except FileNotFoundError:
                say("\n(未找到 openssl，跳过终裁)")
    return res


def write_csv(path, results):
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:  # utf-8-sig 方便 Excel
        wr = csv.writer(f)
        wr.writerow(["cert", "root", "trusted", "openssl", "chain_len", "error"])
        for r in results:
            wr.writerow([r["cert"], r["root"], r["trusted"], r["openssl"],
                         r["chain_len"], r["error"]])


def main():
    ap = argparse.ArgumentParser(
        description="沿 issuer 追到根证书，并与信任库做指纹比对（判断信任锚）；"
                    "支持目录/多文件批量")
    ap.add_argument("certs", nargs="+", help="起点证书路径或目录（可多个）")
    ap.add_argument("--pool", help="证书池目录或文件（中间 CA / 根所在处）")
    ap.add_argument("--trust", help="信任库 PEM bundle（默认系统信任库）")
    ap.add_argument("--download", action="store_true",
                    help="允许联网：本地找不到上级时从 AIA CA-Issuers 下载")
    ap.add_argument("--no-openssl", action="store_true",
                    help="跳过 openssl verify 整链终裁")
    ap.add_argument("--csv", dest="csv_path", metavar="输出.csv",
                    help="批量时输出汇总表（cert/root/trusted/openssl/chain_len/error）")
    ap.add_argument("--detail", action="store_true",
                    help="批量时保留每张的完整追链过程（默认每张一行结论）")
    args = ap.parse_args()

    targets = expand_targets(args.certs)
    if not targets:
        print("错误: 没有找到任何证书文件", file=sys.stderr)
        sys.exit(1)

    # 证书池 / 信任库只加载一次，全部证书共用
    trust = load_bundle(args.trust) if args.trust else default_trust()
    pool = collect_pool(args.pool) if args.pool else []
    # 信任库里的自签根也并入"找上级"的来源：
    # 很多中间 CA 的 AIA 只带 OCSP、没有 CA Issuers（如 GlobalSign RSA OV SSL
    # CA 2018），最后一跳只能靠本地已有的根证书接上 —— 系统信任库就是现成一批。
    pool = pool + [t for t in trust if t.subject == t.issuer]

    # 单张且未要求 CSV → 保持原有的完整过程输出
    if len(targets) == 1 and not args.csv_path:
        trace_cert(targets[0], pool, trust, args.download, args.no_openssl)
        return

    print(f"批量模式: {len(targets)} 张证书（加 --detail 查看完整追链过程）\n")
    results = []
    for i, c in enumerate(targets, 1):
        print(f"[{i}/{len(targets)}] {c}")
        r = trace_cert(c, pool, trust, args.download, args.no_openssl,
                       quiet=not args.detail)
        if r["error"]:
            print(f"  ERROR: {r['error']}")
        else:
            root = r["root"] or "（链中断）"
            print(f"  -> 根: {root} | 信任锚: {r['trusted']} | "
                  f"openssl: {r['openssl'] or '-'} | 链长: {r['chain_len']}")
        results.append(r)

    ok = sum(1 for r in results if not r["error"])
    trusted = sum(1 for r in results if r["trusted"] == "是")
    print(f"\n============ 批量完成 ============")
    print(f"共 {len(results)} 张: 处理成功 {ok} / 失败 {len(results) - ok}；"
          f"构成信任锚 {trusted} 张")
    if args.csv_path:
        write_csv(args.csv_path, results)
        print(f"CSV: {args.csv_path}（{len(results)} 行）")
    sys.exit(0 if ok == len(results) else 1)


if __name__ == "__main__":
    main()
