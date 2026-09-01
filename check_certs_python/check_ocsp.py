#!/usr/bin/env python3
"""
check_ocsp.py —— 用 Python 联网查询证书的 OCSP 状态

依赖: cryptography (OCSP 模块 2.6+ 即可)

流程:
    1. 从证书 AIA 扩展提取 OCSP URL（及 CA Issuers 下载地址）
    2. 加载签发者证书（命令行传入，或从 CA Issuers URL 自动下载）
    3. 构造 OCSP 请求并发给 responder（POST）
    4. 解析响应，输出 GOOD / REVOKED / UNKNOWN

用法:
    python3 check_ocsp.py <证书路径> [签发者证书路径] [--der] [--timeout 秒]
    python3 check_ocsp.py <证书路径> --status        # 只输出状态，静默其他信息
    python3 check_ocsp.py                            # 无参数 → 交互模式

注意:
    - 未提供签发者证书时会尝试从证书的 AIA 下载，可能因网络/防火墙失败
    - 本脚本只查询状态，不做 responder 响应签名验证
"""

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


def load_issuer(issuer_path, cert, ca_issuers_url, quiet=False):
    """优先用本地签发者证书，否则从 CA Issuers URL 下载"""
    if issuer_path:
        with open(issuer_path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())
    if ca_issuers_url:
        if not quiet:
            print(f"从 CA Issuers 下载签发者证书: {ca_issuers_url}")
        data = fetch_url(ca_issuers_url, quiet=quiet)
        try:
            return x509.load_der_x509_certificate(data)
        except ValueError:
            return x509.load_pem_x509_certificate(data)
    raise RuntimeError("未提供签发者证书，且证书 AIA 中没有 CA Issuers 地址")


def query_ocsp(cert, issuer, ocsp_url, timeout=15, quiet=False):
    """构造 OCSP 请求 → POST → 返回响应对象；http 失败自动试 https，失败重试"""
    urls = [ocsp_url]
    if ocsp_url.startswith("http://"):
        urls.append("https://" + ocsp_url[len("http://"):])

    der = (ocsp.OCSPRequestBuilder()
           .add_certificate(cert, issuer, hashes.SHA256())
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


def check_cert(cert_path, issuer_path=None, der=False, status_only=False, timeout=15):
    """加载证书并查询 OCSP，输出结果；失败时按模式输出错误并退出"""
    cert_path = os.path.expanduser(cert_path)
    if issuer_path:
        issuer_path = os.path.expanduser(issuer_path)

    with open(cert_path, "rb") as f:
        data = f.read()
    cert = (x509.load_der_x509_certificate(data) if der
            else x509.load_pem_x509_certificate(data))

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
        issuer = load_issuer(issuer_path, cert, ca_issuers_url, quiet=status_only)
    except Exception as e:
        if status_only:
            print(f"ERROR: 加载签发者证书失败: {e}", file=sys.stderr)
        else:
            print(f"\n加载签发者证书失败: {e}")
            print("替代方案: 用 openssl 从 TLS 连接拉取证书链，取第 2 张（签发者）")
            print("  1) openssl s_client -connect baidu.com:443 -showcerts </dev/null 2>/dev/null | awk '/BEGIN CERTIFICATE/{n++} n==2' > issuer.pem")
            print("  2) python3 check_ocsp.py <证书> issuer.pem")
        sys.exit(1)

    try:
        response = query_ocsp(cert, issuer, ocsp_url, timeout, quiet=status_only)
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

    # 签发者证书：可选，回车自动从 CA Issuers 下载
    issuer_path = os.path.expanduser(
        input("签发者证书路径 (回车自动从 CA Issuers 下载): ").strip())
    if issuer_path.lower() in ("q", "quit"):
        sys.exit(0)
    if issuer_path and not os.path.isfile(issuer_path):
        print(f"  !! 文件不存在: {issuer_path}，改为自动下载")
        issuer_path = ""

    # DER 格式：可选，默认 PEM
    d = input("DER 格式 (y/N): ").strip().lower()
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

    check_cert(cert_path, issuer_path or None, der, status_only, timeout)


def main():
    args = sys.argv[1:]

    if not args:                    # 没有任何参数 → 交互模式
        interactive()
        return

    cert_path = args[0]
    issuer_path = (args[1] if len(args) > 1
                   and not args[1].startswith("--") else None)
    der = "--der" in args
    status_only = "--status" in args
    timeout = 15
    if "--timeout" in args:
        timeout = int(args[args.index("--timeout") + 1])

    check_cert(cert_path, issuer_path, der, status_only, timeout)


if __name__ == "__main__":
    main()
