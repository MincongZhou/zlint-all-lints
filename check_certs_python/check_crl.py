#!/usr/bin/env python3
"""
check_crl.py —— 从证书 CDP 扩展下载 CRL 并转成 PEM，供 zlint 跑 CRL 规则

zlint 对 CRL 输入会执行 18 条 CRL 规则；本脚本负责"下载 + 格式转换"，产物直接可喂:

    zlint -longSummary crl.pem           # 官方 zlint CLI
    ./zlint-all-lints -cert crl.pem      # 本项目的 Go 工具（自动识别输入类型）

流程:
    1. 加载目标证书（PEM/DER 自动识别）
    2. 从 CRL Distribution Points (CDP) 扩展提取 http(s) 下载地址
    3. 逐个下载直到成功（DER/PEM 自动识别，http 失败自动兜底 https + 重试）
    4. 统一转成 PEM 保存（默认 crl.pem），供 zlint 直接消费

用法:
    python3 check_crl.py <证书路径> [--timeout 秒] [--out 输出.pem]
    python3 check_crl.py                                # 无参数 → 交互模式

依赖: cryptography；同目录 check_ocsp.py（复用其下载与 PEM/DER 识别逻辑）
"""

import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

from check_ocsp import fetch_url, load_cert  # 复用：UA/兜底 https/重试 的下载 + 证书自动识别


def get_cdp_urls(cert):
    """返回证书 CRL Distribution Points 扩展里的全部 http(s) 下载地址"""
    try:
        cdp = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS).value
    except x509.ExtensionNotFound:
        return []
    urls = []
    for point in cdp:
        for name in (point.full_name or []):
            if isinstance(name, x509.UniformResourceIdentifier):
                url = name.value
                if url.startswith(("http://", "https://")):
                    urls.append(url)
    return urls


def download_crl_to_pem(cert_path, out_path="crl.pem", timeout=15):
    """下载第一张可用的 CDP CRL，DER/PEM 自动识别并统一输出 PEM"""
    cert_path = os.path.expanduser(cert_path)
    out_path = os.path.expanduser(out_path)
    if not os.path.isfile(cert_path):
        print(f"文件不存在: {cert_path}", file=sys.stderr)
        sys.exit(1)

    with open(cert_path, "rb") as f:
        cert = load_cert(f.read())

    print(f"证书: {cert.subject.rfc4514_string()}")
    urls = get_cdp_urls(cert)
    if not urls:
        print("该证书没有 CDP 扩展（或其中没有 http/https 分发点），无法下载 CRL")
        sys.exit(1)
    print(f"找到 {len(urls)} 个 CDP 分发点")

    data = None
    for url in urls:
        print(f"下载 CRL: {url}")
        try:
            data = fetch_url(url, timeout=timeout)
            break
        except Exception as e:
            print(f"  CDP 下载失败: {type(e).__name__}: {e}")
    if data is None:
        print("所有 CDP 分发点均下载失败", file=sys.stderr)
        sys.exit(1)

    raw = data
    if raw.lstrip().startswith(b"-----BEGIN"):
        # 已是 PEM：仍解析校验（防 HTML 错误页/误传证书）
        crl = x509.load_pem_x509_crl(raw)
    else:
        crl = x509.load_der_x509_crl(raw)
        data = crl.public_bytes(serialization.Encoding.PEM)

    with open(out_path, "wb") as f:
        f.write(data)
    print(f"CRL 签发者: {crl.issuer.rfc4514_string()}")
    print(f"this_update: {crl.last_update_utc}   next_update: {crl.next_update_utc}")
    print(f"已保存 (PEM): {out_path}")
    return out_path


def interactive():
    """无参数时的交互式输入：证书路径必填，其余可回车跳过"""
    print("=== 交互模式（直接回车使用默认值，输入 q 退出）===")

    cert_path = os.path.expanduser(input("证书路径: ").strip())
    while True:
        if cert_path.lower() in ("q", "quit"):
            sys.exit(0)
        if os.path.isfile(cert_path):
            break
        print(f"  !! 文件不存在: {cert_path}")
        cert_path = os.path.expanduser(input("请重新输入证书路径 (q 退出): ").strip())

    t = input("超时秒数 (回车默认 15): ").strip()
    if t.lower() in ("q", "quit"):
        sys.exit(0)
    try:
        timeout = int(t) if t else 15
    except ValueError:
        print(f"  !! '{t}' 不是数字，按默认 15 处理")
        timeout = 15

    o = os.path.expanduser(input("输出文件 (回车默认 crl.pem): ").strip())
    if o.lower() in ("q", "quit"):
        sys.exit(0)

    download_crl_to_pem(cert_path, o or "crl.pem", timeout)


def main():
    args = sys.argv[1:]

    if not args:                    # 没有任何参数 → 交互模式
        interactive()
        return

    timeout = 15
    out_path = "crl.pem"
    rest = []
    i = 0
    while i < len(args):
        if args[i] == "--timeout":
            timeout = int(args[i + 1])
            i += 2
        elif args[i] == "--out":
            out_path = args[i + 1]
            i += 2
        else:
            rest.append(args[i])
            i += 1

    if not rest:
        print("用法: python3 check_crl.py <证书路径> [--timeout 秒] [--out 输出.pem]")
        sys.exit(1)

    download_crl_to_pem(rest[0], out_path, timeout)


if __name__ == "__main__":
    main()
