#!/usr/bin/env python3
"""
extract_sct.py —— 用 cryptography 提取证书里的 SCT（Signed Certificate Timestamp）

依赖 cryptography >= 42.0（原生支持解析 CT Precertificate SCTs 扩展，
OID 1.3.6.1.4.1.11129.2.4.2）。

用法:
    python3 extract_sct.py <证书路径> [--der]     # 命令行模式
    python3 extract_sct.py                         # 无参数 → 交互模式
"""

import datetime
import os
import sys
from cryptography import x509

SCT_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")


def format_sct(sct):
    """把 cryptography 原生解析出的 SCT 对象格式化为字典"""
    dt = sct.timestamp                               # naive UTC datetime（微秒精度）
    ts_ms = int(dt.replace(tzinfo=datetime.timezone.utc).timestamp() * 1000)
    return {
        "version": sct.version.name,
        "log_id": sct.log_id.hex().upper(),
        "timestamp_ms": ts_ms,
        "timestamp_utc": dt.strftime("%b %d %H:%M:%S.%f %Y") + " GMT",
        "hash_algorithm": sct.signature_hash_algorithm.name,
        "signature_algorithm": sct.signature_algorithm.name,
        "signature": sct.signature.hex().upper(),
    }


def get_scts(cert):
    """返回 SCT 字典列表；证书无 SCT 扩展时返回 None"""
    try:
        ext = cert.extensions.get_extension_for_oid(SCT_OID)
    except x509.ExtensionNotFound:
        return None
    return [format_sct(s) for s in ext.value]


def run(path, der=False):
    """解析证书并打印 SCT 信息"""
    with open(path, "rb") as f:
        data = f.read()

    cert = (x509.load_der_x509_certificate(data) if der
            else x509.load_pem_x509_certificate(data))

    scts = get_scts(cert)
    if scts is None:
        print("该证书没有 CT Precertificate SCTs 扩展")
        return

    print(f"共 {len(scts)} 个 SCT:\n")
    for i, s in enumerate(scts, 1):
        print(f"[{i}] Timestamp: {s['timestamp_utc']}")
        print(f"    epoch ms:  {s['timestamp_ms']}")
        print(f"    Log ID:    {s['log_id']}")
        print(f"    version:   {s['version']}")
        print()


def interactive():
    """无参数时的交互式输入：证书路径必填，格式可选"""
    print("=== 交互模式（直接回车使用默认值，输入 q 退出）===")

    # 证书路径：必填，循环直到文件存在（支持 ~ 展开）
    cert_path = os.path.expanduser(input("证书路径: ").strip())
    while True:
        if cert_path.lower() in ("q", "quit"):
            sys.exit(0)
        if os.path.isfile(cert_path):
            break
        print(f"  !! 文件不存在: {cert_path}")
        cert_path = os.path.expanduser(input("请重新输入证书路径 (q 退出): ").strip())

    # 证书格式：可选，回车默认 PEM
    fmt = input("证书格式 (回车默认 PEM, 输入 der 用 DER): ").strip().lower()
    der = fmt in ("der", "d")
    if der:
        print("  已选择 DER 格式")

    run(cert_path, der)


def main():
    args = sys.argv[1:]

    if not args:                    # 没有任何参数 → 交互模式
        interactive()
        return

    der = "--der" in args
    run(args[0], der)


if __name__ == "__main__":
    main()
