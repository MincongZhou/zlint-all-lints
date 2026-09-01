#!/usr/bin/env python3
"""
extract_org.py —— 提取证书的组织名（O 字段）与 subject

依赖: cryptography（pip install cryptography）

用法:
    python3 extract_org.py <证书路径> [--der]     # 命令行模式（默认按 PEM，失败自动试 DER）
    python3 extract_org.py                        # 无参数 → 交互模式

输出:
    subject: CN=baidu.com,O=Baidu\\, Inc.,C=CN
    O 字段:  Baidu, Inc.
    （证书存在多个 O 属性时全部列出）
"""

import os
import sys
from cryptography import x509


def load_cert(cert_path, der=False):
    """按 PEM/DER 加载证书；未指定 --der 时 PEM 失败自动尝试 DER"""
    with open(cert_path, "rb") as f:
        data = f.read()
    if der:
        return x509.load_der_x509_certificate(data)
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        return x509.load_der_x509_certificate(data)


def extract_org(cert_path, der=False):
    """提取并打印 subject 与组织名（O 字段）"""
    cert_path = os.path.expanduser(cert_path)

    if not os.path.isfile(cert_path):
        print(f"错误: 文件不存在 -> {cert_path}", file=sys.stderr)
        sys.exit(1)

    try:
        cert = load_cert(cert_path, der)
    except ValueError as e:
        print(f"错误: 无法解析证书（PEM/DER 均失败）: {e}", file=sys.stderr)
        sys.exit(1)

    subject = cert.subject.rfc4514_string()          # "CN=baidu.com,O=Baidu\, Inc.,C=CN"
    org_names = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    orgs = [a.value for a in org_names] or ["未找到"]

    print(f"subject: {subject}")
    print(f"O 字段:  {'; '.join(orgs)}")


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

    d = input("DER 格式 (y/N): ").strip().lower()
    if d in ("q", "quit"):
        sys.exit(0)
    der = d in ("y", "yes")

    extract_org(cert_path, der)


def main():
    args = sys.argv[1:]

    if not args:                    # 没有任何参数 → 交互模式
        interactive()
        return

    der = "--der" in args
    cert_path = next((a for a in args if not a.startswith("--")), None)
    if not cert_path:
        print(__doc__)
        sys.exit(1)

    extract_org(cert_path, der)


if __name__ == "__main__":
    main()
