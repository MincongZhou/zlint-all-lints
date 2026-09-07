#!/usr/bin/env python3
"""
extract_org.py —— 提取证书主体（subject）与签发者（issuer）的组织名（O 字段）

依赖: cryptography（pip install cryptography）

用法:
    python3 extract_org.py <证书路径> [--der]     # 命令行模式（默认按 PEM，失败自动试 DER）
    python3 extract_org.py                        # 无参数 → 交互模式

输出:
    subject: CN=baidu.com,O=Baidu\\, Inc.,C=CN
    O 字段:  Baidu, Inc.
    issuer:  CN=GlobalSign RSA OV SSL CA 2018,O=GlobalSign nv-sa,C=BE
    签发者 O 字段: GlobalSign nv-sa
    （存在多个 O 属性时全部列出；无 O 字段时显示「未找到」）

供其他脚本调用（无需解析 stdout）:
    from extract_org import get_org_info
    info = get_org_info("certs/baidu.pem")
    # {'subject': ..., 'orgs': [...], 'orgs_str': ...,
    #  'issuer': ..., 'issuer_orgs': [...], 'issuer_orgs_str': ...}
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


def _org_names(name):
    """取 Name 里的组织名（O 字段）列表；不存在时返回 ['未找到']"""
    attrs = name.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    return [a.value for a in attrs] or ["未找到"]


def get_org_info(cert_path, der=False):
    """返回结构化结果 dict，供其他脚本直接 import 调用（无需解析 stdout）

    返回:
        subject / orgs / orgs_str                       主体（subject）的 DN 与组织名
        issuer / issuer_orgs / issuer_orgs_str          签发者（issuer）的 DN 与组织名
    异常: FileNotFoundError（文件不存在）/ ValueError（PEM、DER 均解析失败）
    """
    cert_path = os.path.expanduser(cert_path)

    if not os.path.isfile(cert_path):
        raise FileNotFoundError(f"文件不存在 -> {cert_path}")

    try:
        cert = load_cert(cert_path, der)
    except ValueError as e:
        raise ValueError(f"无法解析证书（PEM/DER 均失败）: {e}") from e

    subject = cert.subject.rfc4514_string()          # "CN=baidu.com,O=Baidu\, Inc.,C=CN"
    issuer = cert.issuer.rfc4514_string()            # 签发者 DN
    orgs = _org_names(cert.subject)
    issuer_orgs = _org_names(cert.issuer)

    return {
        "subject": subject,
        "orgs": orgs,
        "orgs_str": "; ".join(orgs),
        "issuer": issuer,
        "issuer_orgs": issuer_orgs,
        "issuer_orgs_str": "; ".join(issuer_orgs),
    }


def extract_org(cert_path, der=False):
    """提取并打印 subject / issuer 及其组织名（O 字段）

    注意: 前两行输出被 run_all.sh 等外部脚本按文本解析，格式请勿随意改动
    """
    try:
        info = get_org_info(cert_path, der)
    except (FileNotFoundError, ValueError) as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"subject: {info['subject']}")
    print(f"O 字段:  {info['orgs_str']}")
    print(f"issuer:  {info['issuer']}")
    print(f"签发者 O 字段: {info['issuer_orgs_str']}")


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
