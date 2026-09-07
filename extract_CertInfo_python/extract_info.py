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

def extract_info(cert_path, der=False):
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

    print(cert)


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

def extract_issuer_org(cert_path, der=False):
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

    issuer = cert.issuer.rfc4514_string()          # "CN=baidu.com,O=Baidu\, Inc.,C=CN"
    org_names = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    orgs = [a.value for a in org_names] or ["未找到"]

    print(f"issuer: {issuer}")
    print(f"O 字段:  {'; '.join(orgs)}")


if __name__ == "__main__":
    # path = '../certs/baidu.com.pem'
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # 项目根
    path = os.path.join(ROOT, "certs", "baidu.pem")                     # 文件名也修正
    # extract_info(path)
    extract_issuer_org(path)