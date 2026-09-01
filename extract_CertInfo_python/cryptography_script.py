# pip install cryptography
from cryptography import x509
import os
import sys

# 示例：/home/administrator/projects/baidu.pem
cert_path = input("请输入证书路径：").strip()
if not os .path.isfile(cert_path):
    print(f"错误: 文件不存在 -> {cert_path}")
    sys.exit(1)

with open(cert_path, "rb") as f:
    cert = x509.load_pem_x509_certificate(f.read())

subject = cert.subject.rfc4514_string()     # "CN=baidu.com,O=Baidu\, Inc.,C=CN"
not_after = cert.not_valid_after_utc        # datetime 对象

print(subject)
# print(not_after)

org_names = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
# print(org_names)
print(org_names[0].value if org_names else "未找到")
