# # pip install cryptography
# from cryptography import x509

# with open(cert_path, "rb") as f:
#     cert = x509.load_pem_x509_certificate(f.read())

# subject = cert.subject.rfc4514_string()     # "CN=baidu.com,O=Baidu\, Inc.,C=CN"
# not_after = cert.not_valid_after_utc        # datetime 对象


import subprocess
import os
import sys

def openssl_field(cert_path, flag):
    """调用 openssl 提取证书的单个字段，返回去前缀后的值"""
    result = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-noout", flag],
        capture_output=True,   # 捕获 stdout/stderr
        text=True,             # 按文本解码
        timeout=10,            # 防止卡死
    )
    if result.returncode != 0:
        raise RuntimeError(f"openssl 失败: {result.stderr.strip()}")
    # 输出形如 "subject=CN = baidu.com, O = Baidu, Inc., C = CN"，去掉 "xxx=" 前缀
    return result.stdout.strip().split("=", 1)[1]

cert_path = input("请输入证书路径：").strip()
if not os .path.isfile(cert_path):
    print(f"错误: 文件不存在 -> {cert_path}")
    sys.exit(1)

subject  = openssl_field(cert_path, "-subject")
issuer   = openssl_field(cert_path, "-issuer")
not_after = openssl_field(cert_path, "-enddate")

print("subject: ",subject)
print("issuer: ", issuer)
print("not after: ",not_after)

