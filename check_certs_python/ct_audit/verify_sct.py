# -*- coding: utf-8 -*-
# 审计测试：验证证书中嵌入式 SCT 的签名真实性（RFC 6962 §3.2）
#
# 用法: python verify_sct.py <证书.pem|.der> <签发者CA.crt|.der>
# 例  : python verify_sct.py baidu_new.pem gsrsaovsslca2018.crt
#
# ---------------------------------------------------------------
# v2 修正（2026-09-02，源码级核对，替换 v1 的 poison 插入方案）
# ---------------------------------------------------------------
# 权威实现三方交叉验证，确认"嵌入式 SCT 验签的 precert TBS 重建"规则：
#
#   [验证方-Google ct-go] ct/serialization.go MerkleTreeLeafForEmbeddedSCT():
#       tbs, err := x509.RemoveSCTList(cert.RawTBSCertificate)   # 只删 SCT 扩展
#       PreCert{IssuerKeyHash: sha256(issuer.RawSubjectPublicKeyInfo),
#               TBSCertificate: tbs}
#
#   [验证方-Chrome] net/cert/ct_objects_extractor.cc
#       GetPrecertSignedEntry(): 注释原文
#       "Copy all extensions except the embedded SCT extension."
#       —— 同样只排除 SCT 扩展，不插 poison。
#
#   [日志方-Google ct-go] x509.BuildPrecertTBS() 处理 CA 提交的 precert 时
#       调用 removeExtension(tbs, OIDExtensionCTPoison)：
#       "remove the CT poison extension" —— 日志侧对 precert TBS 摘掉 poison。
#
#   => 两侧收敛到同一个 "defanged TBS"（既无 poison 也无 SCT 扩展）：
#      日志签发 SCT 时    = CA提交的precert TBS - poison
#      验证方重建验签输入 = 最终证书 TBS - SCT 扩展
#      两者字节一致的前提是 CA 按 RFC6962 规范构造（final 与 precert 仅
#      poison<->SCT 扩展互换，其余字段/顺序不变）。
#      poison 只是 CA->日志 提交链上的标记，不进入 Merkle leaf 与 SCT 签名输入。
#
#   v1 的错误：往重建 TBS 里插 poison（3 种位置模式），导致 0/3、0/2 全失败。
#
# 签名输入（RFC 6962 §3.2 / ct-go tls.Marshal 等价）：
#   SCT signature input =
#       0x00                      # sct_version = v1
#     || 0x00                      # signature_type = certificate_timestamp
#     || timestamp (8B, 大端)
#     || 0x0001                    # entry_type = precert_entry
#     || issuer_key_hash (32B)     # = SHA256(最终证书签发者 SPKI DER)
#     || TBSCertificate            # defanged TBS，opaque<1..2^24-1> 需 3B 长度前缀
#     || CtExtensions             # 2B 长度前缀 + SCT 自带扩展数据
#                                  # (precert 通常空=0000；非空必须按 SCT 原样拼接)
#   实测案例(2026-09-02, LE letsencrypt.org / Gouda2026h2): SCT 携带 8 字节扩展
#   0000050026d85d88 —— 硬编码空扩展会导致验签失败；按 RFC 拼接后通过。
# ---------------------------------------------------------------
# 归档于 zlint-all-lints check_certs_python/ct_audit/：log list 快照默认取
# 本目录 samples/log_list_v3_snapshot.json（时敏证据固定快照），无快照才在线拉取。
import base64, hashlib, json, os, sys, urllib.request
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

OID_CT_PRECERT_SCTS = bytes.fromhex('2b06010401d679020402')  # 1.3.6.1.4.1.11129.2.4.2 内容(去06标签)
OID_CT_POISON       = bytes.fromhex('2b06010401d679020403')  # .4.3 仅作对照参考，不再插入

# ---------------------------------------------------------------- DER helpers
def read_tlv(buf, p):
    tag = buf[p]; p += 1
    l = buf[p]; p += 1
    if l & 0x80:
        n = l & 0x7f
        l = int.from_bytes(buf[p:p+n], 'big'); p += n
    return tag, p, p + l

def encode_len(n):
    if n < 0x80: return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b

def tlv(tag, content):
    return bytes([tag]) + encode_len(len(content)) + content

def children(buf, start, end):
    """解析 SEQUENCE 内容区[start,end)内所有 child，返回 (tag, TLV起点, 结束偏移)"""
    out, p = [], start
    while p < end:
        s = p
        tag, _, ce = read_tlv(buf, p)
        out.append((tag, s, ce)); p = ce
    return out

def read_pem(path):
    """读取证书/CRL 文件，自动兼容 PEM / DER"""
    raw = open(path, 'rb').read()
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        return raw                       # DER
    if '-----BEGIN' in text:
        b64 = ''.join(l.strip() for l in text.splitlines() if l and '-----' not in l)
        return base64.b64decode(b64)
    return raw

def cert_children(der):
    """纯 DER 解析 X.509 证书：返回 (tbs_children, issuer_spki_der, issuer_der)。
    直接取 DER 原字节切片，与 ct-go RawSubjectPublicKeyInfo / Chrome
    ExtractSPKIFromDERCert 的语义一致（不经任何重序列化）。"""
    _, cs0, _ = read_tlv(der, 0)
    _, _, tce = read_tlv(der, cs0)           # 首 child = tbs；内容终点即 TLV 终点
    tbs = der[cs0:tce]                       # tbs TLV 整段（含 SEQUENCE 头）
    _, content_s, _ = read_tlv(tbs, 0)
    chs = children(tbs, content_s, len(tbs))
    # tbs 字段序: [a0 version(可选)] 02 serial | 30 sig | 30 issuer | 30 validity
    #            | 30 subject | 30 spki | a3 extensions(可选)
    base = 1 if chs[0][0] == 0xa0 else 0
    spki = chs[base + 5]                     # version 后第 6 个 = subjectPublicKeyInfo
    issuer = chs[base + 2]                   # issuer 字段
    return chs, tbs[spki[1]:spki[2]], tbs[issuer[1]:issuer[2]]

# ---------------------------------------------------------------- 核心重建
def build_precert_tbs(cert_der):
    """按 ct-go x509.RemoveSCTList / Chrome GetPrecertSignedEntry 重建 precert TBS：
    仅删除 CT SCT 扩展（必须恰好 1 个），其余扩展保序、逐字节保留；不插 poison。
    返回 DER 编码的新 tbsCertificate。"""
    _, cs0, _ = read_tlv(cert_der, 0)
    _, tcs, tce = read_tlv(cert_der, cs0)
    tbs = cert_der[cs0:tce]                      # 完整 tbs TLV（含 SEQUENCE 头）
    _, content_s, _ = read_tlv(tbs, 0)
    chs = children(tbs, content_s, len(tbs))     # tbs 顶层 children
    idx_a3 = next(i for i, (t, _, _) in enumerate(chs) if t == 0xa3)
    _, ext_cs, ext_ce = read_tlv(tbs, chs[idx_a3][1])   # a3 content = extensions 序列
    ext_seq = tbs[ext_cs:ext_ce]
    _, xcs, _ = read_tlv(ext_seq, 0)
    exts = children(ext_seq, xcs, len(ext_seq))

    removed = 0
    kept = []
    for (tag, s, e) in exts:
        item = ext_seq[s:e]
        _, es, _ = read_tlv(item, 0)
        _, ocs, oce = read_tlv(item, es)         # Extension 第1元素 = OID
        if item[ocs:oce] == OID_CT_PRECERT_SCTS:
            removed += 1
            continue                             # 丢弃 SCT 扩展（Chrome: copy all except）
        kept.append(item)
    if removed != 1:
        raise ValueError('SCT 扩展数量为 %d（ct-go 要求恰好 1 个）' % removed)

    new_ext_seq = tlv(0x30, b''.join(kept))
    new_a3 = tlv(0xa3, new_ext_seq)
    rebuilt = [new_a3 if i == idx_a3 else tbs[s:e] for i, (t, s, e) in enumerate(chs)]
    return tlv(0x30, b''.join(rebuilt))

# ---------------------------------------------------------------- 验签
def sct_signature_input(ts, issuer_spki_der, tbs, ext=b''):
    """RFC 6962 §3.2 precert_entry 签名输入字节串。
    ext = SCT 自带 CtExtensions 数据（不含长度前缀）；序列化时按
    opaque<0..2^16-1> 补 2 字节长度前缀。precert 通常为空（00 00），
    但若日志回填了非空扩展，必须原样拼接（见 2026-09-02 LE/Gouda 案例）。"""
    ihash = hashlib.sha256(issuer_spki_der).digest()
    return (b'\x00'                       # sct_version
            + b'\x00'                     # signature_type = certificate_timestamp
            + ts.to_bytes(8, 'big')
            + b'\x00\x01'                 # entry_type = precert_entry
            + ihash                       # issuer_key_hash (32B)
            + len(tbs).to_bytes(3, 'big') # opaque TBSCertificate<1..2^24-1>
            + tbs
            + len(ext).to_bytes(2, 'big') # CtExtensions opaque<0..2^16-1>
            + ext)

def verify_one(sct, cert_der, issuer_spki_der, log_key_b64):
    tbs = build_precert_tbs(cert_der)
    signed = sct_signature_input(sct['timestamp'], issuer_spki_der, tbs,
                                 sct.get('ext', b''))
    pub = load_der_public_key(base64.b64decode(log_key_b64))
    if sct['sig_algo'] == 1:              # rsa, RFC6962 alg=1
        pub.verify(sct['sig'], signed, padding.PKCS1v15(), hashes.SHA256())
    elif sct['sig_algo'] == 3:            # ecdsa, RFC6962 alg=3 (DER 编码)
        pub.verify(sct['sig'], signed, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError('不支持的签名算法 sig_algo=%d' % sct['sig_algo'])
    return True, tbs

# ---------------------------------------------------------------- 日志列表
def script_dir():
    return os.path.dirname(os.path.abspath(__file__))


def snapshot_candidates():
    """log list 快照查找顺序: samples/ > 脚本目录 > 当前目录"""
    return [os.path.join(script_dir(), 'samples', 'log_list_v3_snapshot.json'),
            os.path.join(script_dir(), 'log_list_v3_snapshot.json'),
            'log_list_v3_snapshot.json']


def load_log_list(cache=None):
    """读取 Google 公共 CT 日志列表。优先本地快照文件（审计证据：log list 是
    时敏数据，应固定审计时点的快照；cache 参数指定时优先用，否则按
    snapshot_candidates() 查找），全部缺失时才在线拉取。"""
    url = 'https://www.gstatic.com/ct/log_list/v3/log_list.json'
    candidates = ([cache] if cache else []) + snapshot_candidates()
    data = None
    for cand in candidates:
        try:
            with open(cand, encoding='utf-8') as f:
                data = json.load(f)
            break
        except OSError:
            continue
    if data is None:
        with urllib.request.urlopen(url, timeout=30) as r:
            data = json.load(r)
    mapping = {}
    def st_name(st):
        # 兼容两种 state 结构：{"state":"usable"} 或 {"usable":{...}}
        if not isinstance(st, dict): return None
        if 'state' in st: return st['state']
        return next(iter(st), None)
    for op in data.get('operators', []):
        for arr in ('logs', 'tiled_logs'):
            for log in op.get(arr, []):
                lid = log.get('log_id')
                if lid:
                    raw = base64.b64decode(lid + '=' * (-len(lid) % 4))
                    mapping[raw] = dict(operator=op.get('name'),
                                        name=log.get('description'),
                                        state=st_name(log.get('state')),
                                        key=log.get('key'))
    return mapping

# ---------------------------------------------------------------- 主流程
def main():
    cert_path  = sys.argv[1] if len(sys.argv) > 1 \
        else os.path.join(script_dir(), 'samples', 'baidu_new.pem')
    issuer_path = sys.argv[2] if len(sys.argv) > 2 \
        else os.path.join(script_dir(), 'samples', 'gsrsaovsslca2018.crt')
    cert_der  = read_pem(cert_path)
    issuer_der = read_pem(issuer_path)

    # issuer_key_hash 输入 = 最终证书签发者 SPKI 的 DER 原字节
    # (ct-go RawSubjectPublicKeyInfo / Chrome ExtractSPKIFromDERCert)
    chs_i, issuer_spki_der, issuer_name_der = cert_children(issuer_der)
    print('issuer SPKI DER 长度: %d 字节' % len(issuer_spki_der))

    # 证书基本信息（供底稿）
    fp = hashlib.sha256(cert_der).digest()
    print('证书 SHA256 = %s' % ':'.join('%02X' % b for b in fp))

    sys.path.insert(0, '.')
    from parse_sct import extract_sct_list, parse_scts
    data = extract_sct_list(cert_der)
    if data is None:
        print('未找到 SCT 扩展'); sys.exit(1)
    scts = parse_scts(data)
    logs = load_log_list()

    print('== SCT 签名真实性验证（RFC 6962 §3.2 / ct-go RemoveSCTList 语义）==')
    print('证书  : %s' % cert_path)
    print('签发者: %s' % issuer_path)
    print('issuer_key_hash = SHA256(签发者SPKI) = %s' % hashlib.sha256(issuer_spki_der).hexdigest())
    print('SCT 数: %d' % len(scts))
    print()

    ok = 0
    for i, s in enumerate(scts, 1):
        lid = s['log_id']
        ts = datetime.fromtimestamp(s['timestamp'] / 1000, tz=timezone.utc)
        info = logs.get(lid)
        print('--- SCT #%d ---' % i)
        print('  声称日志   : %s / %s (state=%s)' % (
            info['operator'] if info else '?',
            info['name'] if info else '?',
            info['state'] if info else '?'))
        print('  log_id     : %s' % base64.b64encode(lid).decode())
        print('  timestamp  : %s UTC' % ts.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3])
        if not info or not info.get('key'):
            print('  [无法验证] 日志公钥缺失（未在 Google log list 中）')
            continue
        try:
            verify_one(s, cert_der, issuer_spki_der, info['key'])
            ok += 1
            print('  [通过] 该 SCT 是日志运营方用其公钥对这张证书(precert)的'
                  '真实签名（defanged TBS 重建成功）')
        except Exception as e:
            print('  [失败] %s' % e)
        print()
    print('== 结果: %d/%d 个 SCT 验签通过 ==' % (ok, len(scts)))
    print('验签通过 => 收据不是伪造：签发 SCT 的实体持有对应日志私钥，')
    print('且证书确实以 precert 形式投递过该日志。')

if __name__ == '__main__':
    main()
