# -*- coding: utf-8 -*-
# 从 X.509 证书中提取 SCT 列表并解析每个 SCT 的 log ID / timestamp / 签名算法
# 归档于 zlint-all-lints check_certs_python/ct_audit/：log list 快照默认取
# 本目录 samples/log_list_v3_snapshot.json（时敏证据固定快照），无快照才在线拉取。
import base64, hashlib, json, os, struct, sys, urllib.request
from datetime import datetime, timezone

OID_CT_PRECERT_SCTS = bytes.fromhex('060a2b06010401d679020402')  # 1.3.6.1.4.1.11129.2.4.2

def read_octet_len(buf, q):
    """buf[q] 处为 OCTET STRING tag (0x04)，返回 (内容长度, 内容起始偏移)"""
    assert buf[q] == 0x04
    l = buf[q+1]; off = q + 2
    if l & 0x80:
        n = l & 0x7f
        l = int.from_bytes(buf[off:off+n], 'big')
        off += n
    return l, off

def extract_sct_list(der):
    """定位 CT 扩展 OID，返回 SignedCertificateTimestampList 原始字节"""
    i = der.find(OID_CT_PRECERT_SCTS)
    if i < 0:
        return None
    l, off = read_octet_len(der, i + len(OID_CT_PRECERT_SCTS))
    inner = der[off:off+l]
    # extnValue 的 OCTET STRING 内可能还有一层 OCTET STRING 包装
    while inner and inner[0] == 0x04:
        ll, q = read_octet_len(inner, 0)
        inner = inner[q:q+ll]
    # TLS 序列化: uint16 总长 + SCT 列表
    total = int.from_bytes(inner[0:2], 'big')
    return inner[2:2+total]

def parse_scts(data):
    """解析 TLS 序列化的 SCT 列表。
    RFC 6962: SignedCertificateTimestampList = uint16 sct_list_length + 若干带
    uint16 长度前缀的 SerializedSCT（version|log_id|timestamp|extensions|signature）"""
    scts, p = [], 0
    while p < len(data):
        slen = int.from_bytes(data[p:p+2], 'big'); p += 2   # 每个 SCT 的长度前缀
        sct = data[p:p+slen]; p += slen
        q = 0
        version = sct[q]; q += 1
        log_id = sct[q:q+32]; q += 32
        ts = int.from_bytes(sct[q:q+8], 'big'); q += 8
        elen = int.from_bytes(sct[q:q+2], 'big'); q += 2
        ext = sct[q:q+elen]; q += elen          # CtExtensions 数据（签名输入的一部分）
        hash_algo = sct[q]; sig_algo = sct[q+1]; q += 2
        slen2 = int.from_bytes(sct[q:q+2], 'big'); q += 2
        sig = sct[q:q+slen2]
        scts.append(dict(version=version, log_id=log_id, timestamp=ts,
                         hash_algo=hash_algo, sig_algo=sig_algo, sig=sig,
                         ext=ext))
    return scts

def script_dir():
    return os.path.dirname(os.path.abspath(__file__))


def snapshot_candidates():
    """log list 快照查找顺序: 脚本同目录 samples/ > 脚本同目录 > 当前目录"""
    return [os.path.join(script_dir(), 'samples', 'log_list_v3_snapshot.json'),
            os.path.join(script_dir(), 'log_list_v3_snapshot.json'),
            'log_list_v3_snapshot.json']


def load_log_list(cache=None):
    """拉取 Google 维护的公共 CT 日志列表 v3，建立 log_id -> 日志信息 映射。
    优先本地快照（log list 时敏，审计应固定快照；cache 参数指定时优先用，
    否则按 snapshot_candidates() 依次查找），全部缺失时才在线拉取。"""
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
    for op in data.get('operators', []):
        for arr in ('logs', 'tiled_logs'):
            for log in op.get(arr, []):
                lid = log.get('log_id')
                if lid:
                    raw = base64.b64decode(lid + '=' * (-len(lid) % 4))
                    mapping[raw] = dict(operator=op.get('name', '?'),
                                        name=log.get('description', '?'),
                                        url=log.get('url') or log.get('submission_url', '?'),
                                        state=log.get('state', {}))
    return mapping

def main():
    cert_path = (sys.argv[1] if len(sys.argv) > 1
                 else os.path.join(script_dir(), 'samples', 'baidu_new.pem'))
    with open(cert_path, encoding='utf-8') as f:
        pem = f.read()
    b64 = ''.join(pem.replace('-----BEGIN CERTIFICATE-----', '')
                     .replace('-----END CERTIFICATE-----', '').split())
    der = base64.b64decode(b64)
    print('== 证书基本信息 ==')
    print('DER 长度:', len(der))
    print('SHA256 指纹:', hashlib.sha256(der).hexdigest().upper())
    print('SHA256 指纹(带冒号):', ':'.join(hashlib.sha256(der).hexdigest().upper()[i:i+2] for i in range(0, 64, 2)))
    print()

    data = extract_sct_list(der)
    if data is None:
        print('未找到 CT Precertificate SCTs 扩展!')
        sys.exit(1)
    scts = parse_scts(data)
    print('== SCT 列表：共 %d 个 ==' % len(scts))
    print()

    mapping = load_log_list()
    for i, s in enumerate(scts, 1):
        lid = s['log_id']
        ts = datetime.fromtimestamp(s['timestamp'] / 1000, tz=timezone.utc)
        print('--- SCT #%d ---' % i)
        print('  version    : %d' % s['version'])
        print('  log_id     : %s' % base64.b64encode(lid).decode())
        print('  timestamp  : %d  (%s UTC)' % (s['timestamp'], ts.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]))
        print('  签名算法   : hash=%d sig=%d (4,1=SHA256+RSA 4,3=SHA256+ECDSA)' % (s['hash_algo'], s['sig_algo']))
        print('  签名长度   : %d 字节' % len(s['sig']))
        if lid in mapping:
            m = mapping[lid]
            print('  -> 匹配到日志: [%s] %s' % (m['operator'], m['name']))
            print('     URL       : %s' % m['url'])
            print('     state     : %s' % json.dumps(m['state'], ensure_ascii=False))
        else:
            print('  -> 未在 Google 日志列表中匹配到（可能是新日志/私有日志）')
        print()

if __name__ == '__main__':
    main()
