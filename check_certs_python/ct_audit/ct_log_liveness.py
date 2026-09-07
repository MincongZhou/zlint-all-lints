# -*- coding: utf-8 -*-
# 审计测试（第三层）：CT 日志在"审计时点"的存活性与密钥持有证明
#
# 对证书中每个嵌入 SCT 声称的日志：
#   1. 从 Google log list 快照取 公钥 / URL / 状态
#   2. 调日志 get-sth API（RFC 6962 §4.3）
#   3. 用该日志公钥验证 STH 签名（RFC 6962 §3.5）
#      STH signature input = version(1B=0) || signature_type(1B=tree_hash=1)
#                          || timestamp(8B) || tree_size(8B) || root_hash(32B)
#   4. 对照快照给出审计时点状态（usable/readonly/retired 等）
#
# STH 验签通过 => 日志当前在线、且持有与签发该 SCT 相同的私钥
#                （SCT 真实性 + 日志存活性 + 密钥保管 一条链闭环）
#
# 用法: python ct_log_liveness.py <证书.pem>
# 归档于 zlint-all-lints check_certs_python/ct_audit/：log list 快照默认取
# 本目录 samples/log_list_v3_snapshot.json（时敏证据固定快照），无快照才在线拉取。
import argparse
import base64, hashlib, json, os, sys, time, urllib.request
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

UA = {'User-Agent': 'workbuddy-audit/1.0 (WebTrust CT testing)'}

def read_pem(path):
    raw = open(path, 'rb').read()
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        return raw
    if '-----BEGIN' in text:
        b64 = ''.join(l.strip() for l in text.splitlines() if l and '-----' not in l)
        return base64.b64decode(b64)
    return raw

def script_dir():
    return os.path.dirname(os.path.abspath(__file__))


def snapshot_candidates():
    """log list 快照查找顺序: samples/ > 脚本目录 > 当前目录"""
    return [os.path.join(script_dir(), 'samples', 'log_list_v3_snapshot.json'),
            os.path.join(script_dir(), 'log_list_v3_snapshot.json'),
            'log_list_v3_snapshot.json']


def load_log_list(cache=None):
    """读取 Google 公共 CT 日志列表 v3 快照（cache 指定时优先用，否则按
    snapshot_candidates() 查找），全部缺失时才在线拉取。
    返回 (mapping, source)：mapping 以 log_id(bytes) 为键；source 为所用的
    快照文件路径，在线拉取时为 'online (<url>)'。"""
    url = 'https://www.gstatic.com/ct/log_list/v3/log_list.json'
    candidates = ([cache] if cache else []) + snapshot_candidates()
    data = None
    source = 'online (%s)' % url
    for cand in candidates:
        try:
            with open(cand, encoding='utf-8') as f:
                data = json.load(f)
            source = cand
            break
        except OSError:
            continue
    if data is None:
        with urllib.request.urlopen(url, timeout=30) as r:
            data = json.load(r)
    mapping = {}
    def st_name(st):
        if not isinstance(st, dict): return None
        if 'state' in st: return st['state']
        return next(iter(st), None)
    for op in data.get('operators', []):
        for arr in ('logs', 'tiled_logs'):
            for l in op.get(arr, []):
                lid = l.get('log_id')
                if lid:
                    raw = base64.b64decode(lid + '=' * (-len(lid) % 4))
                    ti = l.get('temporal_interval') or {}
                    mapping[raw] = dict(operator=op.get('name'),
                                        name=l.get('description'),
                                        state=st_name(l.get('state')),
                                        key=l.get('key'),
                                        url=l.get('url') or l.get('submission_url'),
                                        interval=(ti.get('start_inclusive'), ti.get('end_exclusive')))
    return mapping, source

def verify_sth(key_b64, sth):
    """RFC 6962 §3.5: 验证 STH 的 tree_head_signature"""
    ts = sth['timestamp']; size = sth['tree_size']
    root = base64.b64decode(sth['sha256_root_hash'])
    sig = base64.b64decode(sth['tree_head_signature'])
    # 解析 sig 里的算法字节（前 2 字节 hash+sig，其后 2 字节长度 + 签名）
    assert sig[0] == 4, 'STH hash algo != SHA256'
    sig_algo = sig[1]
    siglen = int.from_bytes(sig[2:4], 'big')
    raw_sig = sig[4:4 + siglen]
    signed = (b'\x00' + b'\x01'                       # v1 + tree_hash
              + ts.to_bytes(8, 'big')
              + size.to_bytes(8, 'big')
              + root)
    pub = load_der_public_key(base64.b64decode(key_b64))
    if sig_algo == 1:
        pub.verify(raw_sig, signed, padding.PKCS1v15(), hashes.SHA256())
    elif sig_algo == 3:
        pub.verify(raw_sig, signed, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError('STH sig_algo=%d' % sig_algo)

def get_sth(url):
    if not url.endswith('/'):
        url += '/'
    with urllib.request.urlopen(urllib.request.Request(url + 'ct/v1/get-sth', headers=UA), timeout=30) as r:
        return json.load(r)

def main():
    ap = argparse.ArgumentParser(
        description='L3 CT 日志存活性 / STH 验签（审计时点取证）')
    ap.add_argument('cert', nargs='?',
                    default=os.path.join(script_dir(), 'samples', 'baidu_new.pem'),
                    help='目标证书 PEM/DER（默认 samples/baidu_new.pem）')
    ap.add_argument('--sth-out', metavar='FILE',
                    help='把审计时点抓取的 STH 原文落盘为 JSON（含审计元数据与逐日志'
                         'STH，供事后复验/取证归档）')
    args = ap.parse_args()

    cert_path = args.cert
    cert_der = read_pem(cert_path)
    sys.path.insert(0, '.')
    from parse_sct import extract_sct_list, parse_scts
    scts = parse_scts(extract_sct_list(cert_der))
    logs, loglist_src = load_log_list()
    now = time.time()

    print('== CT 日志存活性 / STH 验签（审计时点 %s UTC）==' %
          datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))
    print('证书: %s  (SHA256 %s)' % (cert_path,
          ':'.join('%02X' % b for b in hashlib.sha256(cert_der).digest())))
    print()

    results = []
    for i, s in enumerate(scts, 1):
        info = logs.get(s['log_id'])
        ts = datetime.fromtimestamp(s['timestamp'] / 1000, tz=timezone.utc)
        rec = dict(sct_index=i,
                   log_id=base64.b64encode(s['log_id']).decode(),
                   sct_time_utc=ts.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3])
        results.append(rec)
        print('--- SCT #%d ---' % i)
        print('  声称日志: %s / %s' % (info['operator'] if info else '?',
                                        info['name'] if info else '?'))
        print('  SCT 时间: %s UTC' % rec['sct_time_utc'])
        if not info:
            rec.update(operator=None, log_name=None, snapshot_state=None,
                       verification='no_metadata', note='快照中未匹配到该 log_id')
            print('  [无日志元数据] 快照中未匹配'); print(); continue
        rec.update(operator=info['operator'], log_name=info['name'],
                   snapshot_state=info['state'],
                   temporal_interval=list(info['interval']),
                   url=info['url'])
        print('  快照状态: %s    temporal_interval: %s ~ %s' % (
            info['state'], info['interval'][0], info['interval'][1]))
        print('  API URL : %s' % info['url'])
        if not info.get('url') or not info.get('key'):
            rec.update(verification='skipped', note='无 URL 或公钥，无法调测')
            print('  [无法调测] 无 URL 或公钥'); print(); continue
        try:
            sth = get_sth(info['url'])
            verify_sth(info['key'], sth)
            sth_ts = sth['timestamp'] / 1000.0      # get-sth timestamp 单位=毫秒
            age = now - sth_ts
            rec.update(verification='pass', sth=sth,
                       sth_time_utc=datetime.fromtimestamp(sth_ts, tz=timezone.utc)
                                     .strftime('%Y-%m-%d %H:%M:%S'),
                       sth_age_seconds=round(age, 1))
            print('  get-sth : tree_size=%d  STH时间=%s UTC (%.0f 秒前)  root=%s' % (
                sth['tree_size'], rec['sth_time_utc'], age,
                base64.b64encode(base64.b64decode(sth['sha256_root_hash'])[:8]).decode() + '...'))
            print('  [通过] STH 签名有效 —— 日志在线，且持有签发该 SCT 的同一私钥')
            print('  说明  : tree_size 为当前树大小；SCT 条目包含性(inclusion)需另用')
            print('          get-proof-by-hash / monitor API 验证（RFC6962 §4.5）')
        except Exception as e:
            rec.update(verification='fail', error='%s: %s' % (type(e).__name__, e))
            print('  [失败] %s: %s' % (type(e).__name__, e))
        print()

    if args.sth_out:
        doc = dict(
            meta=dict(script='ct_log_liveness.py',
                      audit_time_utc=datetime.now(timezone.utc)
                                     .strftime('%Y-%m-%dT%H:%M:%SZ'),
                      cert_file=os.path.abspath(cert_path),
                      cert_sha256=':'.join('%02X' % b
                                           for b in hashlib.sha256(cert_der).digest()),
                      log_list_source=loglist_src),
            results=results)
        with open(args.sth_out, 'w', encoding='utf-8') as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)
        print('STH 证据已落盘: %s' % os.path.abspath(args.sth_out))

if __name__ == '__main__':
    main()
