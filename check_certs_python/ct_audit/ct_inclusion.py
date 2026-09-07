#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ct_inclusion.py —— L4 包含性审计：拿 SCT 去 CT log 查"这张证书的条目是否真的在树里"

背景: L2 验签通过只证明 SCT 是日志私钥的真实签名（收据真实），L3 证明日志在线且
密钥未换。但日志在"承诺收"与"真正入树"之间存在兑现间隙——若日志只签不收
（错误实现 / 数据库丢失 / 运营违规），L2/L3 全绿也发现不了。本脚本用日志 API
（RFC 6962 §4.x / RFC 9162 §4.x）做 inclusion（包含性）验证：

  1. 从证书 SCT 重建 MerkleTreeLeaf（RFC 9162 §4.3；字节与 verify_sct 的
     precert 签名输入完全一致）并计算 leaf hash = SHA256(0x00 || MerkleTreeLeaf)
  2. 调日志 get-sth 取当前 tree_size 与根哈希
  3. 用 get-entries 定位该叶子的索引 leaf_index：
     先按"条目时间戳随索引近似单调"做二分下界，再线性比对 leaf_input 原字节
     （SCT timestamp 由日志在入树时分配，leaf 内时间戳与 SCT 内时间戳相同）
  4. 取 Merkle audit path（RFC 9162 get-entry-and-proof，回退 RFC 6962
     get-proof-by-hash）并用 STH 根做密码学 inclusion 验证
     （RFC 6962 §3.4.2 / RFC 9162 §2.1.3 的兄弟路径算法）

判定（逐 SCT）:
  - PASS        : leaf 定位成功 且 audit path 验证通过 → 条目确在树中，SCT 兑现
  - 观察        : leaf 已定位但日志不支持任何 proof 端点（需监控服务佐证）/
                  快照未匹配到日志元数据 / 定位区间超限
  - 不一致(退出码1): 树中不存在该 leaf（扫描区间内找不到）——声明入树未兑现
  - 无法验证     : 日志 API 整体不可达（网络/TLS），记 error 不计失败

审计提示: leaf 字节比对成立的前提是 CA 按 RFC 9162 规范构造最终证书（仅
poison <-> SCT 扩展互换、其余字段与顺序不变）；不匹配可能是"真不在树"，也
可能是 CA 重签导致顺序漂移（需人工复核，详见 verify_sct.py 头部注释）。

用法:
    python3 check_certs_python/ct_audit/ct_inclusion.py <证书.pem|.der> [--issuer 签发者]
    python3 check_certs_python/ct_audit/ct_inclusion.py samples/baidu_new.pem
    python3 check_certs_python/ct_audit/ct_inclusion.py certs/ --issuer iss.crt --csv out.csv
    python3 check_certs_python/ct_audit/ct_inclusion.py cert.pem --loglist my.json --offline

选项:
    --issuer <文件>    签发者证书（默认 samples/gsrsaovsslca2018.crt，即 baidu 演示链）
    --loglist <文件>   指定 log list v3 快照（默认按 samples/ 自动找）
    --offline          无本地快照时报错，不回退在线拉取
    --max-scan <N>     线性比对上限（默认 50000 条；命中即停，仅用于防失控）
    --timeout <秒>     联网超时，默认 20
    --csv <文件>       汇总导出 CSV（每 SCT 一行）
    --quiet            每张证书只打印一行结论（批量自动打开）

退出码: 存在任何"不一致" → 1; 其余 → 0（观察/网络失败不计为不一致）
依赖: python3 + cryptography；复用同目录 parse_sct.py 与 verify_sct.py
"""
import argparse
import base64
import csv
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse_sct import extract_sct_list, parse_scts          # noqa: E402
from verify_sct import (read_pem, cert_children,            # noqa: E402
                        build_precert_tbs, sct_signature_input)

UA = {'User-Agent': 'workbuddy-audit/1.0 (WebTrust CT testing)'}


# ---------------------------------------------------------------- Merkle 核心
def leaf_hash_of(leaf_input):
    """RFC 6962 §2.1: 叶哈希 = SHA256(0x00 || MerkleTreeLeaf)"""
    return hashlib.sha256(b'\x00' + leaf_input).digest()


def node_hash(l, r):
    """内部节点哈希 = SHA256(0x01 || 左子哈希 || 右子哈希)"""
    return hashlib.sha256(b'\x01' + l + r).digest()


def root_from_audit_path(leaf_hash, index, size, proof):
    """RFC 6962 §3.4.2 / RFC 9162 §2.1.3 的兄弟路径算法：
    从叶子逐层向上重建根；证明数组只含"有兄弟的层"的兄弟节点，
    最右链（index == 该层最后节点）无兄弟，直接提升不消费证明。
    返回重建的根哈希；与 STH 的 sha256_root_hash 比对即完成 inclusion 验证。
    内部附同源实现 selftest（-t）可自证算法一致性。"""
    fn = leaf_hash
    r = index            # 当前节点在"当前层子树"内的偏移
    sn = size - 1        # 当前层最后节点的全局索引
    p = 0
    while sn > 0:
        if r % 2 == 1:                       # 右孩子：左兄弟在前
            if p >= len(proof):
                raise ValueError('audit path 缺少左兄弟节点')
            fn = node_hash(proof[p], fn)
            p += 1
        elif r == sn:                        # 最右链：无兄弟，提升
            pass
        else:                                # 左孩子：右兄弟在后
            if p >= len(proof):
                raise ValueError('audit path 缺少右兄弟节点')
            fn = node_hash(fn, proof[p])
            p += 1
        r >>= 1
        sn >>= 1
    if p != len(proof):
        raise ValueError('audit path 含多余节点（%d/%d）' % (p, len(proof)))
    return fn


# ---------------------------------------------------------------- 自检
def _split(n):
    """CT 树递归分解: 左子树取严格小于 n 的最大 2 的幂（RFC 9162 §2.1.1.2）"""
    if n <= 1:
        return n
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(leaves, lo, hi):
    """构造 [lo,hi) 叶区间子树的根哈希（叶哈希 = leaf_hash_of）"""
    if hi - lo == 1:
        return leaves[lo]
    k = _split(hi - lo)
    return node_hash(_mth(leaves, lo, lo + k), _mth(leaves, lo + k, hi))


def _audit_path(leaves, lo, hi, m):
    """递归构造叶 m（全局索引）在 [lo,hi) 树中的 audit path（RFC 9162 §2.1.3）。
    返回顺序为叶→根：先内层兄弟、后外层兄弟（与日志 API 返回一致）"""
    n = hi - lo
    if n == 1:
        return []
    k = lo + _split(n)
    if m < k:                              # 在左子树：兄弟是右子树根
        return _audit_path(leaves, lo, k, m) + [_mth(leaves, k, hi)]
    return _audit_path(leaves, k, hi, m) + [_mth(leaves, lo, k)]


def selftest():
    """在内存构造 1..12 叶随机树，全索引验证 root_from_audit_path 与
    MTH/PATH 递归定义一致（两套算法互相独立，防实现同错）"""
    for size in range(1, 13):
        leaves = [hashlib.sha256(bytes([i]) * 37).digest()
                  for i in range(size)]
        root = _mth(leaves, 0, size)
        for idx in range(size):
            path = _audit_path(leaves, 0, size, idx)
            got = root_from_audit_path(leaves[idx], idx, size, path)
            assert got == root, (size, idx)
    return True


# ---------------------------------------------------------------- 日志 API
def script_dir():
    return os.path.dirname(os.path.abspath(__file__))


def snapshot_candidates():
    return [os.path.join(script_dir(), 'samples', 'log_list_v3_snapshot.json'),
            os.path.join(script_dir(), 'log_list_v3_snapshot.json'),
            'log_list_v3_snapshot.json']


def load_log_list(cache=None, offline=False):
    """log_id -> (operator, name, state, url)；无本地快照时在线拉取，
    offline=True 则无快照直接报错（取证纪律）。"""
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
        if offline:
            sys.exit('错误: 无本地 log list 快照（--offline），请用 --loglist 指定')
        with urllib.request.urlopen(url, timeout=30) as r:
            data = json.load(r)
    mapping = {}

    def st_name(st):
        if not isinstance(st, dict):
            return None
        if 'state' in st:
            return st['state']
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
                                        url=log.get('url') or log.get('submission_url'))
    return mapping


def http_get(url, timeout):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def get_sth(url, timeout):
    st, body = http_get(url.rstrip('/') + '/ct/v1/get-sth', timeout)
    if st != 200:
        raise RuntimeError('get-sth HTTP %d' % st)
    return json.loads(body)


def get_entries(url, start, end, timeout):
    """返回 [{leaf_input, extra_data, ...}]（索引含两端）"""
    st, body = http_get(
        url.rstrip('/') + '/ct/v1/get-entries?start=%d&end=%d' % (start, end), timeout)
    if st != 200:
        raise RuntimeError('get-entries HTTP %d' % st)
    return json.loads(body).get('entries', [])


def get_entry_and_proof(url, index, size, timeout):
    """RFC 9162: leaf_index 已知时返回 {leaf_input, extra_data, audit_path}"""
    st, body = http_get(url.rstrip('/') + '/ct/v1/get-entry-and-proof'
                        '?leaf_index=%d&tree_size=%d' % (index, size), timeout)
    if st != 200:
        raise RuntimeError('get-entry-and-proof HTTP %d' % st)
    return json.loads(body)


def get_proof_by_hash(url, leaf_hash_b64, size, timeout):
    """RFC 6962 §4.5: 按叶哈希取 audit path（多数现代日志已移除）"""
    st, body = http_get(url.rstrip('/') + '/ct/v1/get-proof-by-hash'
                        '?hash=%s&tree_size=%d' % (leaf_hash_b64, size), timeout)
    if st != 200:
        raise RuntimeError('get-proof-by-hash HTTP %d' % st)
    return json.loads(body)


def entry_timestamp(entry):
    """leaf_input 前 12 字节: version | leaf_type | timestamp(BE)"""
    raw = base64.b64decode(entry['leaf_input'])
    return int.from_bytes(raw[2:10], 'big')


def entry_type_str(entry):
    raw = base64.b64decode(entry['leaf_input'])
    return int.from_bytes(raw[10:12], 'big')


# ---------------------------------------------------------------- 定位与验证
def locate_leaf(url, target_leaf, target_ts, tree_size, timeout, max_scan):
    """二分下界 + 线性比对。返回 (index, status)，status ∈
    found / notfound（扫描完未匹配）/ ioerror（区间探测或扫描失败）。
    leaf 内 timestamp 与 SCT timestamp 相同且随索引近似单调（同毫秒可乱序，
    故命中前向前补偿少量，避免二分边界滑过同时间戳簇）。"""
    def get(i):
        return get_entries(url, i, i, timeout)

    if tree_size <= 0:
        return None, 'ioerror'
    if tree_size == 1:
        try:
            e = get(0)
        except Exception:
            return None, 'ioerror'
        if e and base64.b64decode(e[0]['leaf_input']) == target_leaf:
            return 0, 'found'
        return None, 'notfound'

    # 二分: 首个 timestamp >= target_ts 的索引
    lo, hi = 0, tree_size
    while lo < hi:
        mid = (lo + hi) // 2
        try:
            e = get(mid)
        except Exception:
            return None, 'ioerror'        # 区间探测失败：无法定位
        if not e:
            hi = mid
            continue
        if entry_timestamp(e[0]) < target_ts:
            lo = mid + 1
        else:
            hi = mid
    # 向后线性比对（同毫秒簇在 lower 附近；命中即停）
    start = max(0, lo - 2000)              # 向前补偿乱序前缀
    end = min(tree_size - 1, lo + max_scan)
    pos = start
    while pos <= end:
        batch_end = min(end, pos + 511)
        try:
            entries = get_entries(url, pos, batch_end, timeout)
        except Exception:
            return None, 'ioerror'
        for i, e in enumerate(entries):
            if base64.b64decode(e['leaf_input']) == target_leaf:
                return pos + i, 'found'
        pos = batch_end + 1
    return None, 'notfound'


def verify_sct_inclusion(sct, leaf_input, tree_size, sth_root, url, timeout,
                         max_scan, verbose=False):
    """尝试取 audit path 并验证。返回 (verdict, detail, leaf_index, proof_ok)。
    端点支持不一：先 RFC 9162 get-entry-and-proof（需已知索引），
    再回退 RFC 6962 get-proof-by-hash；全部失败则只能给"已定位无证明"。"""
    lh = leaf_hash_of(leaf_input)
    lh_b64 = base64.b64encode(lh).decode()
    idx, status = locate_leaf(url, leaf_input, sct['timestamp'], tree_size,
                              timeout, max_scan)
    if status == 'ioerror':
        return '无法验证', 'get-entries 不可达，无法定位叶子（网络或日志不支持区间查询）', None, False
    if status == 'notfound':
        return '不一致', '扫描区间内未找到与该 SCT 对应的叶子（收据未兑现入树？）', None, False

    proof = None
    src = None
    try:
        r = get_entry_and_proof(url, idx, tree_size, timeout)
        if r.get('leaf_input'):
            got = base64.b64decode(r['leaf_input'])
            if got != leaf_input:          # 日志自述 leaf 与重建不一致 → 可疑
                return '不一致', 'get-entry-and-proof 返回的 leaf_input 与重建不一致', idx, False
        proof = [base64.b64decode(p) for p in (r.get('audit_path') or [])]
        src = 'get-entry-and-proof'
    except Exception:
        proof, src = None, None
    if proof is None:
        try:
            r = get_proof_by_hash(url, lh_b64, tree_size, timeout)
            proof = [base64.b64decode(p) for p in (r.get('audit_path') or [])]
            src = 'get-proof-by-hash'
        except Exception:
            proof, src = None, None
    if proof is None:
        return '观察', 'leaf 已定位(index=%d)但日志不支持 proof 端点，缺密码学包含性证明' % idx, idx, False
    try:
        root = root_from_audit_path(lh, idx, tree_size, proof)
    except ValueError as e:
        return '观察', 'audit path 解析失败(%s)' % e, idx, False
    if root != sth_root:
        return '不一致', 'audit path 重建根与 STH 根不一致', idx, False
    return 'PASS', '条目确在树中，audit path 验证通过(%s, index=%d)' % (src, idx), idx, True


# ---------------------------------------------------------------- 主流程
def main():
    ap = argparse.ArgumentParser(
        description='L4 CT 包含性审计: 拿 SCT 查 CT log 条目是否真的在树里')
    ap.add_argument('cert', nargs='?',
                    default=os.path.join(script_dir(), 'samples', 'baidu_new.pem'),
                    help='目标证书 PEM/DER 或目录（默认 samples/baidu_new.pem）')
    ap.add_argument('--issuer', metavar='FILE',
                    default=os.path.join(script_dir(), 'samples', 'gsrsaovsslca2018.crt'),
                    help='签发者证书（构造 precert leaf 需 issuer_key_hash；目录批量时'
                         '所有证书须同一签发者，默认 baidu 演示链签发者）')
    ap.add_argument('--loglist', metavar='FILE', help='log list v3 快照（默认自动找 samples/）')
    ap.add_argument('--offline', action='store_true', help='无本地快照时报错，不联网拉清单')
    ap.add_argument('--max-scan', type=int, default=50000,
                    help='线性比对条数上限（默认 50000；命中即停）')
    ap.add_argument('--timeout', type=int, default=20, help='联网超时秒数（默认 20）')
    ap.add_argument('--csv', metavar='FILE', help='汇总导出 CSV（每 SCT 一行）')
    ap.add_argument('--quiet', action='store_true', help='每证书只打印一行结论')
    args = ap.parse_args()

    selftest()
    print('merkle 自检 OK（MTH/audit path 算法与 root_from_audit_path 一致）')

    certs = []
    if os.path.isdir(args.cert):
        for root, _, files in os.walk(args.cert):
            for f in sorted(files):
                if f.lower().endswith(('.pem', '.crt', '.cer', '.der')):
                    certs.append(os.path.join(root, f))
    else:
        certs = [args.cert]
    if not certs:
        sys.exit('错误: 未找到任何证书（%s）' % args.cert)

    issuer_der = read_pem(args.issuer)
    _, issuer_spki_der, _ = cert_children(issuer_der)
    issuer_key_hash = hashlib.sha256(issuer_spki_der).digest()
    logs = load_log_list(args.loglist, offline=args.offline)
    now = time.time()

    quiet = args.quiet or len(certs) > 1
    csv_rows = []
    any_inconsistent = False

    for cert_path in certs:
        cert_der = read_pem(cert_path)
        tbs = build_precert_tbs(cert_der)          # defanged TBS（无 SCT 扩展）
        data = extract_sct_list(cert_der)
        print('== CT 包含性验证（审计时点 %s UTC）==' %
              datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))
        print('证书  : %s  (SHA256 %s)' % (cert_path,
              ':'.join('%02X' % b for b in hashlib.sha256(cert_der).digest())))
        if data is None:
            print('  无 SCT 扩展（CA 证书或未嵌入 SCT，CT 政策不要求，跳过）')
            continue
        scts = parse_scts(data)
        print('SCT 数: %d\n' % len(scts))
        cert_ok = 0
        for i, s in enumerate(scts, 1):
            if not quiet:
                print('-> 处理 SCT #%d/%d ...' % (i, len(scts)), flush=True)
            info = logs.get(s['log_id'])
            ts = datetime.fromtimestamp(s['timestamp'] / 1000, tz=timezone.utc)
            line = ['--- SCT #%d ---' % i]
            verdict, detail = '观察', '快照未匹配到该 log_id'
            leaf_idx = None
            if info and info.get('url'):
                line.append('  声称日志: %s / %s (state=%s)' %
                            (info['operator'], info['name'], info['state']))
                line.append('  SCT 时间: %s UTC' % ts.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3])
                leaf_input = sct_signature_input(s['timestamp'], issuer_spki_der,
                                                 tbs, s.get('ext', b''))
                lh = leaf_hash_of(leaf_input)
                line.append('  leaf hash: %s' % base64.b64encode(lh).decode())
                if not quiet:
                    print('  → get-sth: %s' % info['url'], flush=True)
                try:
                    sth = get_sth(info['url'], args.timeout)
                    tree_size = sth['tree_size']
                    sth_root = base64.b64decode(sth['sha256_root_hash'])
                    line.append('  get-sth  : tree_size=%d root=%s' % (
                        tree_size,
                        base64.b64encode(sth_root[:8]).decode() + '...'))
                    if not quiet:
                        print('  → get-sth OK: tree_size=%d，开始定位 leaf ...'
                              % tree_size, flush=True)
                    verdict, detail, leaf_idx, ok = verify_sct_inclusion(
                        s, leaf_input, tree_size, sth_root, info['url'],
                        args.timeout, args.max_scan, verbose=not quiet)
                    if ok:
                        cert_ok += 1
                    if verdict == 'PASS':
                        line.append('  [通过] %s' % detail)
                    elif verdict == '不一致':
                        line.append('  [不一致] %s' % detail)
                    elif verdict == '观察':
                        line.append('  [观察] %s' % detail)
                except Exception as e:
                    verdict = '无法验证'
                    detail = '日志 API 不可达: %s' % e
                    line.append('  [无法验证] %s' % detail)
            else:
                line.append('  声称日志: %s' % (info['name'] if info else '? (未匹配快照)'))
            if verdict == '不一致':
                any_inconsistent = True
            if quiet:
                lname = info['name'] if info else '? (未匹配快照)'
                print('  SCT #%d  %-8s  %s' % (i, verdict, lname))
            else:
                print('\n'.join(line) + '\n')
            csv_rows.append(dict(cert=os.path.basename(cert_path), sct_index=i,
                                 log_id=base64.b64encode(s['log_id']).decode(),
                                 operator=info['operator'] if info else '',
                                 log_name=info['name'] if info else '',
                                 sct_time=ts.strftime('%Y-%m-%d %H:%M:%S'),
                                 verdict=verdict,
                                 leaf_index=leaf_idx if leaf_idx is not None else '',
                                 detail=detail))
        if quiet:
            print('证书 %s: %d/%d 个 SCT 包含性 PASS' %
                  (os.path.basename(cert_path), cert_ok, len(scts)))
        print()

    if args.csv:
        with open(args.csv, 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=list(csv_rows[0].keys()) if csv_rows
                               else ['cert', 'sct_index', 'log_id', 'operator',
                                     'log_name', 'sct_time', 'verdict',
                                     'leaf_index', 'detail'])
            w.writeheader()
            w.writerows(csv_rows)
        print('CSV 已写出: %s' % os.path.abspath(args.csv))

    print('== 结论: 存在"不一致"= %s；PASS 即 SCT 收据已兑现（条目在日志树中）==' %
          any_inconsistent)
    if any_inconsistent:
        sys.exit(1)


if __name__ == '__main__':
    main()
