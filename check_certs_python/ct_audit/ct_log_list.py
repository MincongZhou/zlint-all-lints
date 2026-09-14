#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ct_log_list.py —— 从 CT 日志中枚举「由 CFCA 签发」的证书并导出字段。

导出 4 个字段：
    订户证书的序列号 / 订户证书的指纹 / 签发者的公钥 / 签发者的指纹

两种数据源，覆盖度与成本不同：

  --source ctlog  （推荐，覆盖最全：CT 里"由 CFCA 签发"的证书）
      直连 CT 日志（默认用本目录 samples/log_list_v3_snapshot.json 快照里的
      usable 日志），用 get-entries 增量扫描，逐条判断是否由 CFCA 的 CA 签发。
      匹配判据是**精确的密钥/名称比对**，不靠名字子串，因此不会漏掉名字里
      没有 "CFCA" 的子 CA：
        * precert 条目：leaf_input 内的 issuer_key_hash(32B)
              == SHA256(CFCA CA 证书的 SubjectPublicKeyInfo)   ← 零解析，最快
        * 其余情况：日志条目里的签发者链首个证书的 SPKI 哈希
        * 再退一步：叶子证书的 issuer Name 与 CA 池的 Subject Name 逐字节相等
      签发者公钥/指纹直接取自 --ca-dir 的本地 CA 证书池（权威、离线）。

  --source crtsh  （快速摸底，覆盖有限）
      用 crt.sh 聚合索引做关键词/域名发现，再用本地 CA 池按 issuer 精确过滤。
      实测局限（2026-09）：crt.sh 的 JSON 接口只能按"身份(SAN/CN)"检索，
      **没有按 issuer 枚举的接口**（CAID/CAName 只返回 CA 自身、且仅 HTML、
      output=json 直接报 Unsupported），因此本模式只能发现 SAN/CN 里带关键词
      的证书，属"能查到的部分"，不是"CFCA 全部"。

用法:
    # 直连 CT 日志：扫一段时间窗，增量累积（--state 记录进度，可反复续跑）
    python3 ct_log_list.py --source ctlog --since 2026-06-01 \
            --max-entries 50000 --state ct_scan_state.json --out cfca_ct_fields.json

    # 只扫指定日志 / 指定索引区间（先小窗口验证）
    python3 ct_log_list.py --source ctlog --log argon2027h1 --start-index 0 --max-entries 2000

    # crt.sh 快速发现（本地 CA 池提供签发者公钥/指纹）
    python3 ct_log_list.py --source crtsh --limit 30 --delay 1.5

    # crt.sh + 指定域名（该域名证书若确由 CFCA 签发则导出）
    python3 ct_log_list.py --source crtsh --domain example.com

字段口径（重要）:
    * CT 日志以 precert 方式登记的条目存的是 **precert**，不是最终证书。
      序列号与最终证书相同；但 DER 不同（precert 含 poison、不含 SCT），
      所以 subscriber_sha256 是"日志中该条目证书"的指纹；当 entry_type=precert
      时它与最终证书的指纹不一致。要"最终证书指纹"须拿到最终证书（crtsh 模式
      下载的是日志内同一份条目；两者都需注意区分）。
    * 命中方式记在 issuer_match 字段：issuer_key_hash / chain_spki /
      issuer_dn / dn_keyword，便于复核覆盖度。

退出码: 0 正常；2 未取到任何记录（且确有错误）。
依赖: python3 + cryptography（--source crtsh 另需 requests）
"""
import argparse
import base64
import csv
import hashlib
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization

CRT_SH_API = "https://crt.sh/"

CFCA_ISSUER_KEYWORDS = [
    "CFCA",
    "China Financial Certification Authority",
]

USER_AGENT = "ct-audit/cfca-field-export (+zlint-all-lints)"
LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
UA = {"User-Agent": USER_AGENT}
OID_BASIC_CONSTRAINTS = x509.oid.ExtensionOID.BASIC_CONSTRAINTS


# ============================================================ 通用小工具
def script_dir():
    return os.path.dirname(os.path.abspath(__file__))


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest().upper()


def public_key_pem(pubkey):
    return pubkey.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def spki_der(pubkey):
    return pubkey.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def utc_iso(cert, kind):
    v = getattr(cert, "not_valid_%s_utc" % kind, None)      # cryptography >= 42
    if v is not None:
        return v.isoformat()
    return getattr(cert, "not_valid_%s" % kind).replace(tzinfo=timezone.utc).isoformat()


def load_cert(data):
    """把 PEM / DER 字节统一解析为 X.509 证书对象。"""
    if b"-----BEGIN" in data:
        try:
            return x509.load_pem_x509_certificate(data)
        except ValueError:
            pass
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError:
        pass
    raise ValueError("无法解析为 X.509 证书（既非 PEM 也非 DER）")


def read_cert_file(path):
    with open(path, "rb") as f:
        return load_cert(f.read())


# ---------------------------------------------------------- 纯 DER 解析
def _read_tlv(buf, p):
    tag = buf[p]
    p += 1
    ln = buf[p]
    p += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[p:p + n], "big")
        p += n
    return tag, p, p + ln


def _children(buf, start, end):
    out, p = [], start
    while p < end:
        tag, s, ce = _read_tlv(buf, p)
        out.append((tag, s, ce))
        p = ce
    return out


def cert_parts(der):
    """纯 DER 切片取证书的 (SPKI, Subject Name, Issuer Name) 原字节。
    直接原字节比对，避免 Name 重编码/顺序差异导致的假阴性。"""
    _, cs0, _ = _read_tlv(der, 0)
    _, _, tce = _read_tlv(der, cs0)
    tbs = der[cs0:tce]                                  # tbsCertificate TLV 整段
    _, content_s, _ = _read_tlv(tbs, 0)
    chs = _children(tbs, content_s, len(tbs))
    # 字段序: [a0 version] | serial | sig | issuer | validity | subject | spki
    base = 1 if chs[0][0] == 0xA0 else 0
    iss, sub, spki = chs[base + 2], chs[base + 4], chs[base + 5]
    return tbs[spki[1]:spki[2]], tbs[sub[1]:sub[2]], tbs[iss[1]:iss[2]]


def _u24(buf, off):
    return int.from_bytes(buf[off:off + 3], "big")


def _tls_vector(buf, off):
    """CT 的 TLS 编码向量：3 字节总长 + 每项 3 字节长。"""
    end = off + 3 + _u24(buf, off)
    p, out = off + 3, []
    while p + 3 <= end:
        n = _u24(buf, p)
        p += 3
        out.append(buf[p:p + n])
        p += n
    return out


# ============================================================ CA 证书池
class CaPool:
    """CFCA CA 证书池，建 SPKI 哈希 / Subject Name / SKI 三个索引。

    匹配优先级：SPKI 哈希（与 CT 的 issuer_key_hash 同源，最精确）→
    Subject Name 原字节相等（兜底，防 CA 证书被重签或池中缺 SPKI）。
    """

    def __init__(self, dn_keywords=()):
        self.by_spki = {}          # SHA256(SPKI) bytes -> rec
        self.by_name = {}          # Subject Name 原字节 -> rec
        self.by_ski = {}           # SKI bytes -> rec
        self.dn_keywords = [k.upper() for k in dn_keywords]
        self.recs = []

    def add(self, cert, der):
        try:
            spki = cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)
        except Exception:
            return
        rec = {
            "der": der,
            "sha256": sha256_hex(der),
            "spki_sha256": sha256_hex(spki),
            "subject": cert.subject.rfc4514_string(),
            "subject_name_der": cert_parts(der)[1],
            "public_key_pem": public_key_pem(cert.public_key()),
        }
        self.by_spki.setdefault(hashlib.sha256(spki).digest(), rec)
        self.by_name.setdefault(rec["subject_name_der"], rec)
        try:
            ski = cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier).value.digest
            self.by_ski.setdefault(ski, rec)
        except x509.ExtensionNotFound:
            pass
        self.recs.append(rec)

    def match_by_spki(self, spki_hash_32):
        return self.by_spki.get(spki_hash_32)

    def match_by_dn(self, issuer_name_der):
        return self.by_name.get(issuer_name_der)

    def dn_keyword_hit(self, dn_text):
        up = dn_text.upper()
        for k in self.dn_keywords:
            if k and k in up:
                return k
        return None

    def __len__(self):
        return len(self.recs)


def load_ca_pool(ca_dir, dn_keywords=()):
    pool = CaPool(dn_keywords)
    if not ca_dir:
        return pool
    for root, _dirs, files in os.walk(ca_dir):
        for fn in sorted(files):
            if fn.endswith(":Zone.Identifier") or fn == ".DS_Store":
                continue
            fp = os.path.join(root, fn)
            try:
                rec = read_cert_file(fp)
            except Exception:
                continue
            der = rec.public_bytes(serialization.Encoding.DER)
            pool.add(rec, der)
    return pool


# ============================================================ CT 日志读取
def http_get(url, timeout, retries=3):
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:                      # noqa: BLE001
            last = e
            time.sleep(1.5 * (i + 1))
    raise last


def get_sth(url, timeout):
    body = http_get(url.rstrip("/") + "/ct/v1/get-sth", timeout)
    return json.loads(body)


def get_entries(url, start, end, timeout):
    body = http_get(url.rstrip("/") + "/ct/v1/get-entries?start=%d&end=%d"
                    % (start, end), timeout)
    return json.loads(body).get("entries", [])


def entry_timestamp(leaf_input):
    return int.from_bytes(leaf_input[2:10], "big")


def find_index_for_time(url, tree_size, target_ms, timeout):
    """二分首个 timestamp >= target_ms 的索引（timestamp 随索引近似单调）。"""
    lo, hi = 0, tree_size
    while lo < hi:
        mid = (lo + hi) // 2
        try:
            e = get_entries(url, mid, mid, timeout)
        except Exception:
            return None
        if not e:
            hi = mid
            continue
        raw = base64.b64decode(e[0]["leaf_input"])
        if len(raw) < 12:
            hi = mid
            continue
        if entry_timestamp(raw) < target_ms:
            lo = mid + 1
        else:
            hi = mid
    return lo


def extract_ct_entry(leaf_input, extra_data):
    """从一条 CT 条目取出 (entry_type, leaf_der, chain, issuer_key_hash)。

    RFC 6962 §3.4 / RFC 9162 §4.6：
      leaf_input = version(1) | leaf_type(1) | timestamp(8) | LogEntryType(2) | entry
      x509_entry(0)   : ASN.1Cert(3B 长 + DER)                      ← 最终证书
      precert_entry(1): issuer_key_hash(32) | tbs(3B 长 + DER) | extensions
      extra_data:
        x509_entry   : CertificateChain = 3B 总长 + 若干 ASN.1Cert
        precert_entry: ASN.1Cert pre_certificate + PrecertChainEntry 的 3B 链
    """
    if len(leaf_input) < 12:
        return None, None, [], None
    etype = int.from_bytes(leaf_input[10:12], "big")
    leaf_der, chain, ikh = None, [], None
    if etype == 0:
        n = _u24(leaf_input, 12)
        leaf_der = leaf_input[15:15 + n] or None
    elif etype == 1:
        if len(leaf_input) < 47:
            return etype, None, [], None
        ikh = leaf_input[12:44]
        n = _u24(leaf_input, 44)
        # leaf_input 内是 tbs（已摘 poison），拿不到完整证书 → 用 extra_data 的 precert
    if extra_data:
        try:
            if etype == 1:
                n = _u24(extra_data, 0)
                leaf_der = extra_data[3:3 + n] or None
                chain = _tls_vector(extra_data, 3 + n)
            else:
                chain = _tls_vector(extra_data, 0)
        except Exception:
            chain = chain or []
    return etype, leaf_der, chain, ikh


# ============================================================ 记录组装
def build_ctlog_record(log_info, index, etype, leaf, issuer_rec, match_kind):
    der = leaf.public_bytes(serialization.Encoding.DER)
    rec = {
        "source": "ctlog",
        "log_operator": log_info.get("operator"),
        "log_name": log_info.get("name"),
        "log_url": log_info.get("url"),
        "entry_index": index,
        "entry_type": "precert" if etype == 1 else ("x509" if etype == 0 else str(etype)),
        "leaf_subject": leaf.subject.rfc4514_string(),
        "leaf_issuer": leaf.issuer.rfc4514_string(),
        "not_before": utc_iso(leaf, "before"),
        "not_after": utc_iso(leaf, "after"),
        # ---- 目标字段 ----
        "subscriber_serial": "0x%X" % leaf.serial_number,
        "subscriber_sha256": sha256_hex(der),
        "issuer_public_key_pem": None,
        "issuer_cert_sha256": None,
        # ---- 辅助字段 ----
        "issuer_spki_sha256": None,
        "issuer_subject": None,
        "issuer_match": match_kind,
    }
    if issuer_rec is not None:
        rec.update(
            issuer_public_key_pem=issuer_rec["public_key_pem"],
            issuer_cert_sha256=issuer_rec["sha256"],
            issuer_spki_sha256=issuer_rec["spki_sha256"],
            issuer_subject=issuer_rec["subject"],
        )
    return rec


def match_ct_entry(leaf_input, extra_data, pool):
    """判断一条 CT 条目是否由 CA 池中的 CFCA CA 签发。

    返回 (hit, match_kind, etype, leaf_der)；未命中返回 (None, None, etype, leaf_der)。
    快路径：precert 的 issuer_key_hash 直接与 SPKI 哈希比对，无需解析证书。
    """
    etype = int.from_bytes(leaf_input[10:12], "big") if len(leaf_input) >= 12 else None
    if etype == 1 and len(leaf_input) >= 44:
        hit = pool.match_by_spki(leaf_input[12:44])
        if hit is not None:
            _e, leaf_der, _c, _h = extract_ct_entry(leaf_input, extra_data)
            return hit, "issuer_key_hash", etype, leaf_der

    etype, leaf_der, chain, _ikh = extract_ct_entry(leaf_input, extra_data)
    if leaf_der is None:
        return None, None, etype, None

    # 链首证书的 SPKI 哈希（链不一定带，但带了就能精确命中）
    for cder in chain:
        try:
            _spki, _sub, _iss = cert_parts(cder)
        except Exception:
            continue
        if hashlib.sha256(_spki).digest() in pool.by_spki:
            return pool.by_spki[hashlib.sha256(_spki).digest()], "chain_spki", etype, leaf_der

    # 叶子 issuer Name 与 CA 池 Subject Name 原字节相等
    try:
        _spki, _sub, iss_der = cert_parts(leaf_der)
        hit = pool.match_by_dn(iss_der)
        if hit is not None:
            return hit, "issuer_dn", etype, leaf_der
    except Exception:
        pass

    # 最后兜底：issuer DN 文本含 CFCA 关键词（CA 池不全时仍能捞到，标为低置信）
    try:
        leaf = load_cert(leaf_der)
        kw = pool.dn_keyword_hit(leaf.issuer.rfc4514_string())
        if kw:
            return pseudo_issuer(leaf.issuer.rfc4514_string()), \
                "dn_keyword:%s" % kw, etype, leaf_der
    except Exception:
        pass
    return None, None, etype, leaf_der


def pseudo_issuer(dn_text):
    """CA 池缺该 CA 证书时的占位：只知道签发者名称，公钥/指纹留空。"""
    return {"subject": dn_text, "public_key_pem": None,
            "sha256": None, "spki_sha256": None}


# ============================================================ 日志清单
def snapshot_candidates():
    return [os.path.join(script_dir(), "samples", "log_list_v3_snapshot.json"),
            os.path.join(script_dir(), "log_list_v3_snapshot.json"),
            "log_list_v3_snapshot.json"]


def _st_name(st):
    if not isinstance(st, dict):
        return None
    if "state" in st:
        return st["state"]
    return next(iter(st), None)


def load_log_list(cache=None, offline=False):
    """返回 (usable_logs, source)；usable_logs 为状态含 usable 的日志列表。"""
    candidates = ([cache] if cache else []) + snapshot_candidates()
    data, source = None, "online (%s)" % LOG_LIST_URL
    for cand in candidates:
        try:
            with open(cand, encoding="utf-8") as f:
                data = json.load(f)
            source = cand
            break
        except OSError:
            continue
    if data is None:
        if offline:
            sys.exit("错误: 无本地 log list 快照（--offline），请用 --loglist 指定")
        with urllib.request.urlopen(LOG_LIST_URL, timeout=30) as r:
            data = json.load(r)

    logs = []
    for op in data.get("operators", []):
        for arr in ("logs", "tiled_logs"):
            for lg in op.get(arr, []):
                url = lg.get("url") or lg.get("submission_url")
                if not url:
                    continue
                ti = lg.get("temporal_interval") or {}
                logs.append({
                    "operator": op.get("name"),
                    "name": lg.get("description"),
                    "state": _st_name(lg.get("state")),
                    "url": url,
                    "interval": (ti.get("start_inclusive"), ti.get("end_exclusive")),
                })
    return logs, source


def select_logs(logs, patterns, include_all=False):
    out = []
    for lg in logs:
        # --log 显式指定时不再按状态过滤，方便扫已 retired 的日志
        if not include_all and not patterns and lg.get("state") != "usable":
            continue
        if patterns:
            hay = ("%s %s" % (lg.get("name") or "", lg.get("url") or "")).lower()
            if not any(p.lower() in hay for p in patterns):
                continue
        out.append(lg)
    return out


# ============================================================ 扫描
def ts_ms(date_str, end_of_day=False):
    d = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    if end_of_day:
        d = d.replace(hour=23, minute=59, second=59)
    return int(d.timestamp() * 1000)


def scan_log(log_info, pool, args, state, state_lock, sink, sink_lock):
    url = log_info["url"]
    stats = {"log": log_info.get("name"), "url": url, "scanned": 0,
             "hits": 0, "error": None, "start": None, "end": None}
    try:
        sth = get_sth(url, args.timeout)
        tree_size = int(sth["tree_size"])
    except Exception as e:                       # noqa: BLE001
        stats["error"] = "get-sth 失败: %s" % e
        stats["tree_size"] = None
        with sink_lock:
            sink.append(("stats", stats))
        return

    stats["tree_size"] = tree_size
    if tree_size <= 0:
        stats["error"] = "空树"
        with sink_lock:
            sink.append(("stats", stats))
        return

    with state_lock:
        saved = (state.get(url) or {}).get("next_index") if state is not None else None
    if args.since:
        start = find_index_for_time(url, tree_size, ts_ms(args.since), args.timeout)
        if start is None:
            stats["error"] = "--since 二分定位失败"
            with sink_lock:
                sink.append(("stats", stats))
            return
    elif saved is not None:
        start = saved
    else:
        start = max(0, args.start_index)

    end = tree_size - 1
    if args.until:
        idx = find_index_for_time(url, tree_size, ts_ms(args.until, True), args.timeout)
        if idx is not None:
            end = min(end, idx)
    if args.max_entries:
        end = min(end, start + args.max_entries - 1)
    stats["start"], stats["end"] = start, end
    if start > end:
        with sink_lock:
            sink.append(("stats", stats))
        return

    idx = start
    while idx <= end:
        batch_end = min(end, idx + args.batch - 1)
        try:
            entries = get_entries(url, idx, batch_end, args.timeout)
        except Exception as e:                   # noqa: BLE001
            stats["error"] = "get-entries[%d..%d] 失败: %s" % (idx, batch_end, e)
            break
        if not entries:
            break
        for i, e in enumerate(entries):
            try:
                leaf_input = base64.b64decode(e["leaf_input"])
                extra_data = base64.b64decode(e.get("extra_data") or "")
            except Exception:
                continue
            hit, kind, etype, leaf_der = match_ct_entry(leaf_input, extra_data, pool)
            stats["scanned"] += 1
            if hit is None or leaf_der is None:
                continue
            try:
                leaf = load_cert(leaf_der)
            except Exception:
                continue
            rec = build_ctlog_record(log_info, idx + i, etype, leaf, hit, kind)
            stats["hits"] += 1
            with sink_lock:
                sink.append(("record", rec))
        # 日志可能按响应体积截断，返回条数少于请求区间；按实际条数前进才不会漏条目
        # （RFC 6962 §4.6 保证返回的条目自 start 起连续）
        idx += max(1, len(entries))
        if state is not None:
            with state_lock:
                state[url] = {"next_index": idx,
                              "tree_size": tree_size,
                              "updated_utc": datetime.now(timezone.utc)
                                             .strftime("%Y-%m-%dT%H:%M:%SZ")}
            save_state(state, state_lock)
        if not args.quiet:
            print("  [%s] 已扫 %d 条（命中 %d）"
                  % (log_info.get("name"), stats["scanned"], stats["hits"]),
                  file=sys.stderr)
    with sink_lock:
        sink.append(("stats", stats))


def save_state(state, state_lock):
    if not getattr(save_state, "path", None):
        return
    with state_lock:
        doc = dict(state)
    # tmp 名带线程 id：多日志并发时不至于互相覆盖同一个临时文件
    tmp = "%s.%d.tmp" % (save_state.path, threading.get_ident())
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    os.replace(tmp, save_state.path)


# ============================================================ crt.sh 模式
def new_session():
    import requests                                # 延迟导入：ctlog 模式不依赖
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    return s


def crtsh_get(session, params, timeout, retries):
    last = None
    for i in range(retries):
        try:
            r = session.get(CRT_SH_API, params=params, timeout=timeout)
            r.raise_for_status()
            return r
        except Exception as e:                     # noqa: BLE001
            last = e
            time.sleep(2 * (i + 1))
    raise last


def crtsh_json(session, params, timeout, retries):
    try:
        r = crtsh_get(session, dict(params, output="json"), timeout, retries)
    except Exception:
        return []
    text = r.text.strip()
    if not text or text.startswith("<"):
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def crtsh_download(session, cert_id, timeout, retries):
    """?d=<id> 返回 DER 证书本体。"""
    r = crtsh_get(session, {"d": cert_id}, timeout, retries)
    return load_cert(r.content)


def issuer_from_chain_or_aia(leaf, session, pool, args):
    """签发者证书：本地池 → 叶子 AIA 的 CA Issuers。返回 (rec, kind)。"""
    try:
        _spki, _sub, iss_der = cert_parts(leaf.public_bytes(serialization.Encoding.DER))
    except Exception:
        iss_der = None
    if iss_der is not None:
        rec = pool.match_by_dn(iss_der)
        if rec is not None:
            return rec, "pool_dn"
    if args.no_aia:
        return None, None
    try:
        aia = leaf.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return None, None
    for desc in aia:
        if desc.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS \
                and isinstance(desc.access_location, x509.UniformResourceIdentifier):
            try:
                der = http_get(desc.access_location.value, args.timeout)
                ic = load_cert(der)
            except Exception:
                continue
            idr = ic.public_bytes(serialization.Encoding.DER)
            return {"der": idr, "sha256": sha256_hex(idr),
                    "spki_sha256": sha256_hex(spki_der(ic.public_key())),
                    "subject": ic.subject.rfc4514_string(),
                    "subject_name_der": cert_parts(idr)[1],
                    "public_key_pem": public_key_pem(ic.public_key())}, "aia"
    return None, None


def run_crtsh(args, pool):
    session = new_session()
    # 注意：不要把 CA 池里的 CA CN 当作检索词——crt.sh 的 Identity 检索匹配的是
    # 「证书自身的主体 CN/SAN」，CA 的 CN 只会命中 CA 证书本身，命中不到它签发的叶子，
    # 白白多花 20-40 秒/次。要拿"某 CA 签发的叶子"，crt.sh 没有可用接口（CAID 搜索
    # 仅 HTML 且落到 CA 详情页，CAName 只返回 CA 表），只能用身份/域名关键词 + 本地池过滤。
    keywords = list(args.keyword or CFCA_ISSUER_KEYWORDS)

    queries = [("O", "China Financial Certification Authority")]
    queries += [("Identity", kw) for kw in keywords]
    queries += [("Identity", d) for d in (args.domain or [])]

    seen, rows, n_out = set(), [], 0
    # 候选池只作安全阀，不能太小：候选绝大多数会在本地被 issuer 过滤掉，
    # 若在此提前 break，后面的种子查询就根本不会发出（漏检）。
    cap = max(args.limit * 20, 2000)
    for field, term in queries:
        if len(rows) >= cap:
            break
        print("[*] crt.sh ?%s=%s" % (field, term), file=sys.stderr)
        for row in crtsh_json(session, {field: term}, args.timeout, args.retries):
            key = row.get("id")
            if key in seen:
                continue
            seen.add(key)
            if not row_in_window(row, args.since, args.until):
                n_out += 1
                continue
            rows.append(row)
    print("[*] crt.sh 候选 %d 条（时间窗外跳过 %d 条）" % (len(rows), n_out),
          file=sys.stderr)

    out, n_leaf, n_no_issuer, n_fail, n_not_cfca = [], 0, 0, 0, 0
    pool_hashes = set()
    for _r in pool.recs:
        pool_hashes.add(_r["sha256"])
        pool_hashes.add(_r["spki_sha256"])
    # 下载很贵（实测 ~21s/条），先用 crt.sh 记录里的 issuer_name 预筛：
    # 只有"签发者名里含 CA 池的某个 CN 或关键词"的候选才值得下载。
    needles = {k.upper() for k in pool.dn_keywords}
    for _r in pool.recs:
        try:
            for a in load_cert(_r["der"]).subject.get_attributes_for_oid(
                    x509.oid.NameOID.COMMON_NAME):
                if a.value:
                    needles.add(a.value.upper())
        except Exception:
            continue

    def row_issuer_is_candidate(row):
        n = (row.get("issuer_name") or "").upper()
        return any(x in n for x in needles)

    for i, row in enumerate(rows, 1):
        if n_leaf >= args.limit:
            break
        if not row_issuer_is_candidate(row):
            n_not_cfca += 1
            continue                               # 签发者明显不是 CFCA → 不下下载
        try:
            leaf = crtsh_download(session, row.get("id"), args.timeout, args.retries)
        except Exception as e:                     # noqa: BLE001
            n_fail += 1
            print("[!] id=%s 下载失败: %s" % (row.get("id"), e), file=sys.stderr)
            continue
        if args.leaves_only and is_ca(leaf):
            continue
        rec, kind = issuer_from_chain_or_aia(leaf, session, pool, args)
        if rec is not None and kind == "aia":
            # 关键校验：AIA 抓来的签发者必须**确属 CFCA**，否则不算"CFCA 签发"。
            # 否则任何域名里恰好含 "cfca" 的证书都会被误收（如 LE 签发的 cfcaXXXX.org）。
            ok = rec.get("sha256") in pool_hashes or rec.get("spki_sha256") in pool_hashes \
                or pool.dn_keyword_hit(rec.get("subject") or "")
            if not ok:
                rec, kind = None, None
        if rec is None:
            # 池与 AIA 都没拿到：至少记录 issuer DN 文本是否含关键词
            kw = pool.dn_keyword_hit(leaf.issuer.rfc4514_string())
            if kw is None:
                n_not_cfca += 1
                continue                            # 不是 CFCA 签发 → 过滤掉
            kind = "dn_keyword:%s" % kw
        n_leaf += 1
        if rec is None:
            n_no_issuer += 1
        der = leaf.public_bytes(serialization.Encoding.DER)
        out.append({
            "source": "crtsh",
            "cert_id": row.get("id"),
            "crt_sh_issuer_name": row.get("issuer_name"),
            "leaf_subject": leaf.subject.rfc4514_string(),
            "leaf_issuer": leaf.issuer.rfc4514_string(),
            "not_before": utc_iso(leaf, "before"),
            "not_after": utc_iso(leaf, "after"),
            "subscriber_serial": "0x%X" % leaf.serial_number,
            "subscriber_sha256": sha256_hex(der),
            "issuer_public_key_pem": rec["public_key_pem"] if rec else None,
            "issuer_cert_sha256": rec["sha256"] if rec else None,
            "issuer_spki_sha256": rec["spki_sha256"] if rec else None,
            "issuer_subject": rec["subject"] if rec else leaf.issuer.rfc4514_string(),
            "issuer_match": kind,
        })
        print("[%d] serial=%s fp=%s issuer=%s"
              % (n_leaf, out[-1]["subscriber_serial"],
                 out[-1]["subscriber_sha256"][:16],
                 "OK" if rec else "仅名称"), file=sys.stderr)
        time.sleep(args.delay)

    return out, {"候选": len(rows), "时间窗外跳过": n_out, "导出": len(out),
                 "非CFCA签发已过滤": n_not_cfca, "下载失败": n_fail,
                 "未解析到签发者证书": n_no_issuer}


def is_ca(cert):
    try:
        return bool(cert.extensions.get_extension_for_class(
            x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def row_in_window(row, since, until):
    """按 crt.sh 记录里的 not_before 做时间窗过滤（下载前就过滤，省掉最贵的请求）。"""
    nb = (row.get("not_before") or "")[:10]
    if not nb:
        return True
    if since and nb < since:
        return False
    if until and nb > until:
        return False
    return True


# ============================================================ CLI / main
def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        description="枚举 CT 日志中由 CFCA 签发的证书，导出 序列号/指纹/签发者公钥/签发者指纹")
    ap.add_argument("--source", choices=("ctlog", "crtsh"), default="ctlog",
                    help="ctlog=直连日志枚举（推荐，覆盖全）；crtsh=聚合索引快速发现（覆盖有限）")
    ap.add_argument("--ca-dir", default=None,
                    help="CFCA CA 证书池目录（默认自动探测 ../../certs/CFCA）")
    ap.add_argument("--dn-keyword", action="append", default=None,
                    help="issuer DN 文本兜底关键词，可重复（默认 CFCA_ISSUER_KEYWORDS）")
    ap.add_argument("--out", default=None, help="结果写入 JSON 文件")
    ap.add_argument("--csv", default=None, help="结果另存 CSV")
    ap.add_argument("--limit", type=int, default=200, help="最多导出多少条（默认 200）")
    ap.add_argument("--quiet", action="store_true", help="不打印进度")
    ap.add_argument("--timeout", type=float, default=30.0, help="网络超时秒（默认 30）")

    g = ap.add_argument_group("ctlog 模式")
    g.add_argument("--loglist", default=None, help="log list v3 快照（默认 samples/ 自动找）")
    g.add_argument("--offline", action="store_true", help="无快照时报错，不联网拉清单")
    g.add_argument("--log", action="append", default=None,
                   help="只扫名字/URL 含该子串的日志，可重复（默认全部 usable）")
    g.add_argument("--all-states", action="store_true", help="包含非 usable 日志")
    g.add_argument("--since", default=None,
                   help="起始日期 YYYY-MM-DD（ctlog: 二分定位起始索引；crtsh: 下载前按 not_before 过滤）")
    g.add_argument("--until", default=None,
                   help="结束日期 YYYY-MM-DD（两种模式通用；crtsh 按 not_before 上界过滤）")
    g.add_argument("--start-index", type=int, default=0, help="未给 --since 时的起始条目索引")
    g.add_argument("--max-entries", type=int, default=1000,
                   help="每个日志最多扫描条数（默认 1000，0=不限；实测单日志约 3-10 条/秒）")
    g.add_argument("--batch", type=int, default=256, help="get-entries 批大小（默认 256）")
    g.add_argument("--workers", type=int, default=8, help="并发日志数（默认 8）")
    g.add_argument("--state", default=None, help="扫描进度文件（记录每个日志的 next_index，可续跑）")

    g2 = ap.add_argument_group("crtsh 模式")
    g2.add_argument("--keyword", action="append", default=None,
                    help="crt.sh 身份关键词，可重复（默认 CFCA_ISSUER_KEYWORDS + CA 池 CN）")
    g2.add_argument("--domain", action="append", default=None, help="额外按域名检索，可重复")
    g2.add_argument("--leaves-only", action="store_true", help="跳过 CA 证书（CA:TRUE）")
    g2.add_argument("--no-aia", action="store_true", help="禁止按 AIA 联网抓签发者证书")
    g2.add_argument("--delay", type=float, default=1.0, help="crt.sh 请求间隔秒（默认 1.0）")
    g2.add_argument("--retries", type=int, default=3)
    return ap.parse_args(argv)


def resolve_ca_dir(args):
    if args.ca_dir:
        return args.ca_dir
    cand = os.path.normpath(os.path.join(script_dir(), "..", "..", "certs", "CFCA"))
    return cand if os.path.isdir(cand) else None


def emit(records, args, summary):
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2)
        print("[*] 已写入 %s（%d 条）" % (args.out, len(records)), file=sys.stderr)
    else:
        print(json.dumps(records, ensure_ascii=False, indent=2))
    if args.csv:
        keys = list(records[0].keys()) if records else \
            ["source", "subscriber_serial", "subscriber_sha256",
             "issuer_public_key_pem", "issuer_cert_sha256"]
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
            w.writeheader()
            w.writerows(records)
        print("[*] 已写入 %s" % args.csv, file=sys.stderr)
    for k, v in summary.items():
        print("[*] %s: %s" % (k, v), file=sys.stderr)


def main(argv=None):
    args = parse_args(argv)
    ca_dir = resolve_ca_dir(args)
    dn_keywords = args.dn_keyword or CFCA_ISSUER_KEYWORDS
    pool = load_ca_pool(ca_dir, dn_keywords)
    print("[*] CA 池: %s（%d 张）" % (ca_dir or "<未指定>", len(pool)), file=sys.stderr)
    if len(pool) == 0:
        print("[!] 警告: CA 池为空，只能靠 issuer DN 关键词兜底（置信度低、易漏），"
              "建议用 --ca-dir 指定 CFCA CA 证书目录", file=sys.stderr)

    if args.source == "crtsh":
        records, summary = run_crtsh(args, pool)
        emit(records, args, summary)
        return 0 if records else 2

    logs, source = load_log_list(args.loglist, offline=args.offline)
    picked = select_logs(logs, args.log, include_all=args.all_states)
    print("[*] log list: %s（可用日志 %d 个，选中 %d 个）"
          % (source, len(logs), len(picked)), file=sys.stderr)
    if not picked:
        print("[!] 没有匹配的日志（用 --log/--all-states 调整）", file=sys.stderr)
        return 2

    state, state_lock = None, threading.Lock()
    if args.state:
        save_state.path = args.state
        if os.path.exists(args.state):
            try:
                with open(args.state, encoding="utf-8") as f:
                    state = json.load(f)
                print("[*] 续跑: %s（已记录 %d 个日志进度）"
                      % (args.state, len(state)), file=sys.stderr)
            except Exception:
                state = {}
        else:
            state = {}

    sink, sink_lock = [], threading.Lock()
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        for lg in picked:
            ex.submit(scan_log, lg, pool, args, state, state_lock, sink, sink_lock)

    records = [r for k, r in sink if k == "record"]
    stats = [s for k, s in sink if k == "stats"]
    records.sort(key=lambda r: (r["log_name"] or "", r["entry_index"]))
    n_hit = len(records)
    if args.limit and len(records) > args.limit:
        records = records[:args.limit]

    errs = [s for s in stats if s.get("error")]
    for s in stats:
        print("[*] %-40s 扫 %6d 条，命中 %d%s"
              % (s["log"], s["scanned"], s["hits"],
                 "（%s）" % s["error"] if s.get("error") else ""), file=sys.stderr)
    for s in errs:
        print("[!] %s: %s" % (s["log"], s["error"]), file=sys.stderr)

    elapsed = max(1e-6, time.time() - t0)
    n_scan = sum(s["scanned"] for s in stats)
    emit(records, args, {
        "选中日志": len(picked),
        "成功日志": len(stats) - len(errs),
        "扫描条目合计": n_scan,
        "命中": n_hit,
        "导出": len(records),
        "耗时秒": round(elapsed, 1),
        "吞吐(条/秒)": round(n_scan / elapsed, 1),
    })

    if not records:
        print("[i] 提示: 默认只扫每个日志前 --max-entries 条；用 --since 定位时间窗、"
              "用 --state 续跑可逐步覆盖全量。", file=sys.stderr)
    return 0 if records else (2 if errs else 0)


if __name__ == "__main__":
    sys.exit(main())
