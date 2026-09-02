#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_ct_temporal.py —— 交叉核验 SCT 时间戳 × 证书有效期 × 日志时间域（temporal_interval）

背景: 证书透明度(CT)下, 每张证书携带的嵌入式 SCT 由日志运营方签发, 其时间戳
(timestamp) 是日志收录该 precert 的时刻, 受 RFC 6962 签名保护不可篡改。审计中
需要把 SCT 时间戳与下列"时间证据"交叉比对:
  - 证书自身有效期 (notBefore / notAfter):   签发流程应在有效期内完成;
  - 审计时点 (now):                           日志不会签发未来的收据;
  - 日志声明的时间域 temporal_interval:       日志只应在 [start_inclusive,
    end_exclusive) 内接收提交 (log list v3), SCT 落在区间外通常意味着
    "发证时点的 log list 元数据与现在不同"或"日志当时在区间外接收了提交"
    —— 属需要调取签发时点快照复核的观察项;
  - Chrome CT Policy 的 SCT 数量要求:          2018-04-30 后签发的证书 >= 2 个
    来自 usable 日志的 SCT。
跑 zlint 格式规则发现不了这类时间语义问题; 本脚本做自动化交叉核验与批量汇总。

判定结论(verdict, 逐 SCT):
  - PASS        : 该 SCT 时间与证书有效期/审计时点/日志时间域全部自洽
  - 不一致      : SCT 时间戳存在硬伤(晚于审计时点 / 晚于 notAfter /
                  早于 notBefore 超窗口)或落在日志 temporal_interval 之外
  - 观察        : 非硬伤但需人工确认(日志未匹配/非 usable/略早于 notBefore)
证书级另附: 无 SCT 扩展 / SCT 数量不足(2018-04-30 后签发要求 >=2)

用法:
    python3 check_certs_python/ct_audit/check_ct_temporal.py <证书路径|目录> ... [选项]
    python3 check_certs_python/ct_audit/check_ct_temporal.py samples/baidu_new.pem
    python3 check_certs_python/ct_audit/check_ct_temporal.py samples/ --csv result.csv
    python3 check_certs_python/ct_audit/check_ct_temporal.py cert.pem --loglist my.json
    python3 check_certs_python/ct_audit/check_ct_temporal.py certs/ --offline
                 # --offline: 无本地快照时禁止在线拉取 log list(审计取证应固定快照)

选项:
    --loglist <文件>   指定 log list v3 快照(默认按 ct_audit/samples/ 自动找)
    --offline          无本地快照时报错退出, 不回退在线拉取
    --tolerance <秒>   SCT 晚于审计时点的容差, 默认 300(5 分钟, 网络抖动余量)
    --preissue-window <秒>
                       SCT 早于 notBefore 的容忍窗口, 默认 86400(24h);
                       窗口内判"观察", 超出判"不一致"(预签发/backdate 需人工)
    --csv <文件>       汇总导出 CSV(逐 SCT 一行 + 无 SCT 证书占一行)
    --quiet            每张证书只打印一行结论(批量自动打开)
    --no-ocsp          无意义占位, 仅保持与 check_* 家族 CLI 习惯一致(忽略)

退出码: 存在任何"不一致" → 1; 其余 → 0(纯"观察"不计为不一致)
依赖: python3 + cryptography; 复用同目录 parse_sct.py(提取/解析 SCT)
"""
import argparse
import base64
import csv
import datetime
import glob
import json
import os
import sys
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

# 保证"同目录 import parse_sct"无论 cwd 在哪都能命中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse_sct import extract_sct_list, parse_scts  # noqa: E402

UTC = datetime.timezone.utc
CERT_EXTS = (".pem", ".crt", ".cer", ".der", ".cert")
CT_POLICY_DATE = datetime.datetime(2018, 4, 30, tzinfo=UTC)  # Chrome CT Policy 生效日
LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
UA = {"User-Agent": "workbuddy-audit/1.0 (WebTrust CT testing)"}

CSV_HEADER = ["cert", "subject", "serial_hex", "notBefore", "notAfter",
              "audit_at", "sct_idx", "log_operator", "log_name", "log_state",
              "sct_time", "sct_time_ms", "interval_start", "interval_end",
              "verdict", "issue"]


# ---------- 基础工具 ----------

def utc(dt):
    """确保 aware UTC datetime（naive 视为 UTC）"""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def iso(dt):
    return utc(dt).strftime("%Y-%m-%d %H:%M:%S") if dt is not None else ""


def parse_iso(s):
    """log list 的 ISO8601(如 2027-01-01T00:00:00Z) -> aware datetime; 失败返 None"""
    if not s:
        return None
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def read_cert_bytes(raw):
    """PEM / DER 自动识别加载证书"""
    try:
        return x509.load_pem_x509_certificate(raw)
    except ValueError:
        return x509.load_der_x509_certificate(raw)


# ---------- log list 加载(v3: 含 version / temporal_interval) ----------

def snapshot_candidates():
    """log list 快照查找顺序: 脚本同目录 samples/ > 脚本同目录 > 当前目录"""
    base = os.path.dirname(os.path.abspath(__file__))
    return [os.path.join(base, "samples", "log_list_v3_snapshot.json"),
            os.path.join(base, "log_list_v3_snapshot.json"),
            "log_list_v3_snapshot.json"]


def load_log_data(cache=None, offline=False):
    """读取 log list v3 原始 JSON。返回 (data, source)；
    cache 指定时优先, 否则按 snapshot_candidates() 依次找本地快照,
    全部缺失且非 --offline 时才在线拉取。"""
    url = LOG_LIST_URL
    candidates = ([cache] if cache else []) + snapshot_candidates()
    for cand in candidates:
        try:
            with open(cand, encoding="utf-8") as f:
                return json.load(f), f"本地快照 {cand}"
        except OSError:
            continue
    if offline:
        raise SystemExit("错误: 未找到 log list 本地快照且指定了 --offline, "
                         "审计取证请先留存快照再跑")
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA),
                                timeout=30) as r:
        return json.load(r), "在线拉取 " + url


def state_name(st):
    """兼容 log list v3 两种 state 写法: {"state":"usable"} 或 {"usable":{...}}"""
    if not isinstance(st, dict):
        return None
    if "state" in st:
        return st["state"]
    return next(iter(st), None)


def build_log_map(data):
    """log_id(原始 32B) -> {operator,name,state,url,interval:(start,end)}"""
    mapping = {}
    for op in data.get("operators", []):
        for arr in ("logs", "tiled_logs"):
            for log in op.get(arr, []):
                lid = log.get("log_id")
                if not lid:
                    continue
                raw = base64.b64decode(lid + "=" * (-len(lid) % 4))
                ti = log.get("temporal_interval") or {}
                mapping[raw] = dict(
                    operator=op.get("name", "?"),
                    name=log.get("description", "?"),
                    state=state_name(log.get("state")),
                    url=log.get("url") or log.get("submission_url", ""),
                    interval=(parse_iso(ti.get("start_inclusive")),
                              parse_iso(ti.get("end_exclusive"))))
    return mapping


# ---------- 单 SCT 判定 ----------

def judge_sct(sct, cert, now, tol, window):
    """对单个 SCT 做时间交叉核验。
    返回 (verdict, issues): verdict ∈ PASS/观察/不一致; issues 为说明列表"""
    issues = []
    ts = sct["timestamp"] / 1000.0          # RFC 6962 时间戳单位=毫秒
    ts_dt = datetime.datetime.fromtimestamp(ts, tz=UTC)
    nb = utc(cert.not_valid_before_utc)
    na = utc(cert.not_valid_after_utc)

    # 1) 不得晚于审计时点(容差 tol 秒, 防时钟偏移)
    if ts_dt > now + datetime.timedelta(seconds=tol):
        issues.append("不一致: SCT 时间戳晚于审计时点(未来收据)")
    # 2) 不得晚于证书 notAfter
    if na is not None and ts_dt > na:
        issues.append(f"不一致: SCT 时间戳晚于证书 notAfter({iso(na)})")
    # 3) 早于 notBefore 分窗口: 超 window 判不一致, 窗口内判观察
    if nb is not None:
        early = (nb - ts_dt).total_seconds()
        if early > window:
            issues.append(
                f"不一致: SCT 时间戳早于证书 notBefore({iso(nb)}) 达 "
                f"{early/3600:.0f} 小时(超 {window/3600:.0f}h 窗口, "
                f"预签发/backdate 需人工确认)")
        elif early > 0:
            issues.append(
                f"观察: SCT 时间戳略早于 notBefore {early/60:.0f} 分钟"
                f"(签发窗口内, 正常)")
    return ts_dt, issues


def judge_log(sct, log, ts_dt):
    """SCT 声称日志侧核验: log list 匹配 / 状态 / temporal_interval。
    返回 (level, issues): level ∈ PASS/OBSERVE/MISMATCH"""
    issues = []
    level = "PASS"
    if log is None:
        return "OBSERVE", ["观察: 快照中未匹配到该 log_id(可能是新日志/私有日志)"]
    if log["state"] != "usable":
        level = "OBSERVE"
        issues.append(f"观察: 日志状态为 {log['state']}, 非 usable"
                      f"(Chrome CT Policy 要求 usable)")
    start, end = log["interval"]
    if start is None and end is None:
        issues.append("观察: 日志未声明 temporal_interval, 无法比对时间域")
        return ("OBSERVE" if level == "PASS" else level,
                issues or ["(日志未声明 temporal_interval)"])
    if start is not None and ts_dt < start:
        issues.append(
            f"不一致: SCT 早于日志 temporal_interval 起点 {iso(start)} —— 可能"
            f"发证时点 log list 区间与现在不同, 需调取签发时点快照核对(O2 类)")
        level = "MISMATCH"
    if end is not None and ts_dt >= end:
        issues.append(
            f"不一致: SCT 达到/晚于日志 temporal_interval 终点 {iso(end)}")
        level = "MISMATCH"
    if not issues:
        return level, []
    return level, issues


# ---------- 单证书分析 ----------

def analyze_one(cert_path, log_map, now, tol, window, quiet):
    """对单张证书提取 SCT 并逐条核验。返回汇总 dict 与 SCT 级 CSV rows"""
    base = os.path.basename(cert_path)
    row = {"cert": base, "subject": "", "serial_hex": "",
           "notBefore": "", "notAfter": "", "sct_count": 0,
           "verdict": "", "mismatch": False, "observe": False,
           "issue": "", "sct_rows": []}
    with open(cert_path, "rb") as f:
        try:
            cert = read_cert_bytes(f.read())
        except Exception as e:
            row["verdict"] = f"错误: 证书解析失败: {e}"
            row["issue"] = str(e)
            return row

    nb, na = utc(cert.not_valid_before_utc), utc(cert.not_valid_after_utc)
    is_ca = False
    try:
        is_ca = cert.extensions.get_extension_for_class(
            x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        pass
    row["subject"] = cert.subject.rfc4514_string()
    row["serial_hex"] = f"{cert.serial_number:#x}"
    row["notBefore"] = iso(nb)
    row["notAfter"] = iso(na)
    if not quiet:
        print(f"\n===== {base} =====")
        print(f"证书: {row['subject']}")
        print(f"序列号: {row['serial_hex']}")
        print(f"有效期: {iso(nb)} ~ {iso(na)}  (审计时点 {now.strftime('%Y-%m-%d %H:%M:%S')})")

    data = extract_sct_list(cert.public_bytes(Encoding.DER))
    if data is None:
        note = "证书无 CT Precertificate SCTs 扩展"
        if is_ca:
            # CA/中间证书本就无 SCT：CT 政策只约束 TLS 服务器证书(叶子)
            row["verdict"] = f"无SCT(CA/中间证书, CT 政策不适用)"
            row["observe"] = True
        else:
            row["verdict"] = ("不一致: " if nb >= CT_POLICY_DATE else "") + \
                f"无SCT: {note}"
            row["mismatch"] = nb >= CT_POLICY_DATE
            if not quiet:
                print(f"[无 SCT]{' (notBefore 在 2018-04-30 后, 违反 Chrome CT Policy)' if nb >= CT_POLICY_DATE else ' (签发早于 CT 强制期, 政策不适用)'}")
        row["issue"] = note
        return row

    scts = parse_scts(data)
    row["sct_count"] = len(scts)
    if len(scts) < 2 and nb >= CT_POLICY_DATE and not is_ca:
        row["mismatch"] = True
        row["issue"] = (f"SCT 数量 {len(scts)} < 2"
                        f"(Chrome CT Policy 要求 2018-04-30 后签发 >= 2)")
    row["verdict"] = "PASS"
    row["observe"] = False
    cert_issues = [row["issue"]] if row["issue"] else []
    cert_mismatch = row["mismatch"]
    cert_observe = False

    for i, sct in enumerate(scts, 1):
        lid = sct["log_id"]
        log = log_map.get(lid)
        ts_dt, t_issues = judge_sct(sct, cert, now, tol, window)
        l_level, l_issues = judge_log(sct, log, ts_dt)

        sct_mismatch = any(x.startswith("不一致") for x in t_issues) or \
            l_level == "MISMATCH"
        sct_observe = (any(x.startswith("观察") for x in t_issues)
                       or l_level == "OBSERVE") and not sct_mismatch
        issues = t_issues + l_issues
        verdict = ("不一致" if sct_mismatch
                   else ("观察" if (sct_observe or issues) else "PASS"))

        cert_mismatch |= sct_mismatch
        cert_observe |= sct_observe or verdict == "观察"
        if issues:
            cert_issues.append(f"SCT#{i}: {'; '.join(issues)}")

        if not quiet:
            logname = (f"[{log['operator']}] {log['name']} ({log['state']})"
                       if log else "(快照未匹配)")
            iv = ""
            if log and log["interval"] != (None, None):
                iv = (f"  时间域: {iso(log['interval'][0])} ~ "
                      f"{iso(log['interval'][1]) or '∞'}")
            print(f"--- SCT #{i} ---")
            print(f"  声称日志: {logname}")
            print(f"  SCT 时间: {ts_dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}{iv}")
            mark = "!! " if sct_mismatch else ("?? " if verdict == "观察" else "OK ")
            print(f"  {mark}[{verdict}]")
            for x in issues:
                print(f"      · {x}")

        row["sct_rows"].append(dict(
            cert=base, subject=row["subject"], serial_hex=row["serial_hex"],
            notBefore=row["notBefore"], notAfter=row["notAfter"],
            audit_at=now.strftime("%Y-%m-%d %H:%M:%S"),
            sct_idx=i,
            log_operator=log["operator"] if log else "",
            log_name=log["name"] if log else "",
            log_state=log["state"] if log else "",
            sct_time=ts_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            sct_time_ms=sct["timestamp"],
            interval_start=iso(log["interval"][0]) if log else "",
            interval_end=iso(log["interval"][1]) if log else "",
            verdict=verdict,
            issue="; ".join(issues)))

    row["mismatch"] = cert_mismatch
    row["observe"] = cert_observe and not cert_mismatch
    if cert_mismatch:
        row["verdict"] = "不一致"
    elif cert_observe or cert_issues:
        row["verdict"] = "观察"
    else:
        row["verdict"] = "PASS"
    row["issue"] = " | ".join(cert_issues)
    if not row["sct_rows"]:               # 理论不可达(有 SCT 必有行), 防御
        row["sct_rows"] = [dict(cert=base, verdict=row["verdict"],
                                issue=row["issue"])]
    return row


# ---------- 汇总与入口 ----------

def collect_certs(paths):
    out = []
    for p in paths:
        p = os.path.expanduser(p)
        if os.path.isdir(p):
            files = sorted(glob.glob(os.path.join(p, "**", "*"), recursive=True))
            out.extend(f for f in files
                       if f.lower().endswith(CERT_EXTS) and os.path.isfile(f))
        elif os.path.isfile(p):
            out.append(p)
    return out


def summarize(results, quiet):
    any_mismatch = any(r["mismatch"] for r in results)
    if len(results) > 1 or quiet:
        for r in results:
            mark = "!! " if r["mismatch"] else ("?? " if r["observe"] else "   ")
            print(f"{mark}{r['cert']:<40} SCT×{r['sct_count']}  {r['verdict']}")
            if r["issue"]:
                print(f"    └ {r['issue']}")
    else:
        r = results[0]
        print(f"\n[结论] {r['verdict']}")
        if r["issue"]:
            print(f"[备注] {r['issue']}")
    return any_mismatch


def main():
    ap = argparse.ArgumentParser(
        description="交叉核验 SCT 时间戳 × 证书有效期 × 日志 temporal_interval",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("用法:")[1].split("退出码:")[0])
    ap.add_argument("paths", nargs="*", help="证书文件或目录(目录递归)")
    ap.add_argument("--loglist", help="log list v3 快照 JSON(默认自动找 ct_audit/samples/)")
    ap.add_argument("--offline", action="store_true",
                    help="无本地快照时报错退出, 不回退在线拉取")
    ap.add_argument("--tolerance", type=int, default=300,
                    help="SCT 晚于审计时点容差秒数(默认 300)")
    ap.add_argument("--preissue-window", type=int, default=86400,
                    help="SCT 早于 notBefore 容忍窗口秒数(默认 86400=24h)")
    ap.add_argument("--csv", help="汇总导出 CSV(逐 SCT 一行)")
    ap.add_argument("--quiet", action="store_true", help="每张证书只打一行结论")
    args = ap.parse_args()

    if not args.paths:
        ap.print_help()
        sys.exit(1)

    data, source = load_log_data(args.loglist, offline=args.offline)
    log_map = build_log_map(data)
    snap_ver = data.get("version") or data.get("log_list_timestamp") or "?"
    print(f"log list: {source}   (version {snap_ver})")

    certs = collect_certs(args.paths)
    if not certs:
        print("错误: 未找到任何证书文件(.pem/.crt/.cer/.der/.cert)",
              file=sys.stderr)
        sys.exit(1)
    if len(certs) > 1:
        args.quiet = True
        print(f"共 {len(certs)} 张证书, 逐张核验中...")

    now = datetime.datetime.now(tz=UTC)
    results = []
    for c in certs:
        try:
            r = analyze_one(c, log_map, now, args.tolerance,
                            args.preissue_window, args.quiet)
        except Exception as e:
            r = {"cert": os.path.basename(c), "subject": "", "serial_hex": "",
                 "notBefore": "", "notAfter": "", "sct_count": 0,
                 "verdict": f"错误: {type(e).__name__}: {e}",
                 "mismatch": False, "observe": False,
                 "issue": str(e), "sct_rows": []}
        results.append(r)

    any_mismatch = summarize(results, args.quiet)

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=CSV_HEADER, extrasaction="ignore")
            w.writeheader()
            for r in results:
                rows = r.get("sct_rows") or [dict(cert=r["cert"],
                                                  verdict=r["verdict"],
                                                  issue=r["issue"])]
                for sr in rows:
                    w.writerow(sr)
        print(f"\n已汇总 {sum(len(r.get('sct_rows') or [1]) for r in results)}"
              f" 条 SCT 记录 -> {args.csv}")

    n_bad = sum(1 for r in results if r["mismatch"])
    n_obs = sum(1 for r in results if r["observe"])
    print(f"\n完成: {len(results)} 张证书, 不一致 {n_bad} 张, "
          f"观察 {n_obs} 张")
    sys.exit(1 if any_mismatch else 0)


if __name__ == "__main__":
    main()
