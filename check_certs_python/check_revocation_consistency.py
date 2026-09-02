#!/usr/bin/env python3
"""
check_revocation_consistency.py —— 交叉核验 CRL 与 OCSP 的吊销信息一致性

背景: 同一张证书的吊销事实可能同时出现在两条独立渠道:
  - CRL : CA 周期性签发的吊销列表，条目含 (序列号, revocationDate, reasonCode)
  - OCSP: responder 实时回答吊销状态，REVOKED 时携带 revocationTime 与 reason
  正常运营中两渠道对同一证书应结果一致(状态一致、吊销时间一致、原因一致)。
  若出现"CRL 已吊销而 OCSP 未吊销""吊销时间不一致"等，通常是吊销流程事故/
  发布延迟/数据同步残留——这类问题跑 zlint 格式规则发现不了，本脚本专做此核验。

流程(对每张输入证书):
  1. 证书侧: 加载证书(PEM/DER 自动识别)，取序列号/签发者/notBefore
  2. CRL 侧: 用本地 --crl(若给) 或从证书 CDP 自动下载 → 按序列号反查吊销条目
  3. OCSP 侧: 从 AIA 拿 responder，签发者可本地给或从 CA Issuers 自动下载 →
             查询状态，REVOKED 时取吊销时间/原因(无 AIA 或无网络则跳过该源)
  4. 核验:   (a) 状态一致性  (b) 吊销时间交叉比对(精确到秒级比较)
             (c) 吊销原因比对  (d) 时间自洽性: 吊销时间不得晚于该源 this_update、
                 不得早于证书 notBefore、同一序列号两次吊销时间一致
  5. 输出:   单证书打印各源时间戳/差异/结论; 批量(目录)逐行打印 + 可选 --csv 汇总

判定结论(verdict):
  - 未吊销(CRL 无条目 & OCSP GOOD)
  - 一致: 吊销时间与原因都一致 / 一致: 吊销时间一致(原因单侧缺失)
  - 不一致: 吊销状态冲突(一侧已吊销另一侧未吊销)
  - 不一致: 吊销时间差异 X 秒
  - 不一致: 吊销原因不同
  - 单源: 仅 CRL(吊销于…) / 仅 OCSP(GOOD/REVOKED…) / 无吊销源(无法核验)
  - 错误: 证书解析失败等

用法:
    python3 check_certs_python/check_revocation_consistency.py <证书路径|目录> ... [选项]
    python3 check_certs_python/check_revocation_consistency.py certs/baidu.pem
    python3 check_certs_python/check_revocation_consistency.py certs/ --csv result.csv

选项:
    --crl <文件>     用本地 CRL 反查(不给则从证书 CDP 自动下载; 单文件即可, 批量共用)
    --issuer <文件>  本地签发者证书(OCSP 需要; 不给则从证书 AIA 的 CA Issuers 自动下载)
    --timeout <秒>   联网超时, 默认 15
    --csv <文件>     汇总导出 CSV(同时逐张打印一行结论)
    --no-ocsp        跳过 OCSP 侧(离线场景只看 CRL)
    --no-crl         跳过 CRL 侧(只看 OCSP)
    --quiet          每张证书只打印一行简短结论(单证书默认详细)

退出码: 存在任何"不一致"结论 → 1; 其余 → 0(单源/网络失败不计为不一致)

依赖: python3 + cryptography; 复用同目录 check_crl.py 与 check_ocsp.py
"""
import argparse
import csv
import datetime
import glob
import os
import sys

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtensionOID

from check_ocsp import (fetch_url, load_cert, get_aia_urls, load_issuer,
                        query_ocsp)
from check_crl import get_cdp_urls

CERT_EXTS = (".pem", ".crt", ".cer", ".der", ".cert")
UTC = datetime.timezone.utc

CSV_HEADER = ["cert", "subject", "serial_hex", "verdict",
              "crl_revoked_at", "ocsp_revoked_at", "time_diff_seconds",
              "crl_reason", "ocsp_reason",
              "crl_this_update", "ocsp_this_update", "note"]


# ---------- 基础工具 ----------

def utc(dt):
    """确保 aware UTC datetime（naive 视为 UTC）"""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def iso(dt):
    return utc(dt).isoformat() if dt is not None else ""


def load_crl_bytes(raw):
    """PEM / DER 自动识别加载 CRL"""
    try:
        return x509.load_pem_x509_crl(raw)
    except ValueError:
        return x509.load_der_x509_crl(raw)


def find_entry(crl, serial):
    """在 CRL 中按序列号反查吊销条目；无则返回 None"""
    for rc in crl:
        if rc.serial_number == serial:
            return rc
    return None


def entry_reason(rc):
    """吊销条目的 reasonCode（无扩展返回空串）"""
    try:
        return rc.extensions.get_extension_for_class(
            x509.CRLReason).value.reason.name
    except x509.ExtensionNotFound:
        return ""


def fmt_reason(r):
    return r or "(未给出)"


# ---------- 各吊销源 ----------

def source_crl(cert, crl_path, timeout, quiet):
    """CRL 源: 本地 --crl 或从 CDP 自动下载。
    返回 dict: {ok, desc, this_update, revoked_at, reason}；ok=False 时含 error"""
    serial = cert.serial_number
    crl = None
    desc = ""

    if crl_path:
        with open(crl_path, "rb") as f:
            try:
                crl = load_crl_bytes(f.read())
                desc = f"本地文件 {crl_path}"
            except Exception as e:
                return {"ok": False, "error": f"CRL 解析失败: {e}", "desc": desc}
    else:
        urls = get_cdp_urls(cert)
        if not urls:
            return {"ok": False, "error": "证书无 CDP 扩展(或非 http 分发点)",
                    "desc": ""}
        if not quiet:
            print(f"[CRL] 找到 {len(urls)} 个 CDP 分发点")
        for url in urls:
            try:
                if not quiet:
                    print(f"[CRL] 下载: {url}")
                data = fetch_url(url, timeout=timeout, quiet=quiet)
                crl = load_crl_bytes(data)
                desc = url
                break
            except Exception as e:
                if not quiet:
                    print(f"[CRL]   下载失败: {type(e).__name__}: {e}")
        if crl is None:
            return {"ok": False, "error": "所有 CDP 分发点下载/解析失败",
                    "desc": ""}

    if not quiet:
        print(f"[CRL] 来源: {desc}")
        print(f"[CRL] 签发者: {crl.issuer.rfc4514_string()}")
        print(f"[CRL] this_update: {crl.last_update_utc}   next_update: {crl.next_update_utc}")

    rc = find_entry(crl, serial)
    if rc is None:
        return {"ok": True, "desc": desc, "revoked_at": None, "reason": "",
                "this_update": utc(crl.last_update_utc),
                "entry_count": len(crl)}
    return {"ok": True, "desc": desc,
            "revoked_at": utc(rc.revocation_date_utc),
            "reason": entry_reason(rc),
            "this_update": utc(crl.last_update_utc),
            "entry_count": len(crl)}


def source_ocsp(cert, issuer_path, timeout, quiet):
    """OCSP 源: 构造请求查询 responder。
    返回 dict: {ok, error?, desc, status, revoked_at, reason, this_update}"""
    ocsp_url, ca_issuers_url = get_aia_urls(cert)
    if not ocsp_url:
        return {"ok": False, "error": "证书无 AIA OCSP 地址", "desc": ""}
    if not quiet:
        print(f"[OCSP] responder: {ocsp_url}")
    try:
        issuer = load_issuer(issuer_path, cert, ca_issuers_url, quiet=quiet)
    except Exception as e:
        return {"ok": False, "error": f"加载签发者证书失败: {e}", "desc": ocsp_url}
    try:
        resp = query_ocsp(cert, issuer, ocsp_url, timeout=timeout,
                          quiet=quiet, respout=None)
    except Exception as e:
        return {"ok": False, "error": f"OCSP 查询失败: {e}", "desc": ocsp_url}

    if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return {"ok": False,
                "error": f"OCSP 响应状态: {resp.response_status.name}(非成功)",
                "desc": ocsp_url}

    st = resp.certificate_status
    out = {"ok": True, "desc": ocsp_url, "status": st.name,
           "this_update": utc(resp.this_update_utc)}
    if st == ocsp.OCSPCertStatus.REVOKED:
        out["revoked_at"] = utc(resp.revocation_time_utc)
        out["reason"] = (resp.revocation_reason.name
                         if resp.revocation_reason is not None else "")
    else:
        out["revoked_at"] = None
        out["reason"] = ""
    return out


# ---------- 核验判定 ----------

def check_sanity(side_name, revoked_at, this_update, cert):
    """时间自洽性检查，返回 (mismatch, note 列表)"""
    notes = []
    bad = False
    if revoked_at is None:
        return False, notes
    if this_update is not None and revoked_at > this_update:
        bad = True
        notes.append(f"{side_name}: 吊销时间晚于该源 this_update，数据自相矛盾")
    if cert.not_valid_before_utc is not None and \
            revoked_at < utc(cert.not_valid_before_utc):
        bad = True
        notes.append(f"{side_name}: 吊销时间早于证书 notBefore，自相矛盾")
    return bad, notes


def judge(crl, ocs, cert):
    """核心判定。crl/ocs 为 source_* 返回的 dict（已 ok）。
    返回 (verdict, diff_seconds, mismatch, notes)"""
    notes = []
    crl_rev = crl["revoked_at"]
    ocs_rev = ocs["revoked_at"]

    # 状态一致性（两源都有结果时才可比）
    if crl_rev is None and ocs_rev is None:
        return "未吊销(CRL 无条目 & OCSP GOOD)", "", False, notes
    if crl_rev is None and ocs_rev is not None:
        return "不一致: 吊销状态冲突(OCSP 已吊销但 CRL 未收录)", "", True, notes
    if crl_rev is not None and ocs_rev is None:
        return "不一致: 吊销状态冲突(CRL 已吊销但 OCSP 未吊销)", "", True, notes

    # 两源都吊销 → 时间比对
    diff = abs((crl_rev - ocs_rev).total_seconds())
    time_ok = diff == 0
    reason_ok = None
    if crl["reason"] and ocs["reason"]:
        reason_ok = (crl["reason"] == ocs["reason"])
    elif not crl["reason"] and not ocs["reason"]:
        reason_ok = True
        notes.append("两源均未给吊销原因")
    else:
        notes.append(f"吊销原因单侧缺失: CRL={fmt_reason(crl['reason'])}, "
                     f"OCSP={fmt_reason(ocs['reason'])}")

    if not time_ok:
        return f"不一致: 吊销时间差异 {diff:.0f} 秒", f"{diff:.0f}", True, notes
    if reason_ok is False:
        return (f"不一致: 吊销原因不同(CRL={fmt_reason(crl['reason'])}, "
                f"OCSP={fmt_reason(ocs['reason'])})"), "0", True, notes
    if reason_ok is True:
        return "一致: 吊销时间与原因均一致", "0", False, notes
    return "一致: 吊销时间一致(原因单侧缺失)", "0", False, notes


# ---------- 单证书分析 ----------

def analyze_one(cert_path, crl_path, issuer_path, timeout, no_crl, no_ocsp,
                quiet):
    """对单张证书执行双源核验。返回 dict（含 row 供 CSV / 打印）"""
    cert_path = os.path.expanduser(cert_path)
    result = {"cert": os.path.basename(cert_path), "subject": "", "serial_hex": "",
              "verdict": "", "crl_revoked_at": "", "ocsp_revoked_at": "",
              "diff": "", "crl_reason": "", "ocsp_reason": "",
              "crl_this_update": "", "ocsp_this_update": "", "note": "",
              "mismatch": False}

    with open(cert_path, "rb") as f:
        try:
            cert = load_cert(f.read())
        except Exception as e:
            result["verdict"] = "错误: 证书解析失败"
            result["note"] = str(e)
            return result

    result["subject"] = cert.subject.rfc4514_string()
    result["serial_hex"] = f"{cert.serial_number:#x}"
    if not quiet:
        print(f"\n===== {result['cert']} =====")
        print(f"证书: {result['subject']}")
        print(f"序列号: {result['serial_hex']}   notBefore: "
              f"{cert.not_valid_before_utc}")

    notes = []
    crl = ocs = None

    # --- CRL 侧 ---
    if not no_crl:
        crl = source_crl(cert, crl_path, timeout, quiet)
        if crl["ok"]:
            result["crl_this_update"] = iso(crl["this_update"])
            if crl["revoked_at"] is not None:
                result["crl_revoked_at"] = iso(crl["revoked_at"])
                result["crl_reason"] = crl["reason"]
            if not quiet:
                if crl["revoked_at"] is not None:
                    print(f"[CRL] 吊销条目: 序列号命中, 吊销于 "
                          f"{iso(crl['revoked_at'])}  原因 {fmt_reason(crl['reason'])}")
                else:
                    print(f"[CRL] 吊销条目: 未收录该序列号(共 {crl['entry_count']} 条)")
        else:
            notes.append(f"CRL 源不可用: {crl['error']}")
            if not quiet:
                print(f"[CRL] 跳过: {crl['error']}")
            crl = None

    # --- OCSP 侧 ---
    if not no_ocsp:
        ocs = source_ocsp(cert, issuer_path, timeout, quiet)
        if ocs["ok"]:
            result["ocsp_this_update"] = iso(ocs["this_update"])
            if ocs["revoked_at"] is not None:
                result["ocsp_revoked_at"] = iso(ocs["revoked_at"])
                result["ocsp_reason"] = ocs["reason"]
            if not quiet:
                st = ocs["status"]
                if st == "REVOKED":
                    print(f"[OCSP] 状态 REVOKED, 吊销于 {iso(ocs['revoked_at'])}"
                          f"  原因 {fmt_reason(ocs['reason'])}")
                else:
                    print(f"[OCSP] 状态 {st}")
        else:
            notes.append(f"OCSP 源不可用: {ocs['error']}")
            if not quiet:
                print(f"[OCSP] 跳过: {ocs['error']}")
            ocs = None

    # --- 自洽性 + 交叉判定 ---
    bad_sanity = False
    if crl and crl["ok"]:
        b, ns = check_sanity("CRL", crl["revoked_at"], crl["this_update"], cert)
        bad_sanity |= b
        notes.extend(ns)
    if ocs and ocs["ok"]:
        b, ns = check_sanity("OCSP", ocs["revoked_at"], ocs["this_update"], cert)
        bad_sanity |= b
        notes.extend(ns)

    diff = ""
    if crl and ocs:
        verdict, diff, mismatch, ns = judge(crl, ocs, cert)
        notes.extend(ns)
    elif crl:
        verdict = (f"单源: 仅 CRL(吊销于 {iso(crl['revoked_at'])})"
                   if crl["revoked_at"] is not None else
                   "单源: 仅 CRL(未收录该序列号)")
        mismatch = False
    elif ocs:
        verdict = (f"单源: 仅 OCSP(REVOKED, 吊销于 {iso(ocs['revoked_at'])})"
                   if ocs["revoked_at"] is not None else
                   f"单源: 仅 OCSP({ocs['status']})")
        mismatch = False
    else:
        verdict = "无吊销源: 无法核验"
        mismatch = False

    if bad_sanity:
        verdict = f"自洽性异常: {verdict}"
        mismatch = True

    result["verdict"] = verdict
    if diff:
        result["diff"] = diff
    result["note"] = " | ".join(notes) if notes else ""
    result["mismatch"] = mismatch
    return result


def summarize(results, quiet):
    """打印每张证书一行结论(批量) 或全部详情(单张)。返回是否含不一致"""
    any_mismatch = any(r["mismatch"] for r in results)
    if len(results) > 1 or quiet:
        for r in results:
            mark = "!! " if r["mismatch"] else "   "
            diff = f", 差异 {r['diff']} 秒" if r["diff"] else ""
            print(f"{mark}{r['cert']:<40} {r['verdict']}{diff}")
            if r["note"]:
                print(f"    └ {r['note']}")
    else:
        r = results[0]
        print(f"\n[结论] {r['verdict']}{', 差异 ' + r['diff'] + ' 秒' if r['diff'] else ''}")
        if r["note"]:
            print(f"[备注] {r['note']}")
    return any_mismatch


# ---------- 入口 ----------

def collect_certs(paths):
    """展开参数: 文件直接收, 目录递归收集 .pem/.crt/.cer/.der/.cert"""
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


def main():
    ap = argparse.ArgumentParser(
        description="交叉核验 CRL 与 OCSP 的吊销信息一致性",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("用法:")[1].split("退出码:")[0])
    ap.add_argument("paths", nargs="*", help="证书文件或目录(目录递归)")
    ap.add_argument("--crl", help="本地 CRL 文件(不给则从证书 CDP 自动下载)")
    ap.add_argument("--issuer", help="本地签发者证书(不给则从 AIA 自动下载)")
    ap.add_argument("--timeout", type=int, default=15, help="联网超时秒数(默认 15)")
    ap.add_argument("--csv", help="汇总导出 CSV")
    ap.add_argument("--no-ocsp", action="store_true", help="跳过 OCSP 侧")
    ap.add_argument("--no-crl", action="store_true", help="跳过 CRL 侧")
    ap.add_argument("--quiet", action="store_true", help="每张证书只打一行结论")
    args = ap.parse_args()

    if not args.paths:
        ap.print_help()
        sys.exit(1)

    certs = collect_certs(args.paths)
    if not certs:
        print("错误: 未找到任何证书文件(.pem/.crt/.cer/.der/.cert)", file=sys.stderr)
        sys.exit(1)

    if len(certs) > 1:
        args.quiet = True
        print(f"共 {len(certs)} 张证书, 逐张核验中...")

    if args.crl:
        args.crl = os.path.expanduser(args.crl)
        if not os.path.isfile(args.crl):
            print(f"错误: CRL 文件不存在: {args.crl}", file=sys.stderr)
            sys.exit(1)
    if args.issuer:
        args.issuer = os.path.expanduser(args.issuer)
        if not os.path.isfile(args.issuer):
            print(f"错误: 签发者文件不存在: {args.issuer}", file=sys.stderr)
            sys.exit(1)

    results = []
    for c in certs:
        try:
            r = analyze_one(c, args.crl, args.issuer, args.timeout,
                            args.no_crl, args.no_ocsp, args.quiet)
        except Exception as e:
            r = {"cert": os.path.basename(c), "subject": "", "serial_hex": "",
                 "verdict": f"错误: {type(e).__name__}: {e}", "crl_revoked_at": "",
                 "ocsp_revoked_at": "", "diff": "", "crl_reason": "",
                 "ocsp_reason": "", "crl_this_update": "", "ocsp_this_update": "",
                 "note": "", "mismatch": False}
        results.append(r)

    any_mismatch = summarize(results, args.quiet)

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(CSV_HEADER)
            for r in results:
                w.writerow([r["cert"], r["subject"], r["serial_hex"],
                            r["verdict"], r["crl_revoked_at"],
                            r["ocsp_revoked_at"], r["diff"], r["crl_reason"],
                            r["ocsp_reason"], r["crl_this_update"],
                            r["ocsp_this_update"], r["note"]])
        print(f"\n已汇总 {len(results)} 张证书 -> {args.csv}")

    print(f"\n完成: {len(results)} 张, "
          f"不一致 {sum(1 for r in results if r['mismatch'])} 张")
    sys.exit(1 if any_mismatch else 0)


if __name__ == "__main__":
    main()
