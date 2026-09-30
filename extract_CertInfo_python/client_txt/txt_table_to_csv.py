#!/usr/bin/env python3
"""txt_table_to_csv.py —— 把 CFCA 的「txt 表格导出」转成标准「预处理 CSV」，接入既有链路。

链路（产物命名对齐 certs/CFCA订户证书_client_draft/，只把最前面一步换掉）:

    txt 表格 ──[本脚本]──> 预处理-<yymmdd>.csv ──[csv_b64_to_certs.py]──> certs_all/ + jsonl + index
                                                  └─[split_gm_certs.py]───> 国密证书/ + 非国密证书/

背景: certs/CFCA订户证书_client/ 里是 7 份 SQL*Plus 导出的文本表格，证书同样是
base64 DER（列为 CERT_ENTITY），但与 _draft 的 1.csv 有两处差异:
  1. 没有 spool 的「第二列」结构，因此**没有 `,<日期>` 记录边界行**——需要本脚本生成；
  2. 存在两种版式（见下），需要分别解析。

版式 A「箱式」（+---+ / | a | b |）：ovaudit / evocaaudit / eveccaudit / oveccaudit /
    dveccscaudit / evrootaudit。表头为 SERIAL_NUMBER | NOT_BEFORE | CERT_ENTITY[ | CERT_ENTITY2]，
    base64 完整落在单个单元格里；`NULL` 表示该列无值（evrootaudit 两列全 NULL，只有序列号+日期）。
版式 B「SQL*Plus 裸输出」：dvocaaudit。列头与 `----` 分隔线按分页重复出现，长列按 LINESIZE
    折行；记录以 `<SN> <DD-MON-YY>` 行开始，其后跟随 base64 片段。
    ⚠ 该版式里 CERT_ENTITY2 与超长 base64 无法可靠区分/还原：本脚本按「SN 行之后出现的所有
      base64 片段都属于 CERT_ENTITY」处理，并把**片段行数**记进索引便于人工核查。
    两种子变体都支持：SN 行只有序列号+日期（base64 在后续行）、或首个 base64 片段就紧跟在
    SN 行同一行尾（2026-09-21 重新导出的 dvocaaudit.txt 即后者）；分隔线只要由 `-` 与空格组成即跳过。

输出（都落在 --out-root 下，文件名对齐 _draft 的命名习惯）:
    预处理-<yymmdd>.csv   两列 CERT_ENTITY,NOT_BEFORE；每张证书的 base64 占一行，
                          随后紧跟一行 `,<14位时间>` 作为记录边界 —— 与
                          csv_b64_to_certs.py 的 iter_csv_records() 完全兼容
                          （日期取运行当天，可用 --csv-name 覆盖）。
    txt_source_index.csv  核查宽表：源文件/行号/列/状态/序列号/时间/时区差/指纹/有效期/
                          是否 CA/是否国密/去重来源/错误。

时区: 表里的 NOT_BEFORE 是 **UTC+8（北京）**，证书内部 ASN.1 时间是 **UTC**，
      index 的 diff_seconds 期望恒为 +28800（与 _draft 的 certs_all_index.csv 口径一致）。

用法:
    python3 txt_table_to_csv.py certs/CFCA订户证书_client
    python3 txt_table_to_csv.py certs/CFCA订户证书_client --out-root certs/CFCA订户证书_client_extract
    python3 txt_table_to_csv.py 某个.txt --no-dedupe --strict
"""

import argparse
import base64
import csv
import datetime
import hashlib
import os
import re
import sys

from cryptography import x509

# 复用父目录 split_gm_certs.py 的国密判定（SPKI 曲线 OID / 签名算法 OID）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from split_gm_certs import audit as gm_check  # noqa: E402
except Exception:  # noqa: BLE001  （缺依赖时降级：索引里 is_gm 留空）
    gm_check = None

# 默认文件名对齐 _draft：预处理-<yymmdd>.csv / txt_source_index.csv
CSV_NAME = f"预处理-{datetime.date.today():%y%m%d}.csv"
INDEX_NAME = "txt_source_index.csv"

# 版式 A：非 base64 的列（不作为证书内容处理）
META_COLS = ("SERIAL_NUMBER", "NOT_BEFORE")
# 版式 B：需要跳过的列头/提示行前缀
SQLPLUS_SKIP_PREFIXES = ("SQL>", "SERIAL_NUMBER", "NOT_BEFORE", "CERT_ENTITY", "SIGNATURE_CERT")
# 版式 B：记录起始行 `<SN> <DD-MON-YY>`（时间部分可能带 HH:MI:SS），
#         首个 base64 片段可能紧跟在同一行尾（新版导出即如此）
RE_SQLPLUS_START = re.compile(
    r"^([0-9A-Fa-f]{2,})\s+(\d{2}-[A-Z]{3}-\d{2}(?:\s+\d{2}:\d{2}:\d{2})?)"
    r"(?:\s+([A-Za-z0-9+/]+={0,2}))?\s*$")
RE_B64_LINE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
RE_NB_BOX = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})")

_INDEX_FIELDS = [
    "idx", "source_file", "line_no", "col", "status", "dup_of",
    "serial_txt", "cert_serial_hex", "not_before_txt", "not_before_precision",
    "not_before_csv", "not_before_utc", "not_after_utc", "diff_seconds",
    "der_len", "der_sha256", "is_ca", "is_gm",
    "subject", "issuer", "chunk_lines", "error",
]


# ---------------------------------------------------------------------------
# 输入枚举
# ---------------------------------------------------------------------------
def iter_input_files(paths):
    """目录 → 递归收 *.txt（跳过 Windows 下载残留 *.txt:Zone.Identifier）；文件 → 直收。"""
    out = []
    for p in paths:
        p = os.path.abspath(p)
        if os.path.isdir(p):
            for root, _dirs, names in os.walk(p):
                for n in names:
                    if n.lower().endswith(".txt") and ":zone.identifier" not in n.lower():
                        out.append(os.path.join(root, n))
        elif os.path.isfile(p):
            out.append(p)
        else:
            print(f"  !! 路径不存在，跳过: {p}", file=sys.stderr)
    return sorted(set(out))


# ---------------------------------------------------------------------------
# 版式识别 + 两种解析器
# ---------------------------------------------------------------------------
def detect_layout(lines):
    if any(l.startswith("SQL>") for l in lines):
        return "sqlplus"
    if any(l.lstrip().startswith("|") for l in lines):
        return "box"
    return "unknown"


def parse_box(lines):
    """版式 A → [(line_no, {列名: 值})]"""
    header, rows = None, []
    for no, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s.startswith("|"):
            continue                                    # 边框 +---+ 与空行
        cells = [c.strip() for c in s.split("|")[1:-1]]
        if header is None or (cells and cells[0] == "SERIAL_NUMBER"):
            header = cells                              # 首次表头 / 分页重复表头
            continue
        if len(cells) != len(header):
            print(f"    !! 第 {no} 行单元格数 {len(cells)} != 表头 {len(header)}，跳过",
                  file=sys.stderr)
            continue
        rows.append((no, dict(zip(header, cells))))
    return rows


def parse_sqlplus(lines):
    """版式 B → [(line_no, {列名: 值})]，chunk 行数/长度另存于 `_chunks`。"""
    rows, cur, chunks = [], None, []

    def flush():
        if cur is not None:
            cur["_chunks"] = chunks[:]
            rows.append((cur["_line_no"], cur))

    for no, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s or s.startswith(SQLPLUS_SKIP_PREFIXES) or set(s) <= {"-", " "}:
            continue
        m = RE_SQLPLUS_START.match(s)
        if m:                                           # 记录起始行
            flush()
            head = m.group(3) or ""                     # 同行尾部的首个 base64 片段
            cur = {"SERIAL_NUMBER": m.group(1), "NOT_BEFORE": m.group(2),
                   "CERT_ENTITY": head, "_line_no": no}
            chunks = [len(head)] if head else []
            continue
        if cur is not None and RE_B64_LINE.match(s):
            cur["CERT_ENTITY"] += s
            chunks.append(len(s))
    flush()
    return rows


# ---------------------------------------------------------------------------
# 时间换算
# ---------------------------------------------------------------------------
def parse_not_before(text):
    """表里的 NOT_BEFORE → (datetime, 精度)。精度: second / date / ''（无法识别）"""
    t = (text or "").strip()
    m = RE_NB_BOX.match(t)
    if m:
        y, mo, d, hh, mm, ss = (int(x) for x in m.groups())
        try:
            return datetime.datetime(y, mo, d, hh, mm, ss), "second"
        except ValueError:
            return None, ""
    m = re.match(r"^(\d{2})-([A-Z]{3})-(\d{2})$", t.upper())
    if m:
        try:                                            # SQL*Plus 默认日期格式，只有日期
            dt = datetime.datetime.strptime(t.upper(), "%d-%b-%y")
            return dt, "date"
        except ValueError:
            return None, ""
    for fmt, prec in (("%Y%m%d%H%M%S", "second"), ("%Y-%m-%d", "date")):
        try:
            return datetime.datetime.strptime(t, fmt), prec
        except ValueError:
            continue
    return None, ""


# ---------------------------------------------------------------------------
# 证书解析
# ---------------------------------------------------------------------------
def b64decode_cert(s):
    s = re.sub(r"\s+", "", s or "")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def cert_row(der):
    """→ dict（解析失败抛异常）"""
    cert = x509.load_der_x509_certificate(der)
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca = bool(bc.ca)
    except Exception:  # noqa: BLE001
        is_ca = ""
    is_gm = ""
    if gm_check is not None:
        try:
            is_gm = gm_check(der)["is_gm"]
        except Exception:  # noqa: BLE001
            is_gm = ""
    return {
        "cert_serial_hex": format(cert.serial_number, "X"),
        "der_sha256": hashlib.sha256(der).hexdigest().upper(),
        "not_before_utc": cert.not_valid_before_utc.replace(tzinfo=None),
        "not_after_utc": cert.not_valid_after_utc.replace(tzinfo=None),
        "is_ca": is_ca,
        "is_gm": is_gm,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
    }


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def run(args):
    files = iter_input_files(args.inputs)
    if not files:
        sys.exit("错误: 没有找到可解析的 .txt 输入")
    out_root = os.path.abspath(args.out_root)
    os.makedirs(out_root, exist_ok=True)
    csv_path = os.path.join(out_root, args.csv_name)
    index_path = os.path.join(out_root, args.index_name)

    records, index_rows = [], []
    seen = {}                                            # der_sha256 → idx
    stat = {}

    for i, path in enumerate(files, 1):
        name = os.path.basename(path)
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        layout = detect_layout(lines)
        rows = parse_box(lines) if layout == "box" else (
            parse_sqlplus(lines) if layout == "sqlplus" else [])
        print(f"[{i}/{len(files)}] {name}  版式={layout}  数据行={len(rows)}")
        if layout == "unknown":
            print("    !! 无法识别版式（既不是箱式也不含 SQL> 提示），跳过", file=sys.stderr)
            continue

        n_ok = 0
        for line_no, row in rows:
            serial_txt = (row.get("SERIAL_NUMBER") or "").strip()
            nb_txt = (row.get("NOT_BEFORE") or "").strip()
            nb_dt, nb_prec = parse_not_before(nb_txt)
            cands = [(c, v) for c, v in row.items()
                     if c not in META_COLS and not c.startswith("_")
                     and (v or "").strip() and (v or "").strip().upper() != "NULL"]
            if not cands:                                # 只有序列号+日期（如 evrootaudit）
                index_rows.append({
                    "source_file": name, "line_no": line_no, "col": "",
                    "status": "no_der", "serial_txt": serial_txt,
                    "not_before_txt": nb_txt, "not_before_precision": nb_prec,
                    "error": "表中无 base64 证书列（NULL）",
                })
                stat["no_der"] = stat.get("no_der", 0) + 1
                continue

            for col, raw_b64 in cands:
                rec = {"source_file": name, "line_no": line_no, "col": col,
                       "serial_txt": serial_txt, "not_before_txt": nb_txt,
                       "not_before_precision": nb_prec,
                       "chunk_lines": len(row.get("_chunks") or []) or 1,
                       "not_before_csv": (nb_dt.strftime("%Y%m%d%H%M%S") if nb_dt else ""),
                       "status": "ok", "dup_of": "", "error": ""}
                b64 = re.sub(r"\s+", "", raw_b64)
                der = None
                if not RE_B64_LINE.match(b64) and len(b64) < 16:
                    rec.update(status="b64_error", error="base64 片段过短/非法")
                else:
                    try:
                        der = b64decode_cert(b64)
                    except Exception as e:              # noqa: BLE001
                        rec.update(status="b64_error", error=f"base64 解码失败: {e}")
                    if der is not None:
                        try:
                            rec.update(cert_row(der))
                        except Exception as e:          # noqa: BLE001
                            rec.update(status="der_error", error=f"证书解析失败: {e}")
                    if der is not None and rec["status"] == "ok":
                        if args.no_dedupe or rec["der_sha256"] not in seen:
                            seen[rec["der_sha256"]] = len(records) + 1
                            records.append({
                                "idx": len(records) + 1,
                                "cert_b64": b64,
                                "not_before": (nb_dt.strftime("%Y%m%d%H%M%S") if nb_dt else ""),
                                "source": name, "serial": serial_txt, "col": col,
                            })
                            rec["idx"] = len(records)
                            n_ok += 1
                        else:
                            rec.update(status="dup", dup_of=seen[rec["der_sha256"]])
                if der is not None:
                    rec["der_len"] = len(der)
                    nb, na = rec.get("not_before_utc"), rec.get("not_after_utc")
                    if nb_dt and nb:
                        rec["diff_seconds"] = int((nb_dt - nb).total_seconds())
                stat[rec["status"]] = stat.get(rec["status"], 0) + 1
                index_rows.append({k: (v.strftime("%Y%m%d%H%M%S")
                                       if isinstance(v, datetime.datetime) else v)
                                   for k, v in rec.items()})
        print(f"    → 新增证书 {n_ok}")

    # ---- 写预处理 CSV（与 csv_b64_to_certs.py 的记录边界约定一致）----
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        f.write("CERT_ENTITY,NOT_BEFORE\n")
        for r in records:
            f.write(r["cert_b64"] + "\n")
            f.write("," + r["not_before"] + "\n")

    with open(index_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=_INDEX_FIELDS, extrasaction="ignore", restval="")
        w.writeheader()
        w.writerows(index_rows)

    diffs = sorted({r["diff_seconds"] for r in index_rows
                    if isinstance(r.get("diff_seconds"), int)
                    and r.get("not_before_precision") == "second"})
    coarse = sum(1 for r in index_rows if r.get("not_before_precision") == "date")
    print(f"\n输入文件   : {len(files)} 个")
    print(f"数据行     : {len(index_rows)} 行（其中无 DER {stat.get('no_der', 0)} 行）")
    print(f"输出证书   : {len(records)} 张（去重丢弃 {stat.get('dup', 0)}）")
    print(f"状态分布   : { {k: v for k, v in sorted(stat.items())} }")
    if diffs:
        print(f"时区校验   : 表内时间 - 证书内 UTC = {diffs}（秒）"
              f"{'  ← 即表内为 UTC+8，符合预期' if diffs == [28800] else '  ← 与预期的 28800 不符，请核查'}")
    if coarse:
        print(f"             （另 {coarse} 行表内时间只有日期精度，如 SQL*Plus 默认 DATE 格式，"
              f"不参与上面的时区校验）")
    print(f"预处理 CSV : {csv_path}")
    print(f"来源索引   : {index_path}")

    bad = [r for r in index_rows if r["status"] in ("b64_error", "der_error")]
    if bad:
        print(f"\n!! {len(bad)} 条记录未能解析成证书（详见索引 error 列）", file=sys.stderr)
        for r in bad[:10]:
            print(f"   {r['source_file']}:{r['line_no']} {r['serial_txt']} -> {r['error']}",
                  file=sys.stderr)
    if bad and args.strict:
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser(
        description="CFCA txt 表格导出 → 预处理 CSV + 来源索引（衔接 csv_b64_to_certs.py）")
    ap.add_argument("inputs", nargs="+", help="txt 表格文件或所在目录")
    ap.add_argument("--out-root", default=".",
                    help="输出目录（默认当前目录；run_client_txt.sh 默认 "
                         "certs/<样本名>_extract）")
    ap.add_argument("--csv-name", default=CSV_NAME, help=f"预处理 CSV 文件名（默认 {CSV_NAME}）")
    ap.add_argument("--index-name", default=INDEX_NAME, help=f"来源索引文件名（默认 {INDEX_NAME}）")
    ap.add_argument("--no-dedupe", action="store_true",
                    help="不按 DER SHA-256 去重（默认去重，保留首次出现）")
    ap.add_argument("--strict", action="store_true", help="存在解析失败的记录时退出码 1")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
