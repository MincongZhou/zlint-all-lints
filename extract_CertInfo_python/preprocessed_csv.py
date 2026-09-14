#!/usr/bin/env python3
"""preprocessed_csv.py —— 还原「1.csv（SQL*Plus spool）→ 预处理-*.csv」的清洗逻辑

背景: 1.csv 是 SQL*Plus 的 spool 记录（含 SQL 语句回显、列头、分页分隔线、
结尾统计行），证书 base64 被 set linesize 1000 折成固定宽度；预处理后的 CSV
只留数据段并换成 CERT_ENTITY,NOT_BEFORE 表头。

清洗规则（逐条从两个文件对比得出，可用 --verify 验证）:
  1. 丢弃 SQL*Plus 命令回显（以 `SQL>` 开头的行）
  2. 丢弃数据区之前的全部内容：SQL 语句续行（`  2  CE.SIGNATURE_CERT ,`）等，
     即「第二条 ------- 分隔线」之前都不算数据
  3. 丢弃列头文字行（SIGNATURE_CERT / NOT_BEFORE / CERT_ENTITY）与 `-----` 分隔线
     （分页导致列头重复出现时一并丢弃）
  4. 丢弃结尾统计行 `N rows selected.`
  5. 重写一行表头：CERT_ENTITY,NOT_BEFORE
  6. 第二列（日期）改写为 `,<日期>`：**这是记录边界标志**，
     即 csv_b64_to_certs.py 判断「一条记录到此结束」就靠这一行的前导逗号
  7. 其余行原样保留：证书 base64 的折行与补位空格都不动
     （csv_b64_to_certs.py 会自动 strip；--trim 去行尾空格，--drop-blank 去空行）

用法:
    python3 preprocessed_csv.py 1.csv                        # 重建 -> 1_rebuilt.csv
    python3 preprocessed_csv.py 1.csv --out x.csv --trim     # 顺带去掉行尾空格
    python3 preprocessed_csv.py 1.csv --verify 预处理-260914.csv   # 重建并逐项比对

--verify 会报告三件事:
    ① 行级差异（行数、前几处不同）
    ② 证书级差异（把每条记录的 base64 拼回 DER 后按 SHA-256 比对，这才是实质）
    ③ 行尾/换行符等格式差异
"""

import argparse
import base64
import difflib
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from csv_b64_to_certs import iter_csv_records  # noqa: E402  复用记录解析（折行拼回）

HEADER_TEXTS = {"SIGNATURE_CERT", "NOT_BEFORE", "CERT_ENTITY"}
DEFAULT_HEADER = "CERT_ENTITY,NOT_BEFORE"


# ---------------------------------------------------------------------------
# 清洗
# ---------------------------------------------------------------------------
def rebuild(lines, header=DEFAULT_HEADER, trim=False, drop_blank=False):
    """按上面的规则重建。lines 需已去掉行尾换行符（保留行内空格）。"""
    out = [header]
    seps = 0
    started = False
    for line in lines:
        s = line.strip()
        if s.startswith("SQL>"):                  # 规则 1
            continue
        if s and set(s) == {"-"}:                 # 规则 2/3：分隔线
            seps += 1
            if seps >= 2:
                started = True
            continue
        if s in HEADER_TEXTS:                     # 规则 3：列头文字（含分页重复）
            continue
        if s.endswith("rows selected."):          # 规则 4
            break
        if not started:                           # 规则 2：数据区之前
            continue
        if not s:                                 # 空行（可能是补位空格）
            if drop_blank:
                continue
            out.append("")
            continue
        if s.isdigit() and len(s) == 14:           # 规则 6：第二列日期 -> ",<日期>"
            out.append("," + s)
            continue
        out.append(line.rstrip() if trim else line)  # 规则 7
    return out


def read_lines(path):
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        text = f.read()
    crlf = text.count("\r\n")
    lines = text.replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines, crlf, text


# ---------------------------------------------------------------------------
# 证书级比对：拼回 base64 → DER → SHA-256
# ---------------------------------------------------------------------------
def cert_fingerprints(path):
    """{idx: sha256}；解析不了的记录记为 None"""
    out = {}
    for idx, b64, _nb in iter_csv_records(path):
        try:
            out[idx] = hashlib.sha256(base64.b64decode(b64, validate=True)).hexdigest()
        except Exception:                              # noqa: BLE001
            out[idx] = None
    return out


def verify(rebuilt_path, ref_path, show=6):
    print(f"\n================ 与 {os.path.basename(ref_path)} 比对 ================")
    a, a_crlf, a_text = read_lines(rebuilt_path)
    b, b_crlf, _b_text = read_lines(ref_path)

    print(f"行数        : 重建 {len(a)}   参考 {len(b)}   {'一致' if len(a) == len(b) else '不一致'}")
    print(f"换行符      : 重建 {'CRLF' if a_crlf else 'LF'}   参考 {'CRLF' if b_crlf else 'LF'}")
    print(f"字节级相同  : {a_text == _b_text}")

    if a_text != _b_text:
        diff = [d for d in difflib.unified_diff(b, a, lineterm="", n=0,
                                                fromfile="参考", tofile="重建")
                if d[:1] in "+-" and d[:3] not in ("+++", "---")]
        print(f"行级差异行数: {len(diff)}（下为前 {show} 条，- 参考 / + 重建）")
        for d in diff[:show]:
            body = d[1:]
            print(f"   {d[0]} len={len(body):5d} {body[:70]!r}{'...' if len(body) > 70 else ''}")

    fa, fb = cert_fingerprints(rebuilt_path), cert_fingerprints(ref_path)
    only_a = set(fa) - set(fb)
    only_b = set(fb) - set(fa)
    diff_fp = [i for i in set(fa) & set(fb) if fa[i] != fb[i]]
    print("\n--- 证书级（DER SHA-256）---")
    print(f"记录数      : 重建 {len(fa)}   参考 {len(fb)}")
    print(f"指纹不同的  : {len(diff_fp)}")
    print(f"仅在重建中  : {len(only_a)}   仅在参考中: {len(only_b)}")
    ok = not diff_fp and not only_a and not only_b
    print(f"结论        : {'证书内容完全一致 ✔' if ok else '证书内容有差异 ✘'}")
    return ok


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="还原 SQL*Plus spool（1.csv）→ 预处理 CSV 的清洗逻辑")
    ap.add_argument("src", help="SQL*Plus spool 文件（如 1.csv）")
    ap.add_argument("--out", help="重建输出路径（默认 <输入名>_rebuilt.csv）")
    ap.add_argument("--verify", metavar="参考文件",
                    help="重建后与这个已有的预处理 CSV 逐项比对")
    ap.add_argument("--header", default=DEFAULT_HEADER, help="重建的表头行")
    ap.add_argument("--trim", action="store_true", help="去掉每行行尾空格")
    ap.add_argument("--drop-blank", action="store_true", help="丢弃空行")
    ap.add_argument("--crlf", action="store_true", help="用 CRLF 换行（默认 LF）")
    args = ap.parse_args()

    src = os.path.abspath(args.src)
    if not os.path.isfile(src):
        sys.exit(f"错误: 输入文件不存在 -> {src}")
    out_path = os.path.abspath(args.out or
                               os.path.splitext(src)[0] + "_rebuilt.csv")

    lines, src_crlf, _ = read_lines(src)
    rebuilt = rebuild(lines, args.header, args.trim, args.drop_blank)
    eol = "\r\n" if (args.crlf or (args.verify is None and src_crlf)) else "\n"
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        f.write(eol.join(rebuilt) + eol)

    print(f"输入    : {src}（{len(lines)} 行，{'CRLF' if src_crlf else 'LF'}）")
    print(f"重建输出: {out_path}（{len(rebuilt)} 行）")

    if args.verify:
        verify(out_path, os.path.abspath(args.verify))


if __name__ == "__main__":
    main()
