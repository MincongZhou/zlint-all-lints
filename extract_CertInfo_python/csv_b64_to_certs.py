#!/usr/bin/env python3
"""csv_b64_to_certs.py —— 把"折行 base64"的预处理 CSV 拆成
一份 JSONL 证书仓库 + 每张证书一个文件（DER / PEM），供 zlint / openssl 等使用。

背景: 数据是从 SQL*Plus 导出的（set linesize 1000），一列长 base64 被按固定宽度
折成多行，一条记录以「以逗号开头的行」结束，逗号后是第二列（NOT_BEFORE）。

输入格式（假设，见 --help 说明）:
    表头行                       CERT_ENTITY,NOT_BEFORE
    证书 base64（可能被折行）    MIIHUDCC...（每行 1000 字符，末尾补空格）
                                DgQWBBSj...
    ...
    第二列（记录结束标志）       ,20250807175646

输出:
    <out-dir>/<idx:05d>_<serial>.der|.pem   每张证书一个文件
    <jsonl>                                 每行一张证书: {"idx": n, "cert_b64": "..."}
    <index>（可选）                          对照表 csv

用法:
    python3 csv_b64_to_certs.py 预处理-260914.csv --out-dir certs_all \\
            --jsonl certs_all.jsonl --index certs_all_index.csv
    python3 csv_b64_to_certs.py 预处理-260914.csv --no-files   # 只出 JSONL（先验证）
    python3 csv_b64_to_certs.py certs_all.jsonl --from-jsonl   # 从 JSONL 重新出文件
    python3 csv_b64_to_certs.py 预处理-260914.csv --limit 5    # 冒烟测试

注意:
  - JSONL 忠实保存输入里的每一条 base64 记录；base64 坏掉/证书解析失败的记录
    会写进 JSONL 但**不生成文件**，并在末尾统一列出 idx，退出码为 1。
  - 文件名带 5 位序号（保证唯一 + 可排序）+ 序列号（便于人工识别）。
  - 一批几千个小文件放在 OneDrive 目录里同步会很慢，建议输出到本地非同步目录。
"""

import argparse
import base64
import csv
import hashlib
import json
import os
import sys
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes

# 表头行的前缀（这类文件的第一列列名）
_HEADER_PREFIXES = ("CERT_ENTITY",)
_TIME_FMT = "%Y%m%d%H%M%S"


# ---------------------------------------------------------------------------
# 读输入
# ---------------------------------------------------------------------------
def iter_csv_records(path, limit=None):
    """读预处理 CSV，产出 (idx, cert_b64, not_before)。

    - 折行拼回：非逗号开头的行都是 base64 片段，strip 后拼接
    - 记录结束：以逗号开头的行，逗号后是 NOT_BEFORE
    - 纯空白（补位空格）行跳过
    """
    idx = 0
    cur = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\r\n")
            s = line.strip()
            if not s:
                continue
            if line.startswith(","):
                idx += 1
                yield idx, "".join(cur), s[1:].strip()
                cur = []
                if limit and idx >= limit:
                    return
                continue
            if not cur and s.startswith(_HEADER_PREFIXES):
                continue                      # 表头行
            cur.append(s)
    if cur:                                   # 末条缺第二列
        idx += 1
        yield idx, "".join(cur), ""


def iter_jsonl_records(path, limit=None):
    """读 JSONL 仓库，产出 (idx, cert_b64, not_before)"""
    idx = 0
    with open(path, encoding="utf-8") as f:
        for line_no, raw in enumerate(f, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as e:
                print(f"  !! 第 {line_no} 行 JSON 解析失败，跳过: {e}", file=sys.stderr)
                continue
            idx = obj.get("idx", idx + 1)
            if limit and idx > limit:
                return
            yield idx, obj.get("cert_b64", ""), obj.get("not_before", "")


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------
def hex_colon(data):
    h = data.hex().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def to_pem(der):
    """把 DER 包成 PEM。用原始字节编码，不做任何重新序列化。"""
    b64 = base64.b64encode(der).decode("ascii")
    body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


def parse_csv_time(value):
    """'20250807175646' → datetime，失败返回 None"""
    try:
        return datetime.strptime(value, _TIME_FMT)
    except (ValueError, TypeError):
        return None


def unique_path(path):
    """避免重名：a.der → a_2.der"""
    if not os.path.exists(path):
        return path
    root, ext = os.path.splitext(path)
    i = 2
    while os.path.exists(f"{root}_{i}{ext}"):
        i += 1
    return f"{root}_{i}{ext}"


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def run(args):
    src = os.path.abspath(args.src)
    if not os.path.isfile(src):
        sys.exit(f"错误: 输入文件不存在 -> {src}")

    src_dir = os.path.dirname(src)
    out_dir = os.path.abspath(args.out_dir or os.path.join(src_dir, "certs_all"))
    jsonl_path = os.path.abspath(args.jsonl or os.path.join(src_dir, "certs_all.jsonl"))
    ext = "." + args.format

    if not args.no_files:
        os.makedirs(out_dir, exist_ok=True)

    records = (iter_jsonl_records(src, args.limit) if args.from_jsonl
               else iter_csv_records(src, args.limit))

    index_rows = []
    bad = []                     # 解码/解析失败的 idx
    written = 0
    total = 0

    idx_f = open(jsonl_path, "w", encoding="utf-8")
    try:
        for idx, b64, not_before in records:
            total += 1
            idx_f.write(json.dumps({"idx": idx, "cert_b64": b64},
                                   ensure_ascii=False) + "\n")

            der = cert = None
            if b64:
                try:
                    der = base64.b64decode(b64, validate=True)
                except Exception as e:                     # noqa: BLE001
                    bad.append((idx, f"base64 解码失败: {e}"))
                else:
                    try:
                        cert = x509.load_der_x509_certificate(der)
                    except Exception as e:                 # noqa: BLE001
                        bad.append((idx, f"证书解析失败: {e}"))

            if cert is not None and not args.no_files:
                serial_hex = format(cert.serial_number, "X")
                fname = f"{idx:05d}_{serial_hex}{ext}"
                fpath = unique_path(os.path.join(out_dir, fname))
                data = der if args.format == "der" else to_pem(der).encode("ascii")
                with open(fpath, "wb") as f:
                    f.write(data)
                written += 1
            elif cert is not None:
                fpath = ""
            else:
                fpath = ""

            if args.index:
                csv_dt = parse_csv_time(not_before)
                cert_dt = cert.not_valid_before_utc.replace(tzinfo=None) if cert else None
                diff = "" if (csv_dt is None or cert_dt is None) else int(
                    (csv_dt - cert_dt).total_seconds())
                index_rows.append({
                    "idx": idx,
                    "file": os.path.basename(fpath) if fpath else "",
                    "ok": cert is not None,
                    "serial_hex": (format(cert.serial_number, "X") if cert else ""),
                    "sha256": hex_colon(hashlib.sha256(der).digest()) if der else "",
                    "not_before_csv": not_before,
                    "not_before_cert_utc": (cert_dt.strftime(_TIME_FMT) if cert_dt else ""),
                    "diff_seconds": diff,
                    "subject": (cert.subject.rfc4514_string() if cert else ""),
                })

            if total % 500 == 0:
                print(f"  ... 已处理 {total} 条", file=sys.stderr)
    finally:
        idx_f.close()

    if args.index:
        with open(args.index, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=list(index_rows[0].keys()) if index_rows else
                               ["idx", "file", "ok", "serial_hex", "sha256",
                                "not_before_csv", "not_before_cert_utc",
                                "diff_seconds", "subject"])
            w.writeheader()
            w.writerows(index_rows)

    print(f"\n读取记录: {total} 条")
    print(f"JSONL   : {jsonl_path}")
    if not args.no_files:
        print(f"证书文件: {written} 个 -> {out_dir}/（--format {args.format}）")
    if args.index:
        print(f"对照表  : {os.path.abspath(args.index)}")
    if bad:
        print(f"\n!! 有 {len(bad)} 条记录未生成文件:", file=sys.stderr)
        for i, msg in bad[:20]:
            print(f"   idx={i}: {msg}", file=sys.stderr)
        if len(bad) > 20:
            print(f"   ...（其余 {len(bad) - 20} 条省略）", file=sys.stderr)
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser(
        description="把折行 base64 的预处理 CSV 拆成 JSONL + 每张证书一个文件")
    ap.add_argument("src", help="预处理 CSV 路径（或 JSONL，配合 --from-jsonl）")
    ap.add_argument("--from-jsonl", action="store_true",
                    help="输入是 JSONL 仓库（每条含 cert_b64），从它重新生成证书文件")
    ap.add_argument("--out-dir", help="证书文件输出目录（默认 <输入目录>/certs_all）")
    ap.add_argument("--jsonl", help="JSONL 输出路径（默认 <输入目录>/certs_all.jsonl）")
    ap.add_argument("--format", choices=("der", "pem"), default="der",
                    help="证书文件格式（默认 der）")
    ap.add_argument("--index", help="另外输出对照表 csv（idx/文件/SN/指纹/时间差...）")
    ap.add_argument("--no-files", action="store_true", help="只输出 JSONL，不生成文件")
    ap.add_argument("--limit", type=int, help="只处理前 N 条（冒烟测试用）")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
