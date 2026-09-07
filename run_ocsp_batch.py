#!/usr/bin/env python3
"""
run_ocsp_batch.py —— 批量跑 check_ocsp.py，对每个证书联网查询 OCSP 状态

对给定的证书（单个/多个文件或目录，目录递归搜索 .pem/.crt/.cer/.der/.cert），
逐张调用 check_certs_python/check_ocsp.py --status 查询，逐张打印结果；
可选 --csv 输出一张汇总表（cert / status / detail 三列），方便 Excel 打开。

用法:
    python3 run_ocsp_batch.py <证书文件|证书目录> [更多...] [--csv 输出.csv] [--timeout 秒] [--der]
    python3 run_ocsp_batch.py certs/ --csv results/ocsp_batch.csv --timeout 10
    python3 run_ocsp_batch.py a.pem b.pem c.pem --der
    python3 run_ocsp_batch.py                        # 无参数 → 交互模式

状态取值: GOOD / REVOKED / UNKNOWN（查询成功）；ERROR（无 OCSP 地址、
签发者加载失败、网络不通、响应非成功等，详见 detail 列）。

退出码: 全部证书查询成功返回 0，有 ERROR 返回 1。
"""

import argparse
import csv
import glob
import os
import subprocess
import sys
from collections import Counter

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
CHECK_OCSP = os.path.join(PROJECT_ROOT, "check_certs_python", "check_ocsp.py")
CERT_EXTS = (".pem", ".crt", ".cer", ".der", ".cert")

_STATUS_OK = {"GOOD", "REVOKED", "UNKNOWN"}


def err(msg):
    print(f"错误: {msg}", file=sys.stderr)


def collect_certs(paths):
    """收集所有证书文件：文件直接加入；目录递归搜索。返回排序去重列表"""
    certs = []
    for p in paths:
        p = os.path.expanduser(p)
        if os.path.isdir(p):
            certs.extend(
                f for f in glob.glob(os.path.join(p, "**", "*"), recursive=True)
                if os.path.isfile(f) and f.lower().endswith(CERT_EXTS))
        elif os.path.isfile(p):
            certs.append(p)
        else:
            err(f"路径不存在，跳过 -> {p}")
    return sorted(set(certs))


def query_one(cert_path, timeout=15, der=False):
    """调用 check_ocsp.py --status 查询单张证书。
    返回 (status, detail)：status ∈ GOOD/REVOKED/UNKNOWN/ERROR"""
    cmd = [sys.executable, CHECK_OCSP, cert_path, "--status",
           "--timeout", str(timeout)]
    if der:
        cmd.append("--der")
    proc = subprocess.run(cmd, capture_output=True, text=True)

    if proc.returncode == 0:
        line = (proc.stdout.strip().splitlines() or [""])[0]
        if line.startswith("REVOKED "):          # 格式: REVOKED <吊销时间>
            return "REVOKED", line[len("REVOKED "):].strip()
        return (line if line in _STATUS_OK else "UNKNOWN"), ""
    # 失败: stderr 首行形如 "ERROR: 无 OCSP 地址" / "ERROR: OCSP 查询失败: ..."
    detail = (proc.stderr.strip().splitlines() or ["ERROR: 未知错误"])[0]
    if detail.startswith("ERROR: "):
        return "ERROR", detail[len("ERROR: "):].strip()
    return "ERROR", detail


def print_result(i, n, cert_path, status, detail):
    print(f"[{i}/{n}] {cert_path}")
    if status in _STATUS_OK:
        print(f"      {status}" + (f"  ({detail})" if detail else ""))
    else:
        print(f"      ERROR: {detail}")


def write_csv(path, results):
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:  # utf-8-sig 方便 Excel
        wr = csv.writer(f)
        wr.writerow(["cert", "status", "detail"])
        for cert, status, detail in results:
            wr.writerow([cert, status, detail])


def batch(paths, csv_path=None, timeout=15, der=False):
    """批量主流程，返回退出码"""
    if not os.path.isfile(CHECK_OCSP):
        err(f"找不到 {CHECK_OCSP}")
        return 1

    certs = collect_certs(paths)
    if not certs:
        err("没有找到任何证书文件（支持 " + " ".join(CERT_EXTS) + "）")
        return 1
    print(f"批量模式: 发现 {len(certs)} 个证书（timeout={timeout}s）\n")

    results = []
    for i, cert in enumerate(certs, 1):
        status, detail = query_one(cert, timeout, der)
        results.append((cert, status, detail))
        print_result(i, len(certs), cert, status, detail)

    counter = Counter(s for _, s, _ in results)
    print("\n============ 批量完成 ============")
    print(f"共 {len(certs)} 张: " +
          " / ".join(f"{k} {counter.get(k, 0)}" for k in
                     sorted(set(counter) | _STATUS_OK,
                            key=lambda x: (x not in _STATUS_OK, x))))

    failed = [(c, d) for c, s, d in results if s == "ERROR"]
    if failed:
        print("查询失败:")
        for c, d in failed:
            print(f"  [ERROR] {c} -> {d}")

    if csv_path:
        write_csv(csv_path, results)
        print(f"CSV: {csv_path}（{len(results)} 行）")
    return 0 if not failed else 1


def interactive():
    """无参数时的交互式输入：空格/逗号分隔多个路径"""
    print("=== 交互模式（输入文件或目录，空格/逗号分隔多个，q 退出）===")
    raw = input("证书路径或目录: ").strip()
    if raw.lower() in ("q", "quit"):
        sys.exit(0)
    paths = raw.replace(",", " ").split()
    csv_path = None
    d = input("CSV 输出路径 (回车不输出): ").strip()
    if d.lower() in ("q", "quit"):
        sys.exit(0)
    if d:
        csv_path = os.path.expanduser(d)
    t = input("超时秒数 (回车默认 15): ").strip()
    if t.lower() in ("q", "quit"):
        sys.exit(0)
    try:
        timeout = int(t) if t else 15
    except ValueError:
        print(f"  !! '{t}' 不是数字，按默认 15 处理")
        timeout = 15
    der = input("DER 格式 (y/N): ").strip().lower() in ("y", "yes")
    sys.exit(batch(paths, csv_path, timeout, der))


def main():
    ap = argparse.ArgumentParser(
        description="批量跑 check_ocsp.py 查询证书 OCSP 状态")
    ap.add_argument("paths", nargs="*", help="证书文件或目录（可多个）")
    ap.add_argument("--csv", dest="csv_path", metavar="输出.csv",
                    help="把结果写入 CSV 汇总表（cert/status/detail 三列）")
    ap.add_argument("--timeout", type=int, default=15, help="每张证书超时秒数 (默认 15)")
    ap.add_argument("--der", action="store_true", help="证书按 DER 优先解析")
    args = ap.parse_args()

    if not args.paths:          # 无任何路径 → 交互模式
        interactive()
        return
    sys.exit(batch(args.paths, args.csv_path, args.timeout, args.der))


if __name__ == "__main__":
    main()
