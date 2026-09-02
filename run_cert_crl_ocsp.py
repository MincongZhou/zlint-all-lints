#!/usr/bin/env python3
"""
run_cert_crl_ocsp.py —— 对一张证书一键跑齐 zlint 的 CA / CRL / OCSP 三类规则

背景: zlint 对单个输入对象只真实执行其所属类型的规则（证书→CA 414 条，
CRL→18 条，OCSP→1 条），其余标 NA。本脚本把证书的"配套吊销对象"也取下来一起跑，
让三类规则全部真实执行:

    1. 证书侧:  zlint-all-lints -cert <证书>           → cert.json / cert.csv（CA 414 条）
    2. CRL 侧:  check_crl.py 从证书 CDP 下载 CRL 转 PEM → zlint-all-lints 跑 CRL 规则（18 条）
    3. OCSP 侧: check_ocsp.py 查 OCSP 并存原始 DER 响应 → zlint-all-lints 跑 OCSP 规则（1 条）

CRL / OCSP 步骤联网失败（无 CDP / 无 OCSP 地址 / 网络不通 / 下载超时）时自动跳过，
只影响对应侧规则，不中断整体。

用法:
    python3 run_cert_crl_ocsp.py <证书路径|证书目录> [输出目录] [--timeout 秒] [--detail]
    python3 run_cert_crl_ocsp.py                                # 无参数 → 交互模式

输出（默认"精简模式"：批量多张证书也只留三张按侧汇总表 + 每证书的证据文件）:
    输出根/                              （默认 ./results；每张证书再建 <证书名>/ 子目录）
    ├── ca_summary.csv        全部证书的证书侧汇总（每行首列 cert 为证书名）
    ├── crl_summary.csv       全部证书的 CRL 侧汇总
    ├── ocsp_summary.csv      全部证书的 OCSP 侧汇总
    └── <证书名>/             每证书目录，只留联网证据（zlint 中间 JSON/CSV 已删）
        ├── crl.pem           从 CDP 下载的 CRL（PEM，有则）
        └── resp.der          原始 OCSP 响应（有则）

加 --detail 则保留每张证书的完整产物（同旧版行为）:
    <证书名>/
    ├── cert.json / cert.csv      证书侧（433 行，CA 规则真实执行）
    ├── crl.pem                   从 CDP 下载的 CRL（PEM，有则）
    ├── crl.json / crl.csv        18 条 CRL 规则（有则）
    ├── resp.der                  原始 OCSP 响应（有则）
    └── ocsp.json / ocsp.csv      1 条 OCSP 规则（有则）

依赖: python3 + cryptography；zlint-all-lints 需已编译（go build -o zlint-all-lints .）。
"""

import csv
import glob
import json
import os
import subprocess
import sys
from collections import Counter

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
ZLINT_BIN = os.path.join(PROJECT_ROOT, "zlint-all-lints")
CHECK_CRL = os.path.join(PROJECT_ROOT, "check_certs_python", "check_crl.py")
CHECK_OCSP = os.path.join(PROJECT_ROOT, "check_certs_python", "check_ocsp.py")
CERT_EXTS = (".pem", ".crt", ".cer", ".der", ".cert")

# 每侧的中间文件名前缀 与 汇总表文件名
_SIDE_FILE = {"证书侧": "cert", "CRL 侧": "crl", "OCSP 侧": "ocsp"}
_SUMMARY_FILE = {"证书侧": "ca_summary.csv", "CRL 侧": "crl_summary.csv",
                 "OCSP 侧": "ocsp_summary.csv"}


def err(msg):
    print(f"错误: {msg}", file=sys.stderr)


def merge_csv(src_csv, summary_csv, prefix):
    """把 src_csv 的数据行（行首补 prefix）追加进 summary_csv；表头不存在时先写。
    返回合并的数据行数。用 csv 模块读写，字段含逗号/引号也不会串列。"""
    if not os.path.isfile(src_csv):
        return 0
    with open(src_csv, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    if len(rows) < 2:            # 只有表头或空 → 没有数据行
        return 0
    header, data = rows[0], rows[1:]
    is_new = not os.path.isfile(summary_csv)
    with open(summary_csv, "a", newline="", encoding="utf-8") as f:
        wr = csv.writer(f)
        if is_new:
            wr.writerow(["cert"] + header)
        for r in data:
            wr.writerow([prefix] + r)
    return len(data)


def lint_one(obj_path, out_json, out_csv):
    """对单个 PKI 对象跑 zlint-all-lints。返回 (exit_code, input_type)"""
    if not os.path.isfile(ZLINT_BIN):
        err(f"找不到 {ZLINT_BIN}，请先编译: go build -o zlint-all-lints .")
        return 1, None
    cmd = [ZLINT_BIN, "-cert", obj_path, "-out", out_json, "-csv", out_csv,
           "-pretty=false"]
    print(f"执行: {' '.join(cmd)}")
    rc = subprocess.call(cmd)
    itype = None
    if rc == 0 and os.path.isfile(out_json):
        with open(out_json, encoding="utf-8") as f:
            itype = json.load(f).get("meta", {}).get("input_type")
    return rc, itype


def status_stats(json_path):
    """读一份 lint JSON，返回各 status 的计数（如 {'pass': 412, 'NA': 21}）"""
    if not os.path.isfile(json_path):
        return None
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)
    return dict(Counter(l["status"] for l in data.get("lints", [])))


def fmt_stats(stats):
    if not stats:
        return "(无结果)"
    return "  ".join(f"{k}={v}" for k, v in stats.items())


def run_one(cert_path, out_root=None, timeout=15, detail=False):
    """跑单张证书：证书侧 + CRL 侧 + OCSP 侧，各侧结果合并进输出根下的三张汇总表。
    默认精简模式（只留 *_summary.csv + crl.pem / resp.der 证据文件）；
    detail=True 保留每张证书的全部中间产物（json/csv/pem/der）。
    返回是否全部 OK"""
    stem = os.path.splitext(os.path.basename(cert_path))[0]
    summary_dir = out_root or os.path.join(PROJECT_ROOT, "results")
    out_dir = os.path.join(summary_dir, stem)   # 每证书一个子目录
    os.makedirs(out_dir, exist_ok=True)

    rows = []   # (步骤, tag, exit_code)
    ok_all = True

    def append_summary(tag, csv_name):
        """把该侧 csv 数据行合并进对应汇总表（行首补证书名）"""
        n = merge_csv(os.path.join(out_dir, csv_name),
                      os.path.join(summary_dir, _SUMMARY_FILE[tag]), stem)
        if n:
            print(f"  → {_SUMMARY_FILE[tag]} 追加 {n} 行")

    # ---------- [1/3] 证书侧 ----------
    print(f"\n===== [1/3] 证书侧 lint（CA 414 条规则） =====")
    rc, itype = lint_one(cert_path,
                         os.path.join(out_dir, "cert.json"),
                         os.path.join(out_dir, "cert.csv"))
    rows.append(("证书侧", itype, rc))
    ok_all &= rc == 0
    append_summary("证书侧", "cert.csv")

    # ---------- [2/3] CRL 侧：从 CDP 下载 CRL → 跑 18 条 CRL 规则 ----------
    print(f"\n===== [2/3] CRL 侧（从 CDP 下载 CRL → 18 条规则，联网） =====")
    crl_pem = os.path.join(out_dir, "crl.pem")
    rc = subprocess.call([sys.executable, CHECK_CRL, cert_path,
                          "--out", crl_pem, "--timeout", str(timeout)])
    if rc == 0 and os.path.isfile(crl_pem):
        rc, itype = lint_one(crl_pem,
                             os.path.join(out_dir, "crl.json"),
                             os.path.join(out_dir, "crl.csv"))
        rows.append(("CRL 侧", itype, rc))
        ok_all &= rc == 0
        append_summary("CRL 侧", "crl.csv")
    else:
        print("CRL 下载/转换失败，跳过 CRL 规则（不影响其他步骤）")
        rows.append(("CRL 侧", "跳过", rc))

    # ---------- [3/3] OCSP 侧：查询并保存原始响应 → 跑 1 条 OCSP 规则 ----------
    print(f"\n===== [3/3] OCSP 侧（查 OCSP 并存原始响应 → 1 条规则，联网） =====")
    resp_der = os.path.join(out_dir, "resp.der")
    rc = subprocess.call([sys.executable, CHECK_OCSP, cert_path,
                          "--respout", resp_der, "--status",
                          "--timeout", str(timeout)])
    if rc == 0 and os.path.isfile(resp_der):
        rc, itype = lint_one(resp_der,
                             os.path.join(out_dir, "ocsp.json"),
                             os.path.join(out_dir, "ocsp.csv"))
        rows.append(("OCSP 侧", itype, rc))
        ok_all &= rc == 0
        append_summary("OCSP 侧", "ocsp.csv")
    else:
        print("OCSP 查询失败，跳过 OCSP 规则（不影响其他步骤）")
        rows.append(("OCSP 侧", "跳过", rc))

    # ---------- 汇总统计（读 json，须在精简清理之前） ----------
    print("\n================ 汇总 ================")
    print(f"证书: {cert_path}")
    print(f"输出: {out_dir}/")
    print("----------------------------------------")
    for tag, itype, rc in rows:
        f = _SIDE_FILE[tag]
        stats = status_stats(os.path.join(out_dir, f"{f}.json"))
        label = f"{tag} ({itype or '-'})"
        if rc == 0 and stats:
            print(f"  [OK]   {label}: {fmt_stats(stats)}")
        else:
            print(f"  [跳过] {label}")
    print("----------------------------------------")
    print("说明: status 计数里 NA 表示该规则对输入对象不适用；pass/error 为真实执行结果")

    # ---------- 精简模式清理：只留三张汇总表 + 证据文件 ----------
    if not detail:
        removed = []
        for f in _SIDE_FILE.values():
            for ext in ("json", "csv"):
                p = os.path.join(out_dir, f"{f}.{ext}")
                if os.path.isfile(p):
                    os.remove(p)
                    removed.append(os.path.basename(p))
        if removed:
            print(f"精简模式: 已删中间产物 {', '.join(removed)}（各侧已并入 *_summary.csv）")
        # 目录里没有证据文件等任何内容 → 删除空目录
        if os.path.isdir(out_dir) and not os.listdir(out_dir):
            os.rmdir(out_dir)
            print(f"精简模式: 删除空目录 {out_dir}")
    return ok_all


def run_target(target, out_root=None, timeout=15, detail=False):
    """依赖检查 + 单个/批量分发（target 已展开 ~）"""
    if not os.path.exists(target):
        err(f"路径不存在 -> {target}")
        sys.exit(1)
    for s in (ZLINT_BIN, CHECK_CRL, CHECK_OCSP):
        if not os.path.isfile(s):
            err(f"找不到 {s}")
            sys.exit(1)

    # 每次运行重建三张汇总表（避免重跑同一证书时重复追加）
    summary_dir = out_root or os.path.join(PROJECT_ROOT, "results")
    os.makedirs(summary_dir, exist_ok=True)
    for f in _SUMMARY_FILE.values():
        p = os.path.join(summary_dir, f)
        if os.path.isfile(p):
            os.remove(p)
    print(f"三张汇总表重建于: {summary_dir}/"
          f"（{', '.join(_SUMMARY_FILE.values())}）")

    if os.path.isdir(target):
        # ---------- 批量：遍历目录下所有证书 ----------
        certs = sorted(
            p for p in glob.glob(os.path.join(target, "**", "*"), recursive=True)
            if os.path.isfile(p) and p.lower().endswith(CERT_EXTS))
        if not certs:
            err(f"目录下没有找到证书文件（{CERT_EXTS}）-> {target}")
            sys.exit(1)
        print(f"批量模式: 发现 {len(certs)} 个证书")
        ok_all, ok, fail = True, 0, []
        for i, c in enumerate(certs, 1):
            print(f"\n{'='*60}\n[{i}/{len(certs)}] {c}\n{'='*60}")
            ok_one = run_one(c, summary_dir, timeout, detail)
            ok_all &= ok_one
            if ok_one:
                ok += 1
            else:
                fail.append(c)
        print(f"\n============ 批量完成 ============")
        print(f"成功 {ok}/{len(certs)}，失败 {len(fail)} 个")
        for c in fail:
            print(f"  [失败] {c}")
        sys.exit(0 if ok_all else 1)
    else:
        # ---------- 单个证书 ----------
        ok = run_one(target, summary_dir, timeout, detail)
        sys.exit(0 if ok else 1)


def interactive():
    """无参数时的交互式输入：证书路径/目录必填，其余可回车跳过"""
    print("=== 交互模式（直接回车使用默认值，输入 q 退出）===")

    target = os.path.expanduser(input("证书路径或目录: ").strip())
    while True:
        if target.lower() in ("q", "quit"):
            sys.exit(0)
        if os.path.exists(target):
            break
        print(f"  !! 路径不存在: {target}")
        target = os.path.expanduser(input("请重新输入证书路径或目录 (q 退出): ").strip())

    out_dir = os.path.expanduser(input("输出目录 (回车用默认): ").strip())
    if out_dir.lower() in ("q", "quit"):
        sys.exit(0)

    t = input("网络超时秒数 (回车默认 15): ").strip()
    if t.lower() in ("q", "quit"):
        sys.exit(0)
    try:
        timeout = int(t) if t else 15
    except ValueError:
        print(f"  !! '{t}' 不是数字，按默认 15 处理")
        timeout = 15

    # 是否保留完整产物：默认精简（只留三张汇总表 + 证据文件）
    d = input("是否保留每张证书的完整产物 (y/N，默认精简): ").strip().lower()
    detail = d in ("y", "yes")

    run_target(target, out_dir or None, timeout, detail)


def main():
    args = sys.argv[1:]
    if not args:                    # 没有任何参数 → 交互模式
        interactive()
        return
    if args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    timeout = 15
    detail = False
    rest = []
    i = 0
    while i < len(args):
        if args[i] == "--timeout":
            timeout = int(args[i + 1])
            i += 2
        elif args[i] == "--detail":
            detail = True
            i += 1
        else:
            rest.append(args[i])
            i += 1
    if not rest:
        print("用法: python3 run_cert_crl_ocsp.py <证书路径|目录> [输出目录] "
              "[--timeout 秒] [--detail]")
        sys.exit(1)

    target = os.path.expanduser(rest[0])
    out_root = os.path.expanduser(rest[1]) if len(rest) > 1 else None
    run_target(target, out_root, timeout, detail)


if __name__ == "__main__":
    main()
