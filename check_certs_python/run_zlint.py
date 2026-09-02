#!/usr/bin/env python3
"""
run_zlint.py —— 跑 zlint 全部 433 条规则（封装 run_batch.sh）

输入支持:
    - 目录：遍历其中所有证书 / CRL / OCSP 响应
    - 单个文件：自动复制进临时目录跑，跑完自动清理（输出仍写到你指定的 out_dir）
zlint-all-lints 按官方 CLI 顺序自动识别对象类型，对哪类对象就真实执行哪类规则，
其余两类规则标 NA。

用法:
    python3 run_zlint.py <对象目录|文件> [输出目录] [--timeout 秒] [--jsonl] [--detail]
    python3 run_zlint.py                                        # 无参数 → 交互式输入

--jsonl: 跑完后把每个 <name>.json 转成 <name>.jsonl（每行一条 lint 规则）
--detail: 保留每个对象的 <name>.json / <name>.csv（run_batch.sh 默认只留汇总表）
          注意: 加 --jsonl 时自动等价于 --detail（jsonl 由 json 转换而来，必须保留源文件）
"""

import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile

# 本文件在 check_certs_python/ 下，run_batch.sh 在上一级（项目根目录）
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(PROJECT_ROOT, "run_batch.sh")


def convert_to_jsonl(json_dir):
    """把 json_dir 下所有 <name>.json 转成 <name>.jsonl，每行一条 lint 规则"""
    count = 0
    for jf in sorted(glob.glob(os.path.join(json_dir, "*.json"))):
        with open(jf, encoding="utf-8") as f:
            data = json.load(f)
        meta = data["meta"]
        jsonl_path = jf[:-len(".json")] + ".jsonl"   # baidu.json → baidu.jsonl
        with open(jsonl_path, "w", encoding="utf-8") as f:
            for lint in data["lints"]:
                row = {"cert": meta["input_file"], **lint}
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        count += 1
        print(f"已生成 {jsonl_path} ({len(data['lints'])} 行)")
    return count


def run_batch(target, out_dir=None, timeout=None, jsonl=False, detail=False):
    """对目录或单个文件跑 lint；文件模式复制进临时目录，跑完自动清理"""
    # 0. 展开 ~（shell 符号，Python 不会自动展开），命令行/交互模式都覆盖
    target = os.path.expanduser(target)
    if out_dir:
        out_dir = os.path.expanduser(out_dir)

    # jsonl 由 <name>.json 转换而来，必须保留单对象文件 → 自动等价于 --detail
    if jsonl:
        detail = True

    # 1. 前置检查：脚本存在、目标路径存在（目录或文件均可）
    if not os.path.isfile(SCRIPT):
        print(f"错误: 找不到 {SCRIPT}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(target):
        print(f"错误: 路径不存在 -> {target}", file=sys.stderr)
        sys.exit(1)

    # 2. 单文件模式：复制进临时目录，让 run_batch.sh 正常遍历
    tmp_dir = None
    if os.path.isfile(target):
        tmp_dir = tempfile.mkdtemp(prefix="zlint_all_")
        shutil.copy2(target, os.path.join(tmp_dir, os.path.basename(target)))
        print(f"单文件模式: 已复制 {os.path.basename(target)} 到临时目录")
        target = tmp_dir

    # 3. 组装命令（列表传参，路径带空格也安全）
    cmd = [SCRIPT, target]
    if out_dir:
        cmd.append(out_dir)
    if detail:
        cmd.append("--detail")

    print(f"执行: {' '.join(cmd)}")
    # 4. 不捕获输出 → run_batch.sh 的进度会实时打到终端
    result = subprocess.run(cmd, text=True, timeout=timeout)

    # 5. 清理临时目录（输出文件已由 run_batch.sh 写入 out_dir）
    if tmp_dir:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # 6. 检查退出码
    if result.returncode != 0:
        print(f"run_batch.sh 执行失败 (exit code {result.returncode})", file=sys.stderr)
        sys.exit(result.returncode)

    # 7. 只有加了 --jsonl 才转换
    if jsonl:
        real_out = out_dir or "results"   # 与 run_batch.sh 默认值保持一致
        convert_to_jsonl(real_out)


def interactive():
    """无参数时的交互式输入：对象目录或文件必填，其余可回车跳过"""
    print("=== 交互模式（目录或单个文件皆可，直接回车使用默认值，输入 q 退出）===")

    target = os.path.expanduser(input("对象目录或文件: ").strip())
    while True:
        if target.lower() in ("q", "quit"):
            sys.exit(0)
        if os.path.exists(target):
            break
        print(f"  !! 路径不存在: {target}")
        target = os.path.expanduser(input("请重新输入目录或文件 (q 退出): ").strip())

    # 输出目录：可选，回车跳过 → run_batch.sh 用默认 ./results
    out_dir = os.path.expanduser(input("输出目录 (回车默认 ./results): ").strip())
    if out_dir.lower() in ("q", "quit"):
        sys.exit(0)

    # 超时：可选，回车不限时；输入非数字时容错
    t = input("超时秒数 (回车不限时): ").strip()
    if t.lower() in ("q", "quit"):
        sys.exit(0)
    try:
        timeout = int(t) if t else None
    except ValueError:
        print(f"  !! '{t}' 不是数字，按不限时处理")
        timeout = None

    # 是否生成 JSONL：可选，默认不生成（--jsonl 会自动保留单对象文件）
    j = input("是否生成 JSONL (y/N): ").strip().lower()
    jsonl = j in ("y", "yes")

    # 是否保留每个对象的 JSON/CSV：可选，默认不保留（只留汇总表）
    d = input("是否保留每个对象的 JSON/CSV (y/N): ").strip().lower()
    detail = d in ("y", "yes")

    run_batch(target, out_dir or None, timeout, jsonl, detail)


def main():
    args = sys.argv[1:]

    if not args:                    # 没有任何参数 → 交互模式
        interactive()
        return

    # 有参数 → 命令行模式：逐个解析，--timeout / --jsonl / --detail 可放在任意位置
    jsonl = False
    detail = False
    timeout = None
    rest = []
    i = 0
    while i < len(args):
        if args[i] == "--timeout":
            timeout = int(args[i + 1])
            i += 2
        elif args[i] == "--jsonl":
            jsonl = True
            i += 1
        elif args[i] == "--detail":
            detail = True
            i += 1
        else:
            rest.append(args[i])
            i += 1

    target = rest[0] if rest else None
    out_dir = rest[1] if len(rest) > 1 else None

    if not target:
        print("用法: python3 run_zlint.py <对象目录|文件> [输出目录] "
              "[--timeout 秒] [--jsonl] [--detail]")
        sys.exit(1)

    run_batch(target, out_dir, timeout, jsonl, detail)


if __name__ == "__main__":
    main()
