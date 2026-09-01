#!/usr/bin/env python3
"""
run_zlint.py —— 批量跑 zlint 全部 433 条规则（封装 run_batch.sh）

输入对象支持证书 / CRL / OCSP 响应：zlint-all-lints 按官方 CLI 顺序自动识别类型，
对哪类对象就真实执行哪类规则，其余两类规则标 NA。

用法:
    python3 run_zlint.py <对象目录> [输出目录] [--timeout 秒] [--jsonl]
    python3 run_zlint.py                                        # 无参数 → 交互式输入

--jsonl: 跑完后把每个 <name>.json 转成 <name>.jsonl（每行一条 lint 规则）
"""

import glob
import json
import os
import subprocess
import sys

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


def run_batch(cert_dir, out_dir=None, timeout=None, jsonl=False):
    """调用 run_batch.sh 批量跑 lint，可选转 JSONL"""
    # 0. 展开 ~（shell 符号，Python 不会自动展开），命令行/交互模式都覆盖
    cert_dir = os.path.expanduser(cert_dir)
    if out_dir:
        out_dir = os.path.expanduser(out_dir)

    # 1. 前置检查：脚本存在、对象目录存在
    if not os.path.isfile(SCRIPT):
        print(f"错误: 找不到 {SCRIPT}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(cert_dir):
        print(f"错误: 目录不存在 -> {cert_dir}", file=sys.stderr)
        sys.exit(1)

    # 2. 组装命令（列表传参，路径带空格也安全）
    cmd = [SCRIPT, cert_dir]
    if out_dir:
        cmd.append(out_dir)

    print(f"执行: {' '.join(cmd)}")
    # 3. 不捕获输出 → run_batch.sh 的进度会实时打到终端
    result = subprocess.run(cmd, text=True, timeout=timeout)

    # 4. 检查退出码
    if result.returncode != 0:
        print(f"run_batch.sh 执行失败 (exit code {result.returncode})", file=sys.stderr)
        sys.exit(result.returncode)

    # 5. 只有加了 --jsonl 才转换
    if jsonl:
        real_out = out_dir or "results"   # 与 run_batch.sh 默认值保持一致
        convert_to_jsonl(real_out)


def interactive():
    """无参数时的交互式输入：对象目录必填，其余可回车跳过"""
    print("=== 交互模式（直接回车使用默认值，输入 q 退出）===")

    # 对象目录：必填，循环直到存在（支持 ~ 展开）
    cert_dir = os.path.expanduser(input("对象目录: ").strip())
    while True:
        if cert_dir.lower() in ("q", "quit"):
            sys.exit(0)
        if os.path.isdir(cert_dir):
            break
        print(f"  !! 目录不存在: {cert_dir}")
        cert_dir = os.path.expanduser(input("请重新输入对象目录 (q 退出): ").strip())

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

    # 是否生成 JSONL：可选，默认不生成
    j = input("是否生成 JSONL (y/N): ").strip().lower()
    jsonl = j in ("y", "yes")

    run_batch(cert_dir, out_dir or None, timeout, jsonl)


def main():
    args = sys.argv[1:]

    if not args:                    # 没有任何参数 → 交互模式
        interactive()
        return

    # 有参数 → 命令行模式：逐个解析，--timeout / --jsonl 可放在任意位置
    jsonl = False
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
        else:
            rest.append(args[i])
            i += 1

    cert_dir = rest[0] if rest else None
    out_dir = rest[1] if len(rest) > 1 else None

    if not cert_dir:
        print("用法: python3 run_zlint.py <对象目录> [输出目录] [--timeout 秒] [--jsonl]")
        sys.exit(1)

    run_batch(cert_dir, out_dir, timeout, jsonl)


if __name__ == "__main__":
    main()
