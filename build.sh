#!/usr/bin/env bash
#
# 一键编译 zlint-all-lints + extract-cert，并打印当前实际规则数
#
# 用法:
#   ./build.sh [探测用样本]
#     样本默认取 certificates/ 或 certs/ 下的第一个对象；
#     也可显式指定: ./build.sh certs/27monthsEv.pem
#
# 上游 zlint 更新后（cd ../zlint && git pull）重跑本脚本即可：
#   依赖由 go mod tidy 自动同步，规则数变化会直接打印，
#   文档不再写死数量（数量以输出 JSON 的 meta.total_lints / meta.type_counts 为准）。
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

echo "==> go mod tidy"
go mod tidy

echo "==> go build -o zlint-all-lints ."
go build -o zlint-all-lints .

echo "==> go build -o extract-cert ./cmd/extract-cert"
go build -o extract-cert ./cmd/extract-cert

# 选探测样本：优先命令行参数，其次内置样本目录
probe="${1:-}"
if [[ -z "$probe" ]]; then
    shopt -s nullglob
    cand=(certificates/*.pem certificates/*.crt certificates/*.der \
          certs/*.pem certs/*.crt certs/*.cer certs/*.der certs/*.crl)
    probe="${cand[0]:-}"
fi

if [[ -n "$probe" && -f "$probe" ]]; then
    tmp="$(mktemp)"
    if ./zlint-all-lints -cert "$probe" -out "$tmp" -pretty=false >/dev/null 2>&1; then
        echo "==> 当前规则数（样本: $probe）"
        if command -v python3 >/dev/null 2>&1; then
            python3 - "$tmp" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1], encoding="utf-8"))["meta"]
c = meta["type_counts"]
print(f"    total_lints = {meta['total_lints']}"
      f"  (CA={c['CA']}, CRL={c['CRL']}, OCSP={c['OCSP']})")
PY
        else
            # 无 python3 时退化为文本提取（-pretty=false 输出为单行 JSON）
            line="$(sed -n 's/.*"total_lints":[[:space:]]*\([0-9][0-9]*\).*/    total_lints = \1/p' "$tmp" | head -1)"
            echo "${line:-    (未能从输出中提取 total_lints)}"
        fi
    else
        echo "   !! 探测失败: 无法用 $probe 跑出结果（可换一个样本: ./build.sh certs/xxx.pem）" >&2
    fi
    rm -f "$tmp"
else
    echo "   （未找到用于探测的样本，跳过规则数打印）"
fi

echo "完成: ./zlint-all-lints  ./extract-cert"
