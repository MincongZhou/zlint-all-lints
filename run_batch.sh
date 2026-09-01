#!/usr/bin/env bash
#
# 批量对目录下的所有证书运行 zlint-all-lints：
#   - 每个证书输出一份 JSON（<name>.json）
#   - 每个证书输出一份 CSV（<name>.csv）
#   - 汇总全部证书为一份 results_summary.csv（每行第一列是证书文件名）
#
# 用法: ./run_batch.sh <证书目录> [输出目录]
#   证书目录: 直接放 *.pem / *.crt / *.cer / *.der 的目录
#   输出目录: 默认 ./results
#
set -euo pipefail

BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/zlint-all-lints"
CERT_DIR="${1:-certificates}"
OUT_DIR="${2:-results}"

if [[ ! -x "$BIN" ]]; then
    echo "error: 找不到 $BIN，请先编译: go build -o zlint-all-lints ." >&2
    exit 1
fi
if [[ ! -d "$CERT_DIR" ]]; then
    echo "用法: $0 <证书目录> [输出目录]" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"
shopt -s nullglob
certs=("$CERT_DIR"/*.pem "$CERT_DIR"/*.crt "$CERT_DIR"/*.cer "$CERT_DIR"/*.der)
if [[ ${#certs[@]} -eq 0 ]]; then
    echo "在 $CERT_DIR 下没有找到证书 (*.pem / *.crt / *.cer / *.der)" >&2
    exit 1
fi

summary="$OUT_DIR/results_summary.csv"
echo "cert,name,type,description,citation,source,status,details" > "$summary"

total=0
failed=0
for cert in "${certs[@]}"; do
    base="$(basename "$cert")"
    stem="${base%.*}"
    total=$((total + 1))
    printf '[%d/%d] %s\n' "$total" "${#certs[@]}" "$base"

    if ! "$BIN" -cert "$cert" -out "$OUT_DIR/$stem.json" -csv "$OUT_DIR/$stem.csv" -pretty=false >/dev/null 2>&1; then
        echo "  !! 处理失败: $base" >&2
        failed=$((failed + 1))
        continue
    fi

    # 汇总: 去掉每份 CSV 的表头, 在行首补证书文件名
    tail -n +2 "$OUT_DIR/$stem.csv" | awk -v c="$base" '{print c "," $0}' >> "$summary"
done

rows=$(( $(wc -l < "$summary") - 1 ))
echo "----------------------------------------"
echo "完成: 共 $total 个证书, 失败 $failed 个"
echo "JSON/CSV:  $OUT_DIR/"
echo "汇总 CSV:  $summary (数据行 $rows)"
if (( rows != total * 433 )); then
    echo "注意: 数据行数 $rows 不等于 $total * 433, 可能有证书处理失败或缺规则" >&2
fi
