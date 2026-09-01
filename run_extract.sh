#!/usr/bin/env bash
#
# 批量提取目录下所有证书的信息：
#   - 每个证书输出一份完整 JSON（<name>.json）
#   - 汇总所有证书的 summary 为 summary_all.json（数组，每行第一项是证书名）
#
# 用法: ./run_extract.sh <证书目录> [输出目录]
#   证书目录: 直接放 *.pem / *.crt / *.cer / *.der 的目录
#   输出目录: 默认 ./extracted
#
set -euo pipefail

BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/extract-cert"
CERT_DIR="${1:-certificates}"
OUT_DIR="${2:-extracted}"

if [[ ! -x "$BIN" ]]; then
    echo "error: 找不到 $BIN，请先编译: go build -o extract-cert ./cmd/extract-cert" >&2
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

total=0
failed=0
for cert in "${certs[@]}"; do
    base="$(basename "$cert")"
    stem="${base%.*}"
    total=$((total + 1))
    printf '[%d/%d] %s\n' "$total" "${#certs[@]}" "$base"

    if ! "$BIN" -cert "$cert" -out "$OUT_DIR/$stem.json" -pretty=false >/dev/null 2>&1; then
        echo "  !! 处理失败: $base" >&2
        failed=$((failed + 1))
        continue
    fi
done

# 汇总: 提取每份 JSON 的 summary，并注入证书名，输出 summary_all.json
python3 - "$OUT_DIR" <<'PY'
import json, sys, glob, os

out_dir = sys.argv[1]
items = []
for f in sorted(glob.glob(os.path.join(out_dir, "*.json"))):
    try:
        with open(f, encoding="utf-8") as fh:
            d = json.load(fh)
        items.append({"cert": os.path.basename(f)[:-len(".json")], **d["summary"]})
    except Exception as e:
        print(f"warning: 跳过 {f}: {e}", file=sys.stderr)

summary_path = os.path.join(out_dir, "summary_all.json")
with open(summary_path, "w", encoding="utf-8") as fh:
    json.dump(items, fh, indent=2, ensure_ascii=False)
print(f"汇总写入 {summary_path} ({len(items)} 个证书)")
PY

echo "----------------------------------------"
echo "完成: 共 $total 个证书, 失败 $failed 个"
echo "单证书 JSON: $OUT_DIR/*.json"
echo "汇总: $OUT_DIR/summary_all.json"
