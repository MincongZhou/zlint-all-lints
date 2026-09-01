#!/usr/bin/env bash
#
# run_all.sh —— 对单个证书依次跑完项目里的 4 个分析脚本
#
#   1. run_zlint.py   (check_certs_python/)        zlint 全部 433 条规则 → JSON/CSV/JSONL
#   2. extract_org.py (extract_CertInfo_python/)   提取组织名 O 字段
#   3. extract_sct.py (extract_CertInfo_python/)   提取 SCT 时间戳
#   4. check_ocsp.py  (check_certs_python/)        OCSP 状态查询（联网）
#
# 用法: ./run_all.sh <证书路径> [输出目录]
#   证书路径: *.pem / *.crt / *.cer / *.der（PEM/DER 自动识别，扩展名不限）
#   输出目录: 默认 results/<证书名>/，保存 lint 的 JSON/CSV/JSONL
#
# 说明:
#   - run_zlint.py 以目录为输入，脚本会把证书复制进临时目录单独跑，跑完自动清理
#   - check_ocsp.py 需要联网访问 responder，失败不影响其他步骤
#   - 依赖: python3 + cryptography 库；zlint-all-lints 已编译（go build -o zlint-all-lints .）
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT="${1:-}"
OUT_DIR="${2:-}"

usage() {
    echo "用法: $0 <证书路径> [输出目录]" >&2
    echo "  证书路径: *.pem / *.crt / *.cer / *.der（PEM/DER 自动识别）" >&2
    echo "  输出目录: 默认 results/<证书名>/" >&2
    exit 1
}

# ---------- 前置检查 ----------
[[ -n "$CERT" ]] || usage
[[ -f "$CERT" ]] || { echo "错误: 文件不存在 -> $CERT" >&2; exit 1; }

CERT="$(realpath "$CERT")"
stem="$(basename "$CERT")"; stem="${stem%.*}"
OUT_DIR="${OUT_DIR:-$ROOT/results/$stem}"
mkdir -p "$OUT_DIR"

RUN_ZLINT="$ROOT/check_certs_python/run_zlint.py"
CHECK_OCSP="$ROOT/check_certs_python/check_ocsp.py"
EXTRACT_ORG="$ROOT/extract_CertInfo_python/extract_org.py"
EXTRACT_SCT="$ROOT/extract_CertInfo_python/extract_sct.py"
for s in "$RUN_ZLINT" "$CHECK_OCSP" "$EXTRACT_ORG" "$EXTRACT_SCT"; do
    [[ -f "$s" ]] || { echo "错误: 找不到 $s" >&2; exit 1; }
done
command -v python3 >/dev/null || { echo "错误: 需要 python3" >&2; exit 1; }

# ---------- 自动识别格式：以 -----BEGIN 开头视为 PEM，否则按 DER ----------
DER_ARGS=()
if grep -q '^-----BEGIN' "$CERT"; then
    echo "输入: $CERT (PEM)"
else
    echo "输入: $CERT (非 PEM，按 DER 处理)"
    DER_ARGS=(--der)
fi

# ---------- 临时目录：run_zlint.py 以目录为输入，复制证书进去单独跑 ----------
TMP_DIR="$(mktemp -d "$ROOT/results/.run_all_XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT
# 统一重命名为 .pem 后缀，确保 run_batch.sh 的扩展名过滤能识别
cp "$CERT" "$TMP_DIR/$stem.pem"

exit_codes=()
names=(run_zlint.py extract_org.py extract_sct.py check_ocsp.py)

step() { echo; echo "===== [$1/4] $2 ====="; }

step 1 "run_zlint.py（zlint 全部规则 → JSON/CSV/JSONL）"
python3 "$RUN_ZLINT" "$TMP_DIR" "$OUT_DIR" --jsonl
exit_codes+=($?)

step 2 "extract_org.py（组织名 O 字段）"
python3 "$EXTRACT_ORG" "$CERT" "${DER_ARGS[@]}"
exit_codes+=($?)

step 3 "extract_sct.py（SCT 时间戳）"
python3 "$EXTRACT_SCT" "$CERT" "${DER_ARGS[@]}"
exit_codes+=($?)

step 4 "check_ocsp.py（OCSP 状态，联网）"
python3 "$CHECK_OCSP" "$CERT" "${DER_ARGS[@]}" --status
exit_codes+=($?)

# ---------- 汇总 ----------
echo
echo "================ 汇总 ================"
echo "证书: $CERT"
echo "输出: $OUT_DIR/"
echo "----------------------------------------"
ok=1
for i in "${!exit_codes[@]}"; do
    if [[ ${exit_codes[$i]} -eq 0 ]]; then
        echo "  [OK]   ${names[$i]}"
    else
        echo "  [失败 exit=${exit_codes[$i]}] ${names[$i]}"
        ok=0
    fi
done
echo "----------------------------------------"
[[ $ok -eq 1 ]] && echo "全部 4 个脚本执行完成" || echo "部分步骤失败（详见上方输出）"
exit $(( ok ? 0 : 1 ))
