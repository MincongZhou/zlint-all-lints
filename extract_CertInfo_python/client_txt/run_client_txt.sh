#!/usr/bin/env bash
# run_client_txt.sh —— 把 CFCA「txt 表格导出」里的证书抽出来。
# 链路与产物命名都对齐 certs/CFCA订户证书_client_draft/（只把第一步换成 txt_table_to_csv.py）:
#
#   ① txt_table_to_csv.py   txt 表格 → 预处理-<yymmdd>.csv + txt_source_index.csv
#   ② csv_b64_to_certs.py   预处理 CSV → certs_all/（每张 .der）+ certs_all.jsonl + certs_all_index.csv
#   ③ split_gm_certs.py     certs_all/ → 国密证书/ + 非国密证书/ + split_gm_index.csv
#   ④ extract_cert_fields.py（可选 --with-fields）→ 非国密证书的字段宽表
#
# 用法:
#   ./run_client_txt.sh                                  # 默认输入 certs/CFCA订户证书_client
#   ./run_client_txt.sh <输入目录|txt> [输出目录] [选项]
#   ./run_client_txt.sh --force                          # 先清掉上轮产物再跑
#   ./run_client_txt.sh --with-fields                    # 追加第 ④ 步
#   ./run_client_txt.sh --no-dedupe --strict              # 不去重 / 有解析失败就退出码 1
#
# 默认输出目录: <项目根>/certs/<输入目录名>_extract（不覆盖任何已有样本目录）
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"          # extract_CertInfo_python/
ROOT_DIR="$(dirname "$PARENT_DIR")"           # 项目根

IN_ARG=""
OUT_ARG=""
FORCE=0
WITH_FIELDS=0
EXTRA=()

while [ $# -gt 0 ]; do
    case "$1" in
        --force)        FORCE=1 ;;
        --with-fields)  WITH_FIELDS=1 ;;
        --no-dedupe|--strict) EXTRA+=("$1") ;;
        -h|--help)      sed -n '2,19p' "$0"; exit 0 ;;
        -*)             echo "未知选项: $1" >&2; exit 2 ;;
        *)              if [ -z "$IN_ARG" ]; then IN_ARG="$1"
                        elif [ -z "$OUT_ARG" ]; then OUT_ARG="$1"
                        else echo "多余的参数: $1" >&2; exit 2; fi ;;
    esac
    shift
done

IN="${IN_ARG:-$ROOT_DIR/certs/CFCA订户证书_client}"
IN="$(cd "$(dirname "$IN")" && pwd)/$(basename "$IN")"
if [ ! -e "$IN" ]; then echo "错误: 输入不存在 -> $IN" >&2; exit 1; fi

OUT="${OUT_ARG:-$ROOT_DIR/certs/$(basename "$IN")_extract}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

# 中间产物路径（文件名与 _draft 目录一致）
CSV="$OUT/预处理-$(date +%y%m%d).csv"
SRC_INDEX="$OUT/txt_source_index.csv"
CERTS_ALL="$OUT/certs_all"
CERTS_ALL_JSONL="$OUT/certs_all.jsonl"
CERTS_ALL_INDEX="$OUT/certs_all_index.csv"
GM_DIR="$OUT/国密证书"
NON_GM_DIR="$OUT/非国密证书"
GM_JSONL="$OUT/国密证书.jsonl"
GM_LIST="$OUT/国密证书清单.txt"
GM_INDEX="$OUT/split_gm_index.csv"

echo "输入        : $IN"
echo "输出目录    : $OUT"

if [ "$FORCE" -eq 1 ]; then
    echo "== --force: 清理上轮产物 =="
    rm -rf "$CSV" "$SRC_INDEX" "$CERTS_ALL" "$CERTS_ALL_JSONL" \
           "$CERTS_ALL_INDEX" "$GM_DIR" "$NON_GM_DIR" "$GM_JSONL" "$GM_LIST" "$GM_INDEX"
elif [ -e "$CSV" ] || [ -e "$CERTS_ALL_INDEX" ] || [ -e "$GM_INDEX" ]; then
    echo "!! 输出目录里已有上轮产物；要么加 --force 清理，要么换一个输出目录（第 2 个位置参数）" >&2
    exit 1
fi

echo
echo "== ① txt 表格 → 预处理 CSV + 来源索引 =="
echo "   txt_table_to_csv.py \"$IN\" --out-root \"$OUT\" ${EXTRA[*]-}"
python3 "$SCRIPT_DIR/txt_table_to_csv.py" "$IN" --out-root "$OUT" ${EXTRA[@]+"${EXTRA[@]}"}

echo
echo "== ② 预处理 CSV → 每张 .der + JSONL + 对照表 =="
echo "   csv_b64_to_certs.py \"$CSV\" --out-dir certs_all --jsonl certs_all.jsonl --index certs_all_index.csv"
python3 "$PARENT_DIR/csv_b64_to_certs.py" "$CSV" \
    --out-dir "$CERTS_ALL" --jsonl "$CERTS_ALL_JSONL" --index "$CERTS_ALL_INDEX"

echo
echo "== ③ 按国密(SM2/SM3)拆分：国密证书/ + 非国密证书/ =="
echo "   split_gm_certs.py certs_all/ --out-dir 国密证书 --out-dir-non-gm 非国密证书"
python3 "$PARENT_DIR/split_gm_certs.py" "$CERTS_ALL" \
    --out-dir "$GM_DIR" --out-dir-non-gm "$NON_GM_DIR" \
    --jsonl "$GM_JSONL" --files "$GM_LIST" --index "$GM_INDEX"

if [ "$WITH_FIELDS" -eq 1 ]; then
    echo
    echo "== ④ （可选）非国密证书字段宽表 =="
    echo "   extract_cert_fields.py 非国密证书/ --csv cert_fields_非国密.csv --csv-mode wide"
    python3 "$PARENT_DIR/extract_cert_fields.py" "$NON_GM_DIR" \
        --csv "$OUT/cert_fields_非国密.csv" --csv-mode wide
fi

echo
echo "完成。产物在 $OUT"
echo "  预处理-$(date +%y%m%d).csv + txt_source_index.csv"
echo "  certs_all/（每张 .der） + certs_all.jsonl + certs_all_index.csv"
echo "  国密证书/ + 国密证书.jsonl + 国密证书清单.txt + 非国密证书/ + split_gm_index.csv"
