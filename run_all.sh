#!/usr/bin/env bash
# run_all.sh —— 对一个证书（或证书目录）一次跑齐四件套，产物统一放输出目录
#              （不区分 CA 证书与终端/订户证书，任何证书都能跑）
#
#   ① run_cert_crl_ocsp.py     证书 / CRL / OCSP 三类 zlint 规则（联网，最慢）
#   ② extract_cert_fields.py   证书字段宽表（本地）
#   ③ extract_crl_fields.py    ①下载下来的 CRL 的字段宽表（本地，依赖 ①）
#   ④ run_ocsp_batch.py        OCSP 状态汇总 CSV（联网）
#
# 用法:
#   ./run_all.sh <证书文件|证书目录> [输出目录] [超时秒数]
#   ./run_all.sh "certs/CFCA_CA证书" results/CFCA_CA 15
#   ./run_all.sh certs/a.cer results/one_cert 10
#   ./run_all.sh "certs/CFCA订户证书" results/CFCA订户证书 10   # 订户证书同样适用
#
# 输出目录默认 results/<输入目录名>；CSV 一律 UTF-8 with BOM，指纹无冒号。
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR" || exit 1

TARGET=${1:-}
OUT=${2:-}
TIMEOUT=${3:-15}

if [ -z "$TARGET" ]; then
    echo "用法: $0 <证书文件|证书目录> [输出目录] [超时秒数]" >&2
    exit 2
fi
if [ ! -e "$TARGET" ]; then
    echo "路径不存在: $TARGET" >&2
    exit 1
fi
if [ -z "$OUT" ]; then
    OUT="results/$(basename "$TARGET")"
fi
mkdir -p "$OUT"

echo "目标: $TARGET"
echo "输出: $OUT"
echo "超时: ${TIMEOUT}s"
echo "开始: $(date '+%F %T')"
echo

# ---------- ① 三类规则（顺带把 CRL / OCSP 证据下到 $OUT/<证书名>/）----------
echo "===== [1/4] run_cert_crl_ocsp.py（证书 / CRL / OCSP 三类规则，联网） ====="
if ! python3 run_cert_crl_ocsp.py "$TARGET" "$OUT" --timeout "$TIMEOUT"; then
    echo "!! 第 1 步返回非 0（部分证书失败），继续跑后续步骤"
fi

# ---------- ② 证书字段 ----------
echo
echo "===== [2/4] extract_cert_fields.py（证书字段宽表） ====="
# 显式指定 wide：单张证书时默认会退化成 fields 模式（一行一字段），
# 与目录输入的表结构不一致；统一成宽表，一张证书也占一行，便于 join
if ! python3 extract_CertInfo_python/extract_cert_fields.py "$TARGET" \
        --csv "$OUT/cert_fields.csv" --csv-mode wide; then
    echo "!! 第 2 步失败"
fi

# ---------- ③ CRL 字段（输入是 ① 下载的 crl.pem）----------
echo
echo "===== [3/4] extract_crl_fields.py（CRL 字段宽表，输入=① 的 crl.pem） ====="
shopt -s nullglob
CRLS=("$OUT"/*/crl.pem)
shopt -u nullglob
if [ ${#CRLS[@]} -eq 0 ]; then
    echo "没找到 $OUT/*/crl.pem —— 该批证书都没有 CDP 或下载失败，跳过（属正常）"
else
    echo "共 ${#CRLS[@]} 份 crl.pem（同一签发者的 CRL 会被重复下载，"
    echo "  去重看 crl_fields.csv 的 issuer / crl_number / tbs_sha256 列）"
    if ! python3 extract_CertInfo_python/extract_crl_fields.py "${CRLS[@]}" \
            --csv "$OUT/crl_fields.csv" --csv-mode wide; then
        echo "!! 第 3 步失败"
    fi
fi

# ---------- ④ OCSP 状态汇总 ----------
echo
echo "===== [4/4] run_ocsp_batch.py（OCSP 状态汇总，联网） ====="
if ! python3 run_ocsp_batch.py "$TARGET" --csv "$OUT/ocsp_batch.csv" \
        --timeout "$TIMEOUT"; then
    echo "（批量里存在 ERROR 项时本步返回非 0，属正常：无 OCSP 地址 / responder 拒答等）"
fi

# ---------- 产物清单 ----------
echo
echo "===== 产物（$OUT） ====="
for f in cert_fields.csv cert_fields_extensions.csv crl_fields.csv \
         crl_fields_entries.csv ca_summary.csv crl_summary.csv \
         ocsp_summary.csv index.csv ocsp_batch.csv; do
    [ -f "$OUT/$f" ] && printf '  %-32s %s 行\n' "$f" "$(wc -l < "$OUT/$f")"
done
echo "  每证书证据目录: $(ls -d "$OUT"/*/ 2>/dev/null | wc -l) 个（crl.pem / resp.der）"
echo "结束: $(date '+%F %T')"
