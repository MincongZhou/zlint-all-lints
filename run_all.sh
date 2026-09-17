#!/usr/bin/env bash
# run_all.sh —— 对一个证书（或证书目录）一次跑齐四件套，产物统一放输出目录
#              （不区分 CA 证书与终端/订户证书，任何证书都能跑）
#
#   1 run_cert_crl_ocsp.py     证书 / CRL / OCSP 三类 zlint 规则（联网，最慢）
#   2 extract_cert_fields.py   证书字段宽表（本地）
#   3 extract_crl_fields.py    ①下载下来的 CRL 的字段宽表（本地，依赖 ①）
#   4 run_ocsp_batch.py        OCSP 状态汇总 CSV（联网）
#
# 用法:
#   ./run_all.sh <证书文件|证书目录> [输出目录] [超时秒数] [选步参数...]
#   ./run_all.sh "certs/CFCA_CA证书" results/CFCA_CA 15
#   ./run_all.sh certs/a.cer results/one_cert 10
#   ./run_all.sh "certs/CFCA订户证书" results/CFCA订户证书 10 --only 2,4
#   ./run_all.sh "certs/CFCA订户证书" results/CFCA订户证书 10 --skip 1,3
#   ./run_all.sh "certs/CFCA订户证书" results/CFCA订户证书 10 --no-lint     # 等价 --skip 1
#
# 选步参数（1-4 对应上面四步，可逗号分隔；--skip / --no-lint 优先级高于 --only）:
#   --only <步骤>   只跑列出的步骤，如 --only 2,4
#   --skip <步骤>   跳过列出的步骤，如 --skip 1,3
#   --no-lint       等价于 --skip 1（跳过三类 zlint 规则 + 逐张下载 CRL）
#
# 说明: ③ 的输入是 ① 下载的 <输出目录>/<证书名>/crl.pem；跳过 ① 后若该目录里
#       还留着上次的 crl.pem，③ 仍会照跑，否则自动跳过。
#       跳过 ① 则不生成 ca_summary.csv / crl_summary.csv / ocsp_summary.csv / index.csv。
#
# 选项与位置参数可混排（选项以 - 开头，其余按 输入 / 输出目录 / 超时秒数 顺序取；
# 也支持 --only=2,4 这种等号写法）。输出目录默认 results/<输入目录名>；
# CSV 一律 UTF-8 with BOM，指纹无冒号。
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR" || exit 1

usage() {
    cat <<'EOF'
用法: ./run_all.sh <证书文件|证书目录> [输出目录] [超时秒数] [选步参数...]

  ① run_cert_crl_ocsp.py     证书 / CRL / OCSP 三类 zlint 规则（联网，最慢）
  ② extract_cert_fields.py   证书字段宽表（本地）
  ③ extract_crl_fields.py    ①下载下来的 CRL 的字段宽表（本地，依赖 ①）
  ④ run_ocsp_batch.py        OCSP 状态汇总 CSV（联网）

选步参数:
  --only <步骤>   只跑列出的步骤，如 --only 2,4
  --skip <步骤>   跳过列出的步骤，如 --skip 1,3（--no-lint 等价于 --skip 1）
  步骤号 1-4，可逗号分隔；--skip / --no-lint 优先级高于 --only
  -h, --help      显示本帮助

示例:
  ./run_all.sh "certs/CFCA_CA证书" results/CFCA_CA 15
  ./run_all.sh certs/a.cer results/one_cert 10
  ./run_all.sh "certs/CFCA订户证书" results/CFCA订户证书 10 --only 2,4
  ./run_all.sh "certs/CFCA订户证书" results/CFCA订户证书 10 --skip 1,3

输出目录不填时默认 results/<输入目录名>。
EOF
}

TARGET=""
OUT=""
TIMEOUT=15
ONLY=""
SKIP=""

while [ $# -gt 0 ]; do
    case "$1" in
        --no-lint|--skip-lint) SKIP="${SKIP},1"; shift ;;
        --only)   [ -n "${2:-}" ] || { echo "--only 需要一个值，如 --only 2,4" >&2; exit 2; }
                  ONLY=$2; shift 2 ;;
        --skip)   [ -n "${2:-}" ] || { echo "--skip 需要一个值，如 --skip 1,3" >&2; exit 2; }
                  SKIP="${SKIP},$2"; shift 2 ;;
        --only=*) ONLY=${1#*=}; shift ;;
        --skip=*) SKIP="${SKIP},${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        -*)
            echo "未知选项: $1（可用: --only / --skip / --no-lint / -h）" >&2
            exit 2
            ;;
        *)
            if [ -z "$TARGET" ]; then
                TARGET=$1
            elif [ -z "$OUT" ]; then
                OUT=$1
            else
                case "$1" in
                    ''|*[!0-9]*)
                        echo "超时秒数必须是整数，收到: $1" >&2
                        exit 2
                        ;;
                    *) TIMEOUT=$1 ;;
                esac
            fi
            shift
            ;;
    esac
done

if [ -z "$TARGET" ]; then
    usage >&2
    exit 2
fi
if [ ! -e "$TARGET" ]; then
    echo "路径不存在: $TARGET" >&2
    exit 1
fi
if [ -z "$OUT" ]; then
    OUT="results/$(basename "$TARGET")"
fi

# 四步的开关，顺序对应 ①②③④
RUN=(1 1 1 1)
STEP_NAME=("run_cert_crl_ocsp.py（三类 zlint 规则，联网）"
           "extract_cert_fields.py（证书字段宽表）"
           "extract_crl_fields.py（CRL 字段宽表，输入=① 下载的 crl.pem）"
           "run_ocsp_batch.py（OCSP 状态汇总，联网）")

mark_only() {       # 按 --only 打开列出的步骤
    [ -n "$ONLY" ] || return 0
    RUN=(0 0 0 0)
    for n in $(echo "$ONLY" | tr ',' ' '); do
        case "$n" in
            1|2|3|4) RUN[$((n - 1))]=1 ;;
            *) echo "--only 的步骤号只能是 1-4，收到: $n" >&2; exit 2 ;;
        esac
    done
}

mark_skip() {       # 按 --skip 关掉列出的步骤（优先级高于 --only）
    [ -n "$SKIP" ] || return 0
    for n in $(echo "$SKIP" | tr ',' ' '); do
        case "$n" in
            1|2|3|4) RUN[$((n - 1))]=0 ;;
            *) echo "--skip 的步骤号只能是 1-4，收到: $n" >&2; exit 2 ;;
        esac
    done
}

mark_only
mark_skip

TOTAL=0
for v in "${RUN[@]}"; do
    [ "$v" -eq 1 ] && TOTAL=$((TOTAL + 1))
done
if [ "$TOTAL" -eq 0 ]; then
    echo "四步都被跳过了，没有可跑的内容（检查 --only / --skip）" >&2
    exit 2
fi
mkdir -p "$OUT"

STEP=0
step() {                       # 依次打印 [n/总数] 步骤标题（只统计实际执行的步骤）
    STEP=$((STEP + 1))
    echo
    echo "===== [$STEP/$TOTAL] $* ====="
}

EXEC=""
for i in 0 1 2 3; do
    [ "${RUN[$i]}" -eq 1 ] && EXEC="${EXEC}${EXEC:+ }$((i + 1))"
done

echo "目标: $TARGET"
echo "输出: $OUT"
echo "超时: ${TIMEOUT}s"
echo "执行步骤: $EXEC / 4 （①②③④）"
if [ "${RUN[0]}" -eq 0 ]; then
    echo "  跳过 ① 的后果: 不生成 ca_summary / crl_summary / ocsp_summary / index.csv；"
    echo "                ③ 只能用输出目录里已有的旧 crl.pem（没有则自动跳过）"
fi
echo "开始: $(date '+%F %T')"

# ---------- ① 三类规则（顺带把 CRL / OCSP 证据下到 $OUT/<证书名>/）----------
if [ "${RUN[0]}" -eq 1 ]; then
    step "${STEP_NAME[0]}"
    if ! python3 run_cert_crl_ocsp.py "$TARGET" "$OUT" --timeout "$TIMEOUT"; then
        echo "!! 该步返回非 0（部分证书失败），继续跑后续步骤"
    fi
fi

# ---------- ② 证书字段 ----------
if [ "${RUN[1]}" -eq 1 ]; then
    step "${STEP_NAME[1]}"
    # 显式指定 wide：单张证书时默认会退化成 fields 模式（一行一字段），
    # 与目录输入的表结构不一致；统一成宽表，一张证书也占一行，便于 join
    if ! python3 extract_CertInfo_python/extract_cert_fields.py "$TARGET" \
            --csv "$OUT/cert_fields.csv" --csv-mode wide; then
        echo "!! 该步失败"
    fi
fi

# ---------- ③ CRL 字段（输入是 ① 下载的 crl.pem）----------
if [ "${RUN[2]}" -eq 1 ]; then
    step "${STEP_NAME[2]}"
    if [ "${RUN[0]}" -eq 0 ]; then
        echo "提示: 本次没跑 ①，只有当输出目录里已有旧的 <证书名>/crl.pem 时这一步才有输入"
    fi
    shopt -s nullglob
    CRLS=("$OUT"/*/crl.pem)
    shopt -u nullglob
    if [ ${#CRLS[@]} -eq 0 ]; then
        echo "没找到 $OUT/*/crl.pem —— 没有 CDP 或未下载过，跳过（属正常）"
    else
        echo "共 ${#CRLS[@]} 份 crl.pem（同一签发者的 CRL 会被重复下载，"
        echo "  去重看 crl_fields.csv 的 issuer / crl_number / tbs_sha256 列）"
        if ! python3 extract_CertInfo_python/extract_crl_fields.py "${CRLS[@]}" \
                --csv "$OUT/crl_fields.csv" --csv-mode wide; then
            echo "!! 该步失败"
        fi
    fi
fi

# ---------- ④ OCSP 状态汇总 ----------
if [ "${RUN[3]}" -eq 1 ]; then
    step "${STEP_NAME[3]}"
    if ! python3 run_ocsp_batch.py "$TARGET" --csv "$OUT/ocsp_batch.csv" \
            --timeout "$TIMEOUT"; then
        echo "（批量里存在 ERROR 项时本步返回非 0，属正常：无 OCSP 地址 / responder 拒答等）"
    fi
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
[ "${RUN[0]}" -eq 0 ] && \
    echo "  （本次跳过 ①，故无 ca/crl/ocsp_summary.csv 与 index.csv）"
echo "结束: $(date '+%F %T')"
