#!/usr/bin/env bash
# run_all.sh —— 对一个证书（或证书目录）一次跑齐四件套，产物统一放输出目录
#              （不区分 CA 证书与终端/订户证书，任何证书都能跑）
#
#   1 run_cert_crl_ocsp.py     证书 / CRL / OCSP 三类 zlint 规则（联网，最慢）
#   2 extract_cert_fields.py   证书字段宽表（本地）
#   3 extract_crl_fields.py    ①下载下来的 CRL 的字段宽表（本地，依赖 ①）
#   4 run_ocsp_batch.py        OCSP 状态汇总 CSV（联网）
#   5 extract_ocsp_fields.py   ①保存下来的 resp.der 的字段宽表（本地，依赖 ①）
#
# 用法:
#   ./run_all.sh <证书文件|证书目录> [输出目录] [超时秒数] [选步参数...]
#   ./run_all.sh "certs/CFCA_CA证书" results/CFCA_CA 15
#   ./run_all.sh certs/a.cer results/one_cert 10
#   ./run_all.sh "certs/CFCA订户证书" results/CFCA订户证书 10 --only 2,4
#   ./run_all.sh "certs/CFCA订户证书" results/CFCA订户证书 10 --skip 1,3
#   ./run_all.sh "certs/CFCA订户证书" results/CFCA订户证书 10 --no-lint     # 等价 --skip 1
#   ./run_all.sh certs/ --out results/all --timeout 15 --refresh-crl
#
# 选步参数（1-4 对应上面四步，可逗号分隔；--skip / --no-lint 优先级高于 --only）:
#   --only <步骤>   只跑列出的步骤，如 --only 2,4
#   --skip <步骤>   跳过列出的步骤，如 --skip 1,3
#   --no-lint       等价于 --skip 1（跳过三类 zlint 规则 + 逐张下载 CRL）
#
# 其它选项:
#   --out <目录>    输出目录（等价第 2 个位置参数；输出目录名是纯数字时用它消歧）
#   --timeout <秒>  联网超时秒数（等价第 3 个位置参数）
#   --refresh-crl   透传给 ①：忽略 CRL 缓存强制重下（默认缓存过 nextUpdate 才重下）
#
# 说明: ③ 的输入是 ① 下载的 <输出目录>/<证书名>/crl.pem；⑤ 的输入是 ① 保存的
#       <输出目录>/<证书名>/resp.der。① 每轮会先清掉对应证书目录里的旧文件，
#       只有本轮真正下载/命中缓存的证书才会留下文件，所以 ③⑤ 不会解析到上轮的
#       陈旧证据；跳过 ① 时则沿用目录里已有的 crl.pem / resp.der。
#       跳过 ① 则不生成 ca_summary.csv / crl_summary.csv / ocsp_summary.csv / index.csv
#       （输出目录里若已有上轮的这些文件会原样留着，不算本次产物）。
#
# 选项与位置参数可混排（选项以 - 开头，其余按 输入 / 输出目录 / 超时秒数 顺序取；
# 也支持 --only=2,4 / --out=xxx / --timeout=15 这种等号写法）。只给了证书路径和
# 一个纯数字位置参数时，该数字按超时秒数处理（输出目录不填时默认 results/<输入目录名>，
# 输出目录名是纯数字时需显式用 --out）。CSV 一律 UTF-8 with BOM，指纹无冒号。
set -u

# 保存原始调用命令行：下面的参数解析会用 shift 消耗 $@，先留一份供日志回溯
INVOKED_AS="$0"
ORIG_ARGS=("$@")

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR" || exit 1

usage() {
    cat <<'EOF'
用法: ./run_all.sh <证书文件|证书目录> [输出目录] [超时秒数] [选步参数...]

  ① run_cert_crl_ocsp.py     证书 / CRL / OCSP 三类 zlint 规则（联网，最慢）
  ② extract_cert_fields.py   证书字段宽表（本地）
  ③ extract_crl_fields.py    ①下载下来的 CRL 的字段宽表（本地，依赖 ①）
  ④ run_ocsp_batch.py        OCSP 状态汇总 CSV（联网）
  ⑤ extract_ocsp_fields.py   ①保存的 resp.der 的字段宽表（本地，依赖 ①）

选步参数:
  --only <步骤>   只跑列出的步骤，如 --only 2,4
  --skip <步骤>   跳过列出的步骤，如 --skip 1,3（--no-lint 等价于 --skip 1）
  步骤号 1-5，可逗号分隔；--skip / --no-lint 优先级高于 --only

其它选项:
  --out <目录>    输出目录（等价第 2 个位置参数；输出目录名是纯数字时用它消歧）
  --timeout <秒>  联网超时秒数（等价第 3 个位置参数）
  --refresh-crl   透传给 ①：忽略 CRL 缓存，强制重新下载
  --fast          整轮交给同目录的 run_all_fast.py：第 ④ 步优先复用第 ① 步已存的
                  OCSP 响应（<输出>/<stem>/resp.der），取不到（没有 / 已过期 / 响应
                  不成功）才联网；其余三步与原来完全相同。
                  不加此项时第 ④ 步按原逻辑逐张联网查询（默认行为，保证证据最新）
  -h, --help      显示本帮助

示例:
  ./run_all.sh "certs/CFCA_CA证书" results/CFCA_CA 15
  ./run_all.sh certs/a.cer results/one_cert 10
  ./run_all.sh "certs/CFCA订户证书" results/CFCA订户证书 10 --only 2,4
  ./run_all.sh "certs/CFCA订户证书" results/CFCA订户证书 10 --skip 1,3
  ./run_all.sh certs/ --out results/all --timeout 15 --refresh-crl
  ./run_all.sh "certs/CFCA订户证书" results/CFCA订户证书 15 --fast

输出目录不填时默认 results/<输入目录名>；只给证书路径和一个纯数字时该数字按
超时秒数处理（输出目录名是纯数字请用 --out 显式指定）。
EOF
}

TARGET=""
OUT=""
TIMEOUT=15
ONLY=""
SKIP=""
REFRESH_CRL=0     # 1 = 透传 --refresh-crl 给 ①
FAST_MODE=0       # 1 = 整轮交给 run_all_fast.py（第 ④ 步改用本地 OCSP 响应）
SET_OUT=0         # 输出目录是否已确定（--out 或第 2 个位置参数）
SET_TIMEOUT=0     # 超时秒数是否已确定（--timeout 或第 3 个位置参数）

while [ $# -gt 0 ]; do
    case "$1" in
        --no-lint|--skip-lint) SKIP="${SKIP},1"; shift ;;
        --only)   [ -n "${2:-}" ] || { echo "--only 需要一个值，如 --only 2,4" >&2; exit 2; }
                  ONLY=$2; shift 2 ;;
        --skip)   [ -n "${2:-}" ] || { echo "--skip 需要一个值，如 --skip 1,3" >&2; exit 2; }
                  SKIP="${SKIP},$2"; shift 2 ;;
        --only=*) ONLY=${1#*=}
                  [ -n "$ONLY" ] || { echo "--only 需要一个值，如 --only 2,4" >&2; exit 2; }
                  shift ;;
        --skip=*) SKIP_V=${1#*=}
                  [ -n "$SKIP_V" ] || { echo "--skip 需要一个值，如 --skip 1,3" >&2; exit 2; }
                  SKIP="${SKIP},$SKIP_V"; shift ;;
        --out)    [ -n "${2:-}" ] || { echo "--out 需要一个目录" >&2; exit 2; }
                  OUT=$2; SET_OUT=1; shift 2 ;;
        --out=*)  OUT=${1#*=}
                  [ -n "$OUT" ] || { echo "--out 需要一个目录" >&2; exit 2; }
                  SET_OUT=1; shift ;;
        --timeout) [ -n "${2:-}" ] || { echo "--timeout 需要一个整数秒数" >&2; exit 2; }
                  case "$2" in
                      ''|*[!0-9]*) echo "超时秒数必须是整数，收到: $2" >&2; exit 2 ;;
                  esac
                  TIMEOUT=$2; SET_TIMEOUT=1; shift 2 ;;
        --timeout=*) TIMEOUT=${1#*=}
                  case "$TIMEOUT" in
                      ''|*[!0-9]*) echo "超时秒数必须是整数，收到: $TIMEOUT" >&2; exit 2 ;;
                  esac
                  SET_TIMEOUT=1; shift ;;
        --refresh-crl) REFRESH_CRL=1; shift ;;
        -fast|--fast) FAST_MODE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        -*)
            echo "未知选项: $1（可用: --only / --skip / --no-lint / --out / --timeout / --refresh-crl / --fast / -h）" >&2
            exit 2
            ;;
        *)
            case "$1" in
                ''|*[!0-9]*) IS_NUM=0 ;;
                *) IS_NUM=1 ;;
            esac
            if [ -z "$TARGET" ]; then
                TARGET=$1
            elif [ "$SET_OUT" -eq 0 ] && [ "$IS_NUM" -eq 0 ]; then
                OUT=$1; SET_OUT=1          # 非纯数字 → 输出目录
            elif [ "$SET_TIMEOUT" -eq 0 ]; then
                # 纯数字的次位置参数按超时处理（输出目录名是纯数字请用 --out）
                [ "$IS_NUM" -eq 1 ] || { echo "超时秒数必须是整数，收到: $1" >&2; exit 2; }
                TIMEOUT=$1; SET_TIMEOUT=1
            else
                echo "多余的参数: $1（用法见 -h）" >&2
                exit 2
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

# 五步的开关，顺序对应 ①②③④⑤
RUN=(1 1 1 1 1)
STEP_NAME=("run_cert_crl_ocsp.py（三类 zlint 规则，联网）"
           "extract_cert_fields.py（证书字段宽表）"
           "extract_crl_fields.py（CRL 字段宽表，输入=① 下载的 crl.pem）"
           "run_ocsp_batch.py（OCSP 状态汇总，联网）"
           "extract_ocsp_fields.py（OCSP 响应字段宽表，输入=① 保存的 resp.der）")

mark_only() {       # 按 --only 打开列出的步骤
    [ -n "$ONLY" ] || return 0
    RUN=(0 0 0 0 0)
    for n in $(echo "$ONLY" | tr ',' ' '); do
        case "$n" in
            1|2|3|4|5) RUN[$((n - 1))]=1 ;;
            *) echo "--only 的步骤号只能是 1-5，收到: $n" >&2; exit 2 ;;
        esac
    done
}

mark_skip() {       # 按 --skip 关掉列出的步骤（优先级高于 --only）
    [ -n "$SKIP" ] || return 0
    for n in $(echo "$SKIP" | tr ',' ' '); do
        case "$n" in
            1|2|3|4|5) RUN[$((n - 1))]=0 ;;
            *) echo "--skip 的步骤号只能是 1-5，收到: $n" >&2; exit 2 ;;
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
    echo "五步都被跳过了，没有可跑的内容（检查 --only / --skip）" >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "找不到 python3，四步都靠它执行，请先安装" >&2
    exit 1
fi
if ! mkdir -p "$OUT"; then
    echo "无法创建输出目录: $OUT" >&2
    exit 1
fi

# 记录本次调用的命令行，便于事后从日志确认"这批结果是用什么参数跑出来的"。
# 用 %q 逐个引述参数，含空格的路径也能原样复制出来重跑。
printf 'Command: %s' "$INVOKED_AS"
[ "${#ORIG_ARGS[@]}" -gt 0 ] && printf ' %q' "${ORIG_ARGS[@]}"
printf '\n'

# 运行概要（目标/输出/超时/执行步骤/开始）。必须打在下面 exec 之前：
# --fast 模式会在此处交棒给 run_all_fast.py，之后的语句都不会执行。
EXEC=""
for i in 0 1 2 3 4; do
    [ "${RUN[$i]}" -eq 1 ] && EXEC="${EXEC}${EXEC:+ }$((i + 1))"
done

echo "目标: $TARGET"
echo "输出: $OUT"
echo "超时: ${TIMEOUT}s"
echo "执行步骤: $EXEC / 5 （①②③④⑤）"
if [ "${RUN[0]}" -eq 0 ]; then
    echo "  跳过 ① 的后果: 不生成 ca_summary / crl_summary / ocsp_summary / index.csv；"
    echo "                ③ 只能沿用输出目录里已有的 crl.pem（没有则自动跳过），"
    echo "                ⑤ 同理只能沿用已有的 resp.der"
fi
echo "开始: $(date '+%F %T')"

# --fast：把整轮交给同目录的 run_all_fast.py。
# 它跑的 ①②③ 与本脚本完全一致（同样 subprocess 调用项目里的三个脚本），
# 只有第 ④ 步改成「优先复用第 ① 步已存的 OCSP 响应」，所以可以整体接管。
# 全部 --only / --skip / --timeout / --refresh-crl 都透传过去。
if [ "$FAST_MODE" -eq 1 ]; then
    FAST_ARGS=("$TARGET" "$OUT" "$TIMEOUT")
    [ -n "$ONLY" ] && FAST_ARGS+=(--only "$ONLY")
    [ -n "$SKIP" ] && FAST_ARGS+=(--skip "$SKIP")
    [ "$REFRESH_CRL" -eq 1 ] && FAST_ARGS+=(--refresh-crl)
    exec python3 "$SCRIPT_DIR/run_all_fast.py" "${FAST_ARGS[@]}"
fi

STEP=0
step() {                       # 依次打印 [n/总数] 步骤标题（只统计实际执行的步骤）
    STEP=$((STEP + 1))
    echo
    echo "===== [$STEP/$TOTAL] $* ====="
}

# ---------- ① 三类规则（顺带把 CRL / OCSP 证据下到 $OUT/<证书名>/）----------
if [ "${RUN[0]}" -eq 1 ]; then
    step "${STEP_NAME[0]}"
    LINT_ARGS=(--timeout "$TIMEOUT")
    [ "$REFRESH_CRL" -eq 1 ] && LINT_ARGS+=(--refresh-crl)
    if ! python3 run_cert_crl_ocsp.py "$TARGET" "$OUT" "${LINT_ARGS[@]}"; then
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
        # 上万份路径直接进 argv 会触发 "Argument list too long"，改用列表文件传参
        CRL_LIST=$(mktemp "${TMPDIR:-/tmp}/crl_paths.XXXXXX") || CRL_LIST=""
        if [ -z "$CRL_LIST" ]; then
            echo "!! 无法创建临时列表文件，跳过本步"
        else
            printf '%s\n' "${CRLS[@]}" > "$CRL_LIST"
            if ! python3 extract_CertInfo_python/extract_crl_fields.py \
                    --paths-from "$CRL_LIST" \
                    --csv "$OUT/crl_fields.csv" --csv-mode wide; then
                echo "!! 该步失败"
            fi
            rm -f "$CRL_LIST"
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

# ---------- ⑤ OCSP 响应字段（输入是 ① 保存的 resp.der）----------
if [ "${RUN[4]}" -eq 1 ]; then
    step "${STEP_NAME[4]}"
    if [ "${RUN[0]}" -eq 0 ]; then
        echo "提示: 本次没跑 ①，只有当输出目录里已有旧的 <证书名>/resp.der 时这一步才有输入"
    fi
    shopt -s nullglob
    RESPS=("$OUT"/*/resp.der)
    shopt -u nullglob
    if [ ${#RESPS[@]} -eq 0 ]; then
        echo "没找到 $OUT/*/resp.der —— 没有 OCSP 地址或未查询成功，跳过（属正常）"
    else
        echo "共 ${#RESPS[@]} 份 resp.der（同一 responder 的响应会被重复保存，"
        echo "  去重看 ocsp_fields.csv 的 response_sha256 / tbs_sha256 列）"
        RESP_LIST=$(mktemp "${TMPDIR:-/tmp}/resp_paths.XXXXXX") || RESP_LIST=""
        if [ -z "$RESP_LIST" ]; then
            echo "!! 无法创建临时列表文件，跳过本步"
        else
            printf '%s\n' "${RESPS[@]}" > "$RESP_LIST"
            if ! python3 extract_CertInfo_python/extract_ocsp_fields.py \
                    --paths-from "$RESP_LIST" \
                    --csv "$OUT/ocsp_fields.csv" --csv-mode wide; then
                echo "!! 该步失败"
            fi
            rm -f "$RESP_LIST"
        fi
    fi
fi

# ---------- 产物清单 ----------
echo
echo "===== 产物（$OUT） ====="
for f in cert_fields.csv cert_fields_extensions.csv crl_fields.csv \
         crl_fields_entries.csv ca_summary.csv crl_summary.csv \
         ocsp_summary.csv index.csv ocsp_batch.csv ocsp_fields.csv \
         ocsp_fields_responses.csv; do
    [ -f "$OUT/$f" ] && printf '  %-32s %s 行\n' "$f" "$(wc -l < "$OUT/$f")"
done
echo "  每证书证据目录: $(ls -d "$OUT"/*/ 2>/dev/null | wc -l) 个（crl.pem / resp.der）"
[ "${RUN[0]}" -eq 0 ] && \
    echo "  （本次跳过 ①：上面若出现 ca/crl/ocsp_summary.csv 与 index.csv，是输出目录里的旧文件）"
echo "结束: $(date '+%F %T')"
