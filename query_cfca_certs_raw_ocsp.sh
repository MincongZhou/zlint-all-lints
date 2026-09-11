#!/usr/bin/env bash
# query_cfca_certs_raw_ocsp.sh —— 批量导出证书信息 + 原样输出 OCSP 响应（不做任何状态判断）
#
# 与 query_cfca_certs.sh 的区别:
#   - 不对 OCSP 返回做任何解析/归类（不判定 good / revoked / ERROR / SKIP）
#   - 把 openssl ocsp 的 stdout + stderr 原文一字不改地写进输出文件
#   - 可选 --respout 另存每张证书的 DER 原始响应，便于事后复现
#
# 用法:
#     ./query_cfca_certs_raw_ocsp.sh                        # certs/CFCA -> cfca_cert_ocsp_raw.txt
#     ./query_cfca_certs_raw_ocsp.sh <目录>                  # 指定证书目录
#     ./query_cfca_certs_raw_ocsp.sh <目录> <输出.txt>        # 目录 + 输出文件都指定
#     ./query_cfca_certs_raw_ocsp.sh --ocsp-timeout 5        # OCSP 超时秒数（默认 10）
#     ./query_cfca_certs_raw_ocsp.sh --no-ocsp               # 不联网，只导出证书信息
#     ./query_cfca_certs_raw_ocsp.sh --respout <目录>         # 另存 DER 原始响应 <证书文件名>.ocsp.der
#
# 说明:
#   - 输出文件里只有原始事实：证书字段、OCSP 请求用的 issuer、命令退出码、响应原文
#   - OCSP 签发者证书自动在本目录内按 issuer DN 匹配（同名多张时优选自签名那张）
#   - 限时用 coreutils timeout（openssl ocsp 自带的 -timeout 经 http 代理会报
#     missing content type，故不使用）；退出码 124 = 超时
#   - PEM / DER 自动识别（解析失败时改用 -inform DER 重试）
#   - 支持文件名含空格；自动跳过 *:Zone.Identifier、.DS_Store
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

DIR=""; OUT=""; DO_OCSP=1; OCSP_TIMEOUT=10; RESP_OUT_DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --no-ocsp)        DO_OCSP=0 ;;
        --ocsp-timeout)   OCSP_TIMEOUT=${2:?--ocsp-timeout 需要秒数}; shift ;;
        --ocsp-timeout=*) OCSP_TIMEOUT=${1#*=} ;;
        --respout)        RESP_OUT_DIR=${2:?--respout 需要目录}; shift ;;
        --respout=*)      RESP_OUT_DIR=${1#*=} ;;
        -h|--help)        sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)  if   [ -z "$DIR" ]; then DIR=$1
            elif [ -z "$OUT" ]; then OUT=$1
            else echo "多余参数: $1" >&2; exit 1; fi ;;
    esac
    shift
done
DIR=${DIR:-"$SCRIPT_DIR/certs/CFCA"}
OUT=${OUT:-"$SCRIPT_DIR/cfca_cert_ocsp_raw.txt"}

OPTS=(-noout -subject -issuer -serial -dates -fingerprint -sha256)

[ -d "$DIR" ] || { echo "目录不存在: $DIR" >&2; exit 1; }
[ -z "$RESP_OUT_DIR" ] || mkdir -p "$RESP_OUT_DIR" || exit 1

# ---------- 证书列表 ----------
FILES=()
while IFS= read -r -d '' f; do
    case "$f" in *":Zone.Identifier"|*".DS_Store") continue ;; esac
    FILES+=("$f")
done < <(find "$DIR" -type f \
            \( -iname "*.cer" -o -iname "*.pem" -o -iname "*.crt" -o -iname "*.der" \) \
            -print0 | sort -z)

# ---------- 工具函数 ----------
x509_field() {          # x509_field <证书> <openssl 参数...>，自带 PEM/DER 回退
    local f=$1; shift
    local raw
    raw=$(openssl x509 -in "$f" -noout "$@" 2>/dev/null)
    if [ -z "$raw" ]; then
        raw=$(openssl x509 -in "$f" -inform DER -noout "$@" 2>/dev/null)
    fi
    printf '%s\n' "$raw"
}

# ---------- 第一遍：建立 subject -> 文件 索引（用于找 OCSP 签发者）----------
declare -A SUBJ2FILE SUBJ2SELF
for f in "${FILES[@]}"; do
    subj=$(x509_field "$f" -subject); subj=${subj#subject=}
    [ -n "$subj" ] || continue
    iss=$(x509_field "$f" -issuer); iss=${iss#issuer=}
    [ -n "${SUBJ2FILE["$subj"]+set}" ] || SUBJ2FILE["$subj"]=$f
    [ "$iss" = "$subj" ] && SUBJ2SELF["$subj"]=$f     # 同名多张时优选自签名证书
done

# ---------- 主循环 ----------
count=0
: > "$OUT"          # 清空（不存在则新建）
declare -a SUM=()

for f in "${FILES[@]}"; do
    count=$((count + 1))
    name=$(basename "$f")
    serial=""; rc="n/a"; note=""

    out=$(openssl x509 -in "$f" "${OPTS[@]}" 2>/dev/null | sed '/Fingerprint=/s/://g')
    fmt=PEM
    if [ -z "$out" ]; then                      # PEM 解析失败 -> 按 DER 再试一次
        out=$(openssl x509 -in "$f" -inform DER "${OPTS[@]}" 2>/dev/null | sed '/Fingerprint=/s/://g')
        fmt=DER
    fi

    {
        echo "==================== $name ===================="
        echo "file: $f"
        if [ -z "$out" ]; then
            echo "（无法解析为 X.509 证书）"
            note="PARSE-ERROR"
        else
            echo "format: $fmt"
            echo "$out"

            serial=$(x509_field "$f" -serial); serial=${serial#serial=}
            iss=$(x509_field "$f" -issuer);    iss=${iss#issuer=}
            uri=$(x509_field "$f" -ocsp_uri)

            echo "ocspUri=${uri:-<无>}"

            if [ "$DO_OCSP" -eq 0 ]; then
                echo "ocspRaw=（未查询，--no-ocsp）"
                note="未查询"
            elif [ -z "$uri" ]; then
                echo "ocspRaw=（证书无 OCSP 地址，未发起查询）"
                note="无OCSP地址"
            else
                issuer_file=${SUBJ2SELF["$iss"]:-${SUBJ2FILE["$iss"]:-}}
                if [ -z "$issuer_file" ]; then
                    echo "ocspRaw=（目录内找不到签发者证书，未发起查询）"
                    echo "ocspIssuerDN=$iss"
                    note="缺签发者证书"
                else
                    echo "ocspIssuer=$(basename "$issuer_file")"
                    echo "ocspTimeout=${OCSP_TIMEOUT}s"
                    echo
                    echo "---- raw ocsp response begin ----"
                    if [ -n "$RESP_OUT_DIR" ]; then
                        timeout "$OCSP_TIMEOUT" openssl ocsp \
                            -issuer "$issuer_file" -cert "$f" -url "$uri" \
                            -resp_text -no_nonce \
                            -respout "$RESP_OUT_DIR/$name.ocsp.der" 2>&1
                    else
                        timeout "$OCSP_TIMEOUT" openssl ocsp \
                            -issuer "$issuer_file" -cert "$f" -url "$uri" \
                            -resp_text -no_nonce 2>&1
                    fi
                    rc=$?
                    echo "---- raw ocsp response end ----"
                    echo "opensslExitCode=$rc"
                fi
            fi
        fi
        echo
    } >> "$OUT"

    SUM+=("$name|$serial|$rc|$note")
done

# ---------- 汇总表（只记录事实，不判定证书状态）----------
{
    echo "==================== 汇总 ===================="
    echo "（opensslExitCode 只是命令退出码：0=命令执行完毕，124=timeout 超时，其余为命令报错；"
    echo "  证书是否吊销请自行看上面的 raw ocsp response 原文）"
    printf '%-52s %-24s %-16s %s\n' "证书" "序列号" "opensslExitCode" "备注"
    for l in "${SUM[@]}"; do
        IFS='|' read -r n s c t <<<"$l"
        printf '%-52s %-24s %-16s %s\n' "$n" "$s" "$c" "$t"
    done
} >> "$OUT"

echo "共处理 $count 张证书，原始 OCSP 响应已写入: $OUT"
[ -z "$RESP_OUT_DIR" ] || echo "DER 原始响应目录: $RESP_OUT_DIR"
