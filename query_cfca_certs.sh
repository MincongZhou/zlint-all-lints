#!/usr/bin/env bash
# query_cfca_certs.sh —— 批量输出证书关键信息 + OCSP 吊销状态
#
# 对目录下每张证书执行:
#     openssl x509 -in <cert> -noout -subject -issuer -serial -dates -fingerprint -sha256
# 并联网用 openssl ocsp 查询吊销状态，结果汇总写入 txt 文件。
#
# 用法:
#     ./query_cfca_certs.sh                          # 默认 certs/CFCA -> cfca_cert_info.txt
#     ./query_cfca_certs.sh <目录>                    # 指定目录，输出仍为 cfca_cert_info.txt
#     ./query_cfca_certs.sh <目录> <输出.txt>          # 目录 + 输出文件都指定
#     ./query_cfca_certs.sh --no-ocsp                # 不联网，只导出证书信息
#     ./query_cfca_certs.sh --ocsp-timeout 5         # OCSP 超时秒数（默认 10）
#
# 说明:
#   - sha256 指纹去掉冒号输出（openssl 无原生选项，用 sed 后处理）
#   - PEM / DER 自动识别（失败时自动改用 -inform DER 重试）
#   - OCSP 签发者证书自动在本目录内按 issuer DN 匹配（优先选自签名那张），
#     匹配不到或证书本身无 OCSP 地址时标注 SKIP；responder 报错则标注 ERROR
#   - --ocsp-timeout 用 coreutils timeout 限时（openssl ocsp 自带的 -timeout
#     经 http 代理会报 missing content type，故不使用）
#   - 支持文件名含空格；自动跳过 *:Zone.Identifier、.DS_Store
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

DIR=""; OUT=""; DO_OCSP=1; OCSP_TIMEOUT=10
while [ $# -gt 0 ]; do
    case "$1" in
        --no-ocsp)        DO_OCSP=0 ;;
        --ocsp-timeout)   OCSP_TIMEOUT=${2:?--ocsp-timeout 需要秒数}; shift ;;
        --ocsp-timeout=*) OCSP_TIMEOUT=${1#*=} ;;
        -h|--help)        sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)  if   [ -z "$DIR" ]; then DIR=$1
            elif [ -z "$OUT" ]; then OUT=$1
            else echo "多余参数: $1" >&2; exit 1; fi ;;
    esac
    shift
done
DIR=${DIR:-"$SCRIPT_DIR/certs/CFCA"}
OUT=${OUT:-"$SCRIPT_DIR/cfca_cert_info.txt"}

OPTS=(-noout -subject -issuer -serial -dates -fingerprint -sha256)

[ -d "$DIR" ] || { echo "目录不存在: $DIR" >&2; exit 1; }

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

# ---------- OCSP 查询 ----------
n_good=0; n_revoked=0; n_err=0; n_skip=0
OCSP_STATUS=""

ocsp_block() {          # $1=证书文件  $2=ocsp url  $3=issuer DN
    local cert=$1 uri=$2 dn=$3
    OCSP_STATUS="SKIP"

    echo "ocspUri=${uri:-<无>}"
    if [ -z "$uri" ]; then
        echo "ocspStatus=SKIP（证书无 OCSP 地址，通常是根证书）"
        n_skip=$((n_skip + 1)); return
    fi

    local issuer_file=${SUBJ2SELF["$dn"]:-${SUBJ2FILE["$dn"]:-}}
    if [ -z "$issuer_file" ]; then
        echo "ocspStatus=SKIP（目录内找不到签发者证书: $dn）"
        n_skip=$((n_skip + 1)); return
    fi
    echo "ocspIssuer=$(basename "$issuer_file")"

    local resp rc st
    # 两个坑:
    #   1) openssl ocsp 没有 -noout 选项（只有 x509/req/crl 有）
    #   2) openssl ocsp 的 -timeout 会走非阻塞请求路径，经 http 代理时会报
    #      "missing content type"，所以外面套 coreutils 的 timeout 来限时
    resp=$(timeout "$OCSP_TIMEOUT" openssl ocsp -issuer "$issuer_file" -cert "$cert" \
             -url "$uri" -resp_text -no_nonce 2>&1)
    rc=$?

    st=$(printf '%s\n' "$resp" | sed -n 's/^[[:space:]]*Cert Status: //p' | head -n1)
    if [ -n "$st" ]; then
        echo "ocspStatus=$st"
        local v
        for pair in "ocspRevocationTime:Revocation Time" \
                    "ocspRevocationReason:Revocation Reason" \
                    "ocspThisUpdate:This Update" \
                    "ocspNextUpdate:Next Update"; do
            v=$(printf '%s\n' "$resp" | sed -n "s/^[[:space:]]*${pair#*:}: //p" | head -n1)
            [ -n "$v" ] && echo "${pair%%:*}=$v"
        done
        OCSP_STATUS=$st
        case "$st" in
            good)    n_good=$((n_good + 1)) ;;
            revoked) n_revoked=$((n_revoked + 1)) ;;
            *)       n_err=$((n_err + 1)) ;;
        esac
    else
        local emsg
        if [ "$rc" -eq 124 ]; then
            echo "ocspStatus=ERROR（查询超时 >${OCSP_TIMEOUT}s）"
        else
            emsg=$(printf '%s\n' "$resp" | grep -m1 -E 'Responder Error|Error' || true)
            echo "ocspStatus=ERROR（${emsg:-无响应/超时}）"
        fi
        OCSP_STATUS="ERROR"
        n_err=$((n_err + 1))
    fi
}

# ---------- 主循环 ----------
count=0
: > "$OUT"          # 清空（不存在则新建）
declare -a SUM=()

for f in "${FILES[@]}"; do
    count=$((count + 1))
    name=$(basename "$f")
    serial=""

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
            OCSP_STATUS="PARSE-ERROR"
        else
            echo "format: $fmt"
            echo "$out"

            serial=$(x509_field "$f" -serial); serial=${serial#serial=}
            iss=$(x509_field "$f" -issuer);    iss=${iss#issuer=}
            uri=$(x509_field "$f" -ocsp_uri)

            if [ "$DO_OCSP" -eq 1 ]; then
                ocsp_block "$f" "$uri" "$iss"
            else
                echo "ocspStatus=（未查询，--no-ocsp）"
                OCSP_STATUS="SKIP"
            fi
        fi
        echo
    } >> "$OUT"

    SUM+=("$name|$serial|$OCSP_STATUS")
done

# ---------- 汇总表 ----------
{
    echo "==================== 汇总 ===================="
    printf '%-52s %-24s %s\n' "证书" "序列号" "OCSP状态"
    for l in "${SUM[@]}"; do
        IFS='|' read -r n s st <<<"$l"
        printf '%-52s %-24s %s\n' "$n" "$s" "$st"
    done
} >> "$OUT"

echo "共处理 $count 张证书，结果已写入: $OUT"
if [ "$DO_OCSP" -eq 1 ]; then
    echo "OCSP 统计: good=$n_good revoked=$n_revoked error=$n_err skip=$n_skip"
fi
