#!/usr/bin/env python3
"""
run_cert_crl_ocsp.py —— 对一张证书一键跑齐 zlint 的 CA / CRL / OCSP 三类规则

背景: zlint 对单个输入对象只真实执行其所属类型的规则（证书→CA 类，CRL→CRL 类，
OCSP→OCSP 类），其余标 NA。本脚本把证书的"配套吊销对象"也取下来一起跑，
让三类规则全部真实执行:

    1. 证书侧:  zlint-all-lints -cert <证书>           → cert.json / cert.csv（全部 CA 类规则）
    2. CRL 侧:  按证书 CDP 下载 CRL 转 PEM（同一 CDP URL 只下载一次，缓存复用）→
                zlint-all-lints 跑全部 CRL 类规则
    3. OCSP 侧: check_ocsp.py 查 OCSP 并存原始 DER 响应 → zlint-all-lints 跑全部 OCSP 类规则

CRL / OCSP 步骤联网失败（无 CDP / 无 OCSP 地址 / 网络不通 / 下载超时）时自动跳过，
只影响对应侧规则，不中断整体。

CRL 下载按 CDP URL 去重：CRL 是"签发者 + 分区"级文件，同一份 CRL 覆盖该 CA 下所有
证书，所以上万张证书通常只有几十~几百个唯一 URL。首次命中某 URL 时下载一次并缓存到
<输出>/_crl_cache/，之后指向同一 URL 的证书直接复制缓存（每张证书仍各有自己的
crl.pem 证据文件）；批量结束会打印「实际下载 / 命中缓存 / 无 CRL 可下」的次数。

用法:
    python3 run_cert_crl_ocsp.py <证书路径|证书目录> [输出目录]
                                 [--timeout 秒] [--detail] [--refresh-crl]
    python3 run_cert_crl_ocsp.py                                # 无参数 → 交互模式

输出（默认"精简模式"：批量多张证书也只留三张按侧汇总表 + 证书索引 + 每证书的证据文件）:
    输出根/                              （默认 ./results；每张证书再建 <证书名>/ 子目录）
    ├── ca_summary.csv        全部证书的证书侧汇总（每行首列 cert 为证书名）
    ├── crl_summary.csv       全部证书的 CRL 侧汇总
    ├── ocsp_summary.csv      全部证书的 OCSP 侧汇总
    ├── index.csv             证书索引；三张汇总表只用"证书名"标识证书
    │                         （zlint 的输出里没有指纹），需要指纹/有效期
    │                         对账时用本表按 cert 列 join：
    │                         cert, fingerprint_sha256, not_before, not_after,
    │                         path, crl_pem, resp_der
    ├── _crl_cache/           CRL 去重缓存：同一 CDP URL 只下载一次（crl_<url哈希>.pem），
    │                         其余指向同一 URL 的证书直接复制缓存，联网量降到
    │                         「唯一 CDP URL 数」；整个目录可随时删除。
    │                         缓存以 CRL 自身的 nextUpdate 判定是否仍新鲜：已过期
    │                         （或缺 nextUpdate 且文件超过 24h）视为陈旧，自动重新
    │                         下载，避免复跑同一输出目录时把上一轮的旧 CRL 当作
    │                         本次证据；--refresh-crl 可强制忽略全部缓存重下
    └── <证书名>/             每证书目录，只留联网证据（zlint 中间 JSON/CSV 已删）
        ├── crl.pem           该证书对应的 CRL（PEM，有则；可能是缓存复制来的）
        └── resp.der          原始 OCSP 响应（有则）

批量结束时打印一行「CRL 去重统计: 实际下载 N 次，命中缓存 M 次，无 CRL 可下 K 次」，
便于核对去重效果（例如 19 张 CA 证书只有 4 份唯一 CRL 时，N 应接近 4）。

批量时如遇重名证书文件（如不同版本链里的同名 cer），自动逐级补父目录前缀
（__ 连接）生成唯一名，子目录名与汇总表 cert 列同用，不会互相覆盖。

加 --detail 则保留每张证书的完整产物（同旧版行为）:
    <证书名>/
    ├── cert.json / cert.csv      证书侧（行数 = meta.total_lints，CA 规则真实执行）
    ├── crl.pem                   从 CDP 下载的 CRL（PEM，有则）
    ├── crl.json / crl.csv        全部 CRL 类规则（有则）
    ├── resp.der                  原始 OCSP 响应（有则）
    └── ocsp.json / ocsp.csv      全部 OCSP 类规则（有则）

依赖: python3 + cryptography；zlint-all-lints 需已编译（go build -o zlint-all-lints .）。
"""

import csv
import datetime
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter

from cryptography import x509
from cryptography.hazmat.primitives import serialization

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
ZLINT_BIN = os.path.join(PROJECT_ROOT, "zlint-all-lints")
CHECK_OCSP = os.path.join(PROJECT_ROOT, "check_certs_python", "check_ocsp.py")
CERT_EXTS = (".pem", ".crt", ".cer", ".der", ".cert")

# 每侧的中间文件名前缀 与 汇总表文件名
_SIDE_FILE = {"证书侧": "cert", "CRL 侧": "crl", "OCSP 侧": "ocsp"}
_SUMMARY_FILE = {"证书侧": "ca_summary.csv", "CRL 侧": "crl_summary.csv",
                 "OCSP 侧": "ocsp_summary.csv"}
_INDEX_FILE = "index.csv"        # 证书索引表（汇总表只有证书名，指纹/有效期在这张表里）
_CRL_CACHE_DIR = "_crl_cache"    # CRL 按 CDP URL 去重的缓存目录（与 <证书名>/ 同级）
_CRL_CACHE_TTL = 24 * 3600       # 缓存 CRL 缺 nextUpdate 时的兜底有效期（秒）

# 复用 run_ocsp_batch 的 cert_meta()：指纹与有效期用同一套解析口径，
# 保证 index.csv 的 fingerprint_sha256 与 run_ocsp_batch.py 输出的完全一致
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
from run_ocsp_batch import cert_meta  # noqa: E402

# 复用 check_certs_python 里的 CDP 解析与下载（与 check_crl.py 同一套实现）
CHECK_DIR = os.path.join(PROJECT_ROOT, "check_certs_python")
if CHECK_DIR not in sys.path:
    sys.path.insert(0, CHECK_DIR)
from check_crl import get_cdp_urls      # noqa: E402
from check_ocsp import fetch_url, load_cert  # noqa: E402



def err(msg):
    print(f"错误: {msg}", file=sys.stderr)


def merge_csv(src_csv, summary_csv, prefix):
    """把 src_csv 的数据行（行首补 prefix）追加进 summary_csv；表头不存在时先写。
    返回合并的数据行数。用 csv 模块读写，字段含逗号/引号也不会串列。"""
    if not os.path.isfile(src_csv):
        return 0
    with open(src_csv, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    if len(rows) < 2:            # 只有表头或空 → 没有数据行
        return 0
    header, data = rows[0], rows[1:]
    is_new = not os.path.isfile(summary_csv)
    with open(summary_csv, "a", newline="", encoding="utf-8") as f:
        wr = csv.writer(f)
        if is_new:
            # BOM 只在首次建表时写一次（追加时再写会变成文件中部的多余字节）；
            # 效果等同 write_index 的 utf-8-sig，保证 Excel 双击表头不乱码
            f.write("\ufeff")
            wr.writerow(["cert"] + header)
        for r in data:
            wr.writerow([prefix] + r)
    return len(data)


def write_index(path, records):
    """写证书索引表：cert / fingerprint_sha256 / not_before / not_after /
    path / crl_pem / resp_der。

    三张 *_summary.csv 只用"证书名"标识证书（zlint 的输出里没有指纹），
    同名不同版本或需要与台账对账时，用本表按 cert 列 join 出指纹与有效期。
    crl_pem / resp_der 为对应证据文件名，没有则留空。"""
    with open(path, "w", newline="", encoding="utf-8-sig") as f:  # utf-8-sig 方便 Excel
        wr = csv.writer(f)
        wr.writerow(["cert", "fingerprint_sha256", "not_before", "not_after",
                     "path", "crl_pem", "resp_der"])
        for r in records:
            wr.writerow([r["cert"], r["fingerprint_sha256"], r["not_before"],
                         r["not_after"], r["path"], r["crl_pem"], r["resp_der"]])


# ---------- CRL 下载 + 按 CDP URL 去重缓存 ----------

_CRL_STATS = {"download": 0, "hit": 0, "fail": 0}    # 实际下载 / 命中缓存 / 无 CRL 可下


def crl_cache_file(cache_dir, url):
    """缓存文件路径：用 URL 的 sha256 前 16 位命名（URL 里的路径/特殊字符不适合做文件名）"""
    h = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    return os.path.join(cache_dir, f"crl_{h}.pem")


def crl_bytes_to_pem(raw):
    """把下载到的 CRL 统一转 PEM（DER/PEM 自动识别）

    与 check_crl.py 的校验口径一致：即便是 PEM 也解析一遍，挡住 HTML 错误页之类的假数据。
    解析失败会抛异常，由调用方决定是否换下一个 CDP。
    """
    if raw.lstrip().startswith(b"-----BEGIN"):
        x509.load_pem_x509_crl(raw)
        return raw
    return x509.load_der_x509_crl(raw).public_bytes(serialization.Encoding.PEM)


def _crl_cache_fresh(path, now=None):
    """缓存 CRL 是否仍新鲜到可以复用。

    以 CRL 自身的 nextUpdate 为准：已过期即视为陈旧 —— 宁可重新下载，也不把上一轮
    的旧 CRL 当成"本轮证据"（CRL 会随吊销更新重发，旧文件的吊销集合可能不完整）。
    nextUpdate 缺失（RFC 5280 允许）时退化为文件 mtime 的 24h TTL。
    """
    try:
        with open(path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())
    except Exception:                       # 缓存损坏 / 不是 CRL → 当作陈旧
        return False
    next_update = getattr(crl, "next_update_utc", None)
    if next_update is None:                 # cryptography < 42 的旧属性（naive UTC）
        try:
            next_update = crl.next_update
        except Exception:
            next_update = None
    if next_update is not None:
        if next_update.tzinfo is None:
            next_update = next_update.replace(tzinfo=datetime.timezone.utc)
        return next_update > (now or datetime.datetime.now(datetime.timezone.utc))
    try:
        return (time.time() - os.path.getmtime(path)) < _CRL_CACHE_TTL
    except OSError:
        return False


def fetch_crl_cached(cert_path, out_pem, cache_dir, timeout=15, refresh=False):
    """按证书 CDP 下载 CRL：同一 URL 只下一次（缓存到 cache_dir），再复制到 out_pem

    返回 (是否成功, 命中的 URL 或 None, 是否来自缓存)。
    多个 CDP 分发点逐个尝试，全部失败返回 False（调用方跳过 CRL 侧）。
    每张证书仍各有自己的 crl.pem（证据文件布局不变），但网络下载量降到
    「唯一 CDP URL 数」而不是「证书数」。

    缓存按 CRL 的 nextUpdate 判定新鲜度（见 _crl_cache_fresh）：陈旧则重新下载，
    避免复跑同一输出目录时复用过期证据；refresh=True 完全忽略缓存强制重下。
    """
    try:
        with open(cert_path, "rb") as f:
            cert = load_cert(f.read())
        urls = get_cdp_urls(cert)
    except Exception as e:
        print(f"  读取证书 / 解析 CDP 失败: {type(e).__name__}: {e}")
        _CRL_STATS["fail"] += 1
        return False, None, False

    if not urls:
        print("  该证书没有 CDP 扩展（或其中没有 http/https 分发点），跳过 CRL 侧")
        _CRL_STATS["fail"] += 1
        return False, None, False

    for url in urls:
        cached = crl_cache_file(cache_dir, url)
        if not refresh and os.path.isfile(cached):
            if _crl_cache_fresh(cached):
                shutil.copyfile(cached, out_pem)
                _CRL_STATS["hit"] += 1
                return True, url, True
            print(f"  缓存已陈旧（nextUpdate 已过），重新下载: {url}")
        print(f"  下载 CRL: {url}")
        try:
            pem = crl_bytes_to_pem(fetch_url(url, timeout=timeout))
        except Exception as e:
            print(f"  下载 / 解析失败: {type(e).__name__}: {e}")
            continue
        os.makedirs(cache_dir, exist_ok=True)
        with open(cached, "wb") as f:
            f.write(pem)
        shutil.copyfile(cached, out_pem)
        _CRL_STATS["download"] += 1
        return True, url, False

    print("  所有 CDP 分发点都失败，跳过 CRL 侧")
    _CRL_STATS["fail"] += 1
    return False, None, False


def lint_one(obj_path, out_json, out_csv):
    """对单个 PKI 对象跑 zlint-all-lints。返回 (exit_code, input_type)"""
    if not os.path.isfile(ZLINT_BIN):
        err(f"找不到 {ZLINT_BIN}，请先编译: go build -o zlint-all-lints .")
        return 1, None
    cmd = [ZLINT_BIN, "-cert", obj_path, "-out", out_json, "-csv", out_csv,
           "-pretty=false"]
    print(f"执行: {' '.join(cmd)}")
    rc = subprocess.call(cmd)
    itype = None
    if rc == 0 and os.path.isfile(out_json):
        with open(out_json, encoding="utf-8") as f:
            itype = json.load(f).get("meta", {}).get("input_type")
    return rc, itype


def status_stats(json_path):
    """读一份 lint JSON，返回各 status 的计数（如 {'pass': 412, 'NA': 21}）"""
    if not os.path.isfile(json_path):
        return None
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)
    return dict(Counter(l["status"] for l in data.get("lints", [])))


def fmt_stats(stats):
    if not stats:
        return "(无结果)"
    return "  ".join(f"{k}={v}" for k, v in stats.items())


def dedupe_stems(cert_paths):
    """给每张证书生成唯一的显示名/子目录名（默认= 文件名去扩展名）。
    重名时逐级补父目录前缀（用 __ 连接）直到唯一，避免同名证书
    （不同版本链里的同名文件）在输出目录和汇总表 cert 列里混在一起。
    返回 {路径: 唯一名}，顺序与输入一致。"""
    names, used = {}, set()
    for p in cert_paths:
        stem = os.path.splitext(os.path.basename(p))[0]
        if stem not in used:
            names[p] = stem
            used.add(stem)
            continue
        d, prefix = os.path.dirname(p), []
        while True:                      # 逐级向上补父目录，直到唯一
            prefix.insert(0, os.path.basename(d))
            cand = "__".join(prefix + [stem])
            if cand not in used:
                names[p] = cand
                used.add(cand)
                break
            parent = os.path.dirname(d)
            if parent == d:              # 已到根仍冲突（理论不会发生）→ 序号兜底
                i = 2
                while f"{stem}_{i}" in used:
                    i += 1
                cand = f"{stem}_{i}"
                names[p] = cand
                used.add(cand)
                break
            d = parent
    return names


def run_one(cert_path, out_root=None, timeout=15, detail=False, stem=None,
            refresh_crl=False):
    """跑单张证书：证书侧 + CRL 侧 + OCSP 侧，各侧结果合并进输出根下的三张汇总表。
    默认精简模式（只留 *_summary.csv + crl.pem / resp.der 证据文件）；
    detail=True 保留每张证书的全部中间产物（json/csv/pem/der）。
    stem 为显示名/子目录名（默认取文件名去扩展名；批量时由 dedupe_stems 去重）。
    refresh_crl=True 时忽略 CRL 缓存强制重新下载。
    返回 (是否全部 OK, 索引表记录 dict)"""
    stem = stem or os.path.splitext(os.path.basename(cert_path))[0]
    summary_dir = out_root or os.path.join(PROJECT_ROOT, "results")
    out_dir = os.path.join(summary_dir, stem)   # 每证书一个子目录
    os.makedirs(out_dir, exist_ok=True)

    # 索引表用的一行：指纹（无冒号）+ 有效期，解析失败则留空
    fpr, nb, na = cert_meta(cert_path)
    record = {"cert": stem, "fingerprint_sha256": fpr, "not_before": nb,
              "not_after": na, "path": cert_path, "crl_pem": "", "resp_der": ""}

    rows = []   # (步骤, tag, exit_code)
    ok_all = True

    def append_summary(tag, csv_name):
        """把该侧 csv 数据行合并进对应汇总表（行首补证书名）"""
        n = merge_csv(os.path.join(out_dir, csv_name),
                      os.path.join(summary_dir, _SUMMARY_FILE[tag]), stem)
        if n:
            print(f"  → {_SUMMARY_FILE[tag]} 追加 {n} 行")

    # ---------- [1/3] 证书侧 ----------
    print(f"\n===== [1/3] 证书侧 lint（全部 CA 类规则） =====")
    rc, itype = lint_one(cert_path,
                         os.path.join(out_dir, "cert.json"),
                         os.path.join(out_dir, "cert.csv"))
    rows.append(("证书侧", itype, rc))
    ok_all &= rc == 0
    append_summary("证书侧", "cert.csv")

    # ---------- [2/3] CRL 侧：按 CDP URL 去重下载 → 跑全部 CRL 类规则 ----------
    print(f"\n===== [2/3] CRL 侧（按 CDP URL 去重下载 → 全部 CRL 类规则，联网） =====")
    crl_pem = os.path.join(out_dir, "crl.pem")
    # 上一轮可能留下 crl.pem：本轮没下到就必须让它消失，否则 run_all.sh 的 CRL
    # 字段步会把这份陈旧证据当作本次结果解析（index.csv 与磁盘还会互相矛盾）
    if os.path.isfile(crl_pem):
        os.remove(crl_pem)
    ok_crl, crl_url, from_cache = fetch_crl_cached(
        cert_path, crl_pem, os.path.join(summary_dir, _CRL_CACHE_DIR), timeout,
        refresh=refresh_crl)
    if ok_crl:
        print(f"  CRL 来源: {'缓存命中' if from_cache else '本次下载'}  {crl_url}")
        rc, itype = lint_one(crl_pem,
                             os.path.join(out_dir, "crl.json"),
                             os.path.join(out_dir, "crl.csv"))
        rows.append(("CRL 侧", itype, rc))
        ok_all &= rc == 0
        record["crl_pem"] = "crl.pem"
        append_summary("CRL 侧", "crl.csv")
    else:
        print("CRL 未取得，跳过 CRL 规则（不影响其他步骤）")
        rows.append(("CRL 侧", "跳过", 1))

    # ---------- [3/3] OCSP 侧：查询并保存原始响应 → 跑全部 OCSP 类规则 ----------
    print(f"\n===== [3/3] OCSP 侧（查 OCSP 并存原始响应 → 全部 OCSP 类规则，联网） =====")
    resp_der = os.path.join(out_dir, "resp.der")
    if os.path.isfile(resp_der):        # 同上：旧响应不能冒充本次证据
        os.remove(resp_der)
    rc = subprocess.call([sys.executable, CHECK_OCSP, cert_path,
                          "--respout", resp_der, "--status",
                          "--timeout", str(timeout)])
    if rc == 0 and os.path.isfile(resp_der):
        rc, itype = lint_one(resp_der,
                             os.path.join(out_dir, "ocsp.json"),
                             os.path.join(out_dir, "ocsp.csv"))
        rows.append(("OCSP 侧", itype, rc))
        ok_all &= rc == 0
        record["resp_der"] = "resp.der"
        append_summary("OCSP 侧", "ocsp.csv")
    else:
        print("OCSP 查询失败，跳过 OCSP 规则（不影响其他步骤）")
        rows.append(("OCSP 侧", "跳过", rc))

    # ---------- 汇总统计（读 json，须在精简清理之前） ----------
    print("\n================ 汇总 ================")
    print(f"证书: {cert_path}")
    print(f"SHA-256: {fpr or '(解析失败)'}")
    print(f"输出: {out_dir}/")
    print("----------------------------------------")
    for tag, itype, rc in rows:
        f = _SIDE_FILE[tag]
        stats = status_stats(os.path.join(out_dir, f"{f}.json"))
        label = f"{tag} ({itype or '-'})"
        if rc == 0 and stats:
            print(f"  [OK]   {label}: {fmt_stats(stats)}")
        else:
            print(f"  [跳过] {label}")
    print("----------------------------------------")
    print("说明: status 计数里 NA 表示该规则对输入对象不适用；pass/error 为真实执行结果")

    # ---------- 精简模式清理：只留三张汇总表 + 证据文件 ----------
    if not detail:
        removed = []
        for f in _SIDE_FILE.values():
            for ext in ("json", "csv"):
                p = os.path.join(out_dir, f"{f}.{ext}")
                if os.path.isfile(p):
                    os.remove(p)
                    removed.append(os.path.basename(p))
        if removed:
            print(f"精简模式: 已删中间产物 {', '.join(removed)}（各侧已并入 *_summary.csv）")
        # 目录里没有证据文件等任何内容 → 删除空目录
        if os.path.isdir(out_dir) and not os.listdir(out_dir):
            os.rmdir(out_dir)
            print(f"精简模式: 删除空目录 {out_dir}")
    return ok_all, record


def print_crl_stats():
    """打印 CRL 去重缓存统计（每张证书一次计数：实际下载 / 命中缓存 / 无 CRL 可下）"""
    print(f"CRL 去重统计: 实际下载 {_CRL_STATS['download']} 次，"
          f"命中缓存 {_CRL_STATS['hit']} 次，"
          f"无 CRL 可下 {_CRL_STATS['fail']} 次")


def run_target(target, out_root=None, timeout=15, detail=False, refresh_crl=False):
    """依赖检查 + 单个/批量分发（target 已展开 ~）"""
    if not os.path.exists(target):
        err(f"路径不存在 -> {target}")
        sys.exit(1)
    for s in (ZLINT_BIN, CHECK_OCSP):
        if not os.path.isfile(s):
            err(f"找不到 {s}")
            sys.exit(1)

    # 每次运行重建三张汇总表 + 证书索引（避免重跑同一证书时重复追加）
    summary_dir = out_root or os.path.join(PROJECT_ROOT, "results")
    os.makedirs(summary_dir, exist_ok=True)
    for f in list(_SUMMARY_FILE.values()) + [_INDEX_FILE]:
        p = os.path.join(summary_dir, f)
        if os.path.isfile(p):
            os.remove(p)
    _CRL_STATS.update(download=0, hit=0, fail=0)
    print(f"三张汇总表重建于: {summary_dir}/"
          f"（{', '.join(_SUMMARY_FILE.values())}；另有 {_INDEX_FILE} 证书索引）")
    print(f"CRL 缓存目录: {os.path.join(summary_dir, _CRL_CACHE_DIR)}/"
          f"（同一 CDP URL 只下载一次，后续证书直接复制缓存；"
          f"缓存过 nextUpdate 自动重下"
          + ("；本次 --refresh-crl 强制全部重下" if refresh_crl else "") + "）")

    if os.path.isdir(target):
        # ---------- 批量：遍历目录下所有证书 ----------
        certs = sorted(
            p for p in glob.glob(os.path.join(target, "**", "*"), recursive=True)
            if os.path.isfile(p) and p.lower().endswith(CERT_EXTS))
        if not certs:
            err(f"目录下没有找到证书文件（{CERT_EXTS}）-> {target}")
            sys.exit(1)
        print(f"批量模式: 发现 {len(certs)} 个证书")
        names = dedupe_stems(certs)     # 同名证书 → 父目录前缀区分（子目录与 cert 列同用）
        dup = {n for p, n in names.items()
               if n != os.path.splitext(os.path.basename(p))[0]}
        if dup:
            print("检测到重名证书，已加父目录前缀区分: " + ", ".join(sorted(dup)))
        ok_all, ok, fail, records = True, 0, [], []
        for i, c in enumerate(certs, 1):
            print(f"\n{'='*60}\n[{i}/{len(certs)}] {c}\n{'='*60}")
            ok_one, rec = run_one(c, summary_dir, timeout, detail,
                                  stem=names[c], refresh_crl=refresh_crl)
            records.append(rec)
            ok_all &= ok_one
            if ok_one:
                ok += 1
            else:
                fail.append(c)
        index_path = os.path.join(summary_dir, _INDEX_FILE)
        write_index(index_path, records)
        print(f"\n============ 批量完成 ============")
        print(f"成功 {ok}/{len(certs)}，失败 {len(fail)} 个")
        for c in fail:
            print(f"  [失败] {c}")
        print(f"证书索引: {index_path}（{len(records)} 行）")
        print_crl_stats()
        sys.exit(0 if ok_all else 1)
    else:
        # ---------- 单个证书 ----------
        ok, rec = run_one(target, summary_dir, timeout, detail,
                          refresh_crl=refresh_crl)
        index_path = os.path.join(summary_dir, _INDEX_FILE)
        write_index(index_path, [rec])
        print(f"证书索引: {index_path}（1 行）")
        print_crl_stats()
        sys.exit(0 if ok else 1)


def interactive():
    """无参数时的交互式输入：证书路径/目录必填，其余可回车跳过"""
    print("=== 交互模式（直接回车使用默认值，输入 q 退出）===")

    target = os.path.expanduser(input("证书路径或目录: ").strip())
    while True:
        if target.lower() in ("q", "quit"):
            sys.exit(0)
        if os.path.exists(target):
            break
        print(f"  !! 路径不存在: {target}")
        target = os.path.expanduser(input("请重新输入证书路径或目录 (q 退出): ").strip())

    out_dir = os.path.expanduser(input("输出目录 (回车用默认): ").strip())
    if out_dir.lower() in ("q", "quit"):
        sys.exit(0)

    t = input("网络超时秒数 (回车默认 15): ").strip()
    if t.lower() in ("q", "quit"):
        sys.exit(0)
    try:
        timeout = int(t) if t else 15
    except ValueError:
        print(f"  !! '{t}' 不是数字，按默认 15 处理")
        timeout = 15

    # 是否保留完整产物：默认精简（只留三张汇总表 + 证据文件）
    d = input("是否保留每张证书的完整产物 (y/N，默认精简): ").strip().lower()
    detail = d in ("y", "yes")

    run_target(target, out_dir or None, timeout, detail)


def _int_arg(value, flag):
    """解析整数选项值：缺值 / 非数字 / 非正数都直接报错退出，不吐 traceback"""
    try:
        n = int(value)
    except (TypeError, ValueError):
        err(f"{flag} 需要整数秒数，收到: {value!r}")
        sys.exit(2)
    if n <= 0:
        err(f"{flag} 必须为正整数，收到: {n}")
        sys.exit(2)
    return n


def main():
    args = sys.argv[1:]
    if not args:                    # 没有任何参数 → 交互模式
        interactive()
        return
    if args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    timeout = 15
    detail = False
    refresh_crl = False
    rest = []
    i = 0
    while i < len(args):
        if args[i] == "--timeout":
            if i + 1 >= len(args):
                err("--timeout 缺少秒数，如 --timeout 15")
                sys.exit(2)
            timeout = _int_arg(args[i + 1], "--timeout")
            i += 2
        elif args[i] == "--detail":
            detail = True
            i += 1
        elif args[i] == "--refresh-crl":
            refresh_crl = True
            i += 1
        else:
            rest.append(args[i])
            i += 1
    if not rest:
        print("用法: python3 run_cert_crl_ocsp.py <证书路径|目录> [输出目录] "
              "[--timeout 秒] [--detail] [--refresh-crl]")
        sys.exit(1)

    target = os.path.expanduser(rest[0])
    out_root = os.path.expanduser(rest[1]) if len(rest) > 1 else None
    run_target(target, out_root, timeout, detail, refresh_crl)


if __name__ == "__main__":
    main()
