#!/usr/bin/env python3
"""
run_ocsp_batch.py —— 批量跑 check_ocsp.py，对每个证书联网查询 OCSP 状态

对给定的证书（单个/多个文件或目录，目录递归搜索 .pem/.crt/.cer/.der/.cert），
逐张调用 check_certs_python/check_ocsp.py --status 查询，逐张打印结果；
每张证书另附 DER 编码的 SHA-256 指纹（64 位大写十六进制、无冒号，即
openssl x509 -fingerprint -sha256 去掉冒号后的形式，便于粘进 Excel/台账），
证书改名 / 重名 / 多版本链同名文件都能唯一对账；
可选 --csv 输出一张汇总表（cert / fingerprint_sha256 / not_before / not_after /
status / detail 六列），方便 Excel 打开。
其中 not_before / not_after 为证书有效期，从证书本地解析（ISO 8601 UTC，
与 openssl x509 -noout -dates 一致），解析失败或查询失败时依然有值。

签发者证书（OCSP 的 CertID 必须用它构造）来源，按优先级:
    1. --issuer-dir 指定的目录（可多次）
    2. 默认目录 <项目根>/issuers
    3. 证书 AIA 里的 CA Issuers 地址（联网下载，由 check_ocsp.py 兜底）
批量开始时只扫一次目录、按证书 AKI 反查签发者 SKI，逐张命中即复用；
命中不到才回落到 AIA。很多 CA（如 CFCA Identity 体系）的 AIA 只给 OCSP 地址、
不给 CA Issuers，这类证书必须靠 1 或 2，否则只能得到
"ERROR: 加载签发者证书失败"。

用法:
    python3 run_ocsp_batch.py <证书文件|证书目录> [更多...] [--csv 输出.csv] [--timeout 秒] [--der] [--sha256] [--issuer-dir 目录]
    python3 run_ocsp_batch.py certs/ --csv results/ocsp_batch.csv --timeout 10
    python3 run_ocsp_batch.py a.pem b.pem c.pem --der
    python3 run_ocsp_batch.py certs/ --sha256       # CertID 用 SHA-256（默认 SHA-1，兼容性最好）
    python3 run_ocsp_batch.py certs/ --issuer-dir ./mycas --issuer-dir ~/cfca
    python3 run_ocsp_batch.py                        # 无参数 → 交互模式

状态取值: GOOD / REVOKED / UNKNOWN（查询成功）；ERROR（无 OCSP 地址、
签发者加载失败、网络不通、响应非成功等，详见 detail 列）。
其中 detail 为 UNAUTHORIZED 时表示 responder 不受理该 CertID —— 多因该 CA 体系
根本不提供 OCSP（此时吊销状态只能靠 CRL 判断），或签发者传错（已由 check_ocsp.py
的 AKI/SKI 校验拦住，不会静默算错）。

退出码: 全部证书查询成功返回 0，有 ERROR 返回 1。
"""

import argparse
import csv
import glob
import os
import shlex
import subprocess
import sys
from collections import Counter
from datetime import timezone

from cryptography.hazmat.primitives import hashes

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
CHECK_OCSP = os.path.join(PROJECT_ROOT, "check_certs_python", "check_ocsp.py")
CERT_EXTS = (".pem", ".crt", ".cer", ".der", ".cert")

sys.path.insert(0, os.path.join(PROJECT_ROOT, "check_certs_python"))
from check_ocsp import (build_issuer_index, enable_utf8_output,  # noqa: E402
                        find_issuer, load_cert, DEFAULT_ISSUER_DIR)

_STATUS_OK = {"GOOD", "REVOKED", "UNKNOWN"}


def err(msg):
    print(f"错误: {msg}", file=sys.stderr)


def collect_certs(paths):
    """收集所有证书文件：文件直接加入；目录递归搜索。返回排序去重列表"""
    certs = []
    for p in paths:
        p = os.path.expanduser(p)
        if os.path.isdir(p):
            certs.extend(
                f for f in glob.glob(os.path.join(p, "**", "*"), recursive=True)
                if os.path.isfile(f) and f.lower().endswith(CERT_EXTS))
        elif os.path.isfile(p):
            certs.append(p)
        else:
            err(f"路径不存在，跳过 -> {p}")
    return sorted(set(certs))


def iso_utc(dt):
    """datetime → ISO 8601 UTC 字符串（如 2026-06-12T07:18:50+00:00）。
    cryptography < 42 返回的是 naive UTC，这里按 UTC 补上时区。"""
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def cert_meta(cert_path, der=False):
    """读证书，返回 (指纹, not_before, not_after)。解析失败三者都返回空串。

    指纹 = DER 编码的 SHA-256，64 位大写十六进制、无冒号（即
    openssl x509 -fingerprint -sha256 去掉冒号后的形式），用于对账：证书改名、
    同名不同版本都能唯一标识，且不受查询成败影响。
    not_before / not_after = 证书有效期，ISO 8601 UTC（与 openssl -dates 一致）。
    """
    try:
        with open(cert_path, "rb") as f:
            cert = load_cert(f.read(), der)
    except Exception:
        return "", "", ""
    fpr = cert.fingerprint(hashes.SHA256()).hex().upper()   # 无冒号，方便对账粘贴
    nb = getattr(cert, "not_valid_before_utc", None)
    na = getattr(cert, "not_valid_after_utc", None)
    if nb is None or na is None:        # cryptography < 42 无 *_utc 属性，退回旧属性
        nb, na = cert.not_valid_before, cert.not_valid_after
    return fpr, iso_utc(nb), iso_utc(na)


def resolve_issuer(cert_path, index, der=False):
    """用签发者目录索引给证书找签发者，返回证书路径；找不到/解析失败返回 None
    （返回 None 时交给 check_ocsp.py 用 AIA 的 CA Issuers 兜底）"""
    try:
        with open(cert_path, "rb") as f:
            cert = load_cert(f.read(), der)
    except Exception:
        return None
    try:
        return find_issuer(cert, index)
    except Exception:
        return None


def query_one(cert_path, timeout=15, der=False, sha256=False, issuer_path=None):
    """调用 check_ocsp.py --status 查询单张证书。
    issuer_path 非空时显式传给子进程，省得它再扫一遍签发者目录。
    返回 (status, detail)：status ∈ GOOD/REVOKED/UNKNOWN/ERROR"""
    cmd = [sys.executable, CHECK_OCSP, cert_path, "--status",
           "--timeout", str(timeout)]
    if issuer_path:
        cmd += ["--issuer", issuer_path]
    if der:
        cmd.append("--der")
    if sha256:
        cmd.append("--sha256")
    # 两端都锁死 UTF-8：子进程用 PYTHONIOENCODING 强制 UTF-8 输出，父进程按 UTF-8 解码。
    # 只设父进程会出乱码（中文 Windows 上子进程默认按 GBK 输出 "无 OCSP 地址"，
    # 父进程按 utf-8 解就成了 "�� OCSP ��ַ"）；只靠默认解码又会 UnicodeDecodeError
    # 把 stderr 置空导致 AttributeError 崩溃。errors="replace" 作最后兜底。
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=env)

    if proc.returncode == 0:
        line = ((proc.stdout or "").strip().splitlines() or [""])[0]
        if line.startswith("REVOKED "):          # 格式: REVOKED <吊销时间>
            return "REVOKED", line[len("REVOKED "):].strip()
        return (line if line in _STATUS_OK else "UNKNOWN"), ""
    # 失败: stderr 首行形如 "ERROR: 无 OCSP 地址" / "ERROR: OCSP 查询失败: ..."
    detail = ((proc.stderr or "").strip().splitlines() or ["ERROR: 未知错误"])[0]
    if detail.startswith("ERROR: "):
        return "ERROR", detail[len("ERROR: "):].strip()
    return "ERROR", detail


def print_result(i, n, cert_path, fpr, status, detail, issuer_path=None):
    print(f"[{i}/{n}] {cert_path}")
    print(f"      SHA-256: {fpr or '(解析失败)'}")
    if issuer_path:
        print(f"      签发者: {issuer_path}")
    if status in _STATUS_OK:
        print(f"      {status}" + (f"  ({detail})" if detail else ""))
    else:
        print(f"      ERROR: {detail}")


def write_csv(path, results):
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:  # utf-8-sig 方便 Excel
        wr = csv.writer(f)
        wr.writerow(["cert", "fingerprint_sha256", "not_before", "not_after",
                     "status", "detail"])
        for cert, fpr, nb, na, status, detail in results:
            wr.writerow([cert, fpr, nb, na, status, detail])


def batch(paths, csv_path=None, timeout=15, der=False, sha256=False,
          issuer_dirs=None):
    """批量主流程，返回退出码"""
    if not os.path.isfile(CHECK_OCSP):
        err(f"找不到 {CHECK_OCSP}")
        return 1

    certs = collect_certs(paths)
    if not certs:
        err("没有找到任何证书文件（支持 " + " ".join(CERT_EXTS) + "）")
        return 1

    # 签发者目录只扫一次，之后逐张按 AKI 反查复用
    dirs = [DEFAULT_ISSUER_DIR] if issuer_dirs is None else issuer_dirs
    by_ski, by_dn = build_issuer_index(dirs)
    print(f"批量模式: 发现 {len(certs)} 个证书（timeout={timeout}s）")
    print(f"签发者目录: {', '.join(dirs) if dirs else '(未配置)'}"
          f"（索引 {len(by_ski)} 个 SKI / {len(by_dn)} 个 subject DN）\n")

    results = []
    for i, cert in enumerate(certs, 1):
        fpr, nb, na = cert_meta(cert, der)
        issuer_path = resolve_issuer(cert, (by_ski, by_dn), der)
        status, detail = query_one(cert, timeout, der, sha256, issuer_path)
        results.append((cert, fpr, nb, na, status, detail))
        print_result(i, len(certs), cert, fpr, status, detail, issuer_path)

    counter = Counter(s for *_, s, _ in results)
    print("\n============ 批量完成 ============")
    print(f"共 {len(certs)} 张: " +
          " / ".join(f"{k} {counter.get(k, 0)}" for k in
                     sorted(set(counter) | _STATUS_OK,
                            key=lambda x: (x not in _STATUS_OK, x))))

    failed = [(c, d) for c, *_, s, d in results if s == "ERROR"]
    if failed:
        print("查询失败:")
        for c, d in failed:
            print(f"  [ERROR] {c} -> {d}")

    if csv_path:
        write_csv(csv_path, results)
        print(f"CSV: {csv_path}（{len(results)} 行）")
    return 0 if not failed else 1


def _merge_existing(parts):
    """贪心合并：某段自身不是存在的路径时，尝试与后续段用空格拼接，
    拼出的完整路径存在则合并（还原被空格拆散的无引号路径）。
    拼不出来的段保持原样（报"路径不存在"，不吞拼写错误）。"""
    out, i = [], 0
    while i < len(parts):
        cur = parts[i]
        if os.path.exists(os.path.expanduser(cur)):
            out.append(cur)
            i += 1
            continue
        merged, j = cur, i + 1
        while j < len(parts):
            cand = merged + " " + parts[j]
            if os.path.exists(os.path.expanduser(cand)):
                merged, j = cand, j + 1
            else:
                break
        out.append(merged)
        i = j
    return out


def parse_paths(raw):
    """解析交互输入的路径串：逗号分隔优先；空格分隔时支持引号包裹含空格的路径
    （兼容中文引号"" ''）；未加引号的含空格路径若与相邻段拼接后存在也会自动合并。
    返回去空白的路径列表。"""
    raw = (raw.replace("\u201c", '"').replace("\u201d", '"')
              .replace("\u2018", "'").replace("\u2019", "'"))
    if "," in raw:
        parts = raw.split(",")
    else:
        try:
            parts = shlex.split(raw)        # 支持 "路径 含 空格" 引号包裹
        except ValueError:                  # 引号不配对等 → 退回普通空格拆分
            parts = raw.split()
    return [p.strip().strip('"').strip("'")
            for p in _merge_existing([s for s in parts if s.strip()])]


def interactive():
    """无参数时的交互式输入：逗号分隔多个路径；空格分隔时含空格的路径用引号包裹"""
    print('=== 交互模式（输入文件或目录，多个用逗号分隔；'
          '含空格的路径可用引号包裹，q 退出）===')
    raw = input("证书路径或目录: ").strip()
    if raw.lower() in ("q", "quit"):
        sys.exit(0)
    paths = parse_paths(raw)
    csv_path = None
    d = input("CSV 输出路径 (回车不输出): ").strip()
    if d.lower() in ("q", "quit"):
        sys.exit(0)
    if d:
        csv_path = os.path.expanduser(d)
    t = input("超时秒数 (回车默认 15): ").strip()
    if t.lower() in ("q", "quit"):
        sys.exit(0)
    try:
        timeout = int(t) if t else 15
    except ValueError:
        print(f"  !! '{t}' 不是数字，按默认 15 处理")
        timeout = 15
    idir = input(f"签发者目录 (回车用默认 {DEFAULT_ISSUER_DIR}，"
                 "逗号分隔可多个): ").strip()
    if idir.lower() in ("q", "quit"):
        sys.exit(0)
    issuer_dirs = [os.path.expanduser(x).strip()
                   for x in idir.split(",") if x.strip()] or None
    der = input("DER 格式 (y/N): ").strip().lower() in ("y", "yes")
    sys.exit(batch(paths, csv_path, timeout, der, issuer_dirs=issuer_dirs))


def main():
    enable_utf8_output()
    ap = argparse.ArgumentParser(
        description="批量跑 check_ocsp.py 查询证书 OCSP 状态")
    ap.add_argument("paths", nargs="*", help="证书文件或目录（可多个）")
    ap.add_argument("--csv", dest="csv_path", metavar="输出.csv",
                    help="把结果写入 CSV 汇总表（cert/fingerprint_sha256/"
                         "not_before/not_after/status/detail 六列）")
    ap.add_argument("--timeout", type=int, default=15, help="每张证书超时秒数 (默认 15)")
    ap.add_argument("--der", action="store_true", help="证书按 DER 优先解析")
    ap.add_argument("--sha256", action="store_true",
                    help="CertID 摘要用 SHA-256（默认 SHA-1，兼容性最好）")
    ap.add_argument("--issuer-dir", action="append", metavar="目录",
                    help="签发者证书目录（可多次）；批量开始时扫一次，"
                         "按证书 AKI 反查签发者 SKI 自动匹配。"
                         f"指定后不再使用默认目录 {DEFAULT_ISSUER_DIR}")
    args = ap.parse_args()

    if not args.paths:          # 无任何路径 → 交互模式
        interactive()
        return
    sys.exit(batch(args.paths, args.csv_path, args.timeout, args.der,
                   args.sha256, args.issuer_dir))


if __name__ == "__main__":
    main()
