#!/usr/bin/env python3
"""run_all_fast.py —— 跑一遍 run_all.sh 的四步，但把第 ④ 步（OCSP 状态汇总）换成
「优先复用第 ① 步已存的 OCSP 响应」。

本脚本位于项目根目录，`run_all.sh --fast`（`-fast` 亦可）会把整轮交给它；
不加 `--fast` 时 run_all.sh 走原逻辑（第 ④ 步逐张联网），两者可自由选择。

为什么要用它
------------
原 run_all.sh 里，第 ① 步为跑 zlint 的 OCSP 类规则，已经对每张证书查过一次 OCSP 并
把原始响应存成 <输出>/<stem>/resp.der；第 ④ 步 run_ocsp_batch.py 又**重新联网**把同一
个 responder 再查一遍，只为拿 GOOD / REVOKED / UNKNOWN 这个状态列。同一个查询做两遍，
是整个跑批最大的耗时点（第 ④ 步约 55 分钟）。

本脚本把第 ④ 步改成：先在本地解析已有的 resp.der 取状态，取不到（没有 / 已过期 /
响应不成功）才回落到联网查询。第 ①②③ 步完全调用原项目脚本，产物与原 run_all.sh 一致。

可靠性设计
----------
- 复用前会检查 OCSP 响应的 next_update；已过期则视为陈旧，重新联网查。
- 响应 response_status 非 SUCCESSFUL（如 tryLater / unauthorized）一律当"没有响应"处理，
  不会把无效响应当成结果。
- 缺失/陈旧的证书自动回落到项目原本的 query_one 联网查询，联网失败的表现与原脚本一致。
- 用 index.csv 的 fingerprint_sha256 关联，不用文件名猜测，避免重名带来的错配。
- 输出 CSV 直接复用原项目的 write_csv 和 iso_utc，格式与 run_ocsp_batch.py 逐字节一致。

用法
----
    python3 run_all_fast.py <证书文件|证书目录> [输出目录] [超时秒数] [选项]
    ./run_all.sh <证书文件|证书目录> [输出目录] [超时秒数] --fast    # 等价写法

    # 完整四步（第 ④ 步默认复用）
    python3 run_all_fast.py certs/CFCA订户证书_ct_log results/CFCA订户证书_ct_log

    # 只重跑第 ④ 步（复用输出目录里已有的 index.csv 与 resp.der）
    python3 run_all_fast.py certs/X results/X --only 4

    # 完整跳过复用，行为与原 run_all.sh 完全一致
    python3 run_all_fast.py certs/X results/X --no-reuse-ocsp

注意
----
- `--fast` 只改变第 ④ 步「怎么查」，不改变「要不要跑第 ④ 步」：步骤选择仍由
  `--only / --skip / --no-lint` 决定，解析规则与 run_all.sh 一致。
- 复用的原料是第 ① 步产物 `<输出目录>/index.csv` 与 `<输出目录>/<证书名>/resp.der`。
  全新输出目录且跳过第 ① 步时没有可复用内容，第 ④ 步会自动退化为逐张联网。
- 需要「本次实时取证」（合规、举证）时请走 run_all.sh 的默认行为，不加 `--fast`。
- 完整说明见 `RUNBOOK.md` 3.5 节的「`--fast`：第 4 步复用本地 OCSP 响应」。

选项
----
    --project PATH        原项目根目录（默认 $ZLINT_PROJECT 或 ~/projects/zlint-all-lints-master）
    --timeout 秒          联网超时，默认 15
    --detail              第 ① 步保留每证书中间产物（不删 json/csv）
    --refresh-crl         第 ① 步忽略 CRL 缓存强制重下
    --no-reuse-ocsp       第 ④ 步不复用 resp.der，全部重新联网
    --max-age-hours N     resp.der 缺 next_update 时的兜底有效期，默认 168（7 天）
    --index-csv PATH      index.csv 的来源，默认 <输出目录>/index.csv
    --evidence-dir PATH   resp.der 所在根目录，默认 <输出目录>
    --only / --skip       步骤选择，如 --only 4 / --skip 1,3
"""

import csv
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

# ============================== 通用 ==============================

STEP_NAME = ["① 证书/CRL/OCSP 三类 zlint 规则（联网）",
             "② 证书字段宽表（本地）",
             "③ CRL 字段宽表（本地，依赖 ① 下载的 crl.pem）",
             "④ OCSP 状态汇总（复用优先）"]

BANNER = "=" * 68


def resolve_project(explicit=None):
    """定位项目根目录（本脚本已放进项目，默认就是它自己所在的目录）"""
    here = os.path.dirname(os.path.abspath(__file__))
    cand = explicit or os.environ.get("ZLINT_PROJECT") or here
    proj = os.path.abspath(os.path.expanduser(cand))
    need = [os.path.join(proj, "run_cert_crl_ocsp.py"),
            os.path.join(proj, "run_ocsp_batch.py"),
            os.path.join(proj, "zlint-all-lints")]
    missing = [p for p in need if not os.path.exists(p)]
    if missing:
        sys.exit(f"不像 zlint-all-lints 项目根目录（缺少 {missing[0]}）: {proj}\n"
                 f"可用 --project 指定。")
    return proj


def run_step(n, argv, cwd):
    """跑一个子步骤"""
    print(f"\n{BANNER}\n[{n}/4] {STEP_NAME[n - 1]}\n{BANNER}")
    print("执行:", " ".join(argv))
    return subprocess.call(argv, cwd=cwd)


def load_index(path):
    """读 index.csv -> {fingerprint_sha256: (stem, resp_der 相对路径)}"""
    idx = {}
    if not os.path.isfile(path):
        return idx, False
    with open(path, encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            fpr = (r.get("fingerprint_sha256") or "").strip()
            resp = (r.get("resp_der") or "").strip()
            if fpr and resp:
                idx[fpr] = ((r.get("cert") or "").strip(), resp)
    return idx, True


# ============================== ④ OCSP（复用优先） ==============================

def step4_ocsp(project, target, out, timeout=15, reuse=True,
               max_age_hours=168, index_csv=None, evidence_dir=None):
    """第 ④ 步：优先解析本地 resp.der，缺失/陈旧才联网。

    联网部分直接复用原项目的 query_one/write_csv，保证 Fail 时的表现、
    CSV 格式与原 run_ocsp_batch.py 完全一致。
    """
    # 让原项目的模块可被导入（它内部按自身文件位置算 PROJECT_ROOT，
    # 所以 issuers/、check_certs_python/ 都会指向正确的位置）
    if project not in sys.path:
        sys.path.insert(0, project)

    from run_ocsp_batch import (collect_certs, cert_meta, build_issuer_index,
                                resolve_issuer, query_one, write_csv, print_result,
                                iso_utc, DEFAULT_ISSUER_DIR)
    from cryptography.x509 import ocsp

    certs = collect_certs([target])
    if not certs:
        print("没有找到任何证书文件")
        return 1

    idx_csv = index_csv or os.path.join(out, "index.csv")
    evid = evidence_dir or out
    idx, have_index = load_index(idx_csv)

    if reuse:
        print(f"索引: {idx_csv}"
              f"（{'已载入 ' + str(len(idx)) + ' 条有 OCSP 响应的记录' if have_index else '不存在，全部走联网'}）")
        print(f"证据目录: {evid}")
    else:
        print("已指定 --no-reuse-ocsp：全部重新联网查询")

    def parse_local(path):
        """解析一份本地 OCSP 响应 -> (status, detail)；不可用则返回 None"""
        try:
            with open(path, "rb") as f:
                data = f.read()
            resp = ocsp.load_der_ocsp_response(data)
        except Exception:
            return None
        # 非成功响应（tryLater / unauthorized / malformed ...）当"没有"处理
        if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            return None
        # 新鲜度：next_update 已过即陈旧；没有 next_update 就用 this_update + 兜底有效期
        now = datetime.now(timezone.utc)
        nxt = getattr(resp, "next_update_utc", None)
        this = getattr(resp, "this_update_utc", None)
        if nxt is not None:
            if nxt <= now:
                return None
        elif this is None or \
                this + timedelta(hours=max_age_hours) <= now:
            return None

        cs = resp.certificate_status
        if cs == ocsp.OCSPCertStatus.REVOKED:
            return "REVOKED", iso_utc(resp.revocation_time_utc)
        if cs == ocsp.OCSPCertStatus.GOOD:
            return "GOOD", ""
        if cs == ocsp.OCSPCertStatus.UNKNOWN:
            return "UNKNOWN", ""
        return None

    dirs = [DEFAULT_ISSUER_DIR]
    by_ski_by_dn = None

    results = []
    reused_n = miss_n = stale_n = bad_n = 0
    for i, cert in enumerate(certs, 1):
        fpr, nb, na = cert_meta(cert)
        status = detail = None
        src = "联网"

        if reuse:
            hit = idx.get(fpr)
            if hit:
                stem, rel = hit
                p = os.path.join(evid, stem, rel)
                if not os.path.isfile(p):
                    miss_n += 1
                    src = "本地缺失"
                else:
                    got = parse_local(p)
                    if got:
                        status, detail = got
                        reused_n += 1
                        src = "复用"
                    else:
                        stale_n += 1
                        src = "响应陈旧/无效"
            else:
                miss_n += 1
                src = "索引无此证书"

        if status is None:
            if by_ski_by_dn is None:
                by_ski, by_dn = build_issuer_index(dirs)
                by_ski_by_dn = (by_ski, by_dn)
                print(f"\n签发者目录: {', '.join(dirs)}"
                      f"（索引 {len(by_ski)} 个 SKI / {len(by_dn)} 个 subject DN）")
            issuer_path = resolve_issuer(cert, by_ski_by_dn)
            status, detail = query_one(cert, timeout, False, False, issuer_path)
            if status == "ERROR":
                bad_n += 1

        results.append((cert, fpr, nb, na, status, detail))
        tail = f"（{src}）" if src != "联网" else ""
        print(f"[{i}/{len(certs)}] {cert}{tail}")
        print(f"      SHA-256: {fpr or '(解析失败)'}")
        print(f"      {status}" + (f"  ({detail})" if detail else ""))

    print(f"\n{BANNER}")
    if reuse:
        total = len(certs)
        print(f"第 ④ 步统计: 共 {total} 张")
        print(f"  复用本地 OCSP 响应    {reused_n} 张"
              f"（{reused_n / total * 100:.1f}%，未产生任何网络请求）")
        print(f"  索引内无记录          {miss_n} 张")
        print(f"  本地响应陈旧/无效     {stale_n} 张")
        print(f"  → 实际联网查询        {miss_n + stale_n} 张"
              f"（其中失败 {bad_n} 张）")
    else:
        print(f"第 ④ 步统计: 共 {len(certs)} 张（全部联网，失败 {bad_n} 张）")

    out_csv = os.path.join(out, "ocsp_batch.csv")
    write_csv(out_csv, results)
    print(f"CSV: {out_csv}（{len(results)} 行）")
    return 0


# ============================== ①②③（调用原项目脚本） ==============================

def step_run(args):
    """按选步策略跑四步"""
    if len(args.rest) < 2:
        print(__doc__)
        sys.exit(2)

    project = resolve_project(args.project)
    target = os.path.abspath(os.path.expanduser(args.rest[0]))
    out = os.path.abspath(os.path.expanduser(args.rest[1]))
    timeout = args.timeout
    if not os.path.exists(target):
        sys.exit(f"输入路径不存在: {target}")
    os.makedirs(out, exist_ok=True)

    run_map = {i: True for i in (1, 2, 3, 4)}
    if args.only:
        keep = set(int(x) for x in args.only.split(",") if x.strip())
        run_map = {i: i in keep for i in (1, 2, 3, 4)}
    if args.skip:
        drop = set(int(x) for x in args.skip.split(",") if x.strip())
        for i in drop:
            run_map[i] = False

    py = sys.executable
    rc_all = 0

    # ---------- ① 证书 / CRL / OCSP 三类 zlint 规则 ----------
    if run_map[1]:
        argv = [py, os.path.join(project, "run_cert_crl_ocsp.py"),
                target, out, "--timeout", str(timeout)]
        if args.detail:
            argv.append("--detail")
        if args.refresh_crl:
            argv.append("--refresh-crl")
        rc = run_step(1, argv, project)
        rc_all |= rc

    # ---------- ② 证书字段宽表 ----------
    if run_map[2]:
        argv = [py, os.path.join(project, "extract_CertInfo_python",
                                 "extract_cert_fields.py"),
                target, "--csv", os.path.join(out, "cert_fields.csv"),
                "--csv-mode", "wide"]
        rc = run_step(2, argv, project)
        rc_all |= rc

    # ---------- ③ CRL 字段宽表 ----------
    if run_map[3]:
        import glob as _glob
        crls = sorted(_glob.glob(os.path.join(out, "*", "crl.pem")))
        if not crls:
            print(f"\n{BANNER}\n[3/4] {STEP_NAME[2]}\n{BANNER}")
            print("没找到 <输出目录>/*/crl.pem —— 跳过（属正常）")
        else:
            fd, listfile = tempfile.mkstemp(dir="/tmp", prefix="crl_paths.")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(crls) + "\n")
            argv = [py, os.path.join(project, "extract_CertInfo_python",
                                     "extract_crl_fields.py"),
                    "--paths-from", listfile,
                    "--csv", os.path.join(out, "crl_fields.csv"),
                    "--csv-mode", "wide"]
            rc = run_step(3, argv, project)
            rc_all |= rc
            os.remove(listfile)

    # ---------- ④ OCSP 状态汇总（本工具的核心：复用优先） ----------
    if run_map[4]:
        print(f"\n{BANNER}\n[4/4] {STEP_NAME[3]}\n{BANNER}")
        rc = step4_ocsp(project, target, out, timeout,
                        reuse=not args.no_reuse_ocsp,
                        max_age_hours=args.max_age_hours,
                        index_csv=args.index_csv,
                        evidence_dir=args.evidence_dir)
        rc_all |= rc

    print(f"\n结束: {datetime.now().strftime('%F %T')}")
    return rc_all


def build_parser():
    import argparse
    ap = argparse.ArgumentParser(
        description="不改动原项目、第 ④ 步复用本地 OCSP 响应的 run_all.sh 替代方案",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python3 run_all_fast.py certs/CT results/CT\n"
               "  python3 run_all_fast.py certs/CT results/CT --only 4\n"
               "  python3 run_all_fast.py certs/CT results/CT --no-reuse-ocsp\n")
    ap.add_argument("rest", nargs="*", help="<证书文件|目录> [输出目录] [超时秒数]")
    ap.add_argument("--project", help="原项目根目录")
    ap.add_argument("--timeout", type=int, default=15, help="联网超时秒数（默认 15）")
    ap.add_argument("--detail", action="store_true", help="① 保留中间产物")
    ap.add_argument("--refresh-crl", action="store_true", help="① 强制重下 CRL")
    ap.add_argument("--no-reuse-ocsp", action="store_true",
                    help="④ 不复用本地响应，全部联网（等同原行为）")
    ap.add_argument("--max-age-hours", type=float, default=168,
                    help="resp.der 缺 next_update 时的兜底有效期（默认 168 小时）")
    ap.add_argument("--index-csv", help="index.csv 来源（默认 <输出目录>/index.csv）")
    ap.add_argument("--evidence-dir", help="resp.der 所在根目录（默认 <输出目录>）")
    ap.add_argument("--only", help="只跑列出的步骤，如 2,4")
    ap.add_argument("--skip", help="跳过列出的步骤，如 1,3")
    return ap


if __name__ == "__main__":
    ns = build_parser().parse_args()
    # 支持第 3 个位置参数作为超时秒数（与 run_all.sh 的用法一致）
    if len(ns.rest) >= 3 and ns.rest[2].isdigit() and ns.timeout == 15:
        ns.timeout = int(ns.rest[2])
    sys.exit(step_run(ns))
