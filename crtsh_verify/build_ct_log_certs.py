#!/usr/bin/env python3
"""构建 certs/ct_log_certs/ —— 「crt.sh 能看到的、指定时间窗内、指定 CA 签发的正式证书」。

============================================================ 为什么是这个流程
crt.sh 的 SQL 接口做不了这件事，必须 HTTP + SQL 配合：

  ① HTTP 列表  https://crt.sh/?identity=%&iCAID=<ca>&p=<页>&n=<每页>
     · n=5000 可用；结果**严格按 Not Before 倒序**（已实测验证）
     · 表列：crt.sh ID | Not Before | Not After | Subject Name
     · 翻到「本页最旧 < 窗口起点」或「本页不满页」即停

  ② SQL 取本体  select id, encode(certificate,'base64') from certificate where id in (...)
     · encode() 只做字节→base64，**不解析 DER**，比 x509_notbefore() 快两个数量级
     · 不能用 certificate_lifecycle：not_before 是视图，逐行解析 DER，单 CA 全量 229s

============================================================ 三个关键事实（都踩过）
  1. **crt.sh 对同一张证书多数只存 precert 版本**
     CA 6564 窗口内 4471 行里，只有 420 行是正式证书（带 SCT），其余 4051 行是 precert
     （含 CT 毒化扩展 OID 1.3.6.1.4.1.11129.2.4.3、无 SCT）。
     二者 **DN 相同、not_before 日期相同、序列号相同**，只有 DER 不同。
     => 所以「正式证书」的主体会来自本地已有证书，crt.sh 只用于补缺和核对。

  2. **比对键必须是序列号**
     · 不能用文件 sha256：本地 .der 是解析后重新序列化的，字节与 CT 原始 DER 不同
     · 不能用 DN+日期：precert 与正式证书在这两个维度完全相同

  3. **encode(...,'base64') 每 76 字符插换行**，CSV 里是多行字段，用 csv 模块解析

============================================================ 用法
  python3 crtsh_verify/build_ct_log_certs.py \
      --window-start 2025-08-01 --window-end 2026-07-31 \
      --ca-pattern CFCA \
      --local-dir "certs/CFCA全部证书/非国密证书" \
      --out-dir certs/ct_log_certs

产出：
  <out-dir>/*.der                     正式证书，文件名 序号_CA_序列号.der
  <work-dir>/listing.csv              crt.sh 原始列表
  <work-dir>/authoritative.csv        权威清单：(CA, 序列号) 及来源
  <work-dir>/manifest.csv             落盘清单（含 not_before / subject）
"""
import argparse
import base64
import csv
import os
import re
import subprocess
import sys
import time

from cryptography import x509

POISON = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3")
PG_CONN = "host=crt.sh port=5432 dbname=certwatch user=guest"
PG_ENV = {"PGCONNECT_TIMEOUT": "20", "PGSSLMODE": "require"}
PAGE = 5000

ROW_RE = re.compile(
    r'<A href="\?id=(\d+)">\d+</A></TD>\s*<TD[^>]*>([^<]+)</TD>\s*'
    r'<TD[^>]*>([^<]+)</TD>\s*<TD>(.*?)</TD>', re.S)


def sh(cmd, env=None, timeout=600):
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.run(cmd, capture_output=True, env=e, timeout=timeout)


def find_psql():
    from shutil import which
    p = which("psql") or os.path.expanduser("~/.local/pgsql/bin/psql")
    if not os.path.exists(p) and which("psql") is None:
        raise SystemExit("找不到 psql；请先安装 PostgreSQL 客户端（见 RUNBOOK）")
    return p


PSQL = find_psql()


def curl(url, tries=5):
    for i in range(tries):
        p = sh(["curl", "-4", "-s", "--max-time", "180", url])
        b = p.stdout.decode("utf-8", "replace")
        if "crt.sh ID" in b or "No certificates" in b:
            return b
        time.sleep(3 * (i + 1))
    return None


def ns(v):
    return re.sub(r"[^0-9a-fA-F]", "", str(v)).upper().lstrip("0") or "0"


def is_poison(cert):
    try:
        return any(e.oid == POISON for e in cert.extensions)
    except Exception:
        return False


# ------------------------------------------------------------------ ① CA 清单
def discover_cas(pattern, work):
    out = os.path.join(work, "cas.csv")
    sql = os.path.join(work, "cas.sql")
    open(sql, "w").write(
        "\\pset pager off\n"
        f"\\copy (select id, name from ca where name ilike '%{pattern}%' order by id) "
        f"to '{out}' csv header\n")
    for i in range(6):
        sh([PSQL, PG_CONN, "-f", sql], env=PG_ENV)
        if os.path.exists(out) and os.path.getsize(out) > 0:
            return list(csv.DictReader(open(out, encoding="utf-8-sig")))
        time.sleep(10)
    raise SystemExit("无法获取 CA 清单")


# ------------------------------------------------------------------ ② 列表
def list_window(ca_id, ws, we):
    rows, page = [], 1
    while page <= 60:
        html = curl(f"https://crt.sh/?identity=%25&iCAID={ca_id}&p={page}&n={PAGE}")
        if html is None:
            break
        got = ROW_RE.findall(html)
        if not got:
            break
        for cid, nb, na, subj in got:
            nb = nb.strip()
            if ws <= nb <= we:
                rows.append((cid, nb, na.strip(), re.sub(r"\s+", " ", subj).strip()))
        oldest = min(x[1].strip() for x in got)
        if oldest < ws or len(got) < PAGE:
            break
        page += 1
        time.sleep(1)
    return rows


# ------------------------------------------------------------------ ③ 取本体
def fetch_bodies(ids, out_csv, work, chunk=1200):
    """分批取。crt.sh 的 statement_timeout 上限 1min，
    一次性 IN 上千个 id 时快时慢（实测 6167 个曾 44s 跑完，也曾 4471 个就超时），
    所以必须分块并且允许失败重跑（已成功的块会被跳过）。"""
    parts_dir = os.path.join(work, "parts")
    os.makedirs(parts_dir, exist_ok=True)
    ids = sorted(ids)
    nparts = (len(ids) + chunk - 1) // chunk

    ok = fail = 0
    for k in range(nparts):
        part_file = os.path.join(parts_dir, f"p{k:04d}.csv")
        if os.path.exists(part_file) and os.path.getsize(part_file) > 0:
            ok += 1
            continue
        sub = ids[k * chunk:(k + 1) * chunk]
        sql = os.path.join(work, f"get_{k:04d}.sql")
        open(sql, "w").write(
            "\\pset pager off\n"
            "\\copy (select id, encode(certificate,'base64') as b64 from certificate "
            f"where id in ({','.join(sub)}) order by id) to '{part_file}' csv header\n")
        got = False
        for t in range(4):
            r = sh([PSQL, PG_CONN, "-f", sql], env=PG_ENV, timeout=900)
            out = (r.stdout + r.stderr).decode()
            if "COPY" in out and os.path.exists(part_file):
                got = True
                break
            time.sleep(8)
        if got:
            ok += 1
        else:
            fail += 1
            print(f"    块 {k+1}/{nparts} 失败: {out.strip()[:70]}")
        print(f"    进度 {k+1}/{nparts}  成功={ok} 失败={fail}", flush=True)

    # 合并
    with open(out_csv, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["id", "b64"])
        for k in range(nparts):
            p = os.path.join(parts_dir, f"p{k:04d}.csv")
            if not (os.path.exists(p) and os.path.getsize(p) > 0):
                continue
            for r in csv.DictReader(open(p, encoding="utf-8-sig")):
                w.writerow([r["id"], r["b64"]])
    print(f"    合并完成：{ok}/{nparts} 块成功，失败 {fail} 块")
    return fail == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-start", default="2025-08-01")
    ap.add_argument("--window-end", default="2026-07-31")
    ap.add_argument("--ca-pattern", default="CFCA")
    ap.add_argument("--local-dir", action="append", default=None,
                    help="本地正式证书目录（可重复指定）。crt.sh 对多数条目只给 precert，"
                         "正式证书靠本地填充，所以要把所有本地证书目录都列上。"
                         "默认 certs/CFCA全部证书/非国密证书")
    ap.add_argument("--out-dir", default="certs/ct_log_certs")
    ap.add_argument("--work-dir", default="/tmp/ct_log_build")
    a = ap.parse_args()

    os.makedirs(a.work_dir, exist_ok=True)
    os.makedirs(a.out_dir, exist_ok=True)

    print("① CA 清单…")
    cas = discover_cas(a.ca_pattern, a.work_dir)
    print(f"   匹配 {len(cas)} 个")

    print(f"② 逐 CA 拉 {a.window_start} ~ {a.window_end} 列表…")
    listing = []
    for c in cas:
        rs = list_window(c["id"], a.window_start, a.window_end)
        if rs:
            print(f"   {c['id']:>8s} {c['name'].split('CN=')[-1][:36]:38s} {len(rs):5d} 行")
        for cid, nb, na, s in rs:
            listing.append({"ca_id": c["id"], "ca_name": c["name"], "id": cid,
                            "not_before": nb, "not_after": na, "subject": s})
    with open(os.path.join(a.work_dir, "listing.csv"), "w", newline="",
              encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["ca_id", "ca_name", "id", "not_before",
                                          "not_after", "subject"])
        w.writeheader()
        w.writerows(listing)
    if not listing:
        raise SystemExit("列表为空")
    print(f"   合计 {len(listing)} 行（含 precert 孪生）")

    print("③ SQL 取本体…")
    b64csv = os.path.join(a.work_dir, "der_b64.csv")
    fetch_bodies(sorted({r["id"] for r in listing}), b64csv, a.work_dir)

    print("④ 按序列号归并：正式证书优先，其次 precert…")
    meta = {r["id"]: r for r in listing}
    by_ca = {}
    for r in csv.DictReader(open(b64csv, encoding="utf-8-sig")):
        cid = r["id"].strip()
        try:
            der = base64.b64decode(r["b64"].replace("\n", "").replace("\r", "").strip())
            cert = x509.load_der_x509_certificate(der)
        except Exception:
            continue
        ca = meta.get(cid, {}).get("ca_id", "?")
        key = (ca, ns(format(cert.serial_number, "X")))
        poison = is_poison(cert)
        cur = by_ca.get(key)
        if cur is None or (cur["poison"] and not poison):
            by_ca[key] = {"cid": cid, "der": der, "cert": cert, "poison": poison,
                          "src": "crt.sh-precert" if poison else "crt.sh-cert"}

    # 本地正式证书填充：crt.sh 只有 precert 的条目，用本地同序列号的正式证书替换
    local_used, local_total = 0, 0
    local_dirs = a.local_dir or ["certs/CFCA全部证书/非国密证书"]
    for ldir in local_dirs:
        if not os.path.isdir(ldir):
            print(f"   [跳过] 本地目录不存在: {ldir}")
            continue
        idx = {}
        for root, _, files in os.walk(ldir):
            for f in files:
                p = os.path.join(root, f)
                try:
                    c = x509.load_der_x509_certificate(open(p, "rb").read())
                except Exception:
                    continue
                if is_poison(c):
                    continue
                idx.setdefault(ns(format(c.serial_number, "X")), []).append((p, c))
        local_total += sum(len(v) for v in idx.values())
        for key, v in by_ca.items():
            if not v["poison"]:
                continue                       # crt.sh 有正式版就不换
            cands = idx.get(key[1], [])
            if cands:
                p, c = cands[0]
                by_ca[key] = {"cid": v["cid"], "der": open(p, "rb").read(), "cert": c,
                              "poison": False, "src": "local"}
                local_used += 1
    print(f"   本地共 {local_total} 张可用，填充 {local_used} 条")

    # 落盘
    for f in os.listdir(a.out_dir):
        os.remove(os.path.join(a.out_dir, f))
    manifest, auth = [], []
    n = cert_only = 0
    for (ca, ser), v in sorted(by_ca.items()):
        if v["poison"]:
            auth.append([ca, ser, v["cid"], "precert-only"])
            continue
        n += 1
        cert_only += 1
        fn = f"{n:05d}_{ca}_{ser[:24]}.der"
        open(os.path.join(a.out_dir, fn), "wb").write(v["der"])
        manifest.append([fn, v["cid"], ca, ser, v["src"],
                         v["cert"].not_valid_before_utc.date().isoformat(),
                         v["cert"].not_valid_after_utc.date().isoformat(),
                         v["cert"].subject.rfc4514_string()])
        auth.append([ca, ser, v["cid"], v["src"]])

    for name, rows, hdr in (("manifest.csv", manifest,
                             ["file", "crt_sh_id", "ca_id", "serial_hex", "来源",
                              "not_before", "not_after", "subject"]),
                            ("authoritative.csv", auth,
                             ["ca_id", "serial_hex", "crt_sh_id", "来源"])):
        with open(os.path.join(a.work_dir, name), "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(hdr)
            w.writerows(rows)

    print(f"\n完成：正式证书 {cert_only} 张 -> {a.out_dir}")
    print(f"  其中本地填充 {local_used} 张，crt.sh 直接提供 {cert_only - local_used} 张")
    ponly = len(by_ca) - cert_only
    if ponly:
        print(f"  另有 {ponly} 个序列号 crt.sh 只给了 precert、本地也没有正式版（未落盘）")
    print(f"  清单: {os.path.join(a.work_dir, 'manifest.csv')}")


if __name__ == "__main__":
    sys.exit(main())
