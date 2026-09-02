#!/usr/bin/env python3
"""
list_revoked_sers.py —— 列出 CRL 中吊销的所有证书序列号

用法:
    python3 list_revoked_sers.py <crl 文件|目录> ... [--csv 输出.csv]
    python3 list_revoked_sers.py crl.pem                  # baidu 的 CRL
    python3 list_revoked_sers.py crls/                    # 批量
    python3 list_revoked_sers.py crls/ --csv revoked.csv  # 汇总导出（含吊销时间/原因）

输出: 每行一个吊销条目，序列号同时给 16 进制(0x) 和 10 进制
依赖: python3 + cryptography
"""
import csv
import glob
import os
import sys

from cryptography import x509


def load_crl(path):
    """加载 CRL，PEM / DER 自动识别"""
    with open(path, "rb") as f:
        raw = f.read()
    try:
        return x509.load_pem_x509_crl(raw)
    except ValueError:
        return x509.load_der_x509_crl(raw)


def iter_entries(crl):
    """迭代吊销条目 -> (hex_serial, dec_serial, revoke_date, reason)"""
    for rc in crl:
        date = getattr(rc, "revocation_date_utc", None) or rc.revocation_date
        reason = None
        try:
            reason = rc.extensions.get_extension_for_class(
                x509.CRLReason).value.reason.name
        except x509.ExtensionNotFound:
            pass
        yield (f"{rc.serial_number:#x}", str(rc.serial_number),
               str(date), reason or "")


def handle_one(crl_path, writer=None, out_txt=None):
    try:
        crl = load_crl(crl_path)
    except Exception as e:
        print(f"[跳过] {crl_path}: {e}", file=sys.stderr)
        return 0

    print(f"# {crl_path}")
    print(f"# issuer = {crl.issuer.rfc4514_string()}")
    print(f"# this_update = {crl.last_update_utc}   next_update = {crl.next_update_utc}")
    print(f"# 吊销条目数 = {len(crl)}")

    n = 0
    for hex_s, dec_s, date, reason in iter_entries(crl):
        print(f"{hex_s}\t{dec_s}")
        if writer is not None:      # --csv 模式
            writer.writerow([os.path.basename(crl_path), hex_s, dec_s, date, reason])
        n += 1
    return n


def main():
    args = sys.argv[1:]
    paths = [a for a in args if not a.startswith("--")]
    csv_out = None
    if "--csv" in args:
        i = args.index("--csv")
        if i + 1 >= len(args):
            print("错误: --csv 需要文件路径", file=sys.stderr)
            sys.exit(1)
        csv_out = args[i + 1]

    if not paths:
        print(__doc__)
        sys.exit(1)

    fout = open(csv_out, "w", newline="", encoding="utf-8") if csv_out else None
    writer = csv.writer(fout) if fout else None
    if writer:
        writer.writerow(["crl", "serial_hex", "serial_dec", "revoked_at", "reason"])

    total = 0
    for p in paths:
        p = os.path.expanduser(p)
        if os.path.isdir(p):
            files = sorted(glob.glob(os.path.join(p, "**", "*"), recursive=True))
            files = [f for f in files
                     if f.lower().endswith((".pem", ".der", ".crl"))
                     and os.path.isfile(f)]
            for f in files:
                total += handle_one(f, writer)
        else:
            total += handle_one(p, writer)

    if fout:
        fout.close()
        print(f"\n已汇总 {total} 个吊销序列号 -> {csv_out}")
    else:
        print(f"\n共 {total} 个吊销序列号")


if __name__ == "__main__":
    main()
