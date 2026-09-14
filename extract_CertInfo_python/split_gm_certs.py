#!/usr/bin/env python3
"""split_gm_certs.py —— 从证书目录 / JSONL 仓库里筛出国密（SM2 / SM3）证书

为什么需要它: zcrypto（zlint 底座）与 Python cryptography 都不支持 SM2 曲线/SM3，
国密证书在 zlint 侧一张都跑不出来；审计口径上必须把它们单列，不能静默算作"已覆盖"。

判据（任一命中即为国密）:
    SM2 曲线      1.2.156.10197.1.301   取 subjectPublicKeyInfo 算法参数里的曲线 OID
    SM2-with-SM3  1.2.156.10197.1.501   证书签名算法 OID

曲线 OID 直接从证书 DER 里按 ASN.1 结构取出（不依赖 cryptography 的报错文案）；
若结构解析失败，退回从 cert.public_key() 的异常信息里捞 OID 兜底。

输出（都可选，默认只打印统计）:
    --jsonl    国密子集 JSONL（与输入同构，保留 idx，可直接喂 csv_b64_to_certs.py）
    --files    国密证书文件名清单（每行一个，便于排除/包含）
    --index    对照表 csv：idx/文件/是否国密/曲线OID/签名OID/SN/指纹/subject/错误
    --out-dir         把国密证书导出成独立文件（--format der|pem）
    --out-dir-non-gm  把非国密证书导出成独立文件（同一 --format）

用法:
    python3 split_gm_certs.py certs/CFCA全部证书
    python3 split_gm_certs.py certs/CFCA全部证书 --files gm_files.txt --out-dir certs/国密SM2
    python3 split_gm_certs.py certs/certs_all --out-dir 国密证书 --out-dir-non-gm 非国密证书
    python3 split_gm_certs.py certs/certs_all.jsonl --from-jsonl --jsonl gm505.jsonl
"""

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from csv_b64_to_certs import iter_jsonl_records, to_pem, unique_path  # noqa: E402

# 国密相关 OID
GM_CURVE_OIDS = {"1.2.156.10197.1.301": "SM2"}
GM_SIG_OIDS = {"1.2.156.10197.1.501": "SM2-with-SM3"}
GM_HASH_OIDS = {"1.2.156.10197.1.401": "SM3"}

CERT_EXTS = (".pem", ".crt", ".cer", ".der")


# ---------------------------------------------------------------------------
# 最小 ASN.1 解析：只为拿到 subjectPublicKeyInfo 的算法/曲线 OID
# ---------------------------------------------------------------------------
def _tlv(buf, pos):
    """读一个 TLV → (tag, value_bytes, next_pos)"""
    tag = buf[pos]
    pos += 1
    n = buf[pos]
    pos += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[pos:pos + k], "big")
        pos += k
    return tag, buf[pos:pos + n], pos + n


def _oid_str(b):
    """DER 里的 OID 内容字节 → 点分字符串"""
    if not b:
        return ""
    out = [str(b[0] // 40), str(b[0] % 40)]
    n = 0
    for x in b[1:]:
        n = n * 128 + (x & 0x7F)
        if not x & 0x80:
            out.append(str(n))
            n = 0
    return ".".join(out)


def spki_oids(der):
    """取 (公钥算法 OID, 算法参数 OID)。

    路径: Certificate SEQ -> TBSCertificate SEQ -> [version [0]?] -> serial,
    sigAlg, issuer, validity, subject, **subjectPublicKeyInfo** -> AlgorithmIdentifier
    """
    _t, cert, _ = _tlv(der, 0)
    _t, tbs, _ = _tlv(cert, 0)
    items, pos = [], 0
    while pos < len(tbs):
        tag, val, pos = _tlv(tbs, pos)
        items.append((tag, val))
    i = 1 if items and items[0][0] == 0xA0 else 0      # 跳过可选 version [0]
    spki = items[i + 5][1]                              # subjectPublicKeyInfo
    _t, algid, _ = _tlv(spki, 0)                        # AlgorithmIdentifier
    _t, alg_oid_b, p = _tlv(algid, 0)
    param_oid = None
    if p < len(algid):
        tag, val, _ = _tlv(algid, p)
        if tag == 0x06:                                 # 参数本身就是 OID（EC 曲线）
            param_oid = _oid_str(val)
    return _oid_str(alg_oid_b), param_oid


def audit(der):
    """判定单张证书 → dict"""
    cert = x509.load_der_x509_certificate(der)
    sig_oid = cert.signature_algorithm_oid.dotted_string
    alg_oid = curve_oid = None
    error = ""
    try:
        alg_oid, curve_oid = spki_oids(der)
    except Exception as e:                              # noqa: BLE001
        error = f"SPKI 解析失败: {e}"
    pk_error = ""
    try:
        cert.public_key()
    except Exception as e:                              # noqa: BLE001
        pk_error = str(e)
        if not curve_oid:                               # 兜底：从报错文案里捞 OID
            m = re.search(r"\d+(?:\.\d+)+", pk_error)
            if m:
                curve_oid = m.group(0)
    is_gm = curve_oid in GM_CURVE_OIDS or sig_oid in GM_SIG_OIDS
    return {
        "is_gm": is_gm,
        "curve_oid": curve_oid or "",
        "curve_name": GM_CURVE_OIDS.get(curve_oid, ""),
        "sig_oid": sig_oid,
        "sig_name": GM_SIG_OIDS.get(sig_oid, ""),
        "alg_oid": alg_oid or "",
        "pk_error": pk_error,
        "error": error,
        "serial_hex": format(cert.serial_number, "X"),
        "sha256": ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest()),
        "subject": cert.subject.rfc4514_string(),
    }


# ---------------------------------------------------------------------------
# 输入枚举
# ---------------------------------------------------------------------------
def iter_cert_files(paths):
    """目录递归 / 文件直收，返回排序后的文件列表"""
    files = []
    for p in paths:
        p = os.path.abspath(p)
        if os.path.isdir(p):
            for root, _dirs, names in os.walk(p):
                files += [os.path.join(root, n) for n in names
                          if n.lower().endswith(CERT_EXTS)]
        elif os.path.isfile(p):
            files.append(p)
        else:
            print(f"  !! 路径不存在，跳过: {p}", file=sys.stderr)
    return sorted(set(files))


def to_der(raw):
    """PEM / DER 字节 → DER"""
    if raw.lstrip()[:1] == b"-":                        # PEM
        return x509.load_pem_x509_certificate(raw).public_bytes(
            serialization.Encoding.DER)
    return raw


# ---------------------------------------------------------------------------
def run(args):
    out_dir = os.path.abspath(args.out_dir) if args.out_dir else None
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    non_gm_dir = os.path.abspath(args.out_dir_non_gm) if args.out_dir_non_gm else None
    if non_gm_dir:
        os.makedirs(non_gm_dir, exist_ok=True)

    # ---- 收集待判定的证书： (idx, 显示名, DER) ----
    gm_rows, index_rows = [], []
    gm_der, non_gm_der = [], []
    total = 0
    fail = 0
    sig_stat, curve_stat = {}, {}

    def handle(idx, name, der):
        nonlocal total, fail
        total += 1
        try:
            info = audit(der)
        except Exception as e:                          # noqa: BLE001
            fail += 1
            index_rows.append({"idx": idx, "file": name, "is_gm": False,
                               "error": f"证书解析失败: {e}"})
            print(f"  !! 解析失败: {name} -> {e}", file=sys.stderr)
            return
        curve_stat[info["curve_oid"] or "(无/非EC)"] = \
            curve_stat.get(info["curve_oid"] or "(无/非EC)", 0) + 1
        sig_stat[info["sig_oid"]] = sig_stat.get(info["sig_oid"], 0) + 1
        row = {"idx": idx, "file": name, **{k: info[k] for k in (
            "is_gm", "curve_oid", "curve_name", "sig_oid", "sig_name",
            "serial_hex", "sha256", "subject", "pk_error", "error")}}
        index_rows.append(row)
        if info["is_gm"]:
            gm_rows.append(idx)
            gm_der.append((idx, name, info["serial_hex"], der))
        else:
            non_gm_der.append((idx, name, info["serial_hex"], der))
        if total % 500 == 0:
            print(f"  ... 已扫描 {total}", file=sys.stderr)

    if args.from_jsonl:
        src = os.path.abspath(args.inputs[0])
        for idx, b64, _nb in iter_jsonl_records(src, None):
            try:
                handle(idx, f"idx{idx}", base64.b64decode(b64, validate=True))
            except Exception as e:                      # noqa: BLE001
                fail += 1
                print(f"  !! base64 解码失败 idx={idx}: {e}", file=sys.stderr)
    else:
        for i, path in enumerate(iter_cert_files(args.inputs), 1):
            with open(path, "rb") as f:
                raw = f.read()
            try:
                handle(i, os.path.basename(path), to_der(raw))
            except Exception as e:                      # noqa: BLE001
                fail += 1
                print(f"  !! PEM/DER 解析失败: {path} -> {e}", file=sys.stderr)

    # ---- 输出 ----
    if args.jsonl:
        with open(args.jsonl, "w", encoding="utf-8") as f:
            for idx, _name, _sn, der in gm_der:
                f.write(json.dumps(
                    {"idx": idx, "cert_b64": base64.b64encode(der).decode("ascii")},
                    ensure_ascii=False) + "\n")
    if args.files:
        with open(args.files, "w", encoding="utf-8") as f:
            for _idx, name, _sn, _der in gm_der:
                f.write(name + "\n")
    if args.index:
        keys = ["idx", "file", "is_gm", "curve_oid", "curve_name", "sig_oid",
                "sig_name", "serial_hex", "sha256", "subject", "pk_error", "error"]
        with open(args.index, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore",
                               restval="")
            w.writeheader()
            w.writerows(index_rows)
    written = 0
    if out_dir:
        for idx, _name, serial_hex, der in gm_der:
            ext = "." + args.format
            path = unique_path(os.path.join(out_dir, f"{idx:05d}_{serial_hex}{ext}"))
            with open(path, "wb") as f:
                f.write(der if args.format == "der"
                        else to_pem(der).encode("ascii"))
            written += 1
    written_non = 0
    if non_gm_dir:
        for idx, _name, serial_hex, der in non_gm_der:
            ext = "." + args.format
            path = unique_path(
                os.path.join(non_gm_dir, f"{idx:05d}_{serial_hex}{ext}"))
            with open(path, "wb") as f:
                f.write(der if args.format == "der"
                        else to_pem(der).encode("ascii"))
            written_non += 1

    # ---- 统计 ----
    only_pk = sum(1 for r in index_rows
                  if r.get("is_gm") and r.get("sig_oid") not in GM_SIG_OIDS)
    only_sig = sum(1 for r in index_rows
                   if r.get("is_gm") and r.get("curve_oid") not in GM_CURVE_OIDS)
    print(f"\n扫描证书     : {total}（解析失败 {fail}）")
    print(f"国密证书     : {len(gm_rows)}"
          f"（仅公钥 SM2 {only_pk} / 仅签名 SM2-SM3 {only_sig}）")
    print(f"非国密证书   : {len(non_gm_der)}")
    print("签名算法分布 :")
    for oid, n in sorted(sig_stat.items(), key=lambda kv: -kv[1])[:6]:
        tag = f"  <- {GM_SIG_OIDS[oid]}" if oid in GM_SIG_OIDS else ""
        print(f"    {oid}: {n}{tag}")
    print("曲线 OID 分布:")
    for oid, n in sorted(curve_stat.items(), key=lambda kv: -kv[1])[:6]:
        tag = f"  <- {GM_CURVE_OIDS[oid]}" if oid in GM_CURVE_OIDS else ""
        print(f"    {oid}: {n}{tag}")
    if args.jsonl:
        print(f"JSONL        : {os.path.abspath(args.jsonl)}（{len(gm_rows)} 行）")
    if args.files:
        print(f"文件名清单   : {os.path.abspath(args.files)}（{len(gm_rows)} 行）")
    if args.index:
        print(f"对照表       : {os.path.abspath(args.index)}（{len(index_rows)} 行）")
    if out_dir:
        print(f"国密证书文件 : {written} 个 -> {out_dir}/（--format {args.format}）")
    if non_gm_dir:
        print(f"非国密证书文件: {written_non} 个 -> {non_gm_dir}/（--format {args.format}）")


def main():
    ap = argparse.ArgumentParser(
        description="从证书目录 / JSONL 仓库里筛出国密（SM2 / SM3）证书")
    ap.add_argument("inputs", nargs="+", help="证书目录或文件；配合 --from-jsonl 时为 JSONL")
    ap.add_argument("--from-jsonl", action="store_true", help="输入是 JSONL 仓库")
    ap.add_argument("--jsonl", help="输出国密子集 JSONL")
    ap.add_argument("--files", help="输出国密证书文件名清单")
    ap.add_argument("--index", help="输出对照表 csv")
    ap.add_argument("--out-dir", help="把国密证书导出成独立文件到该目录")
    ap.add_argument("--out-dir-non-gm", help="把非国密证书导出成独立文件到该目录")
    ap.add_argument("--format", choices=("der", "pem"), default="der",
                    help="--out-dir / --out-dir-non-gm 的文件格式（默认 der）")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
