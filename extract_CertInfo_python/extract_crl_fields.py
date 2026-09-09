#!/usr/bin/env python3
"""
extract_crl_fields.py —— CRL 吊销清单 + 全字段提取（对齐 extract_cert_fields.py）

一、吊销清单（默认行为，与旧版完全兼容）
    python3 extract_crl_fields.py <crl 文件|目录> ... [--csv 输出.csv] [--issuer 签发者证书]
    python3 extract_crl_fields.py crl.pem                     # 终端列出序列号（hex + dec）
    python3 extract_crl_fields.py crls/                       # 目录批量
    python3 extract_crl_fields.py crls/ --csv revoked.csv     # 汇总导出（含吊销时间/原因）

二、全字段提取（CRL 版 extract_cert_fields）
    python3 extract_crl_fields.py crl.pem --full              # 终端打印全部字段
    python3 extract_crl_fields.py crl.pem --json              # JSON 输出
    python3 extract_crl_fields.py crls/ --csv wide.csv --csv-mode wide
        → wide.csv           每个 CRL 一行：头部固定列 + 扩展按 OID 命名的列
        → wide_entries.csv   每条吊销记录一行：序列号 / 时间 / 原因 / 失效日期 / 条目扩展
    python3 extract_crl_fields.py                        # 无参数 → 交互模式
    wide.csv 只含吊销条数；逐条序列号与原因在 *_entries.csv
        （大 CA 的 CRL 可达数万条，合并进单元格会超出 Excel 的 32767 字符上限）
    宽表列数 = 25 个固定列 + 每种扩展 3 列（ext.<OID名>.present/.critical/.value_json）；
        加 --no-ext-columns 则只输出 25 个固定列，列数恒定便于跨批次比对
    --csv-mode 取值: revoked(默认) / wide / entries / fields
        revoked  每条吊销记录一行，精简 5 列（兼容旧版）
        entries  每条吊销记录一行，全字段（多出失效日期、条目扩展等）
        wide     每个 CRL 一行（头部 + 扩展列）+ 副表 <name>_entries.csv
        fields   每个字段一行（file,field,value），嵌套逐层摊平，字段零丢失

覆盖字段（RFC 5280 CRL 结构）:
  CRL 级: version(推断) / issuer(逐条属性) / thisUpdate / nextUpdate /
          signatureAlgorithm(OID+hash) / signature / tbsCertList(SHA-256) /
          指纹(SHA-256, SHA-1) / 全部扩展（CRLNumber / AKI / IDP /
          DeltaCRLIndicator / FreshestCRL / AIA / IAN / 未知扩展 hex 原文）
  条目级: serialNumber(hex+dec) / revocationDate / CRLReason /
          InvalidityDate / CertificateIssuer / 其它条目扩展
  验签  : --issuer <证书> 时给出 is_signature_valid 结果（CRL 自身不含公钥）

目录递归查找 .pem/.der/.crl；CSV 统一 UTF-8 with BOM（Excel 双击不乱码）。
依赖: python3 + cryptography
"""

import csv
import glob
import json
import os
import sys
from enum import Enum

from cryptography import x509
from cryptography.hazmat.primitives import hashes

CRL_EXTS = (".pem", ".der", ".crl")

# ---------------------------------------------------------------------------
# OID → 可读名映射（遍历 cryptography 自带的 OID 常量类）
# ---------------------------------------------------------------------------
_OID_NAMES = {}


def _build_oid_map():
    for cls in (
        x509.NameOID,
        x509.ExtensionOID,
        x509.SignatureAlgorithmOID,
        x509.AuthorityInformationAccessOID,
        # 条目级扩展 OID（CRLReason / InvalidityDate / CertificateIssuer）
        getattr(x509, "CRLEntryExtensionOID", None),
    ):
        if cls is None:
            continue
        for key, val in vars(cls).items():
            if isinstance(val, x509.ObjectIdentifier):
                _OID_NAMES.setdefault(val.dotted_string, f"{cls.__name__}.{key}")


def oid_name(oid):
    """返回 OID 可读名（如 'ExtensionOID.CRL_NUMBER'），无内置名则加点分串"""
    return _OID_NAMES.get(oid.dotted_string, f"(unknown) {oid.dotted_string}")


def short_oid(name):
    """'ExtensionOID.CRL_NUMBER' → 'CRL_NUMBER'；未知 OID 退回点分串"""
    if not isinstance(name, str):
        return str(name)
    if name.startswith("(unknown) "):
        return name[len("(unknown) "):].strip()
    return name.split(".")[-1]


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------
def jsonify(obj):
    """任意对象 → JSON 可序列化基础类型（兜底用）"""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, Enum):
        return obj.name
    if isinstance(obj, x509.ObjectIdentifier):
        return obj.dotted_string
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [jsonify(i) for i in obj]
    if isinstance(obj, dict):
        return {k: jsonify(v) for k, v in obj.items()}
    return str(obj)


def hex_colon(data, upper=False):
    s = data.hex().upper() if upper else data.hex()
    return ":".join(s[i:i + 2] for i in range(0, len(s), 2))


def gn_str(gn):
    """单个 GeneralName → 'URI: http://...' 这类可读串"""
    if isinstance(gn, x509.DNSName):
        return f"DNS: {gn.value}"
    if isinstance(gn, x509.IPAddress):
        return f"IP: {gn.value}"
    if isinstance(gn, x509.RFC822Name):
        return f"email: {gn.value}"
    if isinstance(gn, x509.UniformResourceIdentifier):
        return f"URI: {gn.value}"
    if isinstance(gn, x509.DirectoryName):
        return f"dirName: {gn.value.rfc4514_string()}"
    if isinstance(gn, x509.RegisteredID):
        return f"registeredID: {oid_name(gn.value)}"
    if isinstance(gn, x509.OtherName):
        return f"otherName: {oid_name(gn.type_id)} (hex: {gn.value.hex().upper()})"
    return str(gn)


def name_attrs(name):
    """Name → 逐条属性 [{'oid','dotted','value'}]"""
    return [{"oid": oid_name(a.oid), "dotted": a.oid.dotted_string,
             "value": a.value} for a in name]


def fmt_reasons(reasons):
    if reasons is None:
        return None
    return sorted(r.name for r in reasons)


def flatten(obj, prefix=""):
    """递归摊平嵌套结构 → [(字段路径, 值)]，值只保留标量"""
    rows = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            rows += flatten(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        if not obj:
            rows.append((prefix, ""))
        for i, v in enumerate(obj, 1):
            rows += flatten(v, f"{prefix}[{i}]")
    elif obj is None:
        rows.append((prefix, ""))
    else:
        rows.append((prefix, obj))
    return rows


# ---------------------------------------------------------------------------
# CRL 扩展格式化（value 为 cryptography 解析后的类型化对象）
# ---------------------------------------------------------------------------
def _fmt_distribution_point(v):
    return {
        "full_name": [gn_str(g) for g in v.full_name] if v.full_name else None,
        "relative_name": (v.relative_name.rfc4514_string()
                          if v.relative_name else None),
        "reasons": fmt_reasons(v.reasons),
        "crl_issuer": [gn_str(g) for g in v.crl_issuer] if v.crl_issuer else None,
    }


def _fmt_crl_number(v):
    return {"crl_number": v.crl_number}


def _fmt_delta(v):
    return {"crl_number": v.crl_number}


def _fmt_aki(v):
    return {
        "key_identifier": (hex_colon(v.key_identifier, upper=True)
                           if v.key_identifier else None),
        "authority_cert_issuer": ([gn_str(g) for g in v.authority_cert_issuer]
                                  if v.authority_cert_issuer else None),
        "authority_cert_serial_number": (
            {"dec": str(v.authority_cert_serial_number),
             "hex": "0x%x" % v.authority_cert_serial_number}
            if v.authority_cert_serial_number is not None else None),
    }


def _fmt_idp(v):
    return {
        "full_name": [gn_str(g) for g in v.full_name] if v.full_name else None,
        "relative_name": (v.relative_name.rfc4514_string()
                          if v.relative_name else None),
        "only_contains_user_certs": v.only_contains_user_certs,
        "only_contains_ca_certs": v.only_contains_ca_certs,
        "only_some_reasons": fmt_reasons(v.only_some_reasons),
        "indirect_crl": v.indirect_crl,
        "only_contains_attribute_certs": v.only_contains_attribute_certs,
    }


def _fmt_freshest(v):
    return {"distribution_points": [_fmt_distribution_point(dp) for dp in v]}


def _fmt_aia(v):
    return {"access_descriptions": [
        {"method": oid_name(d.access_method),
         "dotted": d.access_method.dotted_string,
         "location": gn_str(d.access_location)} for d in v]}


def _fmt_names(v):
    return {"names": [gn_str(n) for n in v]}


_EXT_FORMATTERS = {
    x509.CRLNumber: _fmt_crl_number,
    x509.DeltaCRLIndicator: _fmt_delta,
    x509.AuthorityKeyIdentifier: _fmt_aki,
    x509.IssuingDistributionPoint: _fmt_idp,
    x509.FreshestCRL: _fmt_freshest,
    x509.AuthorityInformationAccess: _fmt_aia,
    x509.IssuerAlternativeName: _fmt_names,
    x509.UnrecognizedExtension: lambda v: {
        "value_hex": hex_colon(v.value, upper=True)},
}


def fmt_extension(ext):
    """尽力把扩展解析成结构化 dict；失败保留原始表示"""
    try:
        fmt = _EXT_FORMATTERS.get(type(ext.value))
        if fmt is not None:
            return {"parsed": jsonify(fmt(ext.value))}
        return {"raw": jsonify(ext.value)}
    except Exception as e:                      # 单个扩展失败不拖垮整体
        raw = None
        try:
            raw = ext.value.public_bytes()
        except Exception:
            raw = None
        return {"parse_error": str(e),
                "raw_hex": hex_colon(raw, upper=True) if raw else repr(ext.value)}


def parse_extensions(crl):
    """CRL 全部扩展（按 OID 排序，保证输出稳定）"""
    try:
        items = sorted(crl.extensions, key=lambda e: e.oid.dotted_string)
    except Exception as e:
        return [{"parse_error": f"迭代 extensions 失败: {e}"}]
    return [{"name": oid_name(e.oid), "oid": e.oid.dotted_string,
             "critical": e.critical, **fmt_extension(e)} for e in items]


# ---------------------------------------------------------------------------
# 吊销条目（条目级扩展: CRLReason / InvalidityDate / CertificateIssuer）
# ---------------------------------------------------------------------------
def _fmt_reason(v):
    return {"reason": v.reason.name}


def _fmt_invalidity_date(v):
    return {"invalidity_date": v.invalidity_date.isoformat()}


def _fmt_cert_issuer(v):
    return {"names": [gn_str(n) for n in v]}


_ENTRY_FORMATTERS = {
    x509.CRLReason: _fmt_reason,
    x509.InvalidityDate: _fmt_invalidity_date,
    x509.CertificateIssuer: _fmt_cert_issuer,
    x509.UnrecognizedExtension: lambda v: {
        "value_hex": hex_colon(v.value, upper=True)},
}


def _entry_ext_value(ext):
    try:
        fmt = _ENTRY_FORMATTERS.get(type(ext.value))
        if fmt is not None:
            return jsonify(fmt(ext.value))
        return jsonify(ext.value)
    except Exception as e:
        return {"parse_error": str(e)}


def parse_entry(rc):
    """单条吊销记录 → 全字段 dict"""
    date = getattr(rc, "revocation_date_utc", None) or rc.revocation_date
    exts = []
    try:
        for e in sorted(rc.extensions, key=lambda x: x.oid.dotted_string):
            exts.append({"name": oid_name(e.oid), "oid": e.oid.dotted_string,
                         "critical": e.critical, "value": _entry_ext_value(e)})
    except Exception as e:
        exts.append({"parse_error": f"迭代条目扩展失败: {e}"})

    def value_of(cls, key):
        for e in exts:
            v = e.get("value")
            if isinstance(v, dict) and key in v:
                return v[key]
        return None

    return {
        "serial_dec": str(rc.serial_number),
        "serial_hex": "0x%x" % rc.serial_number,
        "revoked_at": date.isoformat() if hasattr(date, "isoformat") else str(date),
        "reason": value_of(x509.CRLReason, "reason"),
        "invalidity_date": value_of(x509.InvalidityDate, "invalidity_date"),
        "certificate_issuer": value_of(x509.CertificateIssuer, "names"),
        "extensions": exts,
    }


# ---------------------------------------------------------------------------
# 主解析：CRL → 全字段 dict
# ---------------------------------------------------------------------------
def parse_crl(crl, path, fmt, issuer_pub=None):
    sig_hash = None
    try:
        if crl.signature_hash_algorithm is not None:
            sig_hash = crl.signature_hash_algorithm.name
    except Exception:
        sig_hash = None

    # cryptography 未暴露 CRL version；RFC 5280: 有扩展即 v2
    exts = parse_extensions(crl)
    version_label = "v2" if exts and "parse_error" not in exts[0] else "v1"

    def fp(alg):
        try:
            return hex_colon(crl.fingerprint(alg), upper=True)
        except Exception:
            return None

    entries = [parse_entry(rc) for rc in crl]
    sig_valid = None
    if issuer_pub is not None:
        try:
            sig_valid = bool(crl.is_signature_valid(issuer_pub))
        except Exception as e:
            sig_valid = f"验签异常: {e}"

    return {
        "file": os.path.basename(path),
        "path": path,
        "format": fmt,
        "version": {"label": version_label, "note": "推断：有扩展即 v2"},
        "issuer": {"rfc4514": crl.issuer.rfc4514_string(),
                   "attributes": name_attrs(crl.issuer)},
        "this_update": _iso(crl.last_update_utc),
        "next_update": _iso(crl.next_update_utc),
        "signature_algorithm": {
            "name": oid_name(crl.signature_algorithm_oid),
            "oid": crl.signature_algorithm_oid.dotted_string,
            "hash_algorithm": sig_hash,
        },
        "signature": {"length": len(crl.signature),
                      "hex": hex_colon(crl.signature, upper=True)},
        "tbs_certlist": {"length": len(crl.tbs_certlist_bytes),
                         "sha256": _sha256(crl.tbs_certlist_bytes)},
        "fingerprints": {"sha256": fp(hashes.SHA256()), "sha1": fp(hashes.SHA1())},
        "revoked_count": len(entries),
        "signature_valid": sig_valid,
        "extensions": exts,
        "entries": entries,
    }


def _iso(dt):
    return dt.isoformat() if hasattr(dt, "isoformat") else str(dt)


def _sha256(data):
    from cryptography.hazmat.primitives import hashes as _h
    d = _h.Hash(_h.SHA256())
    d.update(data)
    return hex_colon(d.finalize(), upper=True)


# ---------------------------------------------------------------------------
# 加载
# ---------------------------------------------------------------------------
def load_crl(path):
    """加载 CRL，PEM / DER 自动识别。返回 (crl, format)"""
    with open(path, "rb") as f:
        raw = f.read()
    try:
        return x509.load_pem_x509_crl(raw), "PEM"
    except Exception:
        return x509.load_der_x509_crl(raw), "DER"


def iter_entries(crl):
    """迭代吊销条目 → (hex_serial, dec_serial, revoke_date, reason)
    （兼容旧接口，供外部调用）"""
    for rc in crl:
        date = getattr(rc, "revocation_date_utc", None) or rc.revocation_date
        reason = None
        try:
            reason = rc.extensions.get_extension_for_class(
                x509.CRLReason).value.reason.name
        except Exception:
            pass
        yield (f"{rc.serial_number:#x}", str(rc.serial_number), str(date),
               reason or "")


# ---------------------------------------------------------------------------
# 文本输出
# ---------------------------------------------------------------------------
def print_full(parsed, stream=None):
    out = stream if stream is not None else sys.stdout
    p = lambda *a, **k: print(*a, file=out, **k)          # noqa: E731

    p(f"文件: {parsed['path']}  ({parsed['format']})")
    p(f"版本 (version): {parsed['version']['label']}（{parsed['version']['note']}）")
    p(f"签发者 (issuer): {parsed['issuer']['rfc4514']}")
    for a in parsed["issuer"]["attributes"]:
        p(f"    - {a['oid']} [{a['dotted']}]: {a['value']}")
    p(f"thisUpdate: {parsed['this_update']}")
    p(f"nextUpdate: {parsed['next_update']}")

    sa = parsed["signature_algorithm"]
    p(f"签名算法 (signatureAlgorithm): {sa['name']} [{sa['oid']}]"
      + (f", hash={sa['hash_algorithm']}" if sa["hash_algorithm"] else ""))
    sig = parsed["signature"]
    p(f"签名值 (signature): {sig['length']} 字节")
    p(f"    hex: {sig['hex'][:96]}{'…' if len(sig['hex']) > 96 else ''}")
    p(f"tbsCertList: {parsed['tbs_certlist']['length']} 字节, "
      f"SHA-256={parsed['tbs_certlist']['sha256']}")
    fpp = parsed["fingerprints"]
    if fpp["sha256"]:
        p(f"指纹 SHA-256: {fpp['sha256']}")
    if fpp["sha1"]:
        p(f"指纹 SHA-1  : {fpp['sha1']}")
    if parsed["signature_valid"] is not None:
        p(f"验签结果: {parsed['signature_valid']}")

    p(f"扩展 (extensions): 共 {len(parsed['extensions'])} 个")
    for i, e in enumerate(parsed["extensions"], 1):
        crit = "critical" if e.get("critical") else "non-critical"
        p(f"  [{i}] {e.get('name')} [{e.get('oid')}] ({crit})")
        if "parsed" in e:
            for line in json.dumps(e["parsed"], indent=6,
                                   ensure_ascii=False).splitlines():
                p(line)
        elif "raw" in e:
            p(f"      raw: {e['raw']}")
        elif "parse_error" in e:
            p(f"      !! 解析失败: {e['parse_error']}")

    p(f"吊销条目 (revokedCertificates): 共 {parsed['revoked_count']} 条")
    for i, en in enumerate(parsed["entries"], 1):
        p(f"  [{i}] serial={en['serial_hex']} ({en['serial_dec']})")
        p(f"      revocationDate : {en['revoked_at']}")
        p(f"      reason         : {en['reason'] or '(无)'}")
        if en["invalidity_date"]:
            p(f"      invalidityDate : {en['invalidity_date']}")
        if en["certificate_issuer"]:
            p(f"      certificateIssuer: {en['certificate_issuer']}")
        other = [e for e in en["extensions"]
                 if e.get("name", "").endswith(
                     ("CRL_REASON", "INVALIDITY_DATE", "CERTIFICATE_ISSUER"))]
        if len(en["extensions"]) > len(other):
            p(f"      其它条目扩展: {json.dumps(en['extensions'], ensure_ascii=False, default=jsonify)}")


def print_brief(crl, path):
    """旧版终端输出：头部 4 行 + 序列号两列"""
    print(f"# {path}")
    print(f"# issuer = {crl.issuer.rfc4514_string()}")
    print(f"# this_update = {crl.last_update_utc}   next_update = {crl.next_update_utc}")
    print(f"# 吊销条目数 = {len(crl)}")


# ---------------------------------------------------------------------------
# CSV 输出
# ---------------------------------------------------------------------------
def _ext_value_of(parsed, oid_suffix):
    """按 OID 名后缀取扩展的 parsed dict"""
    for e in parsed["extensions"]:
        if short_oid(e.get("name", "")).upper() == oid_suffix:
            return e.get("parsed") or {}
    return {}


def _attr_value(parsed, suffix):
    """从已解析的 issuer 逐条属性里取值（如 COMMON_NAME / ORGANIZATION_NAME）"""
    for a in parsed["issuer"]["attributes"]:
        if a.get("oid", "").endswith(suffix):
            return a.get("value", "")
    return ""


def wide_row(parsed, include_ext=True):
    """单个 CRL → 宽表一行（固定列 + ext.* 动态列）

    include_ext=False 时只输出固定列（--no-ext-columns），列数恒定，
    适合跨批次比对；扩展明细仍可用 --full / --json / fields 模式查看。"""
    exts = parsed["extensions"]
    row = {
        "file": parsed["file"],
        "format": parsed["format"],
        "version": parsed["version"]["label"],
        "issuer": parsed["issuer"]["rfc4514"],
        # 逐条属性拆列（与 extract_cert_fields.py 的 subject_cn/issuer_o 对齐）：
        # 直接迭代 Name 对象取值，不用字符串 split（DN 值里的逗号会被 RFC4514 转义）
        "issuer_cn": _attr_value(parsed, "COMMON_NAME"),
        "issuer_o": _attr_value(parsed, "ORGANIZATION_NAME"),
        "issuer_ou": _attr_value(parsed, "ORGANIZATIONAL_UNIT_NAME"),
        "issuer_c": _attr_value(parsed, "COUNTRY_NAME"),
        "this_update": parsed["this_update"],
        "next_update": parsed["next_update"],
        "sig_alg": parsed["signature_algorithm"]["name"],
        "sig_oid": parsed["signature_algorithm"]["oid"],
        "sig_hash": parsed["signature_algorithm"]["hash_algorithm"] or "",
        "signature_valid": "" if parsed["signature_valid"] is None
                           else parsed["signature_valid"],
        "sha256": parsed["fingerprints"]["sha256"] or "",
        "sha1": parsed["fingerprints"]["sha1"] or "",
        "tbs_sha256": parsed["tbs_certlist"]["sha256"],
        "crl_number": _ext_value_of(parsed, "CRL_NUMBER").get("crl_number", ""),
        "delta_crl_indicator": _ext_value_of(
            parsed, "DELTA_CRL_INDICATOR").get("crl_number", ""),
        "aki_keyid": _ext_value_of(
            parsed, "AUTHORITY_KEY_IDENTIFIER").get("key_identifier", ""),
        "idp_indirect": _ext_value_of(
            parsed, "ISSUING_DISTRIBUTION_POINT").get("indirect_crl", ""),
        "idp_only_ca": _ext_value_of(
            parsed, "ISSUING_DISTRIBUTION_POINT").get("only_contains_ca_certs", ""),
        "idp_only_user": _ext_value_of(
            parsed, "ISSUING_DISTRIBUTION_POINT").get("only_contains_user_certs", ""),
        "revoked_count": parsed["revoked_count"],
        # 宽表只放吊销条数；逐条序列号与原因一律看 *_entries.csv
        # （大 CA 的 CRL 可达数万条，合并进单元格会超出 Excel 的 32767 字符上限）
        "ext_count": len(exts),
    }
    if include_ext:
        for e in exts:
            base = f"ext.{short_oid(e.get('name', ''))}"
            row[f"{base}.present"] = 1
            row[f"{base}.critical"] = e.get("critical", "")
            value = e.get("parsed", e.get("raw", ""))
            row[f"{base}.value_json"] = json.dumps(
                value, ensure_ascii=False, default=jsonify)
    return row








def entry_rows(parsed, full=False):
    """单个 CRL 的吊销条目行（full=False 时兼容旧版 5 列）"""
    rows = []
    for en in parsed["entries"]:
        if full:
            rows.append({
                "file": parsed["file"],
                "issuer": parsed["issuer"]["rfc4514"],
                "issuer_cn": _attr_value(parsed, "COMMON_NAME"),
                "this_update": parsed["this_update"],
                "crl_number": _ext_value_of(parsed, "CRL_NUMBER").get("crl_number", ""),
                "serial_hex": en["serial_hex"],
                "serial_dec": en["serial_dec"],
                "revoked_at": en["revoked_at"],
                "reason": en["reason"] or "",
                "invalidity_date": en["invalidity_date"] or "",
                "certificate_issuer": "; ".join(en["certificate_issuer"] or []),
                "entry_ext_count": len(en["extensions"]),
                "entry_exts_json": json.dumps(en["extensions"], ensure_ascii=False,
                                              default=jsonify),
            })
        else:
            rows.append({
                "crl": parsed["file"],
                "serial_hex": en["serial_hex"],
                "serial_dec": en["serial_dec"],
                "revoked_at": en["revoked_at"],
                "reason": en["reason"] or "",
            })
    return rows


def write_csv(path, rows, fieldnames):
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore",
                           restval="")
        w.writeheader()
        w.writerows(rows)


def _sibling_path(path, suffix):
    root, ext = os.path.splitext(path)
    return root + suffix + (ext or ".csv")


WIDE_BASE_FIELDS = [
    "file", "format", "version", "issuer",
    "issuer_cn", "issuer_o", "issuer_ou", "issuer_c",
    "this_update", "next_update",
    "sig_alg", "sig_oid", "sig_hash", "signature_valid",
    "sha256", "sha1", "tbs_sha256",
    "crl_number", "delta_crl_indicator", "aki_keyid",
    "idp_indirect", "idp_only_ca", "idp_only_user",
    "revoked_count", "ext_count",
]
ENTRY_FULL_FIELDS = [
    "file", "issuer", "issuer_cn", "this_update", "crl_number",
    "serial_hex", "serial_dec", "revoked_at", "reason",
    "invalidity_date", "certificate_issuer", "entry_ext_count", "entry_exts_json",
]
ENTRY_BRIEF_FIELDS = ["crl", "serial_hex", "serial_dec", "revoked_at", "reason"]


# ---------------------------------------------------------------------------
# 批量 / 单文件分发
# ---------------------------------------------------------------------------
def expand_inputs(paths, exclude=()):
    """展开输入：目录递归查 .pem/.der/.crl，文件直接收录；排序去重。
    exclude 里的绝对路径会被排除（避免把本次输出文件当输入）。"""
    files = []
    for p in paths:
        p = os.path.expanduser(p)
        if os.path.isdir(p):
            files += [f for f in glob.glob(os.path.join(p, "**", "*"), recursive=True)
                      if os.path.isfile(f) and f.lower().endswith(CRL_EXTS)]
        elif os.path.isfile(p):
            files.append(p)
        else:
            print(f"  !! 路径不存在，跳过: {p}", file=sys.stderr)
    skip = {os.path.abspath(os.path.expanduser(x)) for x in exclude if x}
    return sorted({f for f in files if os.path.abspath(f) not in skip})


def load_issuer_pub(path):
    """加载签发者证书公钥（用于 CRL 验签）"""
    from cryptography.hazmat.primitives.serialization import Encoding
    with open(os.path.expanduser(path), "rb") as f:
        raw = f.read()
    try:
        cert = x509.load_pem_x509_certificate(raw)
    except Exception:
        cert = x509.load_der_x509_certificate(raw)
    return cert.public_key()


def run_batch(paths, csv_file=None, csv_mode="revoked", issuer_pub=None,
              as_json=False, full=False, no_ext=False):
    """解析并输出。csv_mode: revoked / entries / wide / fields"""
    files = expand_inputs(paths, exclude=[csv_file] if csv_file else [])
    if not files:
        print(f"错误: 未找到任何 CRL 文件（支持 {'/'.join(CRL_EXTS)}）",
              file=sys.stderr)
        sys.exit(1)
    if csv_mode not in ("revoked", "entries", "wide", "fields"):
        print(f"错误: --csv-mode 只能是 revoked/entries/wide/fields，收到 {csv_mode!r}",
              file=sys.stderr)
        sys.exit(1)

    parsed_list, ok, fail = [], 0, 0
    for fp in files:
        try:
            crl, fmt = load_crl(fp)
            parsed_list.append(parse_crl(crl, fp, fmt, issuer_pub))
            ok += 1
        except Exception as e:
            fail += 1
            print(f"[跳过] {fp}: {e}", file=sys.stderr)

    tail = f"成功 {ok} 个" + (f"，失败 {fail} 个" if fail else "")

    # 单文件且不要 CSV：终端输出（全字段 / 摘要）
    if not csv_file and len(parsed_list) == 1:
        parsed = parsed_list[0]
        if as_json:
            print(json.dumps(parsed, indent=2, ensure_ascii=False, default=jsonify))
        elif full:
            print_full(parsed)
        else:
            crl, _fmt = load_crl(files[0])
            print_brief(crl, files[0])
            for en in parsed["entries"]:
                print(f"{en['serial_hex']}\t{en['serial_dec']}")
        return

    if as_json and not csv_file:           # 多文件 JSON
        print(json.dumps(parsed_list, indent=2, ensure_ascii=False, default=jsonify))
        return

    if full and not csv_file:              # 多文件全字段（目录 --full 原先会静默跳过）
        for p in parsed_list:
            print_full(p)
            print()
        return

    if csv_mode == "wide":
        rows = [wide_row(p, include_ext=not no_ext) for p in parsed_list]
        ext_cols = sorted({k for r in rows for k in r if k.startswith("ext.")})
        write_csv(csv_file, rows, WIDE_BASE_FIELDS + ext_cols)
        ent = [r for p in parsed_list for r in entry_rows(p, full=True)]
        ent_path = _sibling_path(csv_file, "_entries")
        write_csv(ent_path, ent, ENTRY_FULL_FIELDS)
        print(f"已写入: {csv_file}（CRL 宽表，{tail}，{len(rows)} 行 × "
              f"{len(WIDE_BASE_FIELDS) + len(ext_cols)} 列）", file=sys.stderr)
        print(f"已写入: {ent_path}（吊销条目全字段，{len(ent)} 行）", file=sys.stderr)
    elif csv_mode == "fields":
        rows = []
        for p in parsed_list:
            for field, value in flatten(p):
                rows.append({"file": p["file"], "field": field, "value": value})
        write_csv(csv_file, rows, ["file", "field", "value"])
        print(f"已写入: {csv_file}（模式 fields，{tail}，共 {len(rows)} 行）",
              file=sys.stderr)
    else:                       # revoked（默认，兼容旧版） / entries
        full_entries = csv_mode == "entries"
        rows = [r for p in parsed_list for r in entry_rows(p, full=full_entries)]
        fields = ENTRY_FULL_FIELDS if full_entries else ENTRY_BRIEF_FIELDS
        write_csv(csv_file, rows, fields)
        print(f"已写入: {csv_file}（模式 {csv_mode}，{tail}，共 {len(rows)} 行）",
              file=sys.stderr)

    # 多文件且未指定 CSV 模式时，终端也给一份简要清单（保持旧观感）
    if not csv_file:
        for p in parsed_list:
            print(f"# {p['path']}")
            print(f"# issuer = {p['issuer']['rfc4514']}")
            print(f"# this_update = {p['this_update']}   next_update = {p['next_update']}")
            print(f"# 吊销条目数 = {p['revoked_count']}")
            for en in p["entries"]:
                print(f"{en['serial_hex']}\t{en['serial_dec']}")
        print(f"\n共 {sum(p['revoked_count'] for p in parsed_list)} 个吊销序列号")


def interactive():
    """无参数时的交互式输入：路径必填，其余回车用默认值（q 退出）"""
    print("=== 交互模式（直接回车使用默认值，输入 q 退出）===")

    target = os.path.expanduser(input("CRL 文件或目录: ").strip())
    while True:
        if target.lower() in ("q", "quit"):
            sys.exit(0)
        if os.path.exists(target):
            break
        print(f"  !! 路径不存在: {target}")
        target = os.path.expanduser(input("请重新输入 CRL 文件或目录 (q 退出): ").strip())

    way = input("输出方式 (回车=终端清单 / full / json / csv): ").strip().lower()
    if way in ("q", "quit"):
        sys.exit(0)

    csv_file, csv_mode, no_ext = None, "revoked", False
    if way == "csv":
        csv_file = os.path.expanduser(input("CSV 输出文件: ").strip())
        if csv_file.lower() in ("q", "quit"):
            sys.exit(0)
        if not csv_file:
            print("  !! 未给输出文件，改为终端清单输出")
            csv_file = None
        else:
            m = input("CSV 模式 (revoked/entries/wide/fields，回车=revoked): ").strip().lower()
            if m in ("q", "quit"):
                sys.exit(0)
            if m and m not in ("revoked", "entries", "wide", "fields"):
                print(f"  !! '{m}' 无效，按 revoked 处理")
                m = ""
            csv_mode = m or "revoked"
            if csv_mode == "wide":
                no_ext = input("只输出固定列 --no-ext-columns (y/N): ").strip().lower() \
                    in ("y", "yes")

    issuer_path = os.path.expanduser(input("签发者证书路径（验签用，回车跳过）: ").strip())
    if issuer_path.lower() in ("q", "quit"):
        sys.exit(0)

    issuer_pub = load_issuer_pub(issuer_path) if issuer_path else None
    run_batch([target], csv_file, csv_mode, issuer_pub,
              as_json=(way == "json"), full=(way == "full"), no_ext=no_ext)


def _opt_value(args, flag):
    """取 `--flag 值`；无 flag 返回 None，缺值返回 ''"""
    if flag not in args:
        return None
    i = args.index(flag)
    if i + 1 < len(args) and not args[i + 1].startswith("--"):
        return args[i + 1]
    return ""


def main():
    args = sys.argv[1:]
    if not args:                    # 无参数 → 交互模式
        interactive()
        return
    if "-h" in args or "--help" in args:
        print(__doc__)
        return

    csv_file = _opt_value(args, "--csv")
    csv_mode = _opt_value(args, "--csv-mode") or "revoked"
    issuer_path = _opt_value(args, "--issuer")
    as_json = "--json" in args
    full = "--full" in args
    no_ext = "--no-ext-columns" in args

    consumed = {csv_file, csv_mode, issuer_path, None}
    paths = [a for a in args if not a.startswith("--") and a not in consumed]
    if not paths:
        print(__doc__)
        sys.exit(1)
    if csv_file == "":
        print("错误: --csv 需要输出文件名", file=sys.stderr)
        sys.exit(1)

    issuer_pub = load_issuer_pub(issuer_path) if issuer_path else None
    run_batch(paths, csv_file, csv_mode, issuer_pub, as_json, full, no_ext)


# 模块级执行：import 后直接调用 parse_crl() 也能得到可读 OID 名
_build_oid_map()


if __name__ == "__main__":
    main()
