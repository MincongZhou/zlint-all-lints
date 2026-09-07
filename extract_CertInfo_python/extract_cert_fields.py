#!/usr/bin/env python3
"""
extract_cert_fields.py —— 用 cryptography 解析 X.509 证书的所有字段

覆盖范围（对应 RFC 5280 证书结构）:
  1. 基础字段: version / serialNumber / signatureAlgorithm / issuer / validity
     (notBefore, notAfter) / subject / subjectPublicKeyInfo / signature
  2. subject 与 issuer 的逐条 Name 属性（OID + 值）
  3. 公钥: 算法类型 / 位数 / 参数（RSA 模数指数、ECC 曲线、DSA p/q/g、EdDSA）
  4. 全部扩展: 逐项解析每个扩展的 OID、critical 标志与结构化值
     （BasicConstraints / KeyUsage / EKU / SAN / IAN / SKI / AKI / AIA / CDP /
      CertificatePolicies / PolicyConstraints / InhibitAnyPolicy /
      NameConstraints / TLSFeature / OCSPNoCheck / PrecertPoison / SCT /
      MSCertificateTemplate / FreshestCRL / IssuingDistributionPoint /
      未知扩展以 hex 原文展示等）
  5. 指纹: SHA-256（另有 SHA-1，供对照）

依赖: cryptography（pip install cryptography）；SCT 解析需 >= 42.0。

用法:
    python3 extract_cert_fields.py <证书路径> [--der] [--json] [--out 输出文件]
    python3 extract_cert_fields.py <证书路径> --json    # 输出结构化 JSON
    python3 extract_cert_fields.py                       # 无参数 → 交互模式

CSV 输出（--csv）:
    # 单证书 → 字段清单表（field,value 两列，嵌套结构逐层摊平，不丢字段）
    python3 extract_cert_fields.py certs/baidu.pem --csv baidu_fields.csv

    # 目录/多证书 → 汇总表（每张证书一行，常用字段成列，便于横向对比）
    python3 extract_cert_fields.py certs/ --csv certs_summary.csv
    python3 extract_cert_fields.py a.pem b.pem --csv summary.csv

    # 显式指定模式：fields（字段清单）/ summary（一行一证书）
    python3 extract_cert_fields.py certs/ --csv all_fields.csv --csv-mode fields
    python3 extract_cert_fields.py a.pem --csv one_row.csv --csv-mode summary

模式自动选择规则：单个证书 → fields；目录或多个证书 → summary，
显式 --csv-mode 优先。fields 模式下 CSV 为三列 file,field,value（每行一个字段）。
目录递归查找 .pem/.crt/.cer/.der；非证书文件（如 CRL）自动跳过并告警。
CSV 统一 UTF-8 with BOM（Excel 双击直接打开不乱码）。

未指定 --der 时默认按 PEM 解析，失败自动回退 DER。
"""

import csv
import datetime
import io
import json
import os
import sys
import uuid
from enum import Enum

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    rsa,
)

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
        x509.ExtendedKeyUsageOID,
        getattr(x509, "SubjectInformationAccessOID", None),
        getattr(x509, "CertificatePoliciesOID", None),
    ):
        if cls is None:
            continue
        for key, val in vars(cls).items():
            if isinstance(val, x509.ObjectIdentifier):
                _OID_NAMES.setdefault(val.dotted_string, f"{cls.__name__}.{key}")


def oid_name(oid):
    """返回 OID 的可读名（如 'NameOID.COMMON_NAME'），无内置名则带 (unknown) 前缀"""
    return _OID_NAMES.get(oid.dotted_string, f"(unknown) {oid.dotted_string}")


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
def jsonify(obj):
    """把任意对象转成 JSON 可序列化的基础类型（兜底用）"""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.name
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if isinstance(obj, x509.ObjectIdentifier):
        return obj.dotted_string
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [jsonify(i) for i in obj]
    if isinstance(obj, dict):
        return {k: jsonify(v) for k, v in obj.items()}
    return str(obj)


def hex_colon(data, upper=False):
    """字节串 → 冒号分隔 hex（指纹样式）"""
    s = data.hex().upper() if upper else data.hex()
    return ":".join(s[i:i + 2] for i in range(0, len(s), 2))


def gn_str(gn):
    """把单个 GeneralName 序列化为 'DNS: baidu.com' 这类可读字符串"""
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
        return (f"otherName: {oid_name(gn.type_id)} "
                f"(hex: {gn.value.hex().upper()})")
    if isinstance(gn, x509.GUID):
        return f"GUID: {gn.value}"
    return str(gn)


def name_attrs(name):
    """把 Name 拆成逐条属性（OID / dotted / 值），供全字段展示"""
    out = []
    for attr in name:
        out.append({
            "oid": oid_name(attr.oid),
            "dotted": attr.oid.dotted_string,
            "value": attr.value,
        })
    return out


def gn_list(items):
    """GeneralName 列表 → 字符串列表（items 可能为 None）"""
    if items is None:
        return None
    return [gn_str(g) for g in items]


def fmt_reasons(reasons):
    """frozenset[ReasonFlags] → 名字列表；None 保持 None"""
    if reasons is None:
        return None
    return sorted(r.name for r in reasons)


# ---------------------------------------------------------------------------
# 各扩展的结构化解析（value 为 cryptography 解析后的类型化对象）
# ---------------------------------------------------------------------------
def _fmt_basic_constraints(v):
    return {"ca": bool(v.ca), "path_length": v.path_length}


def _fmt_key_usage(v):
    out = {}
    for flag in ("digital_signature", "content_commitment", "key_encipherment",
                 "data_encipherment", "key_agreement", "key_cert_sign",
                 "crl_sign", "encipher_only", "decipher_only"):
        try:
            out[flag] = bool(getattr(v, flag))
        except ValueError:
            # RFC 5280: keyAgreement=false 时 encipherOnly/decipherOnly 位无意义
            out[flag] = None
    return out


def _fmt_ext_key_usage(v):
    return {"usages": [oid_name(u) for u in list(v)]}


def _fmt_names(v):
    return {"names": [gn_str(n) for n in v]}


def _fmt_ski(v):
    return {"key_identifier": hex_colon(v.digest, upper=True)}


def _fmt_aki(v):
    return {
        "key_identifier": (hex_colon(v.key_identifier, upper=True)
                           if v.key_identifier else None),
        "authority_cert_issuer": gn_list(v.authority_cert_issuer),
        "authority_cert_serial_number": (
            {"dec": str(v.authority_cert_serial_number),
             "hex": "0x%x" % v.authority_cert_serial_number}
            if v.authority_cert_serial_number is not None else None),
    }


def _fmt_distribution_point(v):
    """DistributionPoint（CDP / FreshestCRL 共用）"""
    return {
        "full_name": gn_list(v.full_name),
        "relative_name": (v.relative_name.rfc4514_string()
                          if v.relative_name else None),
        "reasons": fmt_reasons(v.reasons),
        "crl_issuer": gn_list(v.crl_issuer),
        "only_has_same_issuer": getattr(v, "only_has_same_issuer", None),
    }


def _fmt_crl_dp(v):
    return {"distribution_points": [_fmt_distribution_point(dp) for dp in v]}


def _fmt_aia(v):
    out = []
    for desc in v:
        out.append({
            "method": oid_name(desc.access_method),
            "dotted": desc.access_method.dotted_string,
            "location": gn_str(desc.access_location),
        })
    return {"access_descriptions": out}


def _fmt_policy_qualifier(q):
    if q is None:
        return None
    if isinstance(q, x509.UserNotice):
        ref = q.notice_reference
        return {
            "type": "UserNotice",
            "notice_reference": (
                {"organization": ref.organization,
                 "notice_numbers": list(ref.notice_numbers)}
                if ref else None),
            "explicit_text": q.explicit_text,
        }
    return {"type": "CPS/URI", "value": str(q)}


def _fmt_policies(v):
    out = []
    for p in v:
        out.append({
            "policy_identifier": oid_name(p.policy_identifier),
            "dotted": p.policy_identifier.dotted_string,
            "qualifiers": [jsonify(_fmt_policy_qualifier(q))
                           for q in (p.policy_qualifiers or [])],
        })
    return {"policies": out}


def _fmt_policy_constraints(v):
    return {
        "require_explicit_policy": v.require_explicit_policy,
        "inhibit_policy_mapping": v.inhibit_policy_mapping,
    }


def _fmt_name_constraints(v):
    def subtrees(items):
        if items is None:
            return None
        return [gn_str(g) for g in items]

    return {
        "permitted_subtrees": subtrees(v.permitted_subtrees),
        "excluded_subtrees": subtrees(v.excluded_subtrees),
    }


def _fmt_tls_feature(v):
    return {"features": [f.name for f in v]}


def _fmt_sct_list(v):
    out = []
    for s in v:
        out.append({
            "version": s.version.name,
            "log_id": hex_colon(s.log_id, upper=True),
            "timestamp": s.timestamp.isoformat() + "+00:00",
            "hash_algorithm": s.signature_hash_algorithm.name,
            "signature_algorithm": s.signature_algorithm.name,
            "signature": hex_colon(s.signature, upper=True),
        })
    return {"scts": out}


def _fmt_ms_template(v):
    return {
        "template_id": oid_name(v.template_id),
        "dotted": v.template_id.dotted_string,
        "major_version": getattr(v, "major_version", None),
        "minor_version": getattr(v, "minor_version", None),
    }


def _fmt_issuing_dp(v):
    return {
        "full_name": gn_list(v.full_name),
        "relative_name": (v.relative_name.rfc4514_string()
                          if v.relative_name else None),
        "only_contains_user_certs": v.only_contains_user_certs,
        "only_contains_ca_certs": v.only_contains_ca_certs,
        "only_some_reasons": fmt_reasons(v.only_some_reasons),
        "indirect_crl": v.indirect_crl,
        "only_contains_attribute_certs": v.only_contains_attribute_certs,
    }


# 扩展类型 → 解析函数
_EXT_FORMATTERS = {
    x509.BasicConstraints: _fmt_basic_constraints,
    x509.KeyUsage: _fmt_key_usage,
    x509.ExtendedKeyUsage: _fmt_ext_key_usage,
    x509.SubjectAlternativeName: _fmt_names,
    x509.IssuerAlternativeName: _fmt_names,
    x509.SubjectKeyIdentifier: _fmt_ski,
    x509.AuthorityKeyIdentifier: _fmt_aki,
    x509.CRLDistributionPoints: _fmt_crl_dp,
    x509.FreshestCRL: _fmt_crl_dp,
    x509.AuthorityInformationAccess: _fmt_aia,
    x509.CertificatePolicies: _fmt_policies,
    x509.PolicyConstraints: _fmt_policy_constraints,
    x509.InhibitAnyPolicy: lambda v: {"value": v.value},
    x509.NameConstraints: _fmt_name_constraints,
    x509.TLSFeature: _fmt_tls_feature,
    x509.PrecertPoison: lambda v: {},
    x509.OCSPNoCheck: lambda v: {},
    x509.PrecertificateSignedCertificateTimestamps: _fmt_sct_list,
    x509.UnrecognizedExtension: lambda v: {"value_hex": hex_colon(v.value, upper=True)},
    x509.IssuingDistributionPoint: _fmt_issuing_dp,
}


def _fmt_extension_value(ext):
    """尽力把扩展值解析成结构化 dict；无法识别/解析失败时保留原始表示"""
    if type(ext.value) is x509.MSCertificateTemplate:
        try:
            return {"parsed": jsonify(_fmt_ms_template(ext.value))}
        except Exception:  # noqa: BLE001
            pass
    try:
        fmt = _EXT_FORMATTERS.get(type(ext.value))
        if fmt is not None:
            return {"parsed": jsonify(fmt(ext.value))}
        return {"raw": jsonify(ext.value)}   # 未注册类型：直接序列化
    except Exception as e:  # noqa: BLE001 —— 单个扩展解析失败不拖垮整体
        raw = None
        if hasattr(ext.value, "public_bytes"):
            try:
                raw = ext.value.public_bytes()
            except Exception:  # noqa: BLE001
                raw = None
        return {"parse_error": str(e),
                "raw_hex": hex_colon(raw, upper=True) if raw else repr(ext.value)}


def parse_extensions(cert):
    """解析证书全部扩展（按 OID 排序，保证输出稳定）"""
    try:
        items = list(cert.extensions)
    except Exception as e:  # noqa: BLE001 —— 个别畸形证书迭代扩展即抛
        return [{"parse_error": f"迭代 extensions 失败: {e}"}]

    items.sort(key=lambda e: e.oid.dotted_string)
    exts = []
    for ext in items:
        exts.append({
            "name": oid_name(ext.oid),
            "oid": ext.oid.dotted_string,
            "critical": ext.critical,
            **_fmt_extension_value(ext),
        })
    return exts


# ---------------------------------------------------------------------------
# 公钥解析
# ---------------------------------------------------------------------------
def parse_public_key(pk):
    """返回 {type, bits, params...}"""
    if isinstance(pk, rsa.RSAPublicKey):
        nums = pk.public_numbers()
        return {
            "type": "RSA",
            "bits": pk.key_size,
            "exponent": nums.e,
            "modulus_hex": "0x%x" % nums.n,
        }
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return {
            "type": "ECDSA",
            "curve": pk.curve.name,
            "bits": pk.key_size,
            "point_hex": pk.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.CompressedPoint).hex().upper(),
        }
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return {"type": "Ed25519", "bits": 256}
    if isinstance(pk, ed448.Ed448PublicKey):
        return {"type": "Ed448", "bits": 456}
    if isinstance(pk, dsa.DSAPublicKey):
        nums = pk.public_numbers()
        params = nums.parameter_numbers
        return {
            "type": "DSA",
            "bits": pk.key_size,
            "y_hex": "0x%x" % nums.y,
            "p_hex": "0x%x" % params.p,
            "q_hex": "0x%x" % params.q,
            "g_hex": "0x%x" % params.g,
        }
    return {"type": pk.__class__.__name__}


# ---------------------------------------------------------------------------
# 主解析：证书 → 全字段 dict
# ---------------------------------------------------------------------------
def parse_cert(cert):
    """把 x509.Certificate 解析为覆盖所有字段的 dict"""
    sig_hash = None
    try:
        if cert.signature_hash_algorithm is not None:
            sig_hash = cert.signature_hash_algorithm.name
    except Exception:  # noqa: BLE001 —— 某些算法（EdDSA）无哈希算法
        sig_hash = None

    try:
        version_num = cert.version.value      # v1=0, v2=1, v3=2
        version_label = cert.version.name     # 如 v3
    except Exception:  # noqa: BLE001
        version_num, version_label = None, str(cert.version)

    return {
        "version": {"label": version_label, "value": version_num},
        "serial_number": {
            "dec": str(cert.serial_number),
            "hex": "0x%x" % cert.serial_number,
        },
        "signature_algorithm": {
            "name": oid_name(cert.signature_algorithm_oid),
            "oid": cert.signature_algorithm_oid.dotted_string,
            "hash_algorithm": sig_hash,
        },
        "issuer": {
            "rfc4514": cert.issuer.rfc4514_string(),
            "attributes": name_attrs(cert.issuer),
        },
        "validity": _parse_validity(cert),
        "subject": {
            "rfc4514": cert.subject.rfc4514_string(),
            "attributes": name_attrs(cert.subject),
        },
        "public_key": parse_public_key(cert.public_key()),
        "signature_value": {
            "length": len(cert.signature),
            "hex": hex_colon(cert.signature, upper=True),
        },
        "fingerprints": {
            "sha256": hex_colon(cert.fingerprint(hashes.SHA256()), upper=True),
            "sha1": hex_colon(cert.fingerprint(hashes.SHA1()), upper=True),
        },
        "extensions": parse_extensions(cert),
    }


def _parse_validity(cert):
    """有效期；cryptography >= 41 用 *_utc（aware datetime），老版本退回 naive 字段"""
    nb = getattr(cert, "not_valid_before_utc", None)   # 新版不再有 naive 字段
    na = getattr(cert, "not_valid_after_utc", None)
    if nb is None:                                     # 老版本回退（有弃用警告）
        nb = cert.not_valid_before
    if na is None:
        na = cert.not_valid_after
    if nb.tzinfo is None:
        nb = nb.replace(tzinfo=datetime.timezone.utc)
    if na.tzinfo is None:
        na = na.replace(tzinfo=datetime.timezone.utc)
    return {
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "duration_days": (na - nb).days,
    }


# ---------------------------------------------------------------------------
# 加载证书
# ---------------------------------------------------------------------------
def load_cert(cert_path, der=False):
    """按 PEM/DER 加载证书；未指定 --der 时 PEM 失败自动尝试 DER。
    返回 (cert, format_str)"""
    with open(cert_path, "rb") as f:
        data = f.read()
    if der:
        return x509.load_der_x509_certificate(data), "DER"
    try:
        return x509.load_pem_x509_certificate(data), "PEM"
    except ValueError:
        return x509.load_der_x509_certificate(data), "DER"


# ---------------------------------------------------------------------------
# 文本输出
# ---------------------------------------------------------------------------
def _print_text(parsed, fmt, stream=None):
    out = stream if stream is not None else sys.stdout
    p = lambda *a, **k: print(*a, file=out, **k)  # noqa: E731

    c = parsed["cert"]
    ver = c["version"]
    p(f"文件格式: {fmt}")
    p(f"版本 (version): {ver['label']}"
      + (f"  [X.509 v{ver['value'] + 1}]" if ver["value"] is not None else ""))

    ser = c["serial_number"]
    p("序列号 (serialNumber):")
    p(f"    dec: {ser['dec']}")
    p(f"    hex: {ser['hex']}")

    sa = c["signature_algorithm"]
    hash_txt = f", hash={sa['hash_algorithm']}" if sa["hash_algorithm"] else ""
    p(f"签名算法 (signatureAlgorithm): {sa['name']}  [{sa['oid']}]{hash_txt}")

    for who, label in (("issuer", "签发者 (issuer)"),
                       ("subject", "主体   (subject)")):
        w = c[who]
        p(f"{label}:")
        p(f"    rfc4514: {w['rfc4514']}")
        for a in w["attributes"]:
            p(f"    - {a['oid']} [{a['dotted']}]: {a['value']}")

    v = c["validity"]
    p("有效期 (validity):")
    p(f"    notBefore: {v['not_before']}")
    p(f"    notAfter:  {v['not_after']}")
    p(f"    时长: {v['duration_days']} 天")

    pk = c["public_key"]
    pk_parts = [f"{k}={val}" for k, val in pk.items()
                if k != "modulus_hex"] + \
               (["modulus_hex=" + pk["modulus_hex"][:16] + "…"] if "modulus_hex" in pk else [])
    p(f"公钥 (subjectPublicKeyInfo): {'; '.join(pk_parts)}")

    sig = c["signature_value"]
    p(f"签名值 (signature): 长度 {sig['length']} 字节")
    p(f"    hex: {sig['hex']}")

    fp = c["fingerprints"]
    p("指纹 (fingerprint):")
    p(f"    SHA-256: {fp['sha256']}")
    p(f"    SHA-1:   {fp['sha1']}")

    exts = c["extensions"]
    p(f"扩展 (extensions): 共 {len(exts)} 个")
    for i, e in enumerate(exts, 1):
        crit = "critical" if e["critical"] else "non-critical"
        p(f"  [{i}] {e['name']}  [{e['oid']}]  ({crit})")
        if "parsed" in e:
            for line in json.dumps(e["parsed"], indent=6,
                                   ensure_ascii=False).splitlines():
                p(line)
        elif "raw" in e:
            p(f"      raw: {e['raw']}")
        elif "parse_error" in e:
            p(f"      !! 解析失败: {e['parse_error']}")
            if "raw_hex" in e:
                p(f"      !! 原始值: {e['raw_hex']}")


# ---------------------------------------------------------------------------
# CSV 输出
# ---------------------------------------------------------------------------
# 扩展 OID（用于汇总表按 OID 取值）
_OID_SAN = "2.5.29.17"
_OID_IAN = "2.5.29.18"
_OID_BASIC = "2.5.29.19"
_OID_KU = "2.5.29.15"
_OID_EKU = "2.5.29.37"
_OID_SKI = "2.5.29.14"
_OID_AKI = "2.5.29.35"
_OID_AIA = "1.3.6.1.5.5.7.1.1"
_OID_CDP = "2.5.29.31"
_OID_POLICIES = "2.5.29.32"
_OID_NAME_CONSTRAINTS = "2.5.29.30"
_OID_SCT = "1.3.6.1.4.1.11129.2.4.2"

# 汇总表列（顺序即 CSV 列顺序）
SUMMARY_FIELDS = [
    "file", "format", "version", "serial_hex",
    "subject", "subject_cn", "subject_o", "issuer",
    "not_before", "not_after", "valid_days",
    "pubkey_type", "pubkey_bits", "pubkey_curve",
    "sig_alg", "sig_hash",
    "is_ca", "path_len", "key_usage", "eku",
    "san_dns", "san_count", "aia_ocsp", "aia_ca_issuers", "cdp",
    "policies", "name_constraints", "sct_count",
    "ext_count", "ext_names", "sha256", "error",
]


def flatten(obj, prefix=""):
    """递归摊平嵌套 dict/list → [(字段路径, 值), ...]，值只保留标量"""
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


def _ext(cert_dict, dotted):
    """按 OID 取扩展 dict；没有该扩展返回 None"""
    for e in cert_dict.get("extensions", []):
        if e.get("oid") == dotted:
            return e
    return None


def _parsed(cert_dict, dotted, default=None):
    """按 OID 取扩展的 parsed 值；扩展不存在或未解析成功时返回 default"""
    e = _ext(cert_dict, dotted)
    if e is None:
        return default
    return e.get("parsed", default)


def _short_oid(name):
    """'ExtensionOID.SUBJECT_ALTERNATIVE_NAME' → 'SUBJECT_ALTERNATIVE_NAME'"""
    return name.split(".")[-1] if isinstance(name, str) else str(name)


def _attr_value(cert_dict, who, suffix):
    """取 subject/issuer 中某个 Name 属性的值（如 COMMON_NAME）"""
    for a in cert_dict.get(who, {}).get("attributes", []):
        if a.get("oid", "").endswith(suffix):
            return a.get("value", "")
    return ""


def _join_uris(items, sep="; "):
    """GeneralName 字符串列表 → 去掉 'URI: ' 前缀后拼接"""
    if not items:
        return ""
    return sep.join(i.split(": ", 1)[1] if ": " in i else i for i in items)


def summary_row(file_path, fmt, cert_dict):
    """单张证书 → 汇总表一行（常用字段成列）"""
    ku = _parsed(cert_dict, _OID_KU) or {}
    ku_true = [k for k, v in ku.items() if v is True]
    eku = _parsed(cert_dict, _OID_EKU) or {}
    san = _parsed(cert_dict, _OID_SAN) or {}
    san_names = san.get("names") or []
    san_dns = [n.split(": ", 1)[1] for n in san_names if n.startswith("DNS: ")]
    basic = _parsed(cert_dict, _OID_BASIC) or {}
    aia = _parsed(cert_dict, _OID_AIA) or {}
    aia_items = aia.get("access_descriptions") or []
    cdp = _parsed(cert_dict, _OID_CDP) or {}
    policies = _parsed(cert_dict, _OID_POLICIES) or {}
    nc = _parsed(cert_dict, _OID_NAME_CONSTRAINTS)
    scts = _parsed(cert_dict, _OID_SCT) or {}
    pk = cert_dict.get("public_key", {})
    exts = cert_dict.get("extensions", [])

    def aia_by(keyword):
        return _join_uris([i["location"] for i in aia_items
                           if keyword.lower() in str(i.get("method", "")).lower()])

    cdp_urls = []
    for dp in (cdp.get("distribution_points") or []):
        cdp_urls.extend(dp.get("full_name") or [])

    return {
        "file": os.path.basename(file_path),
        "format": fmt,
        "version": cert_dict.get("version", {}).get("label", ""),
        "serial_hex": cert_dict.get("serial_number", {}).get("hex", ""),
        "subject": cert_dict.get("subject", {}).get("rfc4514", ""),
        "subject_cn": _attr_value(cert_dict, "subject", "COMMON_NAME"),
        "subject_o": _attr_value(cert_dict, "subject", "ORGANIZATION_NAME"),
        "issuer": cert_dict.get("issuer", {}).get("rfc4514", ""),
        "not_before": cert_dict.get("validity", {}).get("not_before", ""),
        "not_after": cert_dict.get("validity", {}).get("not_after", ""),
        "valid_days": cert_dict.get("validity", {}).get("duration_days", ""),
        "pubkey_type": pk.get("type", ""),
        "pubkey_bits": pk.get("bits", ""),
        "pubkey_curve": pk.get("curve", ""),
        "sig_alg": cert_dict.get("signature_algorithm", {}).get("name", ""),
        "sig_hash": cert_dict.get("signature_algorithm", {}).get("hash_algorithm", "") or "",
        "is_ca": basic.get("ca", ""),
        "path_len": basic.get("path_length", ""),
        "key_usage": ", ".join(ku_true),
        "eku": ", ".join(_short_oid(u) for u in (eku.get("usages") or [])),
        "san_dns": "; ".join(san_dns),
        "san_count": len(san_names),
        "aia_ocsp": aia_by("OCSP"),
        "aia_ca_issuers": aia_by("CA_ISSUERS"),
        "cdp": _join_uris(cdp_urls),
        "policies": "; ".join(p.get("dotted", "") for p in (policies.get("policies") or [])),
        "name_constraints": "; ".join(
            (nc.get("permitted_subtrees") or [])) if isinstance(nc, dict) else "",
        "sct_count": len(scts.get("scts") or []),
        "ext_count": len(exts),
        "ext_names": ", ".join(_short_oid(e.get("name", "")) for e in exts),
        "sha256": cert_dict.get("fingerprints", {}).get("sha256", ""),
    }


def write_csv(path, rows, fieldnames):
    """写 CSV；UTF-8 with BOM，Excel 双击打开中文不乱码"""
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore",
                           restval="")
        w.writeheader()
        w.writerows(rows)


def expand_inputs(paths):
    """展开输入：目录递归查 .pem/.crt/.cer/.der，文件直接收录；结果排序去重"""
    exts = (".pem", ".crt", ".cer", ".der")
    files = []
    for p in paths:
        p = os.path.expanduser(p)
        if os.path.isdir(p):
            for root, _dirs, names in os.walk(p):
                for n in names:
                    if n.lower().endswith(exts):
                        files.append(os.path.join(root, n))
        elif os.path.isfile(p):
            files.append(p)
        else:
            print(f"  !! 路径不存在，跳过: {p}", file=sys.stderr)
    # 去重后排序，保证每次运行顺序一致
    return sorted(set(files))


def run_batch(paths, der, csv_file, csv_mode=None):
    """批量解析并输出 CSV

    csv_mode: fields（每个字段一行）/ summary（每张证书一行）；
              为 None 时自动选择（1 个证书 → fields，多个 → summary）
    """
    files = expand_inputs(paths)
    if not files:
        print("错误: 未找到任何证书文件（支持 .pem/.crt/.cer/.der）", file=sys.stderr)
        sys.exit(1)

    if csv_mode not in (None, "fields", "summary"):
        print(f"错误: --csv-mode 只能是 fields 或 summary，收到 {csv_mode!r}",
              file=sys.stderr)
        sys.exit(1)

    mode = csv_mode or ("fields" if len(files) == 1 else "summary")
    rows = []
    ok, fail = 0, 0

    for fp in files:
        try:
            cert, fmt = load_cert(fp, der)
            cert_dict = parse_cert(cert)
        except Exception as e:  # noqa: BLE001 —— 非证书文件（如 CRL）跳过，不中断
            fail += 1
            print(f"  !! 跳过（解析失败）: {fp} -> {e}", file=sys.stderr)
            if mode == "summary":
                rows.append({"file": os.path.basename(fp), "error": str(e)})
            continue

        ok += 1
        if mode == "fields":
            for field, value in flatten(cert_dict):
                rows.append({"file": os.path.basename(fp),
                             "field": field, "value": value})
        else:
            rows.append(summary_row(fp, fmt, cert_dict))

    fieldnames = (["file", "field", "value"] if mode == "fields"
                  else SUMMARY_FIELDS)
    write_csv(csv_file, rows, fieldnames)

    print(f"已写入: {csv_file}（模式 {mode}，成功 {ok} 个"
          f"{'，失败 ' + str(fail) + ' 个' if fail else ''}，共 {len(rows)} 行）",
          file=sys.stderr)


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
def run(cert_path, der=False, as_json=False, out_file=None):
    cert_path = os.path.expanduser(cert_path)
    if not os.path.isfile(cert_path):
        print(f"错误: 文件不存在 -> {cert_path}", file=sys.stderr)
        sys.exit(1)

    try:
        cert, fmt = load_cert(cert_path, der)
    except Exception as e:  # noqa: BLE001
        print(f"错误: 无法解析证书（PEM/DER 均失败）: {e}", file=sys.stderr)
        sys.exit(1)

    parsed = {
        "meta": {
            "input_file": cert_path,
            "format": fmt,
            "tool": "cryptography " + __import__("cryptography").__version__,
        },
        "cert": parse_cert(cert),
    }

    if as_json:
        text = json.dumps(parsed, indent=2, ensure_ascii=False,
                          default=jsonify)
    else:
        buf = io.StringIO()
        _print_text(parsed, fmt, stream=buf)
        text = buf.getvalue()

    if out_file:
        out_file = os.path.expanduser(out_file)
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"已写入: {out_file}", file=sys.stderr)
    else:
        print(text, end="" if text.endswith("\n") else "\n")


def _opt_value(args, flag):
    """取 `--flag 值` 形式的值；未给 flag 返回 None，给了但缺值返回 ''"""
    if flag not in args:
        return None
    i = args.index(flag)
    if i + 1 < len(args) and not args[i + 1].startswith("--"):
        return args[i + 1]
    return ""


def interactive():
    print("=== 交互模式（直接回车使用默认值，输入 q 退出）===")
    cert_path = os.path.expanduser(input("证书路径（文件或目录）: ").strip())
    while True:
        if cert_path.lower() in ("q", "quit"):
            sys.exit(0)
        if os.path.isfile(cert_path) or os.path.isdir(cert_path):
            break
        print(f"  !! 文件/目录不存在: {cert_path}")
        cert_path = os.path.expanduser(input("请重新输入路径 (q 退出): ").strip())

    d = input("DER 格式 (y/N): ").strip().lower()
    der = d in ("y", "yes")

    csv_out = os.path.expanduser(input("CSV 输出文件 (回车跳过): ").strip())
    if csv_out:
        mode = input("CSV 模式 (回车自动 / fields / summary): ").strip().lower() or None
        run_batch([cert_path], der, csv_out, mode)
        return

    j = input("JSON 输出 (y/N): ").strip().lower()
    as_json = j in ("y", "yes")
    run(cert_path, der, as_json)


def main():
    args = sys.argv[1:]

    if not args:                    # 没有任何参数 → 交互模式
        interactive()
        return

    if "-h" in args or "--help" in args:
        print(__doc__)
        return

    der = "--der" in args
    as_json = "--json" in args

    out_file = _opt_value(args, "--out")
    csv_file = _opt_value(args, "--csv")
    csv_mode = _opt_value(args, "--csv-mode")

    # 已被选项消费掉的值不当作路径
    consumed = {out_file, csv_file, csv_mode}
    paths = [a for a in args
             if not a.startswith("--") and a not in consumed]

    if csv_file is not None:
        if csv_file == "":
            print("错误: --csv 缺少输出文件名", file=sys.stderr)
            sys.exit(1)
        if out_file:
            print("错误: --csv 与 --out 不可同时使用（可分两次运行）",
                  file=sys.stderr)
            sys.exit(1)
        if not paths:
            print("错误: --csv 需要指定证书路径或目录", file=sys.stderr)
            sys.exit(1)
        run_batch(paths, der, csv_file, csv_mode)
        return

    cert_path = paths[0] if paths else None
    if not cert_path:
        print(__doc__)
        sys.exit(1)

    run(cert_path, der, as_json, out_file)


# 模块级执行：import 本模块后直接调用 parse_cert() 也能得到可读 OID 名
_build_oid_map()


if __name__ == "__main__":
    main()
