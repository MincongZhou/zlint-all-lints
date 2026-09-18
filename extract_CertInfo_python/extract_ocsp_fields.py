#!/usr/bin/env python3
"""
extract_ocsp_fields.py —— OCSP 响应字段提取（对齐 extract_crl_fields.py）

输入是 responder 返回的原始 OCSP 响应（DER）。跑批时这些文件由第 ① 步
run_cert_crl_ocsp.py 存成 <输出目录>/<证书名>/resp.der，本脚本只做本地解析，
**不联网**（状态表 ocsp_batch.csv 由第 ④ 步 run_ocsp_batch.py 负责）。

用法:
    python3 extract_ocsp_fields.py resp.der                  # 终端打印全字段
    python3 extract_ocsp_fields.py resp.der --json           # JSON 输出
    python3 extract_ocsp_fields.py results/CT --csv ocsp_fields.csv
        → ocsp_fields.csv            每份响应一行（宽表）
        → ocsp_fields_responses.csv  每个 SingleResponse 一行（多响应时看清每一条；
                                     含 single_ext_count/single_exts_json，单条扩展零丢失）
    python3 extract_ocsp_fields.py --paths-from list.txt --csv ocsp_fields.csv
        # 从列表文件逐行读路径（- 表示 stdin）；上万份 resp.der 时用它避开 ARG_MAX 限制
    python3 extract_ocsp_fields.py                           # 无参数 → 交互模式

目录输入时按 --pattern（默认 resp.der）匹配文件名递归查找；
直接给文件路径时不检查文件名。PEM 包裹的响应（-----BEGIN OCSP RESPONSE-----）也能读。

--csv-mode 取值: wide(默认) / responses / fields
    wide      每份响应一行：固定列 + 响应扩展按 OID 命名的列；副表 <name>_responses.csv
    responses 每个 SingleResponse 一行（一份响应含多条时用）
    fields    每个字段一行（file, field, value），嵌套逐层摊平，字段零丢失

覆盖字段（RFC 6960 OCSP 结构）:
  响应级: responseStatus / responseType 版本（从 DER 解析，缺省 v1）/
          producedAt / responderID（ByName→DN，ByKey→keyHash）/
          响应扩展（nonce / CRL References / Archive Cutoff …）/ 内嵌证书(delegates)
  Single: certStatus(GOOD/REVOKED/UNKNOWN) / CertID(hashAlg + issuerNameHash +
          issuerKeyHash + serialNumber) / thisUpdate / nextUpdate /
          revocationTime / revocationReason
  签名  : signatureAlgorithm(OID+hash) / signature 长度 / tbsResponseData(SHA-256)
  验签  : --issuer <证书> 时给出 signature_valid（响应签名不含公钥：优先用响应内嵌的
          responder 证书，没有才用 --issuer），并给 issuer_dn_match 判断 CA 是否给对
          （内嵌证书的签发者 DN / 无内嵌时的 responderID DN 与 --issuer 的 subject 比）

CSV 统一 UTF-8 with BOM（Excel 双击不乱码）；指纹/哈希为大写十六进制、不带冒号。
依赖: python3 + cryptography >= 42.0（运行时自动检查）
"""

import base64
import csv
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone
from fnmatch import fnmatch

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp

# 目录递归时默认只认这个文件名（跑批产物的固定名字）
DEFAULT_PATTERN = "resp.der"

# ---------------------------------------------------------------------------
# cryptography 版本下限检查（single_extensions / responses / *_utc 需要 >= 42.0）
# ---------------------------------------------------------------------------
_MIN_CRYPTO = (42, 0)


def check_cryptography_version():
    v = __import__("cryptography").__version__
    nums = tuple(int(n) for n in re.findall(r"\d+", v)[:2] or (0,))
    if nums < _MIN_CRYPTO:
        sys.exit(f"错误: 需要 cryptography >= {'.'.join(map(str, _MIN_CRYPTO))}"
                 f"（当前 {v}），请执行: pip install -U cryptography")


# ---------------------------------------------------------------------------
# OID → 可读名映射（遍历 cryptography 自带的 OID 常量类）
# ---------------------------------------------------------------------------
_OID_NAMES = {}


def _build_oid_map():
    for cls in (x509.NameOID, x509.ExtensionOID, x509.SignatureAlgorithmOID,
                x509.AuthorityInformationAccessOID, x509.ObjectIdentifier):
        for key, val in vars(cls).items():
            if isinstance(val, x509.ObjectIdentifier):
                _OID_NAMES.setdefault(val.dotted_string, f"{cls.__name__}.{key}")
    # OCSP 侧常见扩展没有内置常量，手工补几个（RFC 6960 §4.4）
    _OID_NAMES.setdefault("1.3.6.1.5.5.7.48.1.2", "OCSP.NONCE")
    _OID_NAMES.setdefault("1.3.6.1.5.5.7.48.1.3", "OCSP.CRL_REFERENCES")
    _OID_NAMES.setdefault("1.3.6.1.5.5.7.48.1.6", "OCSP.ARCHIVE_CUTOFF")
    _OID_NAMES.setdefault("1.3.6.1.5.5.7.48.1.7", "OCSP.SERVICE_LOCATOR")
    _OID_NAMES.setdefault("1.3.6.1.5.5.7.48.1.4", "OCSP.ACCEPTABLE_RESPONSES")
    _OID_NAMES.setdefault("1.3.6.1.5.5.7.48.1.1", "OCSP.BASIC_RESPONSE")


def oid_name(oid):
    """返回 OID 可读名（如 'OCSP.NONCE'），无内置名则加点分串"""
    return _OID_NAMES.get(oid.dotted_string, f"(unknown) {oid.dotted_string}")


def short_oid(name):
    """'OCSP.NONCE' → 'NONCE'；未知 OID 退回点分串"""
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


def _sha256(data):
    """字节串的 SHA-256，64 位大写十六进制、不带冒号（与 index.csv 指纹口径一致）"""
    d = hashes.Hash(hashes.SHA256())
    d.update(data)
    return d.finalize().hex().upper()


def _safe(fn, default=None):
    """取字段的兜底包装：非 SUCCESSFUL 响应访问多数属性会抛 ValueError，
    单张响应含多个 SingleResponse 时访问顶层 status 也会抛；一律退化成默认值，
    不让一个字段的异常毁掉整行。"""
    try:
        return fn()
    except Exception:
        return default


def _iso(dt):
    if dt is None:
        return ""
    return dt.isoformat() if hasattr(dt, "isoformat") else str(dt)


def _name(dt):
    """枚举/对象 → 名字；None 保持空"""
    if dt is None:
        return ""
    return getattr(dt, "name", str(dt))


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
# DER 辅助：cryptography 不暴露 OCSP 版本号，自己从原始 DER 里取
# OCSPResponse → responseBytes.response → BasicOCSPResponse.tbsResponseData.version
# （[0] EXPLICIT INTEGER，缺省即 v1；解析失败一律返回 None，不影响其它字段）
# ---------------------------------------------------------------------------
def _der_tlv(data, pos):
    """读一个 TLV → (tag, 值起始, 值长度, 下一个位置)；失败抛 ValueError"""
    if pos + 2 > len(data):
        raise ValueError("数据不足")
    tag = data[pos]
    length = data[pos + 1]
    vstart = pos + 2
    if length & 0x80:                       # 长格式长度
        n = length & 0x7F
        if n == 0 or pos + 2 + n > len(data):
            raise ValueError("长度字节异常")
        length = int.from_bytes(data[vstart:vstart + n], "big")
        vstart += n
    if vstart + length > len(data):
        raise ValueError("值长度越界")
    return tag, vstart, length, vstart + length


def _der_body(data):
    """完整 TLV → 值部分（去掉 tag 与长度字节）"""
    _tag, vstart, length, _end = _der_tlv(data, 0)
    return data[vstart:vstart + length]


def _der_items(seq):
    """SEQUENCE（完整 TLV）→ 直接子元素 [(tag, 子元素完整 TLV)]"""
    tag, vstart, length, _end = _der_tlv(seq, 0)
    if tag != 0x30:
        raise ValueError("不是 SEQUENCE")
    buf, out, pos = seq[vstart:vstart + length], [], 0
    while pos < len(buf):
        t, _vs, _ln, nxt = _der_tlv(buf, pos)
        out.append((t, buf[pos:nxt]))
        pos = nxt
    return out


def der_version(raw):
    """从原始 OCSP 响应 DER 里取 tbsResponseData.version（int 或 None）"""
    try:
        top = _der_items(raw)                              # OCSPResponse
        rb = next(v for t, v in top if t == 0xA0)          # [0] responseBytes
        rbs = _der_items(_der_body(rb))                    # ResponseBytes
        resp = next(v for t, v in rbs if t == 0x04)        # OCTET STRING response
        basic = _der_items(_der_body(resp))                # BasicOCSPResponse
        tbs = _der_items(basic[0][1])                      # tbsResponseData
        ver = next((v for t, v in tbs if t == 0xA0), None)  # [0] version（可缺省）
        if ver is None:
            return 0                                       # DEFAULT v1
        return int.from_bytes(_der_body(ver), "big")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 加载
# ---------------------------------------------------------------------------
def load_ocsp(path):
    """加载 OCSP 响应：DER 直接解析；PEM 包裹（-----BEGIN OCSP RESPONSE-----）
    去头后按 DER 解析。返回 (response, raw_bytes, format)"""
    with open(path, "rb") as f:
        raw = f.read()
    try:
        return ocsp.load_der_ocsp_response(raw), raw, "DER"
    except Exception:
        m = re.search(rb"-----BEGIN[^-]*-----(.*?)-----END[^-]*-----", raw, re.S)
        if not m:
            raise
        der = base64.b64decode(re.sub(rb"\s+", b"", m.group(1)))
        return ocsp.load_der_ocsp_response(der), der, "PEM"


def load_cert(path):
    with open(os.path.expanduser(path), "rb") as f:
        raw = f.read()
    try:
        return x509.load_pem_x509_certificate(raw)
    except Exception:
        return x509.load_der_x509_certificate(raw)


# ---------------------------------------------------------------------------
# 扩展格式化（响应级扩展 / 单条响应扩展）
# ---------------------------------------------------------------------------
def _fmt_nonce(v):
    return {"nonce": v.nonce.hex().upper()}


def _fmt_unrecognized(v):
    return {"value_hex": hex_colon(v.value, upper=True)}


def _fmt_crl_refs(v):
    return {"crl_urls": [gn_url(n) for n in v]}


def gn_url(gn):
    """GeneralName → 可读串（CRL References 里一般是 URI）"""
    if isinstance(gn, x509.UniformResourceIdentifier):
        return gn.value
    return str(gn)


_EXT_FORMATTERS = {
    "OCSPNonce": _fmt_nonce,
    "UnrecognizedExtension": _fmt_unrecognized,
}


def parse_extensions(exts):
    """扩展集合 → [{'name','oid','critical','parsed'/'raw'/'parse_error'}]"""
    out = []
    try:
        items = sorted(exts, key=lambda e: e.oid.dotted_string)
    except Exception as e:
        return [{"parse_error": f"迭代扩展失败: {e}"}]
    for e in items:
        row = {"name": oid_name(e.oid), "oid": e.oid.dotted_string,
               "critical": e.critical}
        try:
            fmt = _EXT_FORMATTERS.get(type(e.value).__name__)
            row["parsed"] = jsonify(fmt(e.value) if fmt else e.value)
        except Exception as ex:
            row["parse_error"] = str(ex)
        out.append(row)
    return out


# ---------------------------------------------------------------------------
# 主解析：一份 OCSP 响应 → 全字段 dict
# ---------------------------------------------------------------------------
def verify_signature(resp, signer_cert):
    """用给定证书的公钥验签响应签名。返回 True / False / 说明字符串

    OCSP 响应自带签名与 tbsResponseData，但不带公钥：要么响应里内嵌了 responder
    证书（delegated responder，certs 字段），要么得由 --issuer 从外部提供。
    """
    try:
        pub = signer_cert.public_key()
        sig, tbs = resp.signature, resp.tbs_response_bytes
        alg = resp.signature_hash_algorithm
        # 注意：cryptography 的 verify() 验签成功时返回 None（失败才抛异常），
        # 所以不能用 bool(...) 包，否则恒为 False
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, tbs, padding.PKCS1v15(), alg)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, tbs, ec.ECDSA(alg))
        else:                                  # Ed25519 / Ed448
            pub.verify(sig, tbs)
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        return f"验签异常: {e}"


def parse_response(resp, path, raw, fmt, issuer_cert=None):
    now = datetime.now(timezone.utc)
    status = _safe(lambda: resp.response_status.name, "解析失败")
    successful = _safe(lambda: resp.response_status ==
                       ocsp.OCSPResponseStatus.SUCCESSFUL, False)

    # 多响应时 cryptography 的顶层 status 类属性会抛错，留空由副表承载
    singles = _safe(lambda: list(resp.responses), []) or []

    def certid(prefix, obj):
        """从 OCSPResponse 或 SingleResponse 取 CertID 四个字段"""
        return {
            f"{prefix}_hash_alg": _safe(lambda: _name(obj.hash_algorithm)),
            f"{prefix}_issuer_name_hash": _safe(
                lambda: obj.issuer_name_hash.hex().upper()),
            f"{prefix}_issuer_key_hash": _safe(
                lambda: obj.issuer_key_hash.hex().upper()),
        }

    exts = parse_extensions(_safe(lambda: resp.extensions, []) or [])
    single_exts = parse_extensions(
        _safe(lambda: resp.single_extensions, []) or [])

    delegates = _safe(lambda: list(resp.certificates), []) or []
    # responderID：ByName（DN）或 ByKey（公钥 SHA-1 哈希），二者必居其一
    rname = _safe(lambda: resp.responder_name)
    rkey = _safe(lambda: resp.responder_key_hash)
    rid_type = "ByName" if rname is not None else ("ByKey" if rkey else "")

    # 验签：优先用响应内嵌的 responder 证书（delegated）里的公钥，
    # 没有内嵌证书时才退回用 --issuer 给的 CA 公钥。非 SUCCESSFUL 响应没有
    # tbsResponseData/签名，直接跳过（验签结果留空，不是"验签失败"）
    sig_valid, dn_match = None, None
    if issuer_cert is not None and successful:
        issuer_subject = issuer_cert.subject.rfc4514_string()
        if delegates:
            # 用 --issuer 是不是 responder 证书的签发者来判断"给对 CA 了吗"
            dn_match = _safe(lambda: delegates[0].issuer.rfc4514_string()
                             == issuer_subject)
            if dn_match is False:
                print(f"  !! {path}: 响应内嵌的 responder 证书由 "
                      f"'{delegates[0].issuer.rfc4514_string()}' 签发，与 --issuer "
                      f"的 subject '{issuer_subject}' 不一致，仍用内嵌证书公钥验签",
                      file=sys.stderr)
        elif rname is not None:
            dn_match = _safe(
                lambda: resp.responder_name.rfc4514_string() == issuer_subject)
        sig_valid = verify_signature(resp, delegates[0] if delegates
                                     else issuer_cert)

    nxt = _safe(lambda: resp.next_update_utc)
    ver = der_version(raw) if successful else None
    sig_oid = _safe(lambda: resp.signature_algorithm_oid)

    stem = os.path.basename(os.path.dirname(os.path.abspath(path)))
    base = os.path.basename(path)
    parsed = {
        # file 带父目录名：批量时每份响应都叫 resp.der，只有文件名无法区分
        "file": f"{stem}/{base}" if stem else base,
        "path": path,
        # cert_stem = resp.der 所在目录名 = index.csv 的 cert 列，便于跨表 join
        "cert_stem": stem,
        "format": fmt,
        "size_bytes": len(raw),
        "response_status": status,
        "response_successful": successful,
        "version": {
            "value": (ver + 1) if isinstance(ver, int) else None,
            "label": (f"v{ver + 1}" if isinstance(ver, int) else ""),
            "note": "DER 里的 tbsResponseData.version（缺省即 v1=0）",
        },
        "responses_count": len(singles) or (1 if successful else 0),
        # 单条响应字段（多响应时留空，明细看 _responses.csv）
        "certificate_status": _safe(lambda: _name(resp.certificate_status)),
        "serial_number": _safe(lambda: resp.serial_number),
        "produced_at": _iso(_safe(lambda: resp.produced_at_utc)),
        "this_update": _iso(_safe(lambda: resp.this_update_utc)),
        "next_update": _iso(nxt),
        # 新鲜度：nextUpdate 已过即陈旧（BR/CPS 的响应有效期核查要用）
        "next_update_passed": ("" if nxt is None else bool(nxt <= now)),
        "revoked_at": _iso(_safe(lambda: resp.revocation_time_utc)),
        "revocation_reason": _safe(lambda: _name(resp.revocation_reason)),
        "responder_id_type": rid_type,
        "responder_name": (_safe(lambda: resp.responder_name.rfc4514_string())
                           if rname is not None else ""),
        "responder_key_hash": rkey.hex().upper() if rkey else "",
        "signature_algorithm": {
            "name": oid_name(sig_oid) if sig_oid is not None else "",
            "oid": sig_oid.dotted_string if sig_oid is not None else "",
            "hash_algorithm": _safe(
                lambda: _name(resp.signature_hash_algorithm)),
        },
        "signature": {"length": _safe(lambda: len(resp.signature), 0)},
        "tbs_sha256": _safe(lambda: _sha256(resp.tbs_response_bytes)),
        "response_sha256": _sha256(raw),
        "nonce": _nonce_of(exts),
        "signature_valid": sig_valid,
        "issuer_dn_match": dn_match,
        "extensions": exts,
        "single_extensions": single_exts,
        "delegates": [{
            "subject": _safe(lambda c=c: c.subject.rfc4514_string()),
            "issuer": _safe(lambda c=c: c.issuer.rfc4514_string()),
            "serial_hex": _safe(lambda c=c: "0x%x" % c.serial_number),
            "sha256": _safe(lambda c=c: c.fingerprint(hashes.SHA256())
                            .hex().upper()),
        } for c in delegates],
    }
    parsed.update(certid("certid", resp))

    rows = []
    for i, sr in enumerate(singles, 1):
        # 每条 SingleResponse 可有自己的扩展；顶层 resp.single_extensions 只在单条
        # 响应时可用（多条会抛错），这里按条各自解析 → 副表也能零丢失单条扩展
        sr_exts = parse_extensions(
            _safe(lambda sr=sr: list(sr.single_extensions), []) or [])
        row = {
            "file": parsed["file"],
            "cert_stem": parsed["cert_stem"],
            "idx": i,
            "certificate_status": _safe(lambda: _name(sr.certificate_status)),
            "serial_hex": _safe(lambda: "0x%x" % sr.serial_number),
            "serial_dec": _safe(lambda: str(sr.serial_number)),
            "this_update": _iso(_safe(lambda: sr.this_update_utc)),
            "next_update": _iso(_safe(lambda: sr.next_update_utc)),
            "revoked_at": _iso(_safe(lambda: sr.revocation_time_utc)),
            "revocation_reason": _safe(lambda: _name(sr.revocation_reason)),
            "single_ext_count": len(sr_exts),
            "single_exts_json": json.dumps(sr_exts, ensure_ascii=False,
                                           default=jsonify),
        }
        row.update(certid("certid", sr))
        rows.append(row)
    parsed["single_rows"] = rows
    return parsed


def _nonce_of(exts):
    """从响应扩展里取 nonce（RFC 6960 §4.4.1；responder 常不返回）"""
    for e in exts:
        v = e.get("parsed")
        if isinstance(v, dict) and "nonce" in v:
            return v["nonce"]
    return ""


# ---------------------------------------------------------------------------
# 文本输出
# ---------------------------------------------------------------------------
def print_full(parsed, stream=None):
    out = stream if stream is not None else sys.stdout
    p = lambda *a, **k: print(*a, file=out, **k)          # noqa: E731

    p(f"文件: {parsed['path']}  ({parsed['format']}, {parsed['size_bytes']} 字节)")
    p(f"所属证书目录 (cert_stem): {parsed['cert_stem']}")
    p(f"响应状态 (responseStatus): {parsed['response_status']}")
    if parsed["version"]["label"]:
        p(f"版本 (version): {parsed['version']['label']}"
          f"（{parsed['version']['note']}）")
    p(f"响应 SHA-256: {parsed['response_sha256']}")
    if not parsed["response_successful"]:
        p("（非 SUCCESSFUL 响应：没有 tbsResponseData，以下签名字段为空属正常）")
        return

    p(f"单条响应数 (responses): {parsed['responses_count']}")
    p(f"证书状态 (certStatus): {parsed['certificate_status'] or '(多条，见副表)'}")
    p(f"序列号 (CertID.serialNumber): {parsed['serial_number']}")
    p(f"CertID 摘要算法: {parsed['certid_hash_alg']}")
    p(f"  issuerNameHash: {parsed['certid_issuer_name_hash']}")
    p(f"  issuerKeyHash : {parsed['certid_issuer_key_hash']}")
    p(f"producedAt: {parsed['produced_at']}")
    p(f"thisUpdate: {parsed['this_update']}")
    p(f"nextUpdate: {parsed['next_update'] or '(无)'}"
      + ("  ← 已过期" if parsed["next_update_passed"] is True else ""))
    if parsed["revoked_at"]:
        p(f"revocationTime: {parsed['revoked_at']}"
          f"   原因: {parsed['revocation_reason'] or '(未给)'}")

    p(f"responderID: {parsed['responder_id_type']} "
      f"{parsed['responder_name'] or parsed['responder_key_hash']}")

    sa = parsed["signature_algorithm"]
    p(f"签名算法 (signatureAlgorithm): {sa['name']} [{sa['oid']}]"
      + (f", hash={sa['hash_algorithm']}" if sa["hash_algorithm"] else ""))
    p(f"签名值 (signature): {parsed['signature']['length']} 字节")
    p(f"tbsResponseData SHA-256: {parsed['tbs_sha256']}")
    if parsed["signature_valid"] is not None:
        p(f"验签结果: {parsed['signature_valid']}")
    if parsed["issuer_dn_match"] is False:
        p("  !! --issuer 给的证书不是本响应 responder 证书的签发者，验签结果仅供参考")

    p(f"响应扩展 (responseExtensions): 共 {len(parsed['extensions'])} 个")
    for i, e in enumerate(parsed["extensions"], 1):
        crit = "critical" if e.get("critical") else "non-critical"
        p(f"  [{i}] {e.get('name')} [{e.get('oid')}] ({crit})")
        if "parsed" in e:
            for line in json.dumps(e["parsed"], indent=6,
                                   ensure_ascii=False).splitlines():
                p(line)
        elif "parse_error" in e:
            p(f"      !! 解析失败: {e['parse_error']}")

    if parsed["single_extensions"]:
        p(f"单条响应扩展 (singleExtensions): 共 {len(parsed['single_extensions'])} 个")
        for i, e in enumerate(parsed["single_extensions"], 1):
            p(f"  [{i}] {e.get('name')} [{e.get('oid')}]"
              f" value={e.get('parsed', e.get('parse_error'))}")

    p(f"内嵌证书 (certs，delegated responder): {len(parsed['delegates'])} 张")
    for i, c in enumerate(parsed["delegates"], 1):
        p(f"  [{i}] subject = {c['subject']}")
        p(f"      issuer  = {c['issuer']}")
        p(f"      serial  = {c['serial_hex']}   SHA-256 = {c['sha256']}")


# ---------------------------------------------------------------------------
# CSV 输出
# ---------------------------------------------------------------------------
WIDE_BASE_FIELDS = [
    "file", "cert_stem", "path", "format", "size_bytes",
    "response_status", "response_successful", "version",
    "responses_count", "certificate_status", "serial_hex", "serial_dec",
    "certid_hash_alg", "certid_issuer_name_hash", "certid_issuer_key_hash",
    "produced_at", "this_update", "next_update", "next_update_passed",
    "revoked_at", "revocation_reason",
    "responder_id_type", "responder_name", "responder_key_hash",
    "sig_alg", "sig_oid", "sig_hash", "signature_len",
    "tbs_sha256", "response_sha256", "nonce",
    "delegate_cert_count", "delegate_cert_subjects", "delegate_cert_sha256",
    "signature_valid", "issuer_dn_match",
    "ext_count", "single_ext_count",
    "parse_error",
]

RESPONSE_FIELDS = [
    "file", "cert_stem", "idx", "certificate_status",
    "serial_hex", "serial_dec",
    "certid_hash_alg", "certid_issuer_name_hash", "certid_issuer_key_hash",
    "this_update", "next_update", "revoked_at", "revocation_reason",
    "single_ext_count", "single_exts_json",
]


def wide_row(parsed, include_ext=True):
    """一份响应 → 宽表一行（固定列 + ext.* 动态列）"""
    sa = parsed["signature_algorithm"]
    serial = parsed["serial_number"]
    row = {
        "file": parsed["file"],
        "cert_stem": parsed["cert_stem"],
        "path": parsed["path"],
        "format": parsed["format"],
        "size_bytes": parsed["size_bytes"],
        "response_status": parsed["response_status"],
        "response_successful": parsed["response_successful"],
        "version": parsed["version"]["label"],
        "responses_count": parsed["responses_count"],
        "certificate_status": parsed["certificate_status"],
        "serial_hex": "" if serial is None else "0x%x" % serial,
        "serial_dec": "" if serial is None else str(serial),
        "certid_hash_alg": parsed["certid_hash_alg"] or "",
        "certid_issuer_name_hash": parsed["certid_issuer_name_hash"] or "",
        "certid_issuer_key_hash": parsed["certid_issuer_key_hash"] or "",
        "produced_at": parsed["produced_at"],
        "this_update": parsed["this_update"],
        "next_update": parsed["next_update"],
        "next_update_passed": parsed["next_update_passed"],
        "revoked_at": parsed["revoked_at"],
        "revocation_reason": parsed["revocation_reason"],
        "responder_id_type": parsed["responder_id_type"],
        "responder_name": parsed["responder_name"],
        "responder_key_hash": parsed["responder_key_hash"],
        "sig_alg": sa["name"] if sa["oid"] else "",
        "sig_oid": sa["oid"] or "",
        "sig_hash": sa["hash_algorithm"] or "",
        "signature_len": parsed["signature"]["length"],
        "tbs_sha256": parsed["tbs_sha256"] or "",
        "response_sha256": parsed["response_sha256"],
        "nonce": parsed["nonce"],
        "delegate_cert_count": len(parsed["delegates"]),
        "delegate_cert_subjects": " | ".join(
            c["subject"] or "" for c in parsed["delegates"]),
        "delegate_cert_sha256": " | ".join(
            c["sha256"] or "" for c in parsed["delegates"]),
        "signature_valid": ("" if parsed["signature_valid"] is None
                            else parsed["signature_valid"]),
        "issuer_dn_match": ("" if parsed["issuer_dn_match"] is None
                            else parsed["issuer_dn_match"]),
        "ext_count": len(parsed["extensions"]),
        "single_ext_count": len(parsed["single_extensions"]),
        "parse_error": parsed.get("parse_error", ""),
    }
    if include_ext:
        for e in parsed["extensions"]:
            base = f"ext.{short_oid(e.get('name', ''))}"
            row[f"{base}.present"] = 1
            row[f"{base}.critical"] = e.get("critical", "")
            value = e.get("parsed", e.get("parse_error", ""))
            row[f"{base}.value_json"] = json.dumps(
                value, ensure_ascii=False, default=jsonify)
    return row


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


# ---------------------------------------------------------------------------
# 批量 / 单文件分发
# ---------------------------------------------------------------------------
def expand_inputs(paths, pattern=DEFAULT_PATTERN, exclude=()):
    """展开输入：目录按 pattern 递归匹配文件名，文件直接收录；排序去重"""
    files = []
    for p in paths:
        p = os.path.expanduser(p)
        if os.path.isdir(p):
            hits = [f for f in glob.glob(os.path.join(p, "**", "*"),
                                         recursive=True)
                    if os.path.isfile(f) and fnmatch(os.path.basename(f), pattern)]
            if not hits and pattern == DEFAULT_PATTERN:
                # 没找到 resp.der 时退一步：收 .der（可能是手工改名的响应）
                hits = [f for f in glob.glob(os.path.join(p, "**", "*"),
                                             recursive=True)
                        if os.path.isfile(f) and f.lower().endswith(".der")]
            files += hits
        elif os.path.isfile(p):
            files.append(p)
        else:
            print(f"  !! 路径不存在，跳过: {p}", file=sys.stderr)
    skip = {os.path.abspath(os.path.expanduser(x)) for x in exclude if x}
    return sorted({f for f in files if os.path.abspath(f) not in skip})


def run_batch(paths, csv_file=None, csv_mode="wide", issuer_cert=None,
              as_json=False, full=False, no_ext=False, pattern=DEFAULT_PATTERN):
    files = expand_inputs(paths, pattern,
                          exclude=[csv_file] if csv_file else [])
    if not files:
        print(f"错误: 未找到任何 OCSP 响应文件（目录内按 {pattern} 匹配）",
              file=sys.stderr)
        sys.exit(1)
    if csv_mode not in ("wide", "responses", "fields"):
        print(f"错误: --csv-mode 只能是 wide/responses/fields，收到 {csv_mode!r}",
              file=sys.stderr)
        sys.exit(1)

    parsed_list, csv_rows, single_rows = [], [], []
    ok = fail = 0
    for fp in files:
        try:
            resp, raw, fmt = load_ocsp(fp)
            parsed = parse_response(resp, fp, raw, fmt, issuer_cert)
            ok += 1
        except Exception as e:
            fail += 1
            print(f"[跳过] {fp}: {e}", file=sys.stderr)
            # 解析失败也留一行，便于核对"哪些证书没有可用响应"
            if csv_file:
                _stem = os.path.basename(os.path.dirname(os.path.abspath(fp)))
                _base = os.path.basename(fp)
                csv_rows.append({
                    "file": f"{_stem}/{_base}" if _stem else _base,
                    "path": fp, "cert_stem": _stem,
                    "response_status": "PARSE_ERROR", "parse_error": str(e)})
            continue

        if not csv_file:
            parsed_list.append(parsed)
        elif csv_mode == "wide":
            csv_rows.append(wide_row(parsed, include_ext=not no_ext))
            single_rows.extend(parsed["single_rows"])
        elif csv_mode == "responses":
            csv_rows.extend(parsed["single_rows"])
        else:                                   # fields
            csv_rows.extend({"file": parsed["file"], "field": field,
                             "value": value}
                            for field, value in flatten(parsed))

    tail = f"成功 {ok} 个" + (f"，失败 {fail} 个" if fail else "")

    if not csv_file:
        if as_json:
            print(json.dumps(parsed_list if len(parsed_list) != 1 else
                             parsed_list[0], indent=2, ensure_ascii=False,
                             default=jsonify))
        else:
            for i, p in enumerate(parsed_list):
                if i:
                    print()
                print_full(p)
        return

    if csv_mode == "wide":
        ext_cols = sorted({k for r in csv_rows for k in r if k.startswith("ext.")})
        write_csv(csv_file, csv_rows, WIDE_BASE_FIELDS + ext_cols)
        single_path = _sibling_path(csv_file, "_responses")
        write_csv(single_path, single_rows, RESPONSE_FIELDS)
        print(f"已写入: {csv_file}（OCSP 宽表，{tail}，{len(csv_rows)} 行 × "
              f"{len(WIDE_BASE_FIELDS) + len(ext_cols)} 列）", file=sys.stderr)
        print(f"已写入: {single_path}（每条 SingleResponse 一行，{len(single_rows)} 行）",
              file=sys.stderr)
    elif csv_mode == "responses":
        write_csv(csv_file, csv_rows, RESPONSE_FIELDS)
        print(f"已写入: {csv_file}（模式 responses，{tail}，共 {len(csv_rows)} 行）",
              file=sys.stderr)
    else:
        write_csv(csv_file, csv_rows, ["file", "field", "value"])
        print(f"已写入: {csv_file}（模式 fields，{tail}，共 {len(csv_rows)} 行）",
              file=sys.stderr)


def interactive():
    """无参数时的交互式输入：路径必填，其余回车用默认值（q 退出）"""
    print("=== 交互模式（直接回车使用默认值，输入 q 退出）===")
    target = os.path.expanduser(input("OCSP 响应文件或目录: ").strip())
    while True:
        if target.lower() in ("q", "quit"):
            sys.exit(0)
        if os.path.exists(target):
            break
        print(f"  !! 路径不存在: {target}")
        target = os.path.expanduser(
            input("请重新输入 OCSP 响应文件或目录 (q 退出): ").strip())

    way = input("输出方式 (回车=终端全字段 / json / csv): ").strip().lower()
    if way in ("q", "quit"):
        sys.exit(0)

    csv_file, csv_mode, no_ext = None, "wide", False
    if way == "csv":
        csv_file = os.path.expanduser(input("CSV 输出文件: ").strip())
        if csv_file.lower() in ("q", "quit"):
            sys.exit(0)
        if not csv_file:
            print("  !! 未给输出文件，改为终端输出")
            csv_file = None
        else:
            m = input("CSV 模式 (wide/responses/fields，回车=wide): ").strip().lower()
            if m in ("q", "quit"):
                sys.exit(0)
            if m and m not in ("wide", "responses", "fields"):
                print(f"  !! '{m}' 无效，按 wide 处理")
                m = ""
            csv_mode = m or "wide"
            if csv_mode == "wide":
                no_ext = input("只输出固定列 --no-ext-columns (y/N): ").strip().lower() \
                    in ("y", "yes")

    issuer_path = os.path.expanduser(
        input("验签用证书路径（回车跳过）: ").strip())
    if issuer_path.lower() in ("q", "quit"):
        sys.exit(0)

    issuer_cert = load_cert(issuer_path) if issuer_path else None
    run_batch([target], csv_file, csv_mode, issuer_cert,
              as_json=(way == "json"), full=True, no_ext=no_ext)


# 需要取值的选项（其余 --xxx 一律视为开关）
_VALUE_OPTS = ("--csv", "--csv-mode", "--issuer", "--paths-from", "--pattern")


def read_paths_from(src):
    """从列表文件（src == '-' 表示 stdin）逐行读输入路径（避开 ARG_MAX）"""
    if src == "-":
        stream, closer = sys.stdin, None
    else:
        try:
            stream = open(os.path.expanduser(src), encoding="utf-8")
        except OSError as e:
            print(f"错误: 无法读取路径列表 {src}: {e}", file=sys.stderr)
            sys.exit(1)
        closer = stream
    out = []
    try:
        for line in stream:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    finally:
        if closer is not None:
            closer.close()
    return out


def parse_args(args):
    """顺序扫描 argv → (paths, opts, flags)"""
    paths, opts, flags = [], {}, set()
    i = 0
    while i < len(args):
        a = args[i]
        if a in _VALUE_OPTS:
            if i + 1 >= len(args):
                print(f"错误: {a} 缺少值", file=sys.stderr)
                sys.exit(1)
            opts[a] = args[i + 1]
            i += 2
        elif a.startswith("--"):
            flags.add(a)
            i += 1
        else:
            paths.append(a)
            i += 1
    return paths, opts, flags


def main():
    check_cryptography_version()
    args = sys.argv[1:]
    if not args:
        interactive()
        return
    if "-h" in args or "--help" in args:
        print(__doc__)
        return

    paths, opts, flags = parse_args(args)
    csv_file = opts.get("--csv")
    csv_mode = opts.get("--csv-mode") or "wide"
    issuer_path = opts.get("--issuer")
    paths_from = opts.get("--paths-from")
    pattern = opts.get("--pattern") or DEFAULT_PATTERN
    as_json = "--json" in flags
    full = "--full" in flags
    no_ext = "--no-ext-columns" in flags

    if paths_from is not None:
        if not paths_from:
            print("错误: --paths-from 需要列表文件名（或 - 表示 stdin）",
                  file=sys.stderr)
            sys.exit(1)
        paths += read_paths_from(paths_from)

    if not paths:
        print(__doc__)
        sys.exit(1)
    if csv_file == "":
        print("错误: --csv 需要输出文件名", file=sys.stderr)
        sys.exit(1)

    issuer_cert = load_cert(issuer_path) if issuer_path else None
    run_batch(paths, csv_file, csv_mode, issuer_cert, as_json, full, no_ext,
              pattern)


# 模块级执行：import 后直接调用 parse_response() 也能得到可读 OID 名
_build_oid_map()


if __name__ == "__main__":
    main()
