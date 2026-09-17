# extract_CertInfo_python

证书 / CRL 字段提取与证书数据预处理的 Python 脚本集。

- 运行时依赖：Python 3 + `cryptography >= 42.0`（`extract_cert_fields.py`、`extract_crl_fields.py` 启动时自动检查版本，不满足直接退出）
- 所有 CSV 输出为 UTF-8 with BOM，Excel 双击打开不乱码
- 目录作为输入时递归查找对应扩展名：证书类脚本为 `.pem` / `.crt` / `.cer` / `.der`，CRL 脚本为 `.pem` / `.der` / `.crl`

## 脚本索引

| 脚本 | 用途 | 输入 | 输出 |
|---|---|---|---|
| `extract_cert_fields.py` | 证书全字段提取 | 证书文件 / 目录 | 终端文本、JSON、CSV |
| `extract_crl_fields.py` | CRL 吊销清单 + 全字段提取 | CRL 文件 / 目录 | 终端文本、JSON、CSV |
| `preprocessed_csv.py` | SQL*Plus spool → 预处理 CSV | spool 文本 | CSV（可附带比对报告） |
| `csv_b64_to_certs.py` | 预处理 CSV / JSONL → 证书仓库与证书文件 | 预处理 CSV 或 JSONL | JSONL、DER/PEM 文件、对照表 CSV |
| `split_gm_certs.py` | 国密（SM2/SM3）证书筛选 | 证书目录或 JSONL | 子集 JSONL、文件名清单、对照表 CSV、证书文件 |

---

## extract_cert_fields.py

用 `cryptography` 解析 X.509 证书的字段，覆盖 RFC 5280 结构：基础字段（version / serialNumber / signatureAlgorithm / issuer / validity / subject / subjectPublicKeyInfo / signature）、issuer 与 subject 的逐条 Name 属性、公钥参数、全部扩展、SHA-256 与 SHA-1 指纹。

指纹为 **64 位大写十六进制、不带冒号**（与 `run_ocsp_batch.py` 的 CSV、`run_cert_crl_ocsp.py` 的 `index.csv` 口径一致，便于直接粘进 Excel 对账）；其余 hex 字段（SKI / AKI / SCT log_id / 签名值 / 扩展原文）仍保持冒号分隔。

```bash
python3 extract_cert_fields.py <证书路径> [--der] [--json] [--out 输出文件]
python3 extract_cert_fields.py <证书路径> --csv 输出.csv [--csv-mode fields|summary|wide]
python3 extract_cert_fields.py                      # 无参数 → 交互模式
```

| 参数 | 说明 |
|---|---|
| `--der` | 强制按 DER 解析；不给则先试 PEM，失败自动回退 DER |
| `--json` | 输出结构化 JSON，而非终端文本 |
| `--out` | 把终端文本/JSON 写入文件；与 `--csv` 互斥 |
| `--csv` | 输出 CSV |
| `--csv-mode` | `fields` / `summary` / `wide`；缺省时单个证书用 `fields`，多张用 `wide` |

CSV 三种模式：

| 模式 | 结构 | 适用 |
|---|---|---|
| `fields` | 每字段一行，列 `file,field,value`，嵌套结构逐层摊平 | 单证书逐字段查看 |
| `summary` | 每证书一行，约 30 个常用列 | 精简汇总 |
| `wide` | 每证书一行，固定基础列 + 按扩展 OID 命名的列；**另输出同名 `_extensions.csv` 扩展长表**（每行一个扩展，值为完整 JSON） | 完整性检查、按字段批量比对 |

`wide` 模式的列命名：`ext.<扩展名>.<字段>`，例如 `ext.SUBJECT_ALTERNATIVE_NAME.names_count`、`ext.BASIC_CONSTRAINTS.path_length`；同一列在所有证书中语义一致。多值（SAN 域名、SCT 列表等）合并在同一单元格内（`; ` 分隔），不按位置拆列；未知 OID 以完整点分串作列名。

行为说明：

- 单张证书解析失败会以非零状态退出；批量时逐条报错并继续，末尾汇总成功/失败数，非证书文件（如 CRL）跳过并告警
- `signature_hash_algorithm` 与公钥解析均做降级保护：算法不被 `cryptography` 支持时只标记该字段，不影响其余字段输出。例如国密 SM2 证书的 `public_key` 会输出 `{"type": "unsupported", "error": ..., "algorithm_oid": ...}`，对应列 `pubkey_type=unsupported`、`pubkey_bits` / `pubkey_curve` 为空

---

## extract_crl_fields.py

解析 CRL 的吊销清单与完整字段，字段口径与 `extract_cert_fields.py` 对齐。CRL 级覆盖 version / issuer（逐条属性）/ thisUpdate / nextUpdate / signatureAlgorithm / signature / tbsCertList 指纹 / 全部扩展（CRLNumber、AKI、IDP、DeltaCRLIndicator、FreshestCRL、AIA、IAN、未知扩展原文等）；条目级覆盖 serialNumber（hex + dec）/ revocationDate / CRLReason / InvalidityDate / CertificateIssuer / 其它条目扩展。

**输入就是本地 CRL，本脚本不联网**（下载 CRL 是 `check_certs_python/check_crl.py`、`run_cert_crl_ocsp.py` 的事）。可以直接传自己准备的 CRL：

- 单个文件：显式路径不看扩展名（`my.crl`、`x.bin` 都能读）
- 目录：递归匹配 `.pem` / `.der` / `.crl`
- 多路径混传；`--csv 输出.csv` 的输出文件会自动从输入中排除，避免"上次的输出被当输入"
- 同一目录混放多个体系的 CRL 时会全部解析，靠 `issuer_cn` / `crl_number` / `tbs_sha256` 区分；要确认归属就加 `--issuer` 验签
- 指纹（`sha256` / `sha1` / `tbs_sha256`）为 **64 位大写十六进制、不带冒号**；其它 hex 字段保持冒号分隔。`sha256` 是整份 CRL（含签名）的指纹，`tbs_sha256` 是不含签名的"内容指纹"——ECC 的 CRL 每次重签整体指纹都会变，判断吊销数据有无变化应看 `tbs_sha256` 或 `crl_number`
- **同一份 CRL 传入多次就输出多行**（`wide` / `entries` 都不做内容去重）：`run_all.sh` 的 CRL 字段步会把每张证书的 `crl.pem` 都传进来，19 张 CA 证书实际只有 4 份唯一 CRL，于是宽表 15 行、条目表 85 行（真实吊销记录 14 条）。统计前按 `tbs_sha256` 去重即可；**不要用 `crl_number`**——各 CA 的计数器独立（CFCA 的 `Global ECC ROOT G2` 与 `Global RSA ROOT G2` 都发到 913）

```bash
python3 extract_crl_fields.py <crl 文件|目录> ... [--csv 输出.csv] [--issuer 签发者证书]
python3 extract_crl_fields.py crl.pem --full          # 终端打印全部字段
python3 extract_crl_fields.py crl.pem --json          # JSON 输出
python3 extract_crl_fields.py crls/ --csv w.csv --csv-mode wide
python3 extract_crl_fields.py                         # 无参数 → 交互模式
```

| 参数 | 说明 |
|---|---|
| `--csv` | 输出 CSV |
| `--csv-mode` | `revoked`（默认）/ `entries` / `wide` / `fields` |
| `--no-ext-columns` | `wide` 模式下只输出 25 个固定列，列数恒定 |
| `--issuer` | 传入签发者证书：验证 CRL 签名，并比对证书 subject 与 CRL issuer 的 DN |
| `--full` | 终端打印全部字段 |
| `--json` | JSON 输出 |

`--csv-mode` 取值：

| 模式 | 结构 |
|---|---|
| `revoked`（默认） | 每条吊销记录一行，精简 5 列，兼容旧版 |
| `entries` | 每条吊销记录一行，全字段（含失效日期、条目扩展） |
| `wide` | 每个 CRL 一行（头部 + 扩展列），另输出副表 `<name>_entries.csv` |
| `fields` | 每字段一行，列 `file,field,value`，字段零丢失 |

`wide` 模式不把吊销条目合并进单元格（大 CA 的 CRL 可达数万条，会超出 Excel 单元格 32767 字符上限），逐条信息在 `*_entries.csv` 中；主表只保留吊销条数。

---

## preprocessed_csv.py

把 SQL*Plus 导出的 spool 文本（`set linesize 1000` 会把证书 base64 折成固定宽度）还原成下游可直接消费的预处理 CSV。

```bash
python3 preprocessed_csv.py <spool 文件> [--out 输出.csv]
python3 preprocessed_csv.py <spool 文件> --verify 已有预处理.csv
```

| 参数 | 说明 |
|---|---|
| `--out` | 输出路径，默认 `<输入名>_rebuilt.csv` |
| `--verify` | 重建后与指定的已有预处理 CSV 逐项比对 |
| `--header` | 重写的表头行，默认 `CERT_ENTITY,NOT_BEFORE` |
| `--trim` | 去掉每行行尾空格 |
| `--drop-blank` | 丢弃空行 |
| `--crlf` | 使用 CRLF 换行（默认 LF） |

实现的清洗规则：

1. 丢弃以 `SQL>` 开头的命令回显行
2. 丢弃"第二条 `-----` 分隔线"之前的全部内容（含 SQL 语句续行）
3. 丢弃列头文字行（`SIGNATURE_CERT` / `NOT_BEFORE` / `CERT_ENTITY`）与 `-----` 分隔线；分页导致列头重复出现时一并丢弃
4. 丢弃结尾统计行 `N rows selected.`
5. 重写一行表头
6. 第二列改写为 `,<日期>`——下游以此行的前导逗号判定记录边界
7. 其余行原样保留（base64 折行与补位空格不动，消费端自行 strip）

`--verify` 输出两类比对结果：行级差异（行数、换行符、前若干处不同）与证书级差异（把每条记录的 base64 拼回 DER 后按 SHA-256 比对，给出记录数、指纹不同数、各自独有的记录数）。证书级一致即表示清洗结果的内容正确。

---

## csv_b64_to_certs.py

把预处理 CSV（或 JSONL 仓库）拆成两个产物：一份以 base64 保存证书的 JSONL 仓库，以及每张证书一个文件（DER/PEM），供 zlint、openssl 等只接受文件路径的工具使用。

```bash
python3 csv_b64_to_certs.py <预处理.csv> [--out-dir 目录] [--jsonl 仓库.jsonl] [--index 对照表.csv]
python3 csv_b64_to_certs.py <预处理.csv> --no-files
python3 csv_b64_to_certs.py <仓库.jsonl> --from-jsonl [--out-dir 目录]
python3 csv_b64_to_certs.py <预处理.csv> --limit 5
```

| 参数 | 说明 |
|---|---|
| `--out-dir` | 证书文件目录，默认 `<输入目录>/certs_all` |
| `--jsonl` | JSONL 输出路径，默认 `<输入目录>/certs_all.jsonl` |
| `--format` | `der`（默认）/ `pem` |
| `--index` | 另输出对照表 CSV：`idx,file,ok,serial_hex,sha256,not_before_csv,not_before_cert_utc,diff_seconds,subject` |
| `--from-jsonl` | 输入是 JSONL 仓库，从它重新生成证书文件；此时默认不回写 JSONL |
| `--no-files` | 只输出 JSONL |
| `--limit` | 只处理前 N 条 |

输入格式约定：

- 表头行以 `CERT_ENTITY` 开头，跳过
- 证书 base64 的折行逐行 strip 后拼接
- **以逗号开头的行结束一条记录**，逗号后为第二列（日期）
- 纯空白行跳过

输出约定：

- JSONL 每行为 `{"idx": n, "cert_b64": "..."}`，`cert_b64` 为去掉折行与空白后的单行 base64；`idx` 与输入记录顺序一一对应
- 证书文件名为 `<5 位序号>_<序列号>.der|.pem`；重名自动追加 `_2`、`_3`
- 某条记录 base64 解码失败或证书解析失败时，仍写入 JSONL（仓库保持完整），但不生成文件；末尾列出这些记录的 `idx`，进程以退出码 1 结束
- `--jsonl` 指向输入文件本身时直接报错退出（避免先清空再读取）

---

## split_gm_certs.py

筛选国密证书。`cryptography` 与 zcrypto 均不支持 SM2 曲线与 SM3，国密证书在 zlint 侧无法产出任何规则结果，需要单独归类。

```bash
python3 split_gm_certs.py <证书目录|文件...> [--jsonl 子集.jsonl] [--files 清单.txt] [--index 对照表.csv] [--out-dir 目录] [--out-dir-non-gm 目录]
python3 split_gm_certs.py <仓库.jsonl> --from-jsonl [...]
python3 split_gm_certs.py certs/certs_all --out-dir 国密证书 --out-dir-non-gm 非国密证书
```

| 参数 | 说明 |
|---|---|
| `--from-jsonl` | 输入是 JSONL 仓库 |
| `--jsonl` | 输出国密子集 JSONL，格式与输入一致，保留原 `idx` |
| `--files` | 输出国密证书文件名清单（每行一个） |
| `--index` | 输出对照表 CSV：`idx,file,is_gm,curve_oid,curve_name,sig_oid,sig_name,serial_hex,sha256,subject,pk_error,error` |
| `--out-dir` | 把国密证书导出为独立文件 |
| `--out-dir-non-gm` | 把非国密证书导出为独立文件（与 `--out-dir` 一次即可完成双向分类） |
| `--format` | `--out-dir` / `--out-dir-non-gm` 的文件格式，`der`（默认）/ `pem` |

判定依据（任一命中即为国密）：

| OID | 含义 | 取值方式 |
|---|---|---|
| `1.2.156.10197.1.301` | SM2 曲线 | 按 ASN.1 结构解析 `subjectPublicKeyInfo` 的算法参数 |
| `1.2.156.10197.1.501` | SM2-with-SM3 签名算法 | `cert.signature_algorithm_oid` |

曲线 OID 由脚本内置的最小 TLV 解析器从证书 DER 中取出；若结构解析失败，回退为从 `cert.public_key()` 的异常信息中提取 OID。`--out-dir` 导出的文件名规则为 `<5 位序号>_<序列号>.der|.pem`。

运行时输出统计：扫描总数与解析失败数、国密证书数（并区分"仅公钥为 SM2"与"仅签名为 SM2-with-SM3"两类混搭情况）、签名算法 OID 分布、曲线 OID 分布。
