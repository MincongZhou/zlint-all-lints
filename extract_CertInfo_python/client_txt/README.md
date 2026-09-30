# client_txt —— 从 CFCA「txt 表格导出」抽取证书

目标目录 `certs/CFCA订户证书_client/` 里**没有 .der 文件**，只有 7 份 SQL\*Plus 导出的文本表格，
证书以 base64 DER 放在 `CERT_ENTITY` 列里。本目录的脚本把它们抽成每张一个 `.der`，
**产物命名与链路都对齐 `certs/CFCA订户证书_client_draft/`**（`1.csv` → `预处理-260914.csv` →
`certs_all/` → `国密证书/`），只把最前面一步换掉。

## 脚本

| 文件 | 作用 |
|---|---|
| `txt_table_to_csv.py` | txt 表格 → **标准「预处理 CSV」**（`CERT_ENTITY,NOT_BEFORE`，行尾 `,<14位时间>` 作记录边界）+ 来源索引 |
| `run_client_txt.sh` | 一键串起 ① 本目录脚本 → ② `csv_b64_to_certs.py` → ③ `split_gm_certs.py`（→ ④ `extract_cert_fields.py` 可选） |
| `README.md` | 本文件 |

## 用法

```bash
# 默认：输入 certs/CFCA订户证书_client，输出 certs/CFCA订户证书_client_extract
./extract_CertInfo_python/client_txt/run_client_txt.sh

# 指明输入/输出；加 --force 才允许覆盖上轮产物
./extract_CertInfo_python/client_txt/run_client_txt.sh <输入目录|txt> <输出目录> --force

# 只想要预处理 CSV / 来源索引，不起后面两步
python3 extract_CertInfo_python/client_txt/txt_table_to_csv.py certs/CFCA订户证书_client --out-root <输出目录>

# 追加第 ④ 步（非国密证书的字段宽表，慢）
./extract_CertInfo_python/client_txt/run_client_txt.sh --with-fields
```

## 产物（默认输出目录 `certs/CFCA订户证书_client_extract/`）

与 `_draft` 同名同构，只多一张来源索引：

```
预处理-<yymmdd>.csv   CERT_ENTITY,NOT_BEFORE（与 csv_b64_to_certs.py 直接兼容；
                      日期取运行当天，可用 --csv-name 覆盖）
txt_source_index.csv  来源索引宽表（见下）
certs_all/            每张证书一个 .der（命名 <序号>_<序列号>.der）
certs_all.jsonl       每张证书的 idx + cert_b64（也可喂 csv_b64_to_certs.py --from-jsonl）
certs_all_index.csv   csv_b64_to_certs.py 的对照表
国密证书/ 国密证书.jsonl 国密证书清单.txt      只含 SM2/SM3 的 16 张
非国密证书/                                    其余 203 张
split_gm_index.csv    国密判定的逐张明细（曲线 OID / 签名 OID）
```

`txt_source_index.csv` 列：`idx, source_file, line_no, col, status, dup_of, serial_txt,
cert_serial_hex, not_before_txt, not_before_precision, not_before_csv, not_before_utc,
not_after_utc, diff_seconds, der_len, der_sha256, is_ca, is_gm, subject, issuer,
chunk_lines, error`。
`status` 取值：`ok` / `dup`（同一张证书重复出现）/ `no_der`（表里该行没有 base64）/ `b64_error` / `der_error`。

## 两种版式（脚本自动识别）

* **箱式**（`+---+ / | a | b |`）：`ovaudit / evocaaudit / eveccaudit / oveccaudit / dveccscaudit / evrootaudit`。
  表头 `SERIAL_NUMBER | NOT_BEFORE | CERT_ENTITY[ | CERT_ENTITY2]`，base64 完整。
* **SQL\*Plus 裸输出**：`dvocaaudit.txt`。列头与 `----` 分隔线分页重复，长列按 `LINESIZE 1000` 折行，
  记录以 `<SN> <DD-MON-YY>` 行开始。
  ⚠ 该版式里 `CERT_ENTITY2` 整列丢失、超长 base64 无法可靠区分——脚本按「SN 行之后的所有 base64
  片段都属于 `CERT_ENTITY`」处理，`chunk_lines` 列记录片段行数便于人工核查。

## 已知口径 / 坑

* **时区**：表里 `NOT_BEFORE` 是 **UTC+8（北京）**，证书内部 ASN.1 时间是 **UTC**，
  `diff_seconds` 期望恒为 **+28800**；`dvocaaudit.txt` 只有日期精度（`DD-MON-YY`），
  其 6 行不参与时区校验（`not_before_precision=date`）。
* **去重**：默认按 DER SHA-256 去重（保留首次出现，其余标 `dup`）。`evrootaudit.txt` 里同一序列号
  带/不带前导 0 各出现一次，但 `CERT_ENTITY` 是 NULL，所以只落 8 行 `no_der`。
* **无 DER 的行**：`evrootaudit.txt` 的 8 行只有序列号和日期（**5 个唯一序列号**，其中 3 个带/不带前导 0
  各出现一次），**notAfter 无从得知**，不会出现在 `certs_all/`。这 5 个都是根/中间 CA，
  其中 3 个本地已有：`B4CF943266`(2012-08-08)=CN=CFCA EV OCA、`F9DF6ADFF564BEA68B82`(2015-03-25)=CN=CFCA OV OCA、
  `7D74A24246794D9DC4C7`(2022-10-17)=CN=CFCA DV OCA（见 `certs/CFCA_CA证书/`）；
  `88266DAF4A`(2012-08-08)、`225A3F7974BD6223BFF3`(2015-03-25) 本地没有。
* **国密**：`zlint`/`zcrypto` 与 Python `cryptography` 都不支持 SM2/SM3，这 16 张由
  `split_gm_certs.py` 单独落到 `国密证书/`，不要算作"已覆盖"。
* `*.txt:Zone.Identifier` 是 Windows 下载残留，脚本已自动跳过。
* 索引里 `is_ca` **留空**表示该证书**没有 BasicConstraints 扩展**（219 张里有 35 张），
  `True/False` 才表示扩展存在时的取值。本批 219 张**没有一张 ca=True**（全是订户/OCA 操作员类终端证书）。
* `zlint` 对这批证书同样适用：`非国密证书/` 可直接作为 `run_all.sh` 的输入目录。

## 实测结果（2026-09-18）

输入 7 个 txt / 227 数据行 → **219 张证书**（8 行无 DER，去重丢弃 0）→ 国密 16 + 非国密 203；
证书有效期 notBefore `2012-08-08 06:10:41Z ~ 2026-07-29 04:26:15Z`、
notAfter `2026-07-04 17:07:16Z ~ 2048-09-12 08:31:04Z`（截至 2026-09-18 已过期 149/219）。
抽取结果已用 `openssl` 独立复核（219/219 subject/issuer/serial/有效期/指纹一致，
base64 ↔ DER 长度严格吻合，无截断）。
