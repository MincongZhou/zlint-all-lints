# zlint-all-lints

对输入的 PKI 对象（**证书 / CRL / OCSP 响应**）运行 zlint **全部规则**，输出带 `type` 字段的 JSON，区分每条规则的归属：**CA**（证书）、**CRL**（吊销列表）、**OCSP**（OCSP 响应）。

Run **all** zlint rules against a PKI object (certificate / CRL / OCSP response) and export JSON with a `type` field that classifies every rule as **CA**, **CRL**, or **OCSP**.

> 规则总数随本地 zlint 源码版本变化，不在文档中写死：以任一输出 JSON 的 `meta.total_lints` 为准（`./build.sh` 编译完会直接打印）。

> 常用任务的完整操作步骤（证书/CRL 字段提取、批量查 OCSP、三类规则一起跑）见 **[RUNBOOK.md](RUNBOOK.md)**。

## 输入类型 / Input types

`zlint-all-lints` 按官方 CLI 的顺序（证书 → CRL → OCSP）自动识别输入文件类型；输入是哪类对象，就**真实执行**哪类规则，其余两类规则标记为 `NA`：

| 输入对象 | 真实执行的规则 | 标 `NA` 的规则 |
|----------|----------------|----------------|
| 证书 `cert` | 全部 CA 规则 | 全部 CRL + OCSP 规则 |
| CRL `crl`   | 全部 CRL 规则 | 全部 CA + OCSP 规则 |
| OCSP `ocsp` | 全部 OCSP 规则 | 全部 CA + CRL 规则 |

自动识别偶尔会误判时，可用 `-type cert|crl|ocsp` 强制指定。

## 规则分布 / Rule counts

各类型规则数量随 zlint 版本变化，以输出 JSON 的 `meta.type_counts` 为准：

| type | 说明 |
|------|------|
| CA   | 证书类规则 |
| CRL  | 吊销列表类规则 |
| OCSP | OCSP 响应类规则 |

`go.mod` 通过 `replace` 指令复用本地 zlint v3 源码（`../zlint/v3`），无需联网拉取依赖。

## 构建 / Build

```bash
./build.sh                                  # 推荐：go mod tidy + 编译两个工具 + 打印当前规则数
```

或手动编译：

```bash
go build -o zlint-all-lints .
go build -o extract-cert ./cmd/extract-cert
```

上游 zlint 更新后（`cd ../zlint && git pull`）重跑 `./build.sh` 即可，依赖会由 `go mod tidy` 同步，规则数变化会直接打印。

## 使用 / Usage

```bash
./zlint-all-lints -cert <file.pem|file.der> [-type cert|crl|ocsp|auto] [-out results.json] [-csv results.csv] [-pretty=false]
```

支持 PEM 与 DER 格式的**证书、CRL、OCSP 响应**。不指定 `-out` 时默认写入 `lint_results.json`。
指定 `-csv` 时，会在 JSON 之外**再生成一份同结构的 CSV**，方便在 Excel / WPS 里筛选排序：

```bash
./zlint-all-lints -cert crl.pem -out results.json -csv results.csv
./zlint-all-lints -cert ocsp.der -type ocsp -out results.json          # 强制按 OCSP 解析
```

## 输出示例 / Output sample

```jsonc
{
  "meta": {
    "input_file": "crl.pem",
    "input_type": "crl",                      // cert / crl / ocsp
    "subject": "CN=Test CRL",
    "total_lints": 433,                       // 规则总数：随 zlint 版本变化
    "type_counts": { "CA": 414, "CRL": 18, "OCSP": 1 }   // 示例值，实际以运行为准
  },
  "lints": [
    {
      "name": "e_cab_crl_has_valid_reason_code",
      "type": "CRL",
      "description": "Only the following CRLReasons MAY be present: 1, 3, 4, 5, 9.",
      "citation": "BRs: 7.2.2",
      "source": "CABF_BR",
      "status": "error",
      "details": "reason code 0 is not allowed"
    }
  ]
}
```

> `meta.input_type` 标识实际识别的输入类型（`cert` / `crl` / `ocsp`）。

### CSV 输出示例 / CSV output sample

```csv
name,type,description,citation,source,status,details
e_adobe_extensions_legacy_multipurpose_criticality,CA,"If present, ...",7.1.2.3.m,CABF_SMIME_BR,NA,
e_basic_cons_not_critical,CA,"The BasicConstraints extension MUST be marked critical in CA certificates.",BRs: 7.1.2.7.8,CABF_BR,error,"BasicConstraints not marked critical"
```

`status` 取值：`pass` / `error` / `warn` / `info` / `NA`（不适用）/ `NE`（未生效）。

## 批量跑 / Batch run

`run_batch.sh` 遍历一个目录下的所有对象（证书 / CRL / OCSP），每个对象跑完立即把 CSV 合并进带文件名的总 CSV；**默认只保留汇总表**，单对象的 JSON/CSV 合并完即删（边跑边删，避免成百上千个中间文件占磁盘），加 `--detail` 才保留：

```bash
./run_batch.sh <对象目录> [输出目录] [--detail]   # 输出目录默认 ./results
```

例：

```bash
./run_batch.sh certs results               # 只留汇总表（默认）
./run_batch.sh certs results --detail      # 额外保留每个对象的 JSON/CSV
```

默认产物（只留汇总）：

```text
results/
└── results_summary.csv        # 汇总：全部对象 × 全部规则，首列 cert 为文件名
```

`--detail` 产物（加选项后）：

```text
results/
├── baidu.pem → baidu.csv               # 单对象 CSV（行数 = meta.total_lints）
├── baidu.pem → baidu.json              # 单对象 JSON
├── crl.pem   → crl.csv                 # CRL 输入行数相同（任何输入下恒为全部规则数）
└── results_summary.csv                 # 汇总：全部对象 × 全部规则，首列 cert 为文件名
```

批量跑大量对象时也建议把输出目录指到内存盘（如 `/dev/shm/zlint_results`），跑完释放、不占磁盘。

汇总 CSV 表头比单对象多一列 `cert`，可直接在 Excel 里按文件、按 `status`、按 `type` 透视筛选。

## 内置示例样本 / Sample objects

`certs/` 目录内置了一组可直接开跑的样本：

- 4 张示例证书：`27monthsEv.pem`、`baidu.pem`、`CNWithoutSANSeptember2021.pem`、`SANIPv4Address.pem`
- 61 个 CRL 样本（来自 zlint 官方 testdata，覆盖各种合规/不合规场景）
- 4 个 OCSP 响应样本（`ocspThisUpdateAfterProducedAt`、`ocspThisUpdateNotAfterProducedAt`，各含 DER 与 base64 格式）

```bash
./run_batch.sh certs results   # 一把跑完全部样本
```

## Python 辅助脚本 / Python helper scripts

项目还提供一组 Python 脚本（`check_certs_python/`、`extract_CertInfo_python/`），覆盖 Go 工具未涉及的场景（OCSP 状态查询、SCT 提取等）。依赖：`pip install cryptography`。

### check_certs_python/ —— OCSP 查询与批量 lint 封装

**`check_ocsp.py`**：联网查询证书的 OCSP 状态（GOOD / REVOKED / UNKNOWN）

```bash
python3 check_ocsp.py <证书路径> [签发者证书路径] [--der] [--timeout 秒] [--respout 文件]
python3 check_ocsp.py <证书路径> --status     # 只输出状态，适合脚本调用
python3 check_ocsp.py                          # 无参数 → 交互模式
```

- 从 AIA 扩展自动提取 OCSP URL；签发者证书可本地传入，否则从 CA Issuers 地址自动下载
- http 请求失败自动兜底 https、自动重试
- 证书/签发者证书 PEM/DER 自动识别，`--der` 只表示优先按 DER 解析，标错也会自动回退
- `--respout <文件>`：把 responder 返回的**原始 OCSP 响应(DER)** 保存到文件，供 zlint 跑 OCSP 规则：`zlint -format der -longSummary resp.der`（或 `./zlint-all-lints -cert resp.der`）
- `--status` 模式：stdout 只输出 `GOOD` / `REVOKED`（带吊销时间）/ `UNKNOWN`，错误走 stderr + 非零退出码，便于管道和脚本化调用
- CertID 摘要默认 **SHA-1**（与 `openssl ocsp` 一致，兼容性最好）；部分 responder（DigiCert / 微软等）不接受 SHA-256 的 CertID，会回 `MALFORMED_REQUEST` / `UNAUTHORIZED`，个别仅支持 SHA-256 的 responder 才用 `--sha256`

**`run_ocsp_batch.py`**（根目录）：`check_ocsp.py` 的批量封装——目录递归收集证书逐张查状态，失败不中断；可选 `--csv` 输出汇总表（`cert/status/detail` 三列，utf-8-sig 便于 Excel）：

```bash
python3 run_ocsp_batch.py certs/                                  # 目录批量
python3 run_ocsp_batch.py a.pem b.pem certs/ --csv results/ocsp_batch.csv
python3 run_ocsp_batch.py certs/ --timeout 10 --der               # 调超时 / DER 证书
python3 run_ocsp_batch.py                                         # 无参数 → 交互模式
```

交互模式多个路径建议用**逗号分隔**；含空格的路径可用引号包裹（不加引号也能识别——按"与相邻段拼接后路径存在"自动合并），兼容中文引号。

**`check_crl.py`**：从证书 CDP（CRL Distribution Points）扩展下载 CRL，DER/PEM 自动识别并统一转成 PEM，供 zlint 跑全部 CRL 类规则

```bash
python3 check_crl.py <证书路径> [--timeout 秒] [--out 输出.pem]
python3 check_crl.py                            # 无参数 → 交互模式
./zlint-all-lints -cert crl.pem                # 拿到 crl.pem 后直接喂 zlint
```

- 自动遍历证书 CDP 里的全部 http(s) 分发点，逐个尝试直到下载成功
- 下载内容会校验确实是 CRL（防 HTML 错误页/误传证书）

**`run_zlint.py`**：`run_batch.sh` 的 Python 封装（支持证书/CRL/OCSP 的**目录或单个文件**），支持交互模式与 `--jsonl` 转换。默认同 `run_batch.sh` 只留汇总表；`--detail` 透传给底层脚本以保留单对象 JSON/CSV，`--jsonl` 需要读 JSON 源文件，会自动保留：

```bash
python3 run_zlint.py <对象目录|文件> [输出目录] [--timeout 秒] [--jsonl] [--detail]
python3 run_zlint.py certs/baidu.pem results/    # 单文件：自动临时目录，跑完清理
python3 run_zlint.py certs --detail              # 批量跑并保留每个对象的 JSON/CSV
python3 run_zlint.py certs --jsonl               # 跑完把 JSON 转 JSONL（自动保留源文件）
python3 run_zlint.py                            # 无参数 → 交互模式
```

### extract_CertInfo_python/ —— 证书信息提取

| 脚本 | 作用 | 用法 |
|------|------|------|
| `extract_sct.py` | 提取证书里的 SCT（证书透明度时间戳）：log_id / timestamp / 签名算法 | `python3 extract_sct.py <证书> [--der]` |
| `extract_org.py` | 提取证书**主体（subject）与签发者（issuer）**的组织名（O 字段）及各自 DN | `python3 extract_org.py <证书> [--der]` |
| `extract_cert_fields.py` | 用 cryptography 解析证书**所有字段**：版本/序列号/签名算法/签发者/有效期/主体逐条属性/公钥参数/签名值/指纹，及**全部扩展**逐项结构化解析（SAN/IAN、KU/EKU、BasicConstraints、SKI/AKI、AIA、CDP、策略与约束、SCT、未知扩展 hex 原文…） | `python3 extract_cert_fields.py <证书> [--der] [--json] [--out 文件]`<br>`--csv 文件`：单证书→字段清单表，目录/多证书→wide 宽表（另出扩展长表） |
| `openssl_script.py` | 调用 `openssl x509` 提取 subject / issuer / 有效期 | 交互输入证书路径 |
| `extract_crl_fields.py` | **CRL 版**字段提取：吊销清单（序列号 16/10 进制 + 时间 + 原因码）+ CRL 全字段（头字段 / 全部扩展 / 每条吊销记录），四种 CSV 模式与 `extract_cert_fields.py` 对齐 | `python3 extract_crl_fields.py <crl\|目录> [--csv 文件] [--csv-mode ...] [--full] [--json]` |

> 提示：`extract_sct.py` 需要 `cryptography >= 42.0`（原生支持 CT Precertificate SCTs 扩展解析）。

**`extract_cert_fields.py --csv` 的三种模式**（自动选择：单个证书 → `fields`，目录/多证书 → `wide`；`--csv-mode fields|wide|summary` 可显式指定）：

```bash
# fields：每个字段一行，三列 file,field,value（嵌套结构逐层摊平，不丢字段）
python3 extract_CertInfo_python/extract_cert_fields.py certs/baidu.pem --csv baidu_fields.csv

# wide（推荐）：每行一张证书 + 按 OID 命名的全字段列，另出一张扩展级长表
python3 extract_CertInfo_python/extract_cert_fields.py certs/ --csv certs_wide.csv
#   → certs_wide.csv（宽表）+ certs_wide_extensions.csv（长表，每行一个扩展，值为完整 JSON）

# summary：每行一张证书，仅常用字段成列（比 wide 精简）
python3 extract_CertInfo_python/extract_cert_fields.py certs/ --csv s.csv --csv-mode summary
```

- **`wide` 模式的列怎么命名**（关键：用 OID 名而非位置下标，保证同一列在所有证书中语义一致）
  - 基础列固定 26 个：`file / format / version / serial_dec / serial_hex / subject(+cn,o,ou,c) / issuer(+cn,o) / not_before / not_after / valid_days / pubkey_type / pubkey_bits / pubkey_curve / sig_alg / sig_oid / sig_hash / sha256 / sha1 / ext_count`
  - 扩展列形如 `ext.SUBJECT_ALTERNATIVE_NAME.present` / `.critical` / `.names_count` / `.names`；未知 OID 退回完整点分串（如 `ext.1.3.6.1.4.1.311.21.10.value_hex`）
  - 多值（SAN 域名、SCT 列表、AIA 地址等）**合并进同一单元格**（`; ` 分隔）并另给 `_count` 列，不按位置拆列，避免列爆炸与跨证书语义错位
  - 实测 10 张真实证书：98 列（基础 26 + 扩展 72），填充率 76%；同样数据若按位置完全展平则是 343 列、填充率仅 40%
- `fields` 模式：三列 `file,field,value`，每个字段一行，嵌套结构逐层摊平（如 `cert.extensions[4].parsed.names[1]` → `DNS: baidu.com`），不丢任何字段
- `summary` 模式：每张证书一行，常用字段成列（约 30 列：subject/CN/O、issuer、有效期与天数、公钥、签名算法、是否 CA、KU/EKU、SAN 域名、AIA OCSP、CDP、策略、SCT 数、扩展数、SHA-256）
- 目录递归查找 `.pem/.crt/.cer/.der`；非证书文件（CRL/OCSP 响应）自动跳过并在 CSV 中留一行 `error` 说明，不中断整体
- CSV 为 UTF-8 with BOM，Excel 双击打开中文不乱码

典型用途（配合 Excel 筛选或 `csv`/pandas 处理）：

```python
import csv
rows = list(csv.DictReader(open("certs_wide.csv", encoding="utf-8-sig")))
# 完整性检查：哪些证书缺 CRL 分发点
[x["file"] for x in rows if not x["ext.CRL_DISTRIBUTION_POINTS.present"]]
# 按字段批量测试：所有 ECDSA 证书
[x["file"] for x in rows if x["pubkey_type"] == "ECDSA"]
```

**`extract_crl_fields.py`** —— CRL 版字段提取（与 `extract_cert_fields.py` 同族）：吊销清单 + CRL 全字段

```bash
python3 extract_CertInfo_python/extract_crl_fields.py <crl 文件|目录> ... [--csv 输出.csv] [--csv-mode revoked|entries|wide|fields]
python3 extract_CertInfo_python/extract_crl_fields.py crl.pem                      # 终端逐行输出序列号
python3 extract_CertInfo_python/extract_crl_fields.py crls/ --csv revoked.csv      # 批量导出（含吊销时间/原因）
python3 extract_CertInfo_python/extract_crl_fields.py crl.pem --full               # 全字段：CRL 头 + 扩展 + 每条吊销记录
python3 extract_CertInfo_python/extract_crl_fields.py crl.pem --json               # 全字段 JSON
python3 extract_CertInfo_python/extract_crl_fields.py crls/ --csv wide.csv --csv-mode wide   # 宽表 + 副表 wide_entries.csv
python3 extract_CertInfo_python/extract_crl_fields.py crl.pem --csv f.csv --csv-mode fields  # 每字段一行（零丢失）
python3 extract_CertInfo_python/extract_crl_fields.py crl.pem --issuer ca.pem --full         # 顺带用签发者公钥验签
```

- 覆盖 CRL 级（version / issuer 逐条属性 / thisUpdate / nextUpdate / 签名算法与签名值 / tbsCertList 指纹 / SHA-256+SHA-1 指纹 / 全部扩展 `CRLNumber·AKI·IDP·DeltaCRLIndicator·FreshestCRL·AIA·IAN`）与条目级（`CRLReason·InvalidityDate·CertificateIssuer`）
- `--csv-mode` 四种：`revoked`（默认，精简 5 列）/ `entries`（每条吊销记录全字段）/ `wide`（每 CRL 一行 + 条目副表）/ `fields`（每字段一行，零丢失）
- 宽表列数 = 25 个固定列 + 每种扩展 3 列；加 `--no-ext-columns` 只输出固定列，跨批次列数恒定
- CRL 里只有吊销**序列号**（+吊销时间+原因码），不含证书本体；如需"哪张证书被吊销"，拿序列号去本地证书池反查
- 与 `check_crl.py` 组合，下载 + 解析一条龙：

```bash
python3 check_crl.py certs/baidu.pem --out crl.pem \
  && python3 extract_CertInfo_python/extract_crl_fields.py crl.pem --csv baidu_revoked.csv
```

### run_all.sh / run_all.py —— 一键跑完 4 个分析脚本

对单张证书依次跑完 `run_zlint.py`（zlint 全部规则）+ `extract_org.py`（组织名）+ `extract_sct.py`（SCT 时间）+ `check_ocsp.py`（OCSP 状态）：

```bash
./run_all.sh <证书路径> [输出目录]     # shell 版：只打印各脚本结果
python3 run_all.py <证书路径|证书目录> [输出目录]   # Python 版：额外汇总成 xlsx 大表
python3 run_all.py                     # 无参数 → 交互模式
```

- `run_all.py` 传**目录**则批量跑其中所有证书（递归查找 `.pem/.crt/.cer/.der`），每张证书一个子目录
- 输出 `results/<证书名>/<证书名>_report.xlsx`，共 5 个 sheet：`zlint` / `组织名` / `SCT时间` / `OCSP查询` / `汇总`
- `汇总` sheet 统一为三列 `type / 内容 / status`：zlint 行（内容=规则名，status=规则状态）、组织名行（status=组织名）、SCT时间行（内容=时间戳）、OCSP查询行（status=状态）
- 依赖：`pip install cryptography openpyxl`（xlsx 需要 openpyxl）

### run_cert_crl_ocsp.py —— 对一张证书跑齐 CA / CRL / OCSP 三类规则

zlint 对单个输入对象只真实执行其所属类型的规则（证书→CA 类、CRL→CRL 类、OCSP→OCSP 类，各类数量见 `meta.type_counts`），其余标 `NA`。本脚本把证书的**配套吊销对象**也取下来一起跑，三类规则全部真实执行：

```bash
python3 run_cert_crl_ocsp.py <证书路径|证书目录> [输出目录] [--timeout 秒] [--detail]
python3 run_cert_crl_ocsp.py                        # 无参数 → 交互模式
```

- 证书侧：`zlint-all-lints -cert <证书>`（全部 CA 类规则）
- CRL 侧：`check_crl.py` 从证书 CDP 下载 CRL 转 PEM → 跑全部 CRL 类规则
- OCSP 侧：`check_ocsp.py` 查 OCSP 并存原始 DER 响应 → 跑全部 OCSP 类规则
- CRL/OCSP 联网失败（无 CDP/无 OCSP 地址/网络不通）自动跳过该侧，不中断整体
- 批量时如遇重名证书文件，自动逐级补父目录前缀（`__` 连接）生成唯一名（如 `chain-20260611__CFCA DV OCA`），子目录名与汇总表 cert 列同用，不会互相覆盖

**默认精简模式**：每张证书三侧的结果合并进输出根下的三张汇总表后，中间 JSON/CSV 随跑随删；联网证据 `crl.pem` / `resp.der` 保留在该证书目录。加 `--detail` 则完整保留每张证书的 `cert/crl/ocsp` 的 `.json/.csv`。

```text
results/                    # 默认：只留三张汇总表 + 每证书的证据文件
├── ca_summary.csv          # 全部证书的证书侧汇总（首列 cert 为证书名）
├── crl_summary.csv         # CRL 侧汇总
├── ocsp_summary.csv        # OCSP 侧汇总
└── baidu/
    ├── crl.pem             # 证据：下载的 CRL（有则保留）
    └── resp.der            # 证据：原始 OCSP 响应（有则保留）
```

末尾打印三侧真实执行的 pass/error 统计。传**目录**则批量（每证书一个子目录，默认同样精简）。

批量输出结构（每个证书一个子目录，含 xlsx 大表和 lint 的 JSON/CSV/JSONL）：

```text
results/
└── baidu/
    ├── baidu_report.xlsx      # 5 个 sheet：zlint / 组织名 / SCT时间 / OCSP查询 / 汇总
    ├── baidu.csv              # zlint 全规则 CSV（行数 = meta.total_lints）
    ├── baidu.json / .jsonl    # zlint 全规则 JSON / JSONL
    └── results_summary.csv    # run_batch.sh 的汇总 CSV
```

`汇总` sheet 示例（表头 `type / 内容 / status`，zlint 规则在前，其余三类在后）：

```text
type       内容                                    status
CA         e_aia_ca_issuers_must_have_http_only    pass
CA         e_adobe_extensions_legacy_multipurpose  NA
...
组织名      (空)                                    Beijing Baidu Netcom Science Technology Co., Ltd.
SCT时间    Jul 09 02:33:07.208000 2026 GMT         (空)
OCSP查询   (空)                                    GOOD
```

### check_revocation_consistency.py —— 交叉核验 CRL 与 OCSP 的吊销信息一致性

同一张证书的吊销事实可能同时出现在两条独立渠道——**CRL** 与 **OCSP**。正常运营下二者对同一证书应结果一致（状态、吊销时间、原因码）。本脚本把两源的吊销信息都取下来**交叉比对**，抓"CRL 已吊销但 OCSP 未吊销""吊销时间差几秒/几天""吊销原因码不一致"这类数据不同步问题——这类问题跑 zlint 格式规则（CA/CRL/OCSP 合规）发现不了：

```bash
python3 check_certs_python/check_revocation_consistency.py <证书路径|证书目录> ... [选项]
python3 check_certs_python/check_revocation_consistency.py certs/baidu.pem                   # CDP 下载 CRL + 在线查 OCSP
python3 check_certs_python/check_revocation_consistency.py certs/ --csv result.csv           # 目录批量 + 汇总 CSV
python3 check_certs_python/check_revocation_consistency.py cert.pem --crl crl.pem --no-ocsp  # 离线：只用本地 CRL
```

- CRL 侧：从证书 CDP 自动下载（`--crl <文件>` 可改指本地 CRL）；OCSP 侧：从 AIA 查 responder（签发者可 `--issuer` 本地给，否则从 CA Issuers 自动下载）
- 按**序列号**在 CRL 中反查吊销条目（吊销时间/原因码），与 OCSP 返回比对：状态一致性、吊销时间（精确到秒）、吊销原因
- 顺带做时间自洽性检查：吊销时间不得晚于该源 `this_update`、不得早于证书 `notBefore`（同一源内自相矛盾同样报）
- 判定结论：`未吊销` / `一致` / `不一致`（状态冲突 / 时间差异 X 秒 / 原因不同）/ `单源`（仅 CRL 或仅 OCSP，不判失败）/ `无吊销源`；批量多证书时逐张打印一行 + 可选 `--csv` 汇总（含两源时间戳与秒级差异）
- 退出码：存在任何不一致 → 1，其余 → 0（单源、网络失败不计为不一致），便于脚本化/CI 把关

### check_certs_python/ct_audit/ —— 证书透明度 CT 审计（SCT 证据链）

CT（Certificate Transparency）回答"CA 是否真的把这张证书提交到了公开日志、收据是否真实"，是浏览器信任模型的一环，与 zlint（签发格式合规）、CRL/OCSP（吊销）构成**签发 → 公开登记 → 吊销**三段证据链中的中间段。本目录按三层框架对嵌入式 SCT 做审计（方法学与实测底稿见 `ct_audit/README.md`）：

| 脚本 | 层 | 作用 |
|---|---|---|
| `parse_sct.py` | L1 签发覆盖 | DER 级提取并解析 SCT（log_id / 时间戳 / 签名算法），匹配 Google log list 快照给出运营方/状态 |
| `verify_sct.py` | L2 签名真实性 | RFC 6962 §3.2 密码学验签：证明 SCT 是日志运营方私钥对这张证书(precert)的真实签名 |
| `ct_log_liveness.py` | L3 日志存活性 | 调各日志 `get-sth`，用同一日志公钥验 STH 签名（RFC 6962 §3.5）——日志在线且密钥未换，记录审计时点 tree_size；`--sth-out` 把 STH 原文落盘取证 |
| `check_ct_temporal.py` | 时间交叉核验 | 自动化比对 SCT 时间戳 × 证书 notBefore/notAfter × 审计时点 × 日志 `temporal_interval`，批量 `--csv` 汇总 |

```bash
python3 check_certs_python/ct_audit/parse_sct.py certs/baidu.pem              # L1 提取+匹配(默认读 samples/)
python3 check_certs_python/ct_audit/verify_sct.py cert.pem issuer.crt          # L2 验签(证书+签发者)
python3 check_certs_python/ct_audit/ct_log_liveness.py cert.pem                # L3 存活性(联网 get-sth)
python3 check_certs_python/ct_audit/ct_log_liveness.py cert.pem --sth-out sth.json  # L3 + STH 原文落盘取证(审计时点/证书指纹/逐日志 STH)
python3 check_certs_python/ct_audit/check_ct_temporal.py cert.pem              # 时间交叉核验
python3 check_certs_python/ct_audit/check_ct_temporal.py certs/ --csv t.csv    # 批量 + 汇总 CSV
```

- 自带演示与证据：`samples/` 含 baidu（GlobalSign RSA OV SSL CA 2018 签发）与 LE 对照组证书、签发者，及 **log list v3 快照**（`log_list_v3_snapshot.json`）。log list 是**时敏证据**，审计应在每次时点留存快照；`--loglist` 指定、`--offline` 强制"无本地快照即报错"（防误用在线清单）。STH 同理：`ct_log_liveness.py --sth-out <文件>` 把每次审计抓取的 STH 原文落盘归档，可事后用同一日志公钥复验
- `check_ct_temporal.py` 判定：逐 SCT 与证书有效期、审计时点、日志 `temporal_interval`、日志状态交叉核验——任何"不一致"退出码 1（晚于审计时点 / 晚于 notAfter / 早于 notBefore 超 24h 窗口 / SCT 落在日志时间域外）；"观察"（日志非 usable、快照未匹配、略早于 notBefore）需人工确认；CA/中间证书无 SCT 不算失败（CT 政策只约束 TLS 服务器证书）
- 方法学关键点（详见 `verify_sct.py` 头部注释）：嵌入式 SCT 验签的 precert TBS 重建 = **只删 SCT 扩展、不插 poison**（对齐 Google ct-go `RemoveSCTList` / Chrome `GetPrecertSignedEntry`）；SCT 自带的 CtExtensions **须按原样拼入签名输入**，硬编码空扩展会把真实 SCT 误判为失败
- 实测示例（可复现）：baidu 3/3 SCT 验签通过、3 日志全部在线（STH 验签 OK）；但其 SCT 时间戳落在三条日志当前快照 `temporal_interval`（2027-01-01 起）**之外**，`check_ct_temporal.py` 判"不一致"，需调取签发时点 log list 复核（O2 类时间域观察）；LE 对照组 PASS——演示了时间交叉核验的实际价值

### find_cert_root_python/ —— 沿 issuer 追到根证书（证书链分析）

对任意一张证书沿 issuer 一路追到根证书，并把链顶与信任库（系统 / 指定 bundle）做 SHA-256 指纹比对，判断它是否构成当前环境的"信任锚"——对应审计中"某证书的 root 是谁、是否被信任"这类问题：

```bash
python3 find_cert_root_python/find_cert_root.py <证书路径|目录> [更多...] [选项]
python3 find_cert_root_python/find_cert_root.py certs/baidu.pem --download
        # 允许联网：本地找不齐时从 AIA CA-Issuers 自动下载（http 失败兜底 https）
python3 find_cert_root_python/find_cert_root.py cert.pem --pool <目录|文件>
        # 从本地证书池找上级（可把含中间 CA / 根的目录指进来）
python3 find_cert_root_python/find_cert_root.py cert.pem --trust cacert.pem
        # 指定信任库 bundle（默认自动找系统信任库）
python3 find_cert_root_python/find_cert_root.py certs/ --download --csv results/cert_roots.csv
        # 目录批量：逐张追链，每张一行结论（根/信任锚/openssl/链长），--detail 保留完整过程
```

- 追链逻辑：重复"`issuer` DN == 上级 `subject` DN + 验签"直到 `subject == issuer`（自签候选根）；验签支持 RSA PKCS1/PSS、ECDSA、Ed25519/Ed448
- 找上级的来源依次：本地 `--pool` →（开 `--download` 时）AIA CA-Issuers 下载 → 信任库中的自签根兜底。最后一条很关键：不少中间 CA 的 AIA **只有 OCSP、没有 CA Issuers**（如 GlobalSign RSA OV SSL CA 2018），最后一跳只能靠本地已有的根接上——默认自动并入系统信任库里的根，`--trust` 可换指定 bundle
- 信任库比对：链顶根证书与信任库中同名根证书做 SHA-256 指纹比对——**指纹一致才是信任锚，同名不同钥不可信**
- `--pool` 目录会递归扫 `*.pem / *.crt / *.cer / *.der`；PEM/DER 自动识别，PEM 容忍文件头注释与多证书 bundle
- 链完整且顶部为自签根时，自动调用 `openssl verify` 做整链终裁（`--no-openssl` 跳过）
- 自带演示：`certs/baidu.pem` 是 GlobalSign 链，单条 `--download` 即可从叶子一路追到根并确认信任锚（叶子 → GlobalSign RSA OV SSL CA 2018 → GlobalSign Root CA - R3）
- 依赖：`pip install cryptography`
