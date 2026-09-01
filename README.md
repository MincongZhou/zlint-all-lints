# zlint-all-lints

对输入的 PKI 对象（**证书 / CRL / OCSP 响应**）运行 zlint **全部 433 条规则**，输出带 `type` 字段的 JSON，区分每条规则的归属：**CA**（证书）、**CRL**（吊销列表）、**OCSP**（OCSP 响应）。

Run all 433 zlint rules against a PKI object (certificate / CRL / OCSP response) and export JSON with a `type` field that classifies every rule as **CA**, **CRL**, or **OCSP**.

## 输入类型 / Input types

`zlint-all-lints` 按官方 CLI 的顺序（证书 → CRL → OCSP）自动识别输入文件类型；输入是哪类对象，就**真实执行**哪类规则，其余两类规则标记为 `NA`：

| 输入对象 | 真实执行的规则 | 标 `NA` 的规则 |
|----------|----------------|----------------|
| 证书 `cert` | 414 条 CA 规则 | 18 条 CRL + 1 条 OCSP |
| CRL `crl`   | 18 条 CRL 规则 | 414 条 CA + 1 条 OCSP |
| OCSP `ocsp` | 1 条 OCSP 规则 | 414 条 CA + 18 条 CRL |

自动识别偶尔会误判时，可用 `-type cert|crl|ocsp` 强制指定。

## 规则分布 / Rule counts

| type | 数量 | 说明 |
|------|------|------|
| CA   | 414  | 证书类规则 |
| CRL  | 18   | 吊销列表类规则 |
| OCSP | 1    | OCSP 响应类规则 |

`go.mod` 通过 `replace` 指令复用本地 zlint v3 源码（`../zlint/v3`），无需联网拉取依赖。

## 构建 / Build

```bash
go build -o zlint-all-lints .
```

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

```json
{
  "meta": {
    "input_file": "crl.pem",
    "input_type": "crl",
    "subject": "CN=Test CRL",
    "total_lints": 433,
    "type_counts": { "CA": 414, "CRL": 18, "OCSP": 1 }
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

`run_batch.sh` 遍历一个目录下的所有对象（证书 / CRL / OCSP），每个对象输出一份 JSON + 一份 CSV，并汇总成带文件名的总 CSV：

```bash
./run_batch.sh <对象目录> [输出目录]   # 输出目录默认 ./results
```

例：

```bash
./run_batch.sh certs results
```

产物：

```text
results/
├── baidu.pem → baidu.csv               # 单对象 CSV（433 行）
├── baidu.pem → baidu.json              # 单对象 JSON
├── crl.pem   → crl.csv                 # CRL 输入同样输出 433 行
└── results_summary.csv                 # 汇总：全部对象 × 全部规则，首列 cert 为文件名
```

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
python3 check_ocsp.py <证书路径> [签发者证书路径] [--der] [--timeout 秒]
python3 check_ocsp.py <证书路径> --status     # 只输出状态，适合脚本调用
python3 check_ocsp.py                          # 无参数 → 交互模式
```

- 从 AIA 扩展自动提取 OCSP URL；签发者证书可本地传入，否则从 CA Issuers 地址自动下载
- http 请求失败自动兜底 https、自动重试
- `--status` 模式：stdout 只输出 `GOOD` / `REVOKED`（带吊销时间）/ `UNKNOWN`，错误走 stderr + 非零退出码，便于管道和脚本化调用

**`run_zlint.py`**：`run_batch.sh` 的 Python 封装（支持证书/CRL/OCSP 目录），支持交互模式与 `--jsonl` 转换

```bash
python3 run_zlint.py <对象目录> [输出目录] [--timeout 秒] [--jsonl]
python3 run_zlint.py                            # 无参数 → 交互模式
```

### extract_CertInfo_python/ —— 证书信息提取

| 脚本 | 作用 | 用法 |
|------|------|------|
| `extract_sct.py` | 提取证书里的 SCT（证书透明度时间戳）：log_id / timestamp / 签名算法 | `python3 extract_sct.py <证书> [--der]` |
| `extract_org.py` | 提取证书组织名（O 字段）与 subject | `python3 extract_org.py <证书> [--der]` |
| `openssl_script.py` | 调用 `openssl x509` 提取 subject / issuer / 有效期 | 交互输入证书路径 |

> 提示：`extract_sct.py` 需要 `cryptography >= 42.0`（原生支持 CT Precertificate SCTs 扩展解析）。

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

批量输出结构（每个证书一个子目录，含 xlsx 大表和 lint 的 JSON/CSV/JSONL）：

```text
results/
└── baidu/
    ├── baidu_report.xlsx      # 5 个 sheet：zlint / 组织名 / SCT时间 / OCSP查询 / 汇总
    ├── baidu.csv              # zlint 全规则 CSV（433 行）
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
