# zlint-all-lints

对证书运行 zlint **全部 433 条规则**，输出带 `type` 字段的 JSON，区分每条规则的归属：**CA**（证书）、**CRL**（吊销列表）、**OCSP**（OCSP 响应）。

Run all 433 zlint rules against a certificate and export JSON with a `type` field that classifies every rule as **CA**, **CRL**, or **OCSP**.

## 规则分布 / Rule counts

| type | 数量 | 说明 |
|------|------|------|
| CA   | 414  | 证书类规则，对输入证书真实执行 |
| CRL  | 18   | 吊销列表类规则，对证书不适用（status = `NA`） |
| OCSP | 1    | OCSP 响应类规则，对证书不适用（status = `NA`） |

`go.mod` 通过 `replace` 指令复用本地 zlint v3 源码（`../zlint/v3`），无需联网拉取依赖。

## 构建 / Build

```bash
go build -o zlint-all-lints .
```

## 使用 / Usage

```bash
./zlint-all-lints -cert <cert.pem|cert.der> [-out results.json] [-csv results.csv] [-pretty=false]
```

支持 PEM 与 DER 格式的证书。不指定 `-out` 时默认写入 `lint_results.json`。
指定 `-csv` 时，会在 JSON 之外**再生成一份同结构的 CSV**，方便在 Excel / WPS 里筛选排序：

```bash
./zlint-all-lints -cert cert.pem -out results.json -csv results.csv
```

## 输出示例 / Output sample

```json
{
  "meta": {
    "input_file": "cert.pem",
    "subject": "C=DE, O=Lint, CN=27 months",
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
      "status": "NA",
      "details": "CRL lint: only applicable to a revocation list (CRL), not to a certificate"
    }
  ]
}
```

### CSV 输出示例 / CSV output sample

```csv
name,type,description,citation,source,status,details
e_adobe_extensions_legacy_multipurpose_criticality,CA,"If present, ...",7.1.2.3.m,CABF_SMIME_BR,NA,
e_basic_cons_not_critical,CA,"The BasicConstraints extension MUST be marked critical in CA certificates.",BRs: 7.1.2.7.8,CABF_BR,error,"BasicConstraints not marked critical"
```

`status` 取值：`pass` / `error` / `warn` / `info` / `NA`（不适用）/ `NE`（未生效）。

## 批量跑证书 / Batch run

`run_batch.sh` 遍历一个目录下的所有证书，每个证书输出一份 JSON + 一份 CSV，并汇总成带证书名的总 CSV：

```bash
./run_batch.sh <证书目录> [输出目录]   # 输出目录默认 ./results
```

例：

```bash
mkdir certs && cp ../zlint/v3/testdata/27monthsEv.pem certs/
./run_batch.sh certs results
```

产物：

```text
results/
├── 27monthsEv.csv            # 单证书 CSV（433 行）
├── 27monthsEv.json           # 单证书 JSON
└── results_summary.csv       # 汇总：全部证书 × 全部规则，首列 cert 为证书文件名
```

汇总 CSV 表头比单证书多一列 `cert`，可直接在 Excel 里按证书、按 `status`、按 `type` 透视筛选。
