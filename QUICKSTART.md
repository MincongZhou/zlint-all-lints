# 快速上手 / Quickstart

本项目基于 zmap/zlint 提供两个命令行工具，全部用法围绕它们展开：

| 工具 | 作用 | 产物 |
|------|------|------|
| `zlint-all-lints` | 对证书跑 zlint **全部 433 条规则**，区分 CA/CRL/OCSP 三类 | JSON + CSV |
| `extract-cert` | 提取证书信息（签发人、有效期、指纹、SAN、公钥等） | JSON |

另有 `run_batch.sh` / `run_extract.sh` 两个批量脚本，专门处理"一个目录下有很多证书"的场景。

---

## 1. 环境准备（只需一次）

- **Go 1.25+**（见 `go.mod` 的 `go 1.25.0`），检查：`go version`
- **本地 zlint v3 源码**：`go.mod` 里有 `replace github.com/zmap/zlint/v3 => ../zlint/v3`，
  要求 `../zlint/v3`（即本项目同级目录下的 `zlint` 目录）存在并已 clone zlint 源码：

```text
你的工作目录/
├── zlint-all-lints/   # 本项目
└── zlint/             # zlint v3 源码（git clone https://github.com/zmap/zlint.git）
```

若 `../zlint/v3` 不存在，`go build` 会报 `module github.com/zmap/zlint/v3: reading ../zlint/v3/go.mod: file does not exist`，
clone 一份即可：

```bash
cd .. && git clone https://github.com/zmap/zlint.git
```

## 2. 编译（只需一次）

```bash
cd /path/to/zlint-all-lints
go build -o zlint-all-lints .                    # 生成 run_batch.sh 需要的工具
go build -o extract-cert ./cmd/extract-cert      # 生成 run_extract.sh 需要的工具
```

成功后目录里会多出 `zlint-all-lints` 和 `extract-cert` 两个可执行文件。

## 3. 准备证书

两个工具都**只认 PEM 和 DER 格式**的单个证书（`.pem` / `.crt` / `.cer` / `.der`），不认 P12/PFX 等格式。

```bash
mkdir -p certs
cp ../zlint/v3/testdata/27monthsEv.pem certs/   # 示例：从 zlint 自带测试证书里复制一张
```

---

## 4. 场景一：单张证书跑全部 lint

```bash
./zlint-all-lints -cert certs/27monthsEv.pem                          # 只出 JSON（默认 lint_results.json）
./zlint-all-lints -cert certs/27monthsEv.pem -out r.json -csv r.csv   # JSON + CSV 一起出
./zlint-all-lints -cert certs/27monthsEv.pem -pretty=false            # 紧凑 JSON（文件更小）
```

参数说明：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-cert` | （必填） | 证书文件路径，PEM / DER 均可 |
| `-out` | `lint_results.json` | JSON 输出路径 |
| `-csv` | 空（不输出） | 额外生成一份 CSV，方便 Excel 打开 |
| `-pretty` | `true` | 是否缩进美化 JSON；批量跑时建议 `false` 减小体积 |

## 5. 场景二：批量跑一个目录下的所有证书

```bash
./run_batch.sh certs              # 输出到默认的 ./results
./run_batch.sh certs results      # 指定输出目录
```

脚本自动：
1. 收集 `certs/` 下所有 `*.pem / *.crt / *.cer / *.der`；
2. 每张证书调一次 `zlint-all-lints`，生成 `<证书名>.json` + `<证书名>.csv`；
3. 把每份 CSV 去掉表头、加上证书名，合并成 `results/results_summary.csv`；
4. 最后校验行数是否等于 `证书数 × 433`，不等会提示有证书处理失败。

产物：

```text
results/
├── 27monthsEv.csv           # 单证书 CSV（433 行）
├── 27monthsEv.json          # 单证书 JSON
└── results_summary.csv      # 汇总：全部证书 × 全部规则，首列 cert 是证书文件名
```

## 6. 场景三：单张证书提取信息

```bash
./extract-cert -cert certs/27monthsEv.pem                          # 默认输出 cert_info.json
./extract-cert -cert certs/27monthsEv.pem -out info.json -pretty=false
```

输出分两段：
- `summary`：精选字段，人读友好——subject / issuer / 序列号 / 有效期（含 `validity_days`）/ 签名算法 /
  是否自签名 / SAN（域名与 IP）/ 是否 CA / 公钥算法与位数 / SHA-256、SHA-1、SPKI 三种指纹；
- `full`：zcrypto 的完整 `JSONCertificate`，包含所有扩展（含未知扩展）的原始信息，字段最全。

## 7. 场景四：批量提取一个目录下所有证书的信息

```bash
./run_extract.sh certs              # 输出到默认的 ./extracted
./run_extract.sh certs extracted    # 指定输出目录
```

产物：

```text
extracted/
├── 27monthsEv.json           # 每张证书一份完整 JSON（summary + full）
└── summary_all.json          # 汇总：所有证书的 summary 数组，每项首字段 cert 是证书名
```

---

## 8. 怎么读懂输出

### 8.1 lint 的 JSON

```jsonc
{
  "meta": {
    "input_file": "certs/27monthsEv.pem",
    "subject": "C=DE, O=Lint, CN=27 months",
    "total_lints": 433,                       // 规则总数
    "type_counts": { "CA": 414, "CRL": 18, "OCSP": 1 }
  },
  "lints": [
    {
      "name": "e_cab_crl_has_valid_reason_code",   // 规则名（e_=必须 error，w_=警告，n_=信息）
      "type": "CRL",                               // CA=证书规则 / CRL=吊销列表规则 / OCSP=OCSP响应规则
      "description": "...",                        // 规则要求
      "citation": "BRs: 7.2.2",                    // 依据的标准条文
      "source": "CABF_BR",                         // 规则来源标准
      "status": "NA",                              // 见下表
      "details": "..."                             // 不通过时的具体原因
    }
  ]
}
```

### 8.2 status 取值

| status | 含义 |
|--------|------|
| `pass` | 通过 |
| `error` | 不符合（对应规则名 `e_` 开头） |
| `warn` | 有风险（对应规则名 `w_` 开头） |
| `info` | 仅提示 |
| `NA` | 不适用——CRL/OCSP 类规则对证书不执行，固定为 NA |
| `NE` | 未生效 |

> 一张证书上，414 条 CA 规则会真实执行，18 条 CRL + 1 条 OCSP 规则固定 NA，所以每张证书恒为 433 行。

### 8.3 CSV 与 Excel

CSV 与 JSON 同结构，表头：

```text
name,type,description,citation,source,status,details
```

在 Excel / WPS 里打开后可对 `status`、`type` 列筛选排序：
- 想看证书有哪些问题 → 筛选 `status` 为 `error` / `warn`；
- 想看规则分布 → 按 `type` 列透视。

---

## 9. 推荐工作流（完整走一遍）

```bash
# 1) 准备
go build -o zlint-all-lints . && go build -o extract-cert ./cmd/extract-cert
mkdir -p certs && cp ../zlint/v3/testdata/*.pem certs/   # 放你的证书

# 2) 先提取信息，快速了解证书本身
./run_extract.sh certs extracted

# 3) 再跑全部 lint，看合规性问题
./run_batch.sh certs results

# 4) 看结果
cat extracted/summary_all.json          # 证书概览
# Excel 打开 results/results_summary.csv，筛选 status=error 的规则
```

---

## 10. 常见问题 FAQ

**Q：`./run_batch.sh` 报"找不到 zlint-all-lints"？**
A：没编译，先执行第 2 步的 `go build`。

**Q：`go build` 报 `file does not exist` 提到 `../zlint/v3/go.mod`？**
A：本地缺少 zlint 源码，见第 1 步，`git clone https://github.com/zmap/zlint.git` 到本项目的上一级目录。

**Q：批量跑完提示"数据行数不等于 证书数 × 433"？**
A：说明有证书解析失败（脚本会把失败名单打印在 stderr）。通常原因：文件其实不是证书、是多证书 PEM（一个文件里好几张）、或是 P12 等不支持格式。挑一张手动跑 `zlint-all-lints -cert xx` 看具体报错。

**Q：怎么判断一张证书到底合不合规？**
A：看 `status=error` 的规则。数量为 0 基本合规；有的话看 `details` 里的具体原因，`citation` 指到对应的 CA/Browser Forum 条款。

**Q：GitHub 上的 zlint 更新了规则，怎么用上新规则？**
A：本地 `zlint` 仓库 `git pull` 后重新 `go build` 即可，本项目代码不需要改。注意 `README.md` / `run_batch.sh` 里写死的 433 数字会随之变化（脚本只提示、不影响结果）。
