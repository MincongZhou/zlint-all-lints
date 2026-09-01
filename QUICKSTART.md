# 快速上手 / Quickstart

本项目基于 zmap/zlint 提供命令行工具，全部用法围绕它们展开：

| 工具 | 作用 | 产物 |
|------|------|------|
| `zlint-all-lints` | 对**证书 / CRL / OCSP 响应**跑 zlint **全部 433 条规则**，自动识别输入类型，区分 CA/CRL/OCSP 三类 | JSON + CSV |
| `extract-cert` | 提取证书信息（签发人、有效期、指纹、SAN、公钥等） | JSON |
| `check_ocsp.py` | 联网查询证书 OCSP 状态（GOOD / REVOKED / UNKNOWN） | 终端输出 |

另有 `run_batch.sh` / `run_extract.sh` 两个批量脚本，专门处理"一个目录下有很多对象"的场景。

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

## 3. 准备对象（证书 / CRL / OCSP）

- `zlint-all-lints` 支持 **PEM 和 DER** 格式的证书、CRL、OCSP 响应（`.pem` / `.crt` / `.cer` / `.der`），不认 P12/PFX 等格式；
- `extract-cert` 只处理证书；
- 项目自带 `certs/` 样本目录：4 张证书 + 61 个 CRL + 4 个 OCSP 响应，可直接开跑：

```bash
ls certs/                        # 证书、CRL、OCSP 样本都在这里
```

也可以自己准备：

```bash
mkdir -p certs
cp ../zlint/v3/testdata/27monthsEv.pem certs/    # 证书
cp ../zlint/v3/testdata/crlEmpty.pem certs/      # CRL
```

---

## 4. 场景一：单个对象跑全部 lint

```bash
./zlint-all-lints -cert certs/27monthsEv.pem                          # 自动识别为 cert，只出 JSON
./zlint-all-lints -cert certs/crlEmpty.pem                            # 自动识别为 crl，真实执行 CRL 规则
./zlint-all-lints -cert certs/ocspThisUpdateAfterProducedAt.der       # 自动识别为 ocsp
./zlint-all-lints -cert certs/27monthsEv.pem -out r.json -csv r.csv   # JSON + CSV 一起出
./zlint-all-lints -cert certs/27monthsEv.pem -pretty=false            # 紧凑 JSON（文件更小）
```

参数说明：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-cert` | （必填） | 对象文件路径，PEM / DER 均可（证书 / CRL / OCSP） |
| `-type` | `auto` | 强制输入类型：`cert` \| `crl` \| `ocsp` \| `auto`（默认按 证书→CRL→OCSP 自动识别） |
| `-out` | `lint_results.json` | JSON 输出路径 |
| `-csv` | 空（不输出） | 额外生成一份 CSV，方便 Excel 打开 |
| `-pretty` | `true` | 是否缩进美化 JSON；批量跑时建议 `false` 减小体积 |

## 5. 场景二：批量跑一个目录下的所有对象

```bash
./run_batch.sh certs              # 输出到默认的 ./results
./run_batch.sh certs results      # 指定输出目录
```

脚本自动：
1. 收集目录下所有 `*.pem / *.crt / *.cer / *.der / *.crl`；
2. 每个对象调一次 `zlint-all-lints`（自动识别类型），生成 `<对象名>.json` + `<对象名>.csv`；
3. 把每份 CSV 去掉表头、加上文件名，合并成 `results/results_summary.csv`；
4. 最后校验行数是否等于 `对象数 × 433`，不等会提示有对象处理失败。

产物：

```text
results/
├── 27monthsEv.csv           # 单对象 CSV（433 行）
├── 27monthsEv.json          # 单对象 JSON
├── crlEmpty.csv             # CRL 输入同样是 433 行
└── results_summary.csv      # 汇总：全部对象 × 全部规则，首列 cert 是文件名
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
    "input_file": "certs/crlEmpty.pem",
    "input_type": "crl",                      // 实际识别的输入类型：cert / crl / ocsp
    "subject": "CN=Test CRL",
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
| `NA` | 不适用——该规则类型与输入对象类型不同（如对证书跑 CRL 规则） |
| `NE` | 未生效 |

> 输入是证书：414 条 CA 规则真实执行，18 条 CRL + 1 条 OCSP 规则为 `NA`；
> 输入是 CRL：18 条 CRL 规则真实执行，其余为 `NA`；
> 输入是 OCSP：OCSP 规则真实执行，其余为 `NA`。任何输入下恒为 433 行。

### 8.3 CSV 与 Excel

CSV 与 JSON 同结构，表头：

```text
name,type,description,citation,source,status,details
```

在 Excel / WPS 里打开后可对 `status`、`type` 列筛选排序：
- 想看对象有哪些问题 → 筛选 `status` 为 `error` / `warn`；
- 想看规则分布 → 按 `type` 列透视。

---

## 9. 推荐工作流（完整走一遍）

```bash
# 1) 准备
go build -o zlint-all-lints . && go build -o extract-cert ./cmd/extract-cert

# 2) 跑内置样本（证书 + CRL + OCSP 一起批量）
./run_batch.sh certs results

# 3) 单张证书提取信息
./run_extract.sh certs extracted

# 4) 看结果
cat extracted/summary_all.json          # 证书概览
# Excel 打开 results/results_summary.csv，筛选 status=error 的规则
# 单独看 CRL 问题：筛选 type=CRL 且 status=error
```

---

## 10. 常见问题 FAQ

**Q：`./run_batch.sh` 报"找不到 zlint-all-lints"？**
A：没编译，先执行第 2 步的 `go build`。

**Q：`go build` 报 `file does not exist` 提到 `../zlint/v3/go.mod`？**
A：本地缺少 zlint 源码，见第 1 步，`git clone https://github.com/zmap/zlint.git` 到本项目的上一级目录。

**Q：批量跑完提示"数据行数不等于 对象数 × 433"？**
A：说明有对象解析失败（脚本会把失败名单打印在 stderr）。通常原因：文件其实不是证书/CRL/OCSP、是多证书 PEM（一个文件里好几张）、或是 P12 等不支持格式。挑一个手动跑 `zlint-all-lints -cert xx` 看具体报错。

**Q：怎么判断一个对象到底合不合规？**
A：看 `status=error` 的规则。数量为 0 基本合规；有的话看 `details` 里的具体原因，`citation` 指到对应的 CA/Browser Forum 条款。

**Q：CRL / OCSP 的规则在哪看？**
A：输入是 CRL（或 OCSP）时，对应类型的规则会真实执行，`status` 不再是 `NA`；输入是证书时，CRL/OCSP 规则固定为 `NA`。批量跑混合目录时，用汇总 CSV 按 `type` 列筛选。

**Q：GitHub 上的 zlint 更新了规则，怎么用上新规则？**
A：本地 `zlint` 仓库 `git pull` 后重新 `go build` 即可，本项目代码不需要改。注意 `README.md` / `run_batch.sh` 里写死的 433 数字会随之变化（脚本只提示、不影响结果）。

---

## 11. Python 辅助脚本

除 Go 工具外，`check_certs_python/` 和 `extract_CertInfo_python/` 下还有一组 Python 脚本，依赖 `pip install cryptography`。

### 11.1 查询证书 OCSP 状态（check_ocsp.py）

```bash
python3 check_ocsp.py certs/27monthsEv.pem                     # 详细输出
python3 check_ocsp.py certs/27monthsEv.pem --status            # 只输出 GOOD/REVOKED/UNKNOWN
python3 check_ocsp.py                                          # 无参数 → 交互模式
```

- 未传签发者证书时，自动从证书 AIA 的 CA Issuers 地址下载；http 失败自动兜底 https 并重试
- `--status` 模式 stdout 只输出状态（REVOKED 时带吊销时间），错误走 stderr，适合脚本化调用：

```bash
st=$(python3 check_ocsp.py cert.pem --status 2>/dev/null) && echo "状态: $st"
```

### 11.2 批量跑 lint 的 Python 封装（run_zlint.py）

```bash
python3 run_zlint.py certs                       # 批量跑，输出到默认 ./results
python3 run_zlint.py certs results --jsonl       # 额外把每个 JSON 转成 JSONL（每行一条规则）
python3 run_zlint.py                             # 无参数 → 交互模式
```

### 11.3 提取 SCT（extract_sct.py）

```bash
python3 extract_CertInfo_python/extract_sct.py cert.pem        # PEM
python3 extract_CertInfo_python/extract_sct.py cert.der --der  # DER
```

输出每个 SCT 的 version / log_id / timestamp（epoch 毫秒 + UTC 文本）/ 签名算法与签名。需要 `cryptography >= 42.0`。

### 11.4 提取组织名 / 简单字段提取

```bash
python3 extract_CertInfo_python/extract_org.py cert.pem        # 输出 subject 与组织名（O 字段）
python3 extract_CertInfo_python/openssl_script.py              # 交互式：openssl 提取字段
```
