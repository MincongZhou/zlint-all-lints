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
python3 run_zlint.py certs                       # 批量跑，输出到默认 ./results（默认只留汇总表）
python3 run_zlint.py certs --detail              # 保留每个对象的 JSON/CSV
python3 run_zlint.py certs results --jsonl       # 把每个 JSON 转成 JSONL（自动保留源 JSON）
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

### 11.5 一键跑完 4 个分析脚本（run_all.py / run_all.sh）

对单张证书依次跑 `run_zlint.py` + `extract_org.py` + `extract_sct.py` + `check_ocsp.py`，`run_all.py` 还会汇总成 xlsx 大表：

```bash
./run_all.sh certs/baidu.pem                      # shell 版，只打印各脚本结果
python3 run_all.py certs/baidu.pem                # Python 版，生成 baidu_report.xlsx
python3 run_all.py certs                          # 批量跑 certs 下所有证书
python3 run_all.py                                # 无参数 → 交互模式
```

xlsx 共 5 个 sheet（zlint / 组织名 / SCT时间 / OCSP查询 / 汇总），`汇总` sheet 统一三列 `type / 内容 / status`。需要 `pip install cryptography openpyxl`。

### 11.6 下载证书的 CRL（check_crl.py）

从证书 CDP（CRL Distribution Points）扩展下载 CRL 并统一转成 PEM，供 `zlint-all-lints` 真实执行 18 条 CRL 规则：

```bash
python3 check_certs_python/check_crl.py certs/baidu.pem --out crl.pem
./zlint-all-lints -cert crl.pem           # 下载完直接喂 zlint（自动识别为 crl）
```

- 自动遍历证书 CDP 里的全部 http(s) 分发点，逐个尝试直到成功
- 下载内容会校验确实是 CRL（防 HTML 错误页/误传证书）；无参数运行进入交互模式

### 11.7 解析 CRL 吊销序列号（crl_sourcedata.py）

CRL 本身只含吊销条目的**序列号 + 吊销时间 + 原因码**，不含证书本体。解析出序列号清单后，可拿序列号去本地证书池反查"哪张证书被吊销"：

```bash
python3 check_certs_python/crl_sourcedata.py crl.pem                  # 逐行输出 0x序列号 + 十进制
python3 check_certs_python/crl_sourcedata.py crls/ --csv revoked.csv  # 目录批量 + 导出 CSV（含吊销时间/原因）
```

与 11.6 组合成"下载 + 解析"一条龙：

```bash
python3 check_certs_python/check_crl.py certs/baidu.pem --out crl.pem \
  && python3 check_certs_python/crl_sourcedata.py crl.pem --csv baidu_revoked.csv
```

### 11.8 一张证书跑齐 CA / CRL / OCSP 三类规则（run_cert_crl_ocsp.py）

zlint 对单个输入对象只真实执行所属类型的规则（证书→CA 414 条、CRL→18 条、OCSP→1 条），其余标 `NA`。本脚本把证书的**配套吊销对象**（CRL / OCSP 响应）也取下来一起跑，三类规则全部真实执行：

```bash
python3 run_cert_crl_ocsp.py certs/baidu.pem          # 联网下载 CRL + 查 OCSP，三侧全跑
python3 run_cert_crl_ocsp.py certs                     # 目录批量（每证书一个子目录）
python3 run_cert_crl_ocsp.py certs --detail            # 保留每证书完整产物（默认只留三张汇总表）
```

- 默认精简：每证书三侧结果合并进输出根下的 `ca_summary.csv` / `crl_summary.csv` / `ocsp_summary.csv`（首列 cert 为证书名），中间 JSON/CSV 随跑随删，只保留联网证据 `crl.pem` / `resp.der`
- 证书侧 `zlint-all-lints`（CA 414 条）；CRL 侧由 `check_crl.py` 下载后跑 18 条；OCSP 侧由 `check_ocsp.py` 查询并存 DER 响应后跑 1 条
- CRL/OCSP 联网失败（无 CDP / 无 OCSP 地址 / 网络不通）自动跳过对应侧，不中断整体

### 11.9 沿 issuer 追到根证书（find_cert_root.py）

从任意一张证书出发，沿 issuer 一路追到 root，并把链顶与信任库做 SHA-256 指纹比对，判断它是否构成当前环境的"信任锚"（证书链分析，不跑 lint）：

```bash
python3 find_cert_root_python/find_cert_root.py certs/baidu.pem --download   # 允许联网：AIA 下载缺的中间 CA，根由信任库自签根兜底
python3 find_cert_root_python/find_cert_root.py cert.pem --pool ca_dir       # 本地证书池找上级
python3 find_cert_root_python/find_cert_root.py cert.pem --trust cacert.pem  # 指定信任库 bundle
```

- 重复"issuer DN 匹配 + 验签"直到自签根；`--pool` 支持目录递归（`.pem/.crt/.cer/.der`），PEM/DER 自动识别
- 找上级：本地 `--pool` →（`--download`）AIA 下载 → 信任库自签根兜底。中间 CA 常无 CA Issuers（如 GlobalSign RSA OV SSL CA 2018 仅 OCSP），最后一跳靠系统信任库 / `--trust` bundle 里的根接上
- 链顶与信任库同名根证书比对指纹：一致才是信任锚，同名不同钥不可信
- 链完整且顶部自签时自动调 `openssl verify` 终裁；`certs/baidu.pem` 即 GlobalSign 链，可作演示

### 11.10 交叉核验 CRL 与 OCSP 的吊销一致性（check_revocation_consistency.py）

同一张证书的吊销事实可能同时出现在 **CRL**（CA 周期签发，条目含序列号 + 吊销时间 + 原因码）与 **OCSP**（responder 实时回答）两条独立渠道，正常应结果一致。本脚本把两源的吊销信息都取下来交叉比对，抓"CRL 已吊销但 OCSP 未吊销""吊销时间不一致""吊销原因码不一致"这类**数据不同步**问题——跑 zlint 格式规则（CA/CRL/OCSP 合规）发现不了，需语义层核验：

```bash
python3 check_certs_python/check_revocation_consistency.py certs/baidu.pem                  # CDP 下载 CRL + 在线查 OCSP
python3 check_certs_python/check_revocation_consistency.py certs/ --csv result.csv          # 目录批量 + 汇总 CSV
python3 check_certs_python/check_revocation_consistency.py cert.pem --crl crl.pem --no-ocsp # 离线：只用本地 CRL
python3 check_certs_python/check_revocation_consistency.py cert.pem --no-crl                # 只看 OCSP 侧
```

- CRL 侧：从证书 CDP 自动下载（`--crl <文件>` 可改指本地 CRL）；OCSP 侧：从 AIA 查 responder（签发者可 `--issuer` 本地给，否则从 CA Issuers 自动下载）
- 按**序列号**在 CRL 中反查吊销条目（吊销时间/原因码），与 OCSP 返回比对：状态一致性、吊销时间（精确到秒）、吊销原因
- 顺带做时间自洽性检查：吊销时间不得晚于该源 `this_update`、不得早于证书 `notBefore`
- 判定结论：`未吊销` / `一致` / `不一致`（状态冲突 / 时间差异 X 秒 / 原因不同）/ `单源`（仅 CRL 或仅 OCSP，不判失败）/ `无吊销源`
- 批量多证书时逐张打印一行；`--csv` 汇总每张证书两源时间戳与秒级差异
- 退出码：存在任何不一致 → 1，其余 → 0（单源、网络失败不计为不一致），适合脚本化/CI 把关

### 11.11 证书透明度 CT 审计：SCT 证据链（check_certs_python/ct_audit/）

CT 审计回答"CA 是否真的把证书提交到了公开日志、SCT 收据是否真实、声称的日志是否在线"，与 zlint（签发合规）、CRL/OCSP（吊销）互补。四脚本三层审计 + 一个自动化时间交叉核验（方法学与实测底稿见 `ct_audit/README.md`）：

```bash
# L1 签发覆盖: 提取解析 SCT 并匹配 Google log list 快照（运营方/状态）
python3 check_certs_python/ct_audit/parse_sct.py certs/baidu.pem
# L2 签名真实性: RFC 6962 §3.2 验签（目标证书 + 签发者证书）
python3 check_certs_python/ct_audit/verify_sct.py cert.pem issuer.crt
# L3 日志存活性: get-sth + 日志公钥验 STH 签名（联网），记录 tree_size
python3 check_certs_python/ct_audit/ct_log_liveness.py cert.pem
# 自动化时间交叉核验: SCT 时间戳 × 有效期 × 审计时点 × 日志 temporal_interval
python3 check_certs_python/ct_audit/check_ct_temporal.py certs/ --csv ct_temporal.csv
```

- `samples/` 自带可复现演示：baidu（GlobalSign 2018 签发，3 个 SCT）+ LE 对照组（2 个 SCT）+ 签发者 + log list v3 快照（时敏证据，审计固定快照；`--loglist` 指定、`--offline` 防误用在线清单）
- 时间核验判定：逐 SCT 交叉比对证书 notBefore/notAfter、审计时点、日志 `temporal_interval` 与状态；任何"不一致"退出码 1，"观察"项需人工确认，CA 证书无 SCT 不算失败
- 关键方法学：验签的 precert TBS 重建 = 只删 SCT 扩展、不插 poison（对齐 ct-go/Chrome）；SCT 自带 CtExtensions 须原样拼入签名输入（见 `verify_sct.py` 头部注释）
- 实测示例：baidu 3/3 验签通过、3 日志在线；但 3 个 SCT 均落在日志当前快照时间域（2027-01-01 起）之外 → `check_ct_temporal.py` 判不一致（O2 类，需调取签发时点 log list 复核）；LE 对照组 PASS
