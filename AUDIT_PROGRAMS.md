# 审计程序全景 —— 本项目在审计什么

本文按**审计维度**逐个说明本项目提供的审计程序：每个程序回答什么问题、覆盖哪些证据、用什么判定、输出什么。

## 0. 一张图看懂审计覆盖

对一张目标证书，本项目覆盖了完整的证据链：

```text
签发合规          公开登记            吊销状态           信任链
zlint 全规则  →   CT / SCT 审计  →    CRL × OCSP    →    沿 issuer 追根
(静态格式/策略)   (是否进了公开日志    (是否被吊销、        (根是谁、
                  + 收据是否真实)      两源是否一致)        是否被信任)
```

- **静态合规**：证书 / CRL / OCSP 响应本身的格式与策略是否合规 —— zlint **433 条规则**；
- **公开登记**：CA 是否真的把证书提交到了公开 CT 日志、SCT 收据是否为日志私钥的真实签名 —— CT 三层审计 + 时间交叉核验；
- **吊销**：这张证书当下是否已被吊销 —— CRL / OCSP 在线查询，以及两源**交叉核验**（语义层，格式规则发现不了）；
- **信任链**：它由哪家根签发、能否构成当前环境的信任锚 —— 证书链分析。

## 1. 静态合规审计（zlint 全规则）

### 1.1 `zlint-all-lints`（Go，根目录）—— 核心审计引擎

对任意 PKI 对象跑 zlint **全部 433 条规则**，输出每条规则的判定结果。

| 输入对象 | 真实执行的规则 | 其余标 `NA` |
|---|---|---|
| 证书 `cert` | 414 条 CA 规则（RFC 5280 / CABF BR / EV / SMIME / Mozilla 等） | 18 CRL + 1 OCSP |
| CRL `crl` | 18 条 CRL 规则 | 414 CA + 1 OCSP |
| OCSP 响应 `ocsp` | 1 条 OCSP 规则 | 414 CA + 18 CRL |

**审计点**：每张证书/每份 CRL/每个 OCSP 响应，逐条对照 CA/Browser Forum、RFC 5280 等标准条文（规则自带的 `citation` 字段直接指到条款，如 `BRs: 7.2.2`）。

**判读**：`status` 取值 `pass` / `error` / `warn` / `info` / `NA` / `NE`。`error` 数 = 0 基本合规；有 error 时看 `details`（具体原因）与 `citation`（对应条款）。输入类型自动识别，可 `-type` 强制指定。

**输出**：JSON（`meta` 含输入类型/对象总数统计 + `lints` 数组），可同时 `-csv` 出同结构 CSV 便于 Excel 透视筛选。

```bash
./zlint-all-lints -cert certs/27monthsEv.pem -out r.json -csv r.csv
```

### 1.2 批量跑 —— `run_batch.sh` / `run_zlint.py`

对目录下**所有对象**（证书 + CRL + OCSP 混排）逐个跑 433 条规则，合并成一张"全部对象 × 全部规则"汇总表：

```text
results/results_summary.csv     # 首列 cert = 文件名，末行列数自动校验 = 对象数 × 433
```

```bash
./run_batch.sh certs results            # shell 版
python3 run_zlint.py certs --detail     # Python 封装：支持单文件/目录、--jsonl 转换
```

### 1.3 一张证书跑齐三类规则 —— `run_cert_crl_ocsp.py`

zlint 对单个输入只真实执行其所属类型的规则，其余标 `NA`。本程序把证书的**配套吊销对象也取下来**（CRL 从 CDP 下载、OCSP 从 AIA 查询并存原始响应），于是 **CA 414 + CRL 18 + OCSP 1 全部真实执行**：

- 证书侧：`zlint-all-lints`；CRL 侧：`check_crl.py` 下载转 PEM 后跑；OCSP 侧：`check_ocsp.py` 查询存 DER 后跑；
- 任一联网侧失败（无 CDP/无 OCSP/网络不通）自动跳过，不中断整体；
- 产物：`ca_summary.csv` / `crl_summary.csv` / `ocsp_summary.csv` 三张汇总表 + 每证书的联网证据（`crl.pem`、`resp.der`），`--detail` 保留完整 JSON/CSV。

```bash
python3 run_cert_crl_ocsp.py certs/baidu.pem     # 或传目录批量
```

## 2. 证书信息提取（静态信息，非判定）

这几支程序不做"合规判定"，而是把证书的原始事实提取出来，供人工研判或其他程序喂料：

| 程序 | 提取内容 | 输出 |
|---|---|---|
| `extract-cert`（Go，`cmd/extract-cert`） | subject / issuer / 序列号 / 有效期（含 `validity_days`）/ 签名算法 / 是否自签名 / SAN / 是否 CA / 公钥算法位数 / SHA-256、SHA-1、SPKI 指纹 | JSON（`summary` 人读友好 + `full` 全扩展原文） |
| `extract_org.py` | subject / issuer 与两者的组织名（O 字段） | 终端输出 |
| `openssl_script.py` | 调 `openssl x509` 提取 subject / issuer / 有效期 | 终端输出 |
| `extract_sct.py` | 证书里的 SCT 扩展：每个 SCT 的 version / log_id / 时间戳 / 签名算法 | 终端输出 |

配套批量脚本：`run_extract.sh`（目录批量 + `summary_all.json` 汇总）、`run_all.py`（4 脚本一键跑 + xlsx 大表，见第 6 节）。

```bash
./extract-cert -cert certs/baidu.pem
python3 extract_CertInfo_python/extract_sct.py certs/baidu.pem     # 需要 cryptography >= 42.0
```

## 3. 吊销状态与吊销一致性审计（CRL / OCSP）

### 3.1 `check_ocsp.py` —— OCSP 实时状态查询

从证书 AIA 扩展取 responder URL 联网查询：**GOOD / REVOKED（带吊销时间）/ UNKNOWN**。签发者证书可本地传（`--issuer`），否则自动从 CA Issuers 下载；http 失败自动兜底 https 并重试。

`--status` 模式 stdout 只输出状态、错误走 stderr + 非零退出码，可直接脚本化：

```bash
st=$(python3 check_ocsp.py cert.pem --status 2>/dev/null) && echo "$st"
```

`--respout <文件>` 把 responder 返回的**原始 OCSP 响应 (DER)** 存下来，可再喂 `zlint-all-lints` 跑那 1 条 OCSP 规则。

### 3.2 `check_crl.py` —— CDP 下载 CRL

从证书 CDP（CRL Distribution Points）扩展下载 CRL，DER/PEM 自动识别并统一转成 PEM（校验下载内容确实是 CRL，防 HTML 错误页/误传证书）。拿到的 `crl.pem` 直接喂 `zlint-all-lints` 跑 18 条 CRL 规则。

```bash
python3 check_certs_python/check_crl.py certs/baidu.pem --out crl.pem
./zlint-all-lints -cert crl.pem
```

### 3.3 `crl_sourcedata.py` —— 解析吊销条目

把 CRL 里的吊销条目解析成清单：**序列号（16/10 进制）+ 吊销时间 + 原因码**。CRL 只含序列号不含证书本体，可拿序列号去本地证书池反查"哪张证书被吊销"。支持目录批量 + `--csv` 导出。

```bash
python3 check_certs_python/crl_sourcedata.py crl.pem --csv revoked.csv
```

### 3.4 `check_revocation_consistency.py` —— 两源吊销信息交叉核验

同一张证书的吊销事实可能同时出现在 **CRL**（CA 周期签发）与 **OCSP**（responder 实时回答）两条独立渠道，正常运营下应一致。本程序把两源都取下来按**序列号**交叉比对，抓格式规则发现不了的**数据不同步**问题：

- **状态一致性**：CRL 已吊销但 OCSP 未吊销（或反之）；
- **吊销时间**：两源吊销时间秒级差异（差几秒/几天都是同步事故的线索）；
- **吊销原因码**：两源原因不一致；
- **时间自洽**：吊销时间不得晚于该源 `this_update`、不得早于证书 `notBefore`（同源内自相矛盾也报）。

**判定结论**：`未吊销` / `一致` / `不一致`（状态冲突 / 时间差异 X 秒 / 原因不同）/ `单源`（只有一侧有数据，不判失败）/ `无吊销源`。

**退出码**：存在任何不一致 → 1，其余 → 0（单源、网络失败不计），适合 CI 把关。

```bash
python3 check_certs_python/check_revocation_consistency.py certs/ --csv result.csv
python3 check_certs_python/check_revocation_consistency.py cert.pem --crl crl.pem --no-ocsp  # 离线单源
```

## 4. CT（Certificate Transparency）审计 —— `check_certs_python/ct_audit/`

CT 回答"**CA 是否真的把这张证书提交到了公开日志、SCT 收据是否真实、声称的日志是否在线**"——浏览器信任模型的一环。与 zlint（签发合规）、CRL/OCSP（吊销）构成**签发 → 公开登记 → 吊销**三段证据链的中间段。目录内按三层框架 + 一个自动化时间核验（方法学与实测底稿见 `ct_audit/README.md`）：

| 程序 | 层 | 审计点 | 判据 |
|---|---|---|---|
| `parse_sct.py` | L1 签发覆盖 | DER 级提取解析 SCT（log_id / 时间戳 / 签名算法），匹配 Google log list 快照得运营方/状态 | 这张证书有没有 SCT？谁签的？ |
| `verify_sct.py` | L2 签名真实性 | RFC 6962 §3.2 密码学验签 | SCT 是日志运营方私钥对这张证书(precert)的**真实签名**，还是伪造收据？ |
| `ct_log_liveness.py` | L3 日志存活性 | 调各日志 `get-sth` 并用同一日志公钥验 STH 签名（RFC 6962 §3.5） | 日志**当前在线**、密钥未换？记录审计时点 tree_size（`--sth-out` 可把 STH 原文落盘取证） |
| `check_ct_temporal.py` | 自动化时间交叉核验 | 逐 SCT 比对：时间戳 × 证书 notBefore/notAfter × 审计时点 × 日志 `temporal_interval` × Chrome 政策 SCT 数量要求 | 时间证据链是否自洽 |

**关键方法学**（`verify_sct.py` 头部注释详述）：
- precert TBS 重建 = **只删 SCT 扩展、不插 poison**（对齐 Google ct-go `RemoveSCTList` / Chrome `GetPrecertSignedEntry`）——插了 poison 会把真实 SCT 误判失败；
- SCT 自带的 CtExtensions **须按原样拼入签名输入**，硬编码空扩展同样误伤真实 SCT。

**`check_ct_temporal.py` 判定**：
- `PASS`：时间全部自洽；
- `不一致`（退出码 1）：SCT 晚于审计时点 / 晚于 notAfter / 早于 notBefore 超 24h 窗口 / SCT 落在日志 `temporal_interval` 之外；
- `观察`（需人工确认，不计失败）：日志非 usable、快照未匹配、略早于 notBefore；
- 证书级附注：无 SCT 扩展 / 2018-04-30 后签发 SCT 数量 < 2（Chrome CT Policy）。

**取证纪律**：log list 是时敏证据，审计应在每次时点留存快照（`samples/log_list_v3_snapshot.json` 即留档样例）；`--loglist` 指定快照、`--offline` 强制"无本地快照即报错"，防审计时误用"现在的"在线清单评判"过去的"签发。**STH 同理**：`ct_log_liveness.py --sth-out <文件>` 把每次审计抓取的 STH 原文（tree_size/时间/根哈希/签名）连同审计时点、证书 SHA-256 落盘为 JSON，事后可用同一日志公钥复验，形成可追溯的审计证据链。

```bash
python3 check_certs_python/ct_audit/parse_sct.py certs/baidu.pem          # L1
python3 check_certs_python/ct_audit/verify_sct.py cert.pem issuer.crt      # L2（证书 + 签发者）
python3 check_certs_python/ct_audit/ct_log_liveness.py cert.pem            # L3（联网 get-sth）
python3 check_certs_python/ct_audit/ct_log_liveness.py cert.pem --sth-out sth_audit.json   # L3 + STH 原文落盘取证
python3 check_certs_python/ct_audit/check_ct_temporal.py certs/ --csv t.csv  # 时间核验（批量）
```

`ct_audit/samples/` 自带可复现演示：baidu（GlobalSign 2018 签发，3 个 SCT）与 LE 对照组——实测 baidu 3/3 验签通过、3 日志在线，但 3 个 SCT 均落在日志当前快照 `temporal_interval`（2027-01-01 起）**之外**，`check_ct_temporal.py` 判不一致（需调取签发时点 log list 复核），LE 对照组 PASS——演示了时间交叉核验的实际价值。

## 5. 信任链与根证书审计 —— `find_cert_root_python/find_cert_root.py`

对任意证书沿 issuer **一路追到根**（重复"issuer DN == 上级 subject DN + 验签"直到自签候选根），并把链顶与信任库做 **SHA-256 指纹比对**，回答审计中的"某证书的 root 是谁、是否被信任"：

- 找上级的顺序：本地 `--pool` →（开 `--download`）AIA CA-Issuers 下载 → 信任库自签根兜底。最后一条很关键：不少中间 CA 的 AIA **只有 OCSP 没有 CA Issuers**（如 GlobalSign RSA OV SSL CA 2018），最后一跳只能靠本地根接上；
- 信任判定：链顶根证书与信任库中**同名**根证书比对 SHA-256 指纹——**指纹一致才是信任锚，同名不同钥不可信**；
- 链完整且顶部自签时，自动调 `openssl verify` 做整链终裁；
- 验签覆盖 RSA PKCS1/PSS、ECDSA、Ed25519/Ed448；
- 内置演示链：`certs/baidu.pem` 叶子 → GlobalSign RSA OV SSL CA 2018 → GlobalSign Root CA - R3。

```bash
python3 find_cert_root_python/find_cert_root.py certs/baidu.pem --download   # 允许 AIA 联网下载
python3 find_cert_root_python/find_cert_root.py cert.pem --pool ca_dir --trust cacert.pem
```

## 6. 一键编排 —— `run_all.py` / `run_all.sh`

对单张证书**依次串起 4 个分析程序**：`run_zlint.py`（zlint 全规则）→ `extract_org.py`（组织名）→ `extract_sct.py`（SCT 时间）→ `check_ocsp.py`（吊销状态），覆盖"静态合规 + 公开登记 + 吊销"三个维度。

`run_all.py` 额外把结果汇总成 **xlsx 大表**（5 个 sheet：`zlint` / `组织名` / `SCT时间` / `OCSP查询` / `汇总`），`汇总` sheet 统一三列 `type / 内容 / status`——CA 规则逐行在前，组织名 / SCT 时间 / OCSP 状态三类跟随，一张表纵览一张证书的完整审计画像：

```text
type     内容                                     status
CA       e_aia_ca_issuers_must_have_http_only     pass
CA       e_adobe_extensions_legacy_multipurpose   NA
...
组织名    (空)                                    Beijing Baidu Netcom Science Technology Co., Ltd.
SCT时间  Jul 09 02:33:07.208000 2026 GMT         (空)
OCSP查询  (空)                                    GOOD
```

```bash
./run_all.sh certs/baidu.pem              # shell 版：只打印各脚本结果
python3 run_all.py certs/baidu.pem        # Python 版：生成 baidu_report.xlsx
python3 run_all.py certs                  # 目录批量：每张证书一个子目录
```

## 7. 程序与审计问题速查表

| 审计问题 | 用哪个程序 | 判定/输出 |
|---|---|---|
| 证书/CRL/OCSP 格式与策略是否合规？ | `zlint-all-lints` | 433 条规则 status + 条款引用 |
| 一批对象里谁不合规？ | `run_batch.sh` / `run_zlint.py` | `results_summary.csv`（对象 × 规则） |
| 证书的三类规则（CA/CRL/OCSP）全真实跑？ | `run_cert_crl_ocsp.py` | 三张汇总表 + 证据文件 |
| 证书由谁签发、有效期/指纹/扩展？ | `extract-cert` 等 4 支 | JSON / 终端 |
| 证书当前吊销状态？ | `check_ocsp.py` / `check_crl.py` | GOOD/REVOKED/UNKNOWN |
| CRL 里吊销了哪些序列号、何时、何原因？ | `crl_sourcedata.py` | 终端 / CSV |
| CRL 与 OCSP 两源吊销信息是否一致？ | `check_revocation_consistency.py` | 一致/不一致/单源，退出码 1 把关 |
| 证书有没有 SCT、谁签的？ | `parse_sct.py` | 提取 + log list 匹配 |
| SCT 是不是日志私钥的真实签名？ | `verify_sct.py` | 验签通过/失败 |
| 声称的日志现在还活着吗？ | `ct_log_liveness.py` | 在线 + STH 验签 + tree_size |
| SCT 时间与证书/日志时间证据自洽吗？ | `check_ct_temporal.py` | PASS/不一致/观察，退出码 1 |
| 证书的根是谁、是否构成信任锚？ | `find_cert_root.py` | 完整链 + 指纹比对 + openssl verify |
| 单张证书一次性总览？ | `run_all.py` | xlsx 5-sheet 报告 |
