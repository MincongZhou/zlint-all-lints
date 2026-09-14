# ct_audit —— 证书透明度 CT 审计（嵌入式 SCT 证据链）

对证书的**嵌入式 SCT** 做三层审计 + 一项自动化时间交叉核验，回答：
证书是否真的被提交到公开 CT 日志（L1）→ 收据是否由日志私钥真实签发（L2）→
声称的日志当前是否在线且仍持有同一私钥（L3）→ SCT 时间戳与证书有效期、
审计时点、日志声明时间域是否自洽（时间核验）。

本目录程序可直接独立拷贝使用；作为 `zlint-all-lints` 的 Python 辅助脚本，
与 zlint（签发格式合规）、CRL/OCSP（吊销）互补，构成
**签发 → 公开登记 → 吊销**三段证据链。

## 文件

| 文件 | 说明 |
|---|---|
| `parse_sct.py` | L1：DER 级提取 SCT 列表并解析（log_id / timestamp / 算法），匹配 log list 快照 |
| `verify_sct.py` | L2：RFC 6962 §3.2 密码学验签（重建 defanged precert TBS） |
| `ct_log_liveness.py` | L3：逐日志 `get-sth` + 日志公钥验 STH 签名（RFC 6962 §3.5）；`--sth-out` 把 STH 原文落盘取证 |
| `check_ct_temporal.py` | 自动化时间交叉核验（批量目录 + `--csv` 汇总） |
| `ct_log_list.py` | CFCA 归属枚举：从 CT 日志中枚举**由 CFCA 签发**的证书，导出 序列号/指纹/签发者公钥/签发者指纹。`--source ctlog` 直连日志（覆盖最全），`--source crtsh` 走聚合索引快速摸底 |
| `samples/` | 演示与证据：baidu（GlobalSign 2018 签发）+ LE 对照组 + 签发者 + **log list v3 快照**（v90.1，2026-09-01T13:39:01Z） |

依赖：`python3 + cryptography`（仅 `ct_log_list.py --source crtsh` 额外需要 `requests`）。各脚本 log list 快照默认取 `samples/log_list_v3_snapshot.json`
（依次找 脚本目录 samples/ → 脚本目录 → 当前目录），全部缺失才在线拉取；
取证环境请用 `--loglist` 固定快照或 `--offline` 禁止在线回退。

## 用法

```bash
# L1 签发覆盖：提取解析 SCT + 匹配日志（默认读 samples/baidu_new.pem）
python3 parse_sct.py [证书.pem]

# L2 签名真实性：<证书> <签发者>（默认指 samples/ 的 baidu 与 GlobalSign 签发者）
python3 verify_sct.py [证书.pem] [签发者.crt]
python3 verify_sct.py samples/le_leaf.pem samples/le_issuer.pem   # LE 对照组

# L3 存活性（联网 get-sth + STH 验签）
python3 ct_log_liveness.py [证书.pem]
# L3 + 取证：把审计时点抓取的 STH 原文（tree_size/时间/根哈希/签名）落盘为 JSON
python3 ct_log_liveness.py samples/baidu_new.pem --sth-out sth_audit_2026-09-02.json

# 时间交叉核验（单张 / 目录批量 / CSV 汇总）
python3 check_ct_temporal.py samples/baidu_new.pem
python3 check_ct_temporal.py samples/ --csv out.csv
python3 check_ct_temporal.py cert.pem --offline      # 无快照时报错，不联网拉清单

# CFCA 归属枚举（推荐）：直连 CT 日志，按 issuer 精确匹配，增量累积
python3 ct_log_list.py --source ctlog --since 2026-06-01 \
        --max-entries 20000 --state ct_scan_state.json --out cfca_ct_fields.json
python3 ct_log_list.py --source ctlog --log argon2027h1 --start-index 0 --max-entries 2000  # 小窗口试跑

# 快速摸底：crt.sh 聚合索引（覆盖有限，见下文）
python3 ct_log_list.py --source crtsh --ca-dir ../../certs/CFCA --leaves-only --out cfca_ct_fields.json
python3 ct_log_list.py --source crtsh --limit 20 --delay 1.5 --domain cfca.work
```

## 判定标准

**L1（签发覆盖，Chrome CT Policy / BR §7.1.2.3）**
- 2018-04-30 后签发的证书 ≥ 2 个来自「log list 中状态 usable」日志的 SCT；
- SCT 时间戳与证书有效期自洽、落在日志声明的 `temporal_interval` 内；
- 日志属主多元化（≥ 2 个不同运营方）。

**L2（密码学验签）** —— 逐 SCT 用日志公钥验 RFC 6962 §3.2 签名，全部通过 =
收据由持有日志私钥者签发，非伪造。
> 关键重建规则（经 Google ct-go / Chrome 源码三方核对，公共文档常写错）：
> - 验证方从最终证书重建 precert TBS = **只删除 SCT 扩展，不插入 poison**
>   （ct-go `x509.RemoveSCTList`；Chrome `GetPrecertSignedEntry` 注释
>   "Copy all extensions except the embedded SCT extension"）；
> - 日志侧对 CA 提交的 precert 摘 poison 后签名/入树；两侧收敛于同一
>   "defanged TBS"（无 poison、无 SCT 扩展）；
> - SCT 自带 CtExtensions 参与签名输入，**非恒空**：LE Gouda2026h2 曾携带
>   8 字节扩展 `0000050026d85d88`，硬编码空扩展会误判真实 SCT 为失败。

**L3（存活性 / 密钥持有）** —— STH 验签通过 = 日志在线且持有签发 SCT 的同一私钥；
STH 时间接近审计时点（分钟级）表明持续签发；记录 tree_size 供后续
`get-proof-by-hash` inclusion 复核（RFC 6962 §4.5）。
取证建议：STH 与 log list 一样是时敏证据，审计应把 STH 原文落盘
（`--sth-out <文件>`，含审计时点/证书指纹/逐日志 STH），事后可随时用
同一日志公钥复验该 STH 签名，证明"这个时点日志确实活着、树有多大"。

**check_ct_temporal.py（时间交叉核验）** —— 逐 SCT 输出：
- `不一致`（退出码 1）：SCT 晚于审计时点（容差默认 5 分钟）/
  晚于 notAfter / 早于 notBefore 超窗口（默认 24h）/
  落在日志 `temporal_interval` 之外（O2 类，需调取签发时点快照复核）；
- `观察`：日志状态非 usable、快照未匹配到 log_id、略早于 notBefore 等需人工确认；
- CA/中间证书无 SCT 不算失败（CT 政策只约束 TLS 服务器证书）。

## 审计发现示例（本仓库样例可复现）

| 发现 | 对象 | 说明 |
|---|---|---|
| O1（方法学） | 全部 | precert 验签重建"只删 SCT 扩展不插 poison + CtExtensions 原样拼接"，已固化为 verify_sct.py |
| O2（待复核） | baidu | 3 个 SCT 时间戳（2026-07-09）均早于三条日志在**审计时点快照**的 `temporal_interval` 起点（2027-01-01）；SCT 验签通过（时间戳在签名输入内不可能错）→ 发证时点 log list 区间或与现在不同，需向 CA/日志运营方质询；对照组 LE 无此问题 |
| O3（证据管理） | 全部 | log list 是时敏证据，本目录已留审计时点快照 `samples/log_list_v3_snapshot.json`；签发/审计时应每次都留存。STH 同理：`ct_log_liveness.py --sth-out` 把每次审计抓取的 STH 原文落盘归档 |
| O4（环境限制） | IPng Gouda2026h2 | get-sth 端点从部分环境 TLS 不可达，属网络限制非 SCT 问题；建议具备直连条件的环境复核存活性 |

## ct_log_list.py（CFCA 归属枚举）

回答一个问题：**CT 日志里有哪些证书是由 CFCA 签发的**，并导出 4 个字段。

| 字段 | 来源 | 说明 |
|---|---|---|
| 订户证书的序列号 | 日志条目 / 下载证书 | `cert.serial_number`（原始值，不去前导零） |
| 订户证书的指纹 | 日志条目 / 下载证书 | 对证书 DER 计算 SHA-256 |
| 签发者的公钥 | `--ca-dir` 本地 CA 池 | CFCA CA 证书的 SubjectPublicKeyInfo（PEM） |
| 签发者的指纹 | `--ca-dir` 本地 CA 池 | 签发者证书 DER 的 SHA-256（另附公钥 SPKI SHA-256） |

### 为什么默认直连日志（`--source ctlog`）

关键是**用 issuer 精确匹配，而不是名字子串**。脚本把 `--ca-dir`（默认自动探测
`../../certs/CFCA`）建成三个索引，逐条 CT 条目比对：

1. precert 条目的 `issuer_key_hash`（32B）== SHA256(CFCA CA 的 SPKI) —— 零解析、最快、最准；
2. 条目内签发者链首个证书的 SPKI 哈希；
3. 叶子 `issuer` Name 与 CA 池 `subject` Name **原字节相等**（避免 Name 重编码假阴性）；
4. 兜底：issuer DN 文本含 `CFCA` 等关键词（记 `dn_keyword:*`，低置信，仅在 CA 池不全时用）。

因此**不会漏掉名字里不含 "CFCA" 的子 CA**——判据是密钥/名称，不是字符串。

命中时签发者公钥/指纹直接取自本地 CA 池（离线、权威）；日志条目自带的签发者链
仅在需要时解析。实测单日志吞吐约 3-10 条/秒，故默认每日志扫 2000 条、并发 8 个日志。

### 覆盖全量的做法（增量 + 续跑）

CT 日志树极大树（单日志树可达 10^9），全量扫描要长期跑；脚本按此设计：

```bash
# 每天跑一次，从记录处继续，逐步推进全量
python3 ct_log_list.py --source ctlog --state ct_scan_state.json \
        --max-entries 50000 --out cfca_ct_fields_$(date +%F).json
# 指定时间窗（二分定位起始索引）
python3 ct_log_list.py --source ctlog --since 2026-06-01 --until 2026-09-01
```

`--state` 记录每个日志的 `next_index`，下次运行自动续跑；在数组里按
`log_name + entry_index` 排序，配合 `--out` 可累积成可比对的取证结果。

### `--source crtsh` 的定位与实测限制

crt.sh 是第三方聚合索引，只能做**定向发现**。2026-09 逐项实测其能力边界：

| 入口 | 结果 |
|---|---|
| `?q=<身份>`（Identity，含 CN/SAN） | ✅ 可用；但匹配的是**证书自身主体**，不是 issuer |
| `?q=<dn>&searchtype=CAName` | ⚠️ 返回的是 **CA 证书本身**（含 Entrust/NII/Certum 交叉签名的副本），不是它签发的叶子 |
| `?q=<id>&searchtype=CAID` | ❌ `output=json` 报 `Unsupported output type: json`；`output=csv/html` 落到 CA 详情页（仅 1 个 `?id=` 链接） |
| `?CAID=<id>`、`?caid=<id>` | ⚠️ 就是 CA 证书详情页，**没有"该 CA 签发的证书"列表** |
| `?d=<id>` 下载证书本体 | ✅ 可用，但**实测约 21 秒/条** |
| 其它 | 每次请求普遍 20-40s，且间歇性 404/502 |

**结论：crt.sh 没有"按 issuer 枚举"的接口**（CAID 走不通、CAName 只给 CA 证书）。
所以：

- 要拿**真实客户证书**，只能把已知客户域名用 `--domain` 喂进去做 Identity 检索，
  再用本地 CA 池按 issuer 精确过滤。命中率取决于种子域名本身是否用 CFCA 签发。
- 因 `?d=` 极慢，脚本加了两道过滤，避免白下载：
  1. `--since/--until` 按 crt.sh 记录的 `not_before` **在下载前**过滤；
  2. 按记录的 `issuer_name` 预筛，只有含 CA 池 CN（或 `--dn-keyword`）的候选才下载。
- **AIA 抓来的签发者必须回查本地池确认确属 CFCA**，否则任何域名里恰好含 `cfca`
  的证书（如 Let's Encrypt 签发的 `cfcaXXXX.org`）都会被误收。

```bash
# 2024-2026 时间窗 + 客户域名种子（客户证书只能这样定向发现）
python3 ct_log_list.py --source crtsh --since 2024-01-01 --until 2026-12-31 \
    --keyword CFCA \
    --domain ccb.com.cn --domain boc.cn --domain bankcomm.com \
    --ca-dir ../../certs/CFCA --limit 60 \
    --out cfca_ct_2024_2026.json --csv cfca_ct_2024_2026.csv
```

### 字段口径提醒

- `entry_type=x509` 时才是**最终证书**；`entry_type=precert` 时日志里存的是 precert，
  与最终证书 **DER 不同**（precert 含 poison、无 SCT），故 `subscriber_sha256` 是
  "日志中该条目证书"的指纹，此时与最终证书指纹不一致（序列号两者相同）。
- `issuer_match` 记录命中方式（`issuer_key_hash` / `chain_spki` / `issuer_dn` /
  `dn_keyword:*`），便于评估覆盖度与置信度。
- 取证环境建议配 `--offline` 固定 log list 快照，避免在线清单漂移。

