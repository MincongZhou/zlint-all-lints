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
| `ct_log_liveness.py` | L3：逐日志 `get-sth` + 日志公钥验 STH 签名（RFC 6962 §3.5） |
| `check_ct_temporal.py` | 自动化时间交叉核验（批量目录 + `--csv` 汇总） |
| `samples/` | 演示与证据：baidu（GlobalSign 2018 签发）+ LE 对照组 + 签发者 + **log list v3 快照**（v90.1，2026-09-01T13:39:01Z） |

依赖：`python3 + cryptography`。四脚本 log list 快照默认取 `samples/log_list_v3_snapshot.json`
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

# 时间交叉核验（单张 / 目录批量 / CSV 汇总）
python3 check_ct_temporal.py samples/baidu_new.pem
python3 check_ct_temporal.py samples/ --csv out.csv
python3 check_ct_temporal.py cert.pem --offline      # 无快照时报错，不联网拉清单
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
| O3（证据管理） | 全部 | log list 是时敏证据，本目录已留审计时点快照 `samples/log_list_v3_snapshot.json`；签发/审计时应每次都留存 |
| O4（环境限制） | IPng Gouda2026h2 | get-sth 端点从部分环境 TLS 不可达，属网络限制非 SCT 问题；建议具备直连条件的环境复核存活性 |
