# RUNBOOK —— 四件常用任务的完整操作步骤

本文覆盖四件事，从环境准备到结果自检：

1. **证书字段提取** —— `extract_CertInfo_python/extract_cert_fields.py`（纯本地）
2. **CRL 字段提取 + 吊销清单** —— `extract_CertInfo_python/extract_crl_fields.py`（纯本地）
3. **批量查询 OCSP 状态** —— `run_ocsp_batch.py`（联网）
4. **一张证书跑齐 CA / CRL / OCSP 三类规则** —— `run_cert_crl_ocsp.py`（联网）

> 四件事互不依赖，可只做其中一件。任务 1、2 不依赖 zlint；任务 4 需要先编译 `zlint-all-lints`。
> 全貌与依赖说明见 `README.md`；CFCA 整链批量查询见 `query_cfca_certs.sh` / `query_cfca_certs_raw_ocsp.sh`。

---

## 0. 环境准备（一次性）

```bash
# ① Python 与依赖（两个 extract 脚本要求 cryptography >= 42，启动时会自检）
python3 -V
python3 -c "import cryptography; print(cryptography.__version__)"
pip3 install -U cryptography
#   受管环境（Ubuntu 24 的 PEP 668）报错时改用：
#   pip3 install --break-system-packages -U cryptography

# ② Go（编译 zlint 工具用）
go version                                   # 需 >= 1.25

# ③ 联网能力：任务 3、4 要访问 CA 的 CRL / OCSP 服务
curl -sI https://www.baidu.com >/dev/null && echo "联网正常"
```

目录布局必须是下面这样（`go.mod` 里的 `replace` 指向同级 `zlint/`）：

```text
~/projects/
├── zlint/                # zmap/zlint 源码（不属于本项目，但构建必需）
└── zlint-all-lints/      # 本项目
```

缺少 zlint 源码时：

```bash
cd ~/projects && git clone https://github.com/zmap/zlint.git
```

---

## 1. 编译（一次性；换 zlint 版本后需重跑）

```bash
cd ~/projects/zlint-all-lints
./build.sh
# 期望输出： total_lints = 433  (CA=414, CRL=18, OCSP=1)
```

等价的手动命令：

```bash
go mod tidy
go build -o zlint-all-lints .
go build -o extract-cert ./cmd/extract-cert
```

验证：`ls -la zlint-all-lints extract-cert` 两个可执行文件存在。

> 规则总数随本地 zlint 源码版本变化，`./build.sh` 会直接打印，不在文档里写死。

---

## 2. 准备样本

| 用途 | 需要什么 | 样本从哪来 |
|---|---|---|
| 证书字段提取 / 任务 4 | 证书 PEM 或 DER | 自备（把证书放到 `certs/` 即可，该目录不入库） |
| CRL 字段提取 | CRL PEM 或 DER | 自备 `.crl`，或用 `check_crl.py` 从证书 CDP 下载 |
| 批量 OCSP 状态 | 证书（**须含 AIA / OCSP 地址**） | 自备 |

- 目录输入会**递归**扫描；扩展名范围：证书 `.pem/.crt/.cer/.der`，CRL 另加 `.crl`
- 不支持 P12/PFX
- 多证书合并的 PEM（一个文件多张证书）会被判为解析失败，请拆开

---

## 3. 逐项执行

### 3.1 证书字段提取（纯本地，秒级）

```bash
cd ~/projects/zlint-all-lints

# ① 单张：终端可读输出
python3 extract_CertInfo_python/extract_cert_fields.py certs/www.baidu.com.pem

# ② 单张：JSON 落盘
python3 extract_CertInfo_python/extract_cert_fields.py certs/www.baidu.com.pem \
        --json --out /tmp/baidu.json

# ③ 批量：宽表 + 扩展长表（两张 CSV）
python3 extract_CertInfo_python/extract_cert_fields.py certs/ \
        --csv /tmp/certs_wide.csv --csv-mode wide
#   → /tmp/certs_wide.csv             每证书一行（基础列 + ext.<OID名>.* 列）
#   → /tmp/certs_wide_extensions.csv  每扩展一行（值为完整 JSON）

# ④ 单证书逐字段摊平（排查某个具体字段时最好用）
python3 extract_CertInfo_python/extract_cert_fields.py certs/www.baidu.com.pem \
        --csv /tmp/fields.csv --csv-mode fields
```

- `--csv-mode`：`fields`（每字段一行）/ `summary`（约 30 列常用字段）/ `wide`（全字段列）
- 不加 `--csv-mode` 时自动选择：单文件 → `fields`，目录 → `wide`
- 默认按 PEM 解析，失败自动回退 DER；`--der` 可强制按 DER 解析

### 3.2 CRL 字段提取 + 吊销清单（纯本地）

```bash
# ① 终端列出吊销序列号（默认模式）
python3 extract_CertInfo_python/extract_crl_fields.py ~/share/

# ② 宽表 + 吊销条目表
python3 extract_CertInfo_python/extract_crl_fields.py ~/share/ \
        --csv ~/share/crl_all.csv --csv-mode wide
#   → crl_all.csv          每份 CRL 一行（头部字段 + ext.* 扩展列）
#   → crl_all_entries.csv  每条吊销记录一行（序列号 / 时间 / 原因）

# ③ 全字段逐项打印（扩展、指纹、tbsCertList、条目详情）
python3 extract_CertInfo_python/extract_crl_fields.py ~/share/allCRL.crl --full

# ④ 验签 + issuer DN 比对（传入签发者证书）
python3 extract_CertInfo_python/extract_crl_fields.py ~/share/allCRL.crl \
        --issuer /path/to/ca.pem
#   证书 subject 与 CRL issuer 不匹配时会告警，并在结果里记 issuer_dn_match=False
```

- `--csv-mode`：`revoked`（默认）/ `entries` / `wide` / `fields`
- 大 CA 的 CRL 可达数万条，`wide` 只放吊销条数，逐条看 `*_entries.csv`
- 可选 `--json`（JSON 输出）、`--no-ext-columns`（宽表只输出固定列）

### 3.3 批量查询 OCSP 状态（联网）

```bash
# ① 目录批量 + 汇总 CSV
python3 run_ocsp_batch.py certs/ --csv /tmp/ocsp_batch.csv --timeout 10

# ② 指定多张证书；DER 格式加 --der
python3 run_ocsp_batch.py certs/www.baidu.com.pem certs/www.qq.com.pem --der

# ③ CertID 摘要换 SHA-256（默认 SHA-1，兼容性最好）
python3 run_ocsp_batch.py certs/ --sha256
```

产物 `/tmp/ocsp_batch.csv`，三列 `cert,status,detail`：

| status | 含义 |
|---|---|
| `GOOD` | 未吊销 |
| `REVOKED` | 已吊销 |
| `UNKNOWN` | responder 不认识该证书 |
| `ERROR` | 查询失败（无 OCSP 地址 / 签发者加载失败 / 网络不通 / 响应非成功），原因见 `detail` |

**退出码**：全部成功返回 `0`，出现 `ERROR` 返回 `1`，便于脚本判断。

### 3.4 一张证书跑齐 CA / CRL / OCSP 三类规则（联网）

必须先有 `zlint-all-lints` 二进制（见第 1 节）。

```bash
# ① 单张证书
python3 run_cert_crl_ocsp.py certs/www.baidu.com.pem /tmp/three

# ② 整个目录批量（重名证书自动补父目录前缀，避免互相覆盖）
python3 run_cert_crl_ocsp.py certs/ /tmp/three --timeout 15

# ③ 保留每张证书的完整中间产物（cert / crl / ocsp 的 json + csv）
python3 run_cert_crl_ocsp.py certs/www.baidu.com.pem /tmp/three --detail
```

产物（默认精简模式）：

```text
/tmp/three/
├── ca_summary.csv       全部证书的证书侧汇总
├── crl_summary.csv      全部证书的 CRL 侧汇总
├── ocsp_summary.csv     全部证书的 OCSP 侧汇总
└── www.baidu.com/       每证书目录（只留联网证据文件）
    ├── crl.pem          从 CDP 下载的 CRL（有则）
    └── resp.der         原始 OCSP 响应（有则）
```

终端会打印三侧统计（实测示例）：

```text
[OK] 证书侧 (cert): NA=244  pass=182  NE=13  warn=3
[OK] CRL 侧 (crl):  NA=425  pass=17
[OK] OCSP 侧 (ocsp): NA=441  pass=1
```

- 每侧行数恒等于 `meta.total_lints`；`NA` = 该规则不适用于输入对象类型，`NE` = 规则尚未生效
- CRL / OCSP 侧联网失败（无 CDP、无 OCSP 地址、网络不通、超时）会**自动跳过该侧**，不中断整体

---

## 4. 一次性串起来（推荐顺序）

```bash
cd ~/projects/zlint-all-lints

./build.sh                                                  # 0) 编译（首次 / 换 zlint 后）

python3 extract_CertInfo_python/extract_cert_fields.py certs/ \
        --csv /tmp/certs_wide.csv --csv-mode wide           # 1) 证书字段（本地）

python3 extract_CertInfo_python/extract_crl_fields.py ~/share/ \
        --csv /tmp/crl_all.csv --csv-mode wide              # 2) CRL 字段（本地）

python3 run_ocsp_batch.py certs/ --csv /tmp/ocsp_batch.csv --timeout 10   # 3) 吊销状态（联网）

python3 run_cert_crl_ocsp.py certs/ /tmp/three --timeout 15              # 4) 三类 lint（联网，最慢）
```

顺序建议：先跑本地任务（1、2，秒级）摸清事实，再跑联网任务（3、4，慢且受网络影响）。

---

## 5. 结果自检

```bash
# 证书宽表：行数应等于目录内证书数
python3 -c "import csv;print(len(list(csv.DictReader(open('/tmp/certs_wide.csv',encoding='utf-8-sig')))),'张证书')"

# CRL：宽表（每 CRL 一行）+ 条目表
wc -l /tmp/crl_all.csv /tmp/crl_all_entries.csv

# OCSP 状态分布
python3 -c "
import csv;from collections import Counter
r=list(csv.DictReader(open('/tmp/ocsp_batch.csv',encoding='utf-8-sig')))
print(Counter(x['status'] for x in r))"
```

CSV 均为 **UTF-8 with BOM**，Excel / WPS 双击即可正常显示中文。

---

## 6. 常见问题速查

| 现象 | 原因与处理 |
|---|---|
| `找不到 zlint-all-lints，请先编译` | 未编译 → 执行 `./build.sh` |
| `go build` 报 `reading ../zlint/v3/go.mod: file does not exist` | `~/projects/zlint` 缺失 → `git clone https://github.com/zmap/zlint.git` |
| `错误: 需要 cryptography >= 42.0（当前 x.y）` | `pip3 install -U cryptography`（受管环境加 `--break-system-packages`） |
| OCSP 批量大量 `ERROR: 无 OCSP 地址` | 证书没有 AIA/OCSP 地址（自签或内部证书），属正常 |
| `run_cert_crl_ocsp.py` 某侧显示跳过 | 无 CDP / OCSP 地址或网络不通，只影响该侧，其它侧照跑 |
| 提取脚本跑完没生成文件 | 默认只在终端输出，需显式加 `--csv` / `--out` |
| 目录里混入 CRL / OCSP 导致证书解析报错 | `extract_cert_fields.py` 会自动跳过并告警；也可只传证书文件 |
| 结果会不会被提交进 git | 不会，`/results*/`、根目录 `*.csv`、`/certs/`、编译产物等均在 `.gitignore` 中 |
| OCSP 查到 `GOOD` 能否直接当审计证据 | `check_ocsp.py` / `run_ocsp_batch.py` **不做响应签名验证**，仅供参考；取证请用 `openssl ocsp`（带 `-issuer` 与 `-CAfile`）并确认输出里有 `Response verify OK` |
| 批量 OCSP 里 `UNKNOWN` / `ERROR` 怎么算 | 都不等于 `GOOD`。OCSP 是 soft-fail 语义，查不到只能是"未知"，不能兜底成"未吊销" |

---

## 7. 相关命令速查表

| 目的 | 命令 |
|---|---|
| 编译 / 查当前规则数 | `./build.sh` |
| 证书全字段 | `python3 extract_CertInfo_python/extract_cert_fields.py <路径> --json` |
| 证书批量宽表 | `python3 extract_CertInfo_python/extract_cert_fields.py <目录> --csv out.csv --csv-mode wide` |
| CRL 吊销清单 | `python3 extract_CertInfo_python/extract_crl_fields.py <路径>` |
| CRL 全字段 | `python3 extract_CertInfo_python/extract_crl_fields.py <路径> --full` |
| CRL 批量宽表 | `python3 extract_CertInfo_python/extract_crl_fields.py <目录> --csv out.csv --csv-mode wide` |
| CRL 验签 | `python3 extract_CertInfo_python/extract_crl_fields.py <crl> --issuer ca.pem` |
| 批量 OCSP 状态 | `python3 run_ocsp_batch.py <目录> --csv out.csv --timeout 10` |
| 三类规则一起跑 | `python3 run_cert_crl_ocsp.py <证书\|目录> <输出目录> [--detail]` |
| 单张 OCSP 查询 | `python3 check_certs_python/check_ocsp.py <证书> [签发者证书] --status` |
| 单张 CRL 下载 | `python3 check_certs_python/check_crl.py <证书> --out crl.pem` |
| CRL / OCSP 一致性核验 | `python3 check_certs_python/check_revocation_consistency.py <证书\|目录> [--csv 结果.csv]` |
| CFCA 批量：证书信息 + OCSP 状态 | `./query_cfca_certs.sh <目录> [输出.txt]` |
| CFCA 批量：证书信息 + OCSP 原文 | `./query_cfca_certs_raw_ocsp.sh <目录> [输出.txt] [--respout 目录]` |
