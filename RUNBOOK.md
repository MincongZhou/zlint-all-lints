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
- `--paths-from <列表文件>`：从文件逐行读输入路径（`-` 表示 stdin，空行与 `#` 注释忽略）。
  路径成千上万时直接写进命令行会触发 `Argument list too long`，这时改用列表文件传参
  （`run_all.sh` 的 CRL 字段步就是这么传的）：
  `ls results/x/*/crl.pem > /tmp/crls.txt` 后
  `python3 extract_CertInfo_python/extract_crl_fields.py --paths-from /tmp/crls.txt --csv out.csv --csv-mode wide`
- 写 CSV 时是「边解析边累积结果行」，不会把所有 CRL 的完整解析结果同时留在内存里
- **输入就是本地 CRL，本步不联网**（下载 CRL 见 3.4 的 CDP 流程或 `check_crl.py`）：
  单个 CRL 文件（显式路径不看扩展名）、目录（递归 `.pem/.der/.crl`）、多路径混传都行；
  `--csv` 的输出文件会自动从输入里排除。同一目录混放多个体系的 CRL 时靠
  `issuer_cn` / `crl_number` / `tbs_sha256` 区分，要确认归属就加 `--issuer` 验签
- 指纹（`sha256` / `sha1` / `tbs_sha256`）为 64 位大写十六进制、**无冒号**；
  `sha256` = 整份 CRL（含签名），`tbs_sha256` = 不含签名的内容指纹
  （ECC 的 CRL 每次重签整体指纹都变，判断吊销数据有没有变化看 `tbs_sha256` 或 `crl_number`）
- **同一份 CRL 传入多次就输出多行**（`wide` / `entries` 都不做内容去重）：`run_all.sh` 的
  CRL 字段步是把「每证书一份 `<证书名>/crl.pem`」都传进来，所以重复行是常态——
  19 张 CA 证书实际只有 **4 份唯一 CRL**，宽表却是 15 行、条目表 85 行（真实吊销记录 14 条）。
  按 CRL 计数 / 求平均前先按 `tbs_sha256` 去重（**别用 `crl_number`**：各 CA 计数器独立，
  CFCA 的 `Global ECC ROOT G2` 与 `Global RSA ROOT G2` 都发到 913）：

```bash
python3 - <<'EOF'
import csv
rows = list(csv.DictReader(open('results/CFCA_CA证书/crl_fields.csv', encoding='utf-8-sig')))
seen, uniq = set(), []
for r in rows:
    if r['tbs_sha256'] in seen:
        continue
    seen.add(r['tbs_sha256'])
    uniq.append(r)
with open('/tmp/crl_fields_uniq.csv', 'w', newline='', encoding='utf-8-sig') as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys())
    w.writeheader()
    w.writerows(uniq)
print(len(rows), '->', len(uniq))    # 15 -> 4
EOF
```

### 3.3 批量查询 OCSP 状态（联网）

```bash
# ① 目录批量 + 汇总 CSV
python3 run_ocsp_batch.py certs/ --csv /tmp/ocsp_batch.csv --timeout 10

# ② 指定多张证书；DER 格式加 --der
python3 run_ocsp_batch.py certs/www.baidu.com.pem certs/www.qq.com.pem --der

# ③ CertID 摘要换 SHA-256（默认 SHA-1，兼容性最好）
python3 run_ocsp_batch.py certs/ --sha256

# ④ 签发者证书放本地目录（CA 的 AIA 没给 CA Issuers 时必须）
python3 run_ocsp_batch.py certs/ --issuer-dir ./mycas --issuer-dir ~/cfca
```

**签发者证书**（OCSP 的 CertID 必须用它构造）按优先级查找：
`--issuer-dir` 指定目录 → 默认目录 `<项目根>/issuers` → 证书 AIA 里的 `CA Issuers`。
批量开始时只扫一次目录，按证书 AKI 反查签发者 SKI，逐张命中即复用；
取到的签发者一律做 AKI/SKI 校验，不匹配立即报错 —— 否则会算出错误的 CertID，
responder 回 `UNAUTHORIZED`，看起来像"服务端拒绝"，其实只是传错了签发者。
很多 CA（如 CFCA Identity 体系）的 AIA 只给 OCSP 地址、不给 `CA Issuers`，
这类证书必须靠前两级，否则只能得到 `ERROR: 加载签发者证书失败`。

产物 `/tmp/ocsp_batch.csv`，六列
`cert,fingerprint_sha256,not_before,not_after,status,detail`
（`fingerprint_sha256` = 证书 DER 编码的 SHA-256 指纹，**64 位大写十六进制、无冒号**
（即 `openssl x509 -fingerprint -sha256` 去掉冒号后的形式）；`not_before` / `not_after` = 证书有效期，
ISO 8601 UTC，与 `openssl x509 -noout -dates` 一致。这几列都从证书本地解析，
证书改名 / 重名 / 多版本链同名文件都能唯一定位，且解析失败或查询失败时依然有值，
便于与台账对账）：

| status | 含义 |
|---|---|
| `GOOD` | 未吊销 |
| `REVOKED` | 已吊销 |
| `UNKNOWN` | responder 不认识该证书 |
| `ERROR` | 查询失败（无 OCSP 地址 / 签发者加载失败 / 网络不通 / 响应非成功），原因见 `detail` |
| `ERROR` 且 detail = `UNAUTHORIZED` | responder 不受理该 CertID：该 CA 体系根本不提供 OCSP（吊销状态只能靠 CRL 判断），或签发者传错（已被 AKI/SKI 校验拦住，不会静默算错） |

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

# ④ 忽略 CRL 缓存，强制重新下载（默认只有缓存过了 nextUpdate 才重下）
python3 run_cert_crl_ocsp.py certs/ /tmp/three --refresh-crl
```

产物（默认精简模式）：

```text
/tmp/three/
├── ca_summary.csv       全部证书的证书侧汇总
├── crl_summary.csv      全部证书的 CRL 侧汇总
├── ocsp_summary.csv     全部证书的 OCSP 侧汇总
├── index.csv            证书索引：cert / fingerprint_sha256（无冒号）/ not_before /
│                        not_after / path / crl_pem / resp_der
├── _crl_cache/          CRL 去重缓存：同一 CDP URL 只下载一次（crl_<url哈希>.pem），
│                        可随时删除。缓存以 CRL 自身的 nextUpdate 为有效期：已过期
│                        （或缺 nextUpdate 且文件超过 24h）就自动重新下载，复跑同一
│                        输出目录不会拿上一轮的旧 CRL 当本次证据；--refresh-crl
│                        可强制忽略全部缓存重下
└── www.baidu.com/       每证书目录（只留联网证据文件）
    ├── crl.pem          该证书对应的 CRL（有则；可能是从缓存复制来的）
    └── resp.der         原始 OCSP 响应（有则）
```

三张 `*_summary.csv` 里**没有指纹**（zlint 的 CSV 输出本身不含指纹），只用 `cert` 列
（证书名，同名时带父目录前缀 `__`）标识证书；需要指纹或有效期时，用 `index.csv` 按
`cert` 列 join 即可。

终端会打印三侧统计（实测示例）：

```text
[OK] 证书侧 (cert): NA=244  pass=182  NE=13  warn=3
[OK] CRL 侧 (crl):  NA=425  pass=17
[OK] OCSP 侧 (ocsp): NA=441  pass=1
```

- 每侧行数恒等于 `meta.total_lints`；`NA` = 该规则不适用于输入对象类型，`NE` = 规则尚未生效
- CRL / OCSP 侧联网失败（无 CDP、无 OCSP 地址、网络不通、超时）会**自动跳过该侧**，不中断整体
- **CRL 按 CDP URL 去重下载**：CRL 是「签发者 + 分区」级文件（同一 CA 可能同时发布
  `crl1.crl` 给终端证书、`allCRL.crl` 给 CA 证书），一张 CRL 覆盖该分区下所有证书。
  首个命中某 URL 的证书触发下载并缓存到 `_crl_cache/`，其余指向同一 URL 的证书直接
  复制缓存（每张证书仍各有自己的 `crl.pem`）。批量结束打印
  `CRL 去重统计: 实际下载 N 次，命中缓存 M 次，无 CRL 可下 K 次`
- 缓存**不是永久有效**：命中前会看缓存 CRL 的 `nextUpdate`，已过期的当作陈旧并重新下载，
  避免复跑同一输出目录时把上一轮的旧 CRL（吊销集合可能不完整）当成"本轮证据"。想不等
  `nextUpdate` 就直接重下，加 `--refresh-crl`
- 每张证书开跑前会先删掉自己目录里**上一轮遗留**的 `crl.pem`（OCSP 的 `resp.der` 同理）：
  本轮没取到证据时目录里不会有旧文件冒充本次结果，`run_all.sh` 的 CRL 字段步也就不会
  解析到陈旧 CRL
- 去重效果实测（`certs/CFCA_CA证书`，19 张证书 / 15 张有 CDP）：5 个唯一 URL，
  下载 **15 次 → 5 次**，CRL 下载环节 **2.78 s → 0.45 s（−84%）**（单次下载约 146 ms，
  缓存命中是文件复制，约 0.09 ms）；整脚本 19 张约 9.4 s → **7.2 s**——省下的只有下载
  那 2.3 s，其余花在 19 次 OCSP 查询和 57 次 zlint（单对象约 24 ms，不是瓶颈）。
  `certs/CFCA订户证书` 11878 张 → 唯一 CDP **335 个**（其中 327 个是 `oca31/SM2` 国密
  CRL），下载量由「证书数」降到「唯一 URL 数」；证书越多、URL 越集中，收益越大
  （1 万张 / 200 个唯一 URL：约 24 分钟 → 约 30 秒）
- OCSP **无法**这样去重：请求带 CertID（签发者哈希 + 序列号），一次只能查一张证书，
  请求数等于证书数；要提速只能并发（当前为逐张串行）

### 3.5 一键跑齐五步（`run_all.sh`）

把 3.1–3.4 串成一条命令，产物统一落到同一个输出目录；其中 CRL 字段步直接复用
三类规则步下载到本地的 `crl.pem`，OCSP 响应字段步复用它保存的 `resp.der`，
都不必自己拼通配符参数：

```bash
./run_all.sh <证书文件|证书目录> [输出目录] [超时秒数] [选步参数...]

./run_all.sh "certs/CFCA_CA证书" results/CFCA_CA 15              # 五步全跑
./run_all.sh "certs/CFCA订户证书" results/x 10 --only 2,4         # 只跑 2) 证书字段 + 4) OCSP 状态
./run_all.sh "certs/CFCA订户证书" results/x 10 --only 5           # 只把已有的 resp.der 解析成字段表
./run_all.sh "certs/CFCA订户证书" results/x 10 --skip 1,3         # 跳过 1) 三类规则、3) CRL 字段
./run_all.sh "certs/CFCA订户证书" results/x 10 --no-lint          # 等价 --skip 1（最省时）
./run_all.sh certs/ --out results/all --timeout 15 --refresh-crl  # 选项写法：强制重下 CRL
./run_all.sh "certs/CFCA订户证书" results/x 15 --fast             # 第 4 步复用本地 OCSP 响应（见下方小节）
./run_all.sh -h                                                  # 帮助
```

> 步骤号是 `run_all.sh` 自己的编号（`1` 三类规则 / `2` 证书字段 / `3` CRL 字段 /
> `4` OCSP 状态 / `5` OCSP 响应字段），与上面 3.1–3.4 的排列顺序**不同**
> （脚本把最慢的联网 lint 放在了第 1 步）。第 5 步与第 3 步一样是纯本地解析，
> 输入分别是第 1 步存下的 `resp.der` 与 `crl.pem`。

| 选步参数 | 含义 |
|---|---|
| `--only <步骤>` | 只跑列出的步骤。步骤号：`1` 证书/CRL/OCSP 三类 lint、`2` 证书字段、`3` CRL 字段、`4` OCSP 状态、`5` OCSP 响应字段 |
| `--skip <步骤>` | 跳过列出的步骤（`--no-lint` 等价 `--skip 1`）；`--skip` 优先级高于 `--only` |

其它选项：

| 选项 | 含义 |
|---|---|
| `--out <目录>` | 指定输出目录（等价第 2 个位置参数；输出目录名是纯数字时用它消歧） |
| `--timeout <秒>` | 联网超时秒数（等价第 3 个位置参数） |
| `--refresh-crl` | 透传给第 1 步：忽略 CRL 缓存强制重新下载 |
| `--fast` | 第 4 步改为复用本地 OCSP 响应（详见下方「`--fast`：第 4 步复用本地 OCSP 响应」）；不加则逐张联网查询 |
| `-h, --help` | 显示帮助 |

#### `--fast`：第 4 步复用本地 OCSP 响应

第 1 步（`run_cert_crl_ocsp.py`）为了跑 zlint 的 OCSP 类规则，已经对每张证书查过一次
OCSP，并把原始响应存成 `<输出目录>/<证书名>/resp.der`；第 4 步（`run_ocsp_batch.py`）
又**对同一个 responder 重新联网查一遍**，只为拿 `GOOD / REVOKED / UNKNOWN` 这个状态列。
同一批查询因此被做了两次，是整个跑批最大的耗时点。

`--fast` 把整轮交给同目录的 `run_all_fast.py`：第 1、2、3 步照旧（同样 subprocess 调用
项目里的三个脚本），**只有第 4 步**改成——先在本地解析已有的 `resp.der` 取状态，
取不到才联网：

```bash
./run_all.sh "certs/CFCA订户证书" results/x 15 --fast
python3 run_all_fast.py "certs/CFCA订户证书" results/x 15     # 等价的直接调用
```

复用要同时满足三条，任一条不满足就回落到联网：

1. `index.csv` 里该证书有 `resp_der` 记录，且对应文件存在
2. OCSP 响应的 `response_status` 为 SUCCESSFUL（`tryLater` / `unauthorized` 等一律当作没有）
3. 响应新鲜——`next_update` 未过期；响应没带 `next_update` 时按
   `this_update + 168 小时` 判定（可用 `--max-age-hours` 调整）

**实测（CFCA订户证书_ct_log，8142 张，2026-09-18）**

| 方式 | 耗时 | 联网次数 |
|---|---|---|
| 原第 4 步（逐张联网） | 约 55 分钟 | 8142 |
| `--only 4 --fast` | **8.9 秒** | 29（都是没有 `resp.der` 的证书） |

结果与逐张联网的 `ocsp_batch.csv` **8142/8142 完全一致**（含 REVOKED 的吊销时间字符串）。

什么时候用 / 什么时候没用：

- ✅ 重跑、补跑第 4 步，或输出目录里已有第 1 步产物时——最划算
- ✅ `--only 1,4`：第 1 步刚产出 `resp.der`，第 4 步立刻复用
- ⚠️ **全新输出目录且跳过第 1 步**（`--skip 1` / `--no-lint`）时没有可复用内容，
  第 4 步会退化为逐张联网，此时加不加 `--fast` 没有差别
- ⚠️ 需要「本次实时取证」（合规、举证场景）时**不要加**：复用用的是已有响应，
  默认行为才是每张当场查

`--fast` **不改变跑哪些步骤**：`--only / --skip / --no-lint` 完全照旧生效并透传，
参数校验也仍在 `run_all.sh` 里先完成（例如 `--only 1 --no-lint --fast` 依旧报
「五步都被跳过」、退出码 2，与不加 `--fast` 一致）。只有真正要跑第 4 步时它才有意义。

约定与注意：

- 输出目录不填时默认 `results/<输入目录名>`；选项与位置参数可混排，也支持
  `--only=2,4` / `--out=xxx` / `--timeout=15` 这类等号写法
- 只给了证书路径和**一个纯数字**位置参数时，该数字按超时秒数处理（输出目录名是纯数字
  请用 `--out`）；第 4 个及以后的位置参数会直接报错，不再静默覆盖超时
- **CRL 字段步依赖三类规则步**：跳过后者时，输出目录里**已有的** `<证书名>/crl.pem`
  仍会被解析；跑了后者时每张证书会先清掉自己目录里上一轮的 `crl.pem`，只留本轮证据，
  因此不会解析到陈旧 CRL
- **OCSP 响应字段步（第 5 步）同理**：输入是第 1 步存下的 `<证书名>/resp.der`，本地解析、
  不联网，产物 `ocsp_fields.csv`（每份响应一行）+ `ocsp_fields_responses.csv`
  （每条 SingleResponse 一行）。同一 responder 的响应会被每张证书各存一份，统计前按
  `tbs_sha256` / `response_sha256` 去重；`response_status` 非 SUCCESSFUL 的行没有
  签名与状态字段（属正常，不是解析失败）
- 跳过三类规则步则不生成 `ca_summary.csv` / `crl_summary.csv` / `ocsp_summary.csv` / `index.csv`
  （输出目录里若已有上轮的这些文件会原样留着，不算本次产物）
- 单张证书也会强制 `--csv-mode wide`，保证与目录输入的表结构一致（一张证书也占一行）
- 屏幕上的步骤编号按**实际执行**的步骤重排（如 `[1/2]`、`[2/2]`），结尾打印产物清单
- 规模大时建议 `--skip 1`：三类规则步是「每张证书跑 3 次 zlint + 取一次 CRL + 查一次
  OCSP」，上千张仍会非常慢——CRL 下载已按 CDP URL 去重，但 **zlint 与 OCSP 都是逐张串行**，
  省不下来
- CRL 字段步把每份 `<证书名>/crl.pem` 通过列表文件（`--paths-from`）交给
  `extract_crl_fields.py`，上万份也不会撞上命令行长度上限
- CRL 字段步的输入是「每证书一份 `<证书名>/crl.pem`」，同一份 CRL 会因此出现多次
  （本仓库 19 张 CA 证书 → 宽表 15 行但只有 4 份唯一 CRL，条目表 85 行但真实吊销记录 14 条）。
  做统计前先按 `tbs_sha256` 去重，详见 3.2 最后一条

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

不想逐条敲就用一键脚本（等价于上面 1–4 按序执行，产物落同一个目录）：

```bash
./run_all.sh certs/ /tmp/all 15              # 四步全跑
./run_all.sh certs/ /tmp/all 15 --only 2,4   # 只要证书字段 + OCSP 状态
```

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

CSV（含 `ca_summary.csv` / `crl_summary.csv` / `ocsp_summary.csv` 三张汇总表）均为
**UTF-8 with BOM**，Excel / WPS 双击即可正常显示中文。

---

## 6. 常见问题速查

| 现象 | 原因与处理 |
|---|---|
| `找不到 zlint-all-lints，请先编译` | 未编译 → 执行 `./build.sh` |
| `go build` 报 `reading ../zlint/v3/go.mod: file does not exist` | `~/projects/zlint` 缺失 → `git clone https://github.com/zmap/zlint.git` |
| `错误: 需要 cryptography >= 42.0（当前 x.y）` | `pip3 install -U cryptography`（受管环境加 `--break-system-packages`） |
| OCSP 批量大量 `ERROR: 无 OCSP 地址` | 证书没有 AIA/OCSP 地址（自签或内部证书），属正常 |
| OCSP 批量大量 `ERROR: 加载签发者证书失败` | 证书 AIA 没有 `CA Issuers`（如 CFCA Identity 体系），且签发者目录里没有匹配的证书 → 把签发者证书放进 `<项目根>/issuers/`，或用 `--issuer-dir` 指定 |
| OCSP 报 `ERROR: 加载签发者证书失败: 签发者与证书不匹配` | 传错了签发者证书（AKI/SKI 对不上）→ 换成该证书真正的签发者 |
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
| 三类规则一起跑 | `python3 run_cert_crl_ocsp.py <证书\|目录> <输出目录> [--detail] [--refresh-crl]` |
| 一键跑齐五步 | `./run_all.sh <证书\|目录> [输出目录] [超时秒数] [选步参数]` |
| 只跑证书字段 + OCSP 状态 | `./run_all.sh <证书\|目录> <输出目录> 15 --only 2,4` |
| 跳过三类 lint（最省时） | `./run_all.sh <证书\|目录> <输出目录> 15 --no-lint` |
| 强制重下 CRL（忽略缓存） | `./run_all.sh <证书\|目录> <输出目录> --refresh-crl` |
| CRL 批量（路径列表文件） | `python3 extract_CertInfo_python/extract_crl_fields.py --paths-from list.txt --csv out.csv --csv-mode wide` |
| 单张 OCSP 查询 | `python3 check_certs_python/check_ocsp.py <证书> [签发者证书] --status` |
| OCSP 响应全字段 | `python3 extract_CertInfo_python/extract_ocsp_fields.py <resp.der>` |
| OCSP 响应批量宽表 | `python3 extract_CertInfo_python/extract_ocsp_fields.py <目录> --csv out.csv --csv-mode wide` |
| OCSP 响应验签 | `python3 extract_CertInfo_python/extract_ocsp_fields.py <resp.der> --issuer ca.pem` |
| 单张 OCSP + 签发者目录 | `python3 check_certs_python/check_ocsp.py <证书> --issuer-dir <目录> --status` |
| 单张 CRL 下载 | `python3 check_certs_python/check_crl.py <证书> --out crl.pem` |
| CRL / OCSP 一致性核验 | `python3 check_certs_python/check_revocation_consistency.py <证书\|目录> [--csv 结果.csv]` |
| CFCA 批量：证书信息 + OCSP 状态 | `./query_cfca_certs.sh <目录> [输出.txt]` |
| CFCA 批量：证书信息 + OCSP 原文 | `./query_cfca_certs_raw_ocsp.sh <目录> [输出.txt] [--respout 目录]` |
