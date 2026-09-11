# zlint-all-lints —— 证书 / CRL / OCSP 审计分支

本分支（`master`）只保留**证书吊销状态与字段审计**相关的脚本，克隆下来即可跑通下面四件事。
CT 审计、组织名 / SCT 提取、追链寻根等其它功能不在本分支，见 `main`。

| # | 功能 | 入口脚本 | 联网 |
|---|---|---|---|
| 1 | 证书全字段提取（含全部扩展） | `extract_CertInfo_python/extract_cert_fields.py` | 否 |
| 2 | CRL 全字段提取 + 吊销清单 | `extract_CertInfo_python/extract_crl_fields.py` | 否 |
| 3 | 批量查询证书 OCSP 状态 | `run_ocsp_batch.py` | 是 |
| 4 | 一张证书跑齐 zlint 的 CA / CRL / OCSP 三类规则 | `run_cert_crl_ocsp.py` | 是 |

另有几个配套脚本（同样属于本分支范围）：

| 脚本 | 用途 |
|---|---|
| `check_certs_python/check_ocsp.py` | 单张证书查 OCSP：从 AIA 取 responder 与签发者，输出 GOOD / REVOKED / UNKNOWN |
| `check_certs_python/check_crl.py` | 单张证书从 CDP 下载 CRL 并转 PEM |
| `check_certs_python/check_revocation_consistency.py` | CRL 与 OCSP 两渠道吊销信息交叉核验（状态 / 吊销时间 / 原因） |
| `query_cfca_certs.sh` | 批量导出证书关键信息 + OCSP 吊销状态，结果汇总进 txt |
| `query_cfca_certs_raw_ocsp.sh` | 同上，但**原样输出** OCSP 响应原文、不做状态判断，可选 `--respout` 留 DER |

---

## 环境准备

```bash
# ① Python 与依赖（两个 extract 脚本要求 cryptography >= 42，启动时会自检）
python3 -V
pip3 install -U cryptography
#   受管环境（Ubuntu 24 的 PEP 668）报错时改用：
#   pip3 install --break-system-packages -U cryptography

# ② Go（仅任务 4 需要；编译 zlint 工具用）
go version                    # 需 >= 1.25

# ③ openssl（仅 query_cfca_certs*.sh 需要）
openssl version

# ④ 联网能力：任务 3、4 与 CFCA 脚本要访问 CA 的 CRL / OCSP 服务
curl -sI https://www.baidu.com >/dev/null && echo "联网正常"
```

## 编译 zlint 工具（任务 4 必需）

`run_cert_crl_ocsp.py` 调用 `./zlint-all-lints` 跑三类规则。**编译产物不入库**
（`.gitignore` 已排除，且是平台专属文件），需要本地编译。

`go.mod` 里有 `replace github.com/zmap/zlint/v3 => ../zlint/v3`，因此上游 zlint 源码
必须放在**同级目录**：

```text
~/projects/
├── zlint/                # zmap/zlint 源码（不属于本项目，但构建必需）
└── zlint-all-lints/      # 本项目
```

缺少时：

```bash
cd ~/projects && git clone https://github.com/zmap/zlint.git
cd zlint-all-lints && ./build.sh        # 打印当前实际规则数
```

验证：`ls -la zlint-all-lints` 存在即可。**任务 1~3 不需要编译，也不需要 Go。**

---

## 快速开始

四件事的完整步骤（环境准备 → 逐项执行 → 结果自检 → 常见问题）见 **[RUNBOOK.md](RUNBOOK.md)**。最短路径：

```bash
# 1) 证书字段（本地，秒级）
python3 extract_CertInfo_python/extract_cert_fields.py certs/ --csv certs_wide.csv --csv-mode wide

# 2) CRL 字段 + 吊销清单（本地）
python3 extract_CertInfo_python/extract_crl_fields.py ~/share/ --csv crl_all.csv --csv-mode wide

# 3) 批量 OCSP 状态（联网）
python3 run_ocsp_batch.py certs/ --csv ocsp_batch.csv --timeout 10

# 4) 一张证书跑齐三类 zlint 规则（联网，需先 ./build.sh）
python3 run_cert_crl_ocsp.py certs/ results_three --timeout 15
```

无参数运行任一脚本会进入交互模式。CFCA 整链批量查询：

```bash
./query_cfca_certs.sh <证书目录> cfca_cert_info.txt
./query_cfca_certs_raw_ocsp.sh <证书目录> cfca_cert_ocsp_raw.txt --respout resp_der/
```

---

## 目录结构

```text
.
├── README.md                        本文件
├── RUNBOOK.md                       四件事的完整操作手册（主文档）
├── build.sh                         编译 zlint-all-lints / extract-cert
├── run_ocsp_batch.py                任务 3
├── run_cert_crl_ocsp.py             任务 4
├── query_cfca_certs.sh              CFCA 批量：证书信息 + OCSP 状态
├── query_cfca_certs_raw_ocsp.sh     CFCA 批量：证书信息 + OCSP 原文
├── check_certs_python/
│   ├── check_ocsp.py                OCSP 查询底层实现
│   ├── check_crl.py                 CRL 下载底层实现
│   └── check_revocation_consistency.py  CRL / OCSP 交叉核验
├── extract_CertInfo_python/
│   ├── extract_cert_fields.py       任务 1
│   └── extract_crl_fields.py        任务 2
├── main.go / cmd/ / go.mod / go.sum zlint 工具源码（编译用）
└── .gitignore                       运行产物不入库
```

---

## 使用须知

- **OCSP 状态不等于证书有效**：`GOOD` 只说明「该序列号在该 issuer 名下未被吊销」，
  不代表证书未过期、签名算法未被淘汰。
- **`check_ocsp.py` / `run_ocsp_batch.py` 不做 OCSP 响应签名验证**，输出状态仅供排查参考；
  要作为证据使用请用 `openssl ocsp` 并确认输出里有 `Response verify OK`。
- **没有 AIA-OCSP 地址的证书查不了 OCSP**（如 Let's Encrypt 证书只保留 CRL），
  批量结果里会记为 `ERROR: 无 OCSP 地址`，属正常现象。
- 运行产物（`results*/`、`*.csv`、`certs/`、编译出的二进制等）均已在 `.gitignore` 中，不会误提交。
