# 0scan

**Mobile-first secret scanner** — hunt hardcoded API keys & passwords in GitHub repositories, right from your phone (Termux) or desktop. All findings are auto-masked before display.

**手机优先的密钥安检工具** —— 把 GitHub 仓库拉下来，扫出硬编码的密钥与密码，输出自动脱敏的报告。手机（Termux）、桌面皆可运行。

## ✨ Features / 功能

- 🔑 **20+ 类凭证检测**：OpenAI / Anthropic / AWS / GitHub / GitLab / Google / Slack / Stripe / SendGrid / Twilio / Mailgun / npm / PyPI / Shopify / Telegram / Facebook / JWT / PEM·PGP 私钥 / 数据库连接串 / 硬编码密码 / 通用 API Key 赋值 / Detects 20+ secret types incl. OpenAI, AWS, GitHub, Slack, Stripe, private keys, JWT, database URLs
- 🎲 **熵值兜底检测**：Shannon 熵 + 字符启发式，捕获未知格式的高随机度密钥 / Entropy detection for unknown formats
- 🧺 **全量脱敏**：密钥与上下文行一律打码 / Auto-masking everywhere, including context lines
- 🕰️ **Git 历史扫描**：检出"已删除"但仍留在提交历史中的密钥 / Scan full git history for deleted-but-recoverable secrets
- 🏷️ **置信度分级**：厂商格式 high / 通用启发式 medium / Confidence levels
- 📁 **高价值文件标记**：`.env` / 凭证 / 私钥文件命中即置顶 / High-value file pinning
- ⚙️ **自定义规则与白名单**：`zeroscan.toml` 加规则，`.zeroscanignore` 豁免误报 / Custom rules & allowlist
- ✅ **密钥在线验证（opt-in）**：`--verify` 只读验证 GitHub/OpenAI 密钥是否仍有效 / Optional online verification
- 🖥️ **双入口**：CLI（文本/JSON/HTML/SARIF）与 Web 界面（异步进度、扫描历史、报告下载、结果筛选）/ CLI + async Web UI
- 🧪 离线 `demo` 模式 / Offline demo mode
- 🛡️ 安全加固：GitHub-URL 白名单、独立临时目录保证清理、自动转义报告、错误绝不静默 / Hardened by design
- 📱 纯 Python（3.12+），无 ripgrep 等外部依赖 / Pure Python, zero external tools

## 📦 Install / 安装

Requires **Python 3.12+** and **git**. / 需要 Python 3.12+ 与 git。

```bash
git clone https://github.com/Aria-C1/0scan
cd 0scan
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e .          # 开发安装
# 或 pip install zeroscan（发布后）
```

Docker（修复版）：

```bash
docker build -t zeroscan .
docker run -p 8080:8080 zeroscan
```

## 🚀 Usage / 使用

### CLI

```bash
zeroscan scan https://github.com/owner/repo   # 扫描 GitHub 仓库
zeroscan scan .                               # 扫描本地目录
zeroscan scan demo                            # 离线演示
zeroscan scan owner/repo --full-history       # 含全部提交历史（较慢）
zeroscan scan demo --json                     # JSON 输出（CI 友好）
zeroscan scan demo --html report.html         # HTML 报告
zeroscan scan demo --sarif report.sarif       # SARIF（GitHub Code Scanning）
zeroscan scan owner/repo --verify             # 在线验证密钥（opt-in）
zeroscan scan . --config my-rules.toml        # 自定义规则
zeroscan scan owner/repo --timeout 120        # 克隆超时（秒）
```

Exit codes / 退出码：`0` clean 干净 · `1` findings 有发现 · `2` target error 目标错误

### Web

```bash
zeroscan web                       # http://127.0.0.1:8080
zeroscan web --host 0.0.0.0        # 暴露给局域网（注意风险）
```

Web 界面支持：实时进度（克隆 → 扫描文件数）、扫描历史回看、报告下载（HTML/JSON/SARIF）、结果关键词/类型筛选、一键复制脱敏密钥、离线 demo 按钮、"包含 Git 历史"开关。无 JS 环境自动回退为同步扫描。

## ⚙️ 配置

### 自定义规则 `zeroscan.toml`（用户侧）

```toml
[[rule]]
id = "my-internal-token"
pattern = 'internal-[0-9a-f]{32}'
confidence = "high"    # 或 medium
```

CLI `--config` 指定；未指定时自动加载当前目录的 `zeroscan.toml`。

### 误报白名单 `.zeroscanignore`（仓库侧）

放在被扫描仓库根目录，自动生效：

```gitignore
tests/fixtures/*          # glob 豁免整个文件/目录
docs/example.py:42        # 精确到行
```

## 🔍 检测能力 / Detection

| 类别 | 说明 |
|---|---|
| 厂商格式（high） | `sk-`、`sk-ant-`、`AKIA/ASIA`、`gh?_`、`glpat-`、`AIza`、`xox?`、`sk_live_`、`SG.`、Twilio `SK`、`key-`、`npm_`、`pypi-`、`shp??_`、Telegram、Facebook、JWT、PEM/PGP 私钥、数据库 URL 密码 |
| 通用赋值（medium） | `password[:=]`、`api_key[:=]` 等关键字赋值（兼容 .env 无引号 / yaml 冒号风格） |
| 熵值兜底（medium） | 20+ 字符、熵 ≥ 4.5、含字母与数字的高随机度字符串 |

规则集中在 `src/zeroscan/detectors.py` 一处管理；同一密钥重叠命中时只按最具体的规则报告一次。

## ⚠️ Limitations / 局限

- 在线验证仅支持 GitHub Token 与 OpenAI Key 的只读端点（隐私考量，opt-in）。/ Verification is opt-in and read-only.
- 历史扫描在大仓库上较慢。/ Full-history scan can be slow on large repos.
- 远程目标仅支持 GitHub https 地址（SSRF 防护，有意为之）。/ GitHub HTTPS only, by design.

## 🧱 Project layout / 项目结构

```
src/zeroscan/
├── config.py     # 过滤规则、占位符、性能护栏（唯一配置源）
├── detectors.py  # 检测器注册表 + 熵值 + 脱敏逻辑
├── scanner.py    # 并行扫描引擎（LineEngine 单行匹配）
├── history.py    # Git 历史扫描
├── repo.py       # 目标获取：URL 白名单 / 克隆 / demo / 清理
├── rules.py      # zeroscan.toml 自定义规则 + .zeroscanignore 白名单
├── verify.py     # 密钥在线验证（opt-in）
├── report.py     # HTML / JSON / SARIF 报告
├── cli.py        # 命令行入口
└── webapp.py     # Flask 异步任务应用
tests/            # pytest 测试套件（117 项）
```

## 🛠️ Development / 开发

```bash
pip install -e ".[dev]"
pytest                 # 运行测试
```

Contributions welcome — new detectors, entropy tuning, and more report formats are good first issues. / 欢迎贡献。

## 📄 License / 许可证

MIT — see [LICENSE](LICENSE).
