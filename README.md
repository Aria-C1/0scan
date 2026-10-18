# 0scan

**Mobile-first secret scanner** — hunt hardcoded API keys & passwords in GitHub repositories, right from your phone (Termux) or desktop. All findings are auto-masked before display.

**手机优先的密钥安检工具** —— 把 GitHub 仓库拉下来，扫出硬编码的密钥与密码，输出自动脱敏的报告。手机（Termux）、桌面皆可运行。

## ✨ Features / 功能

- 🔑 Detects OpenAI / AWS / GitHub / Google keys and hardcoded passwords / 识别五类凭证
- 🧺 Auto-masking everywhere — including report context lines / 全量脱敏，上下文行同样打码
- 🧹 Noise filtering — placeholder values (`test`, `your_api_key`…), junk files (`.min.js`, lockfiles, images, `node_modules`…), binaries and oversized files are skipped / 占位符与噪声文件过滤
- 🖥️ Two interfaces — CLI (text / JSON / HTML) and a built-in Web UI / 命令行 + Web 双入口
- 🧪 Offline `demo` mode — try it without touching the network / 离线演示模式
- 🛡️ Hardened — GitHub-URL allowlist, per-scan temp dirs with guaranteed cleanup, auto-escaped reports, scan errors surfaced (never a silent "safe") / 安全加固
- 📱 Pure Python (3.12+), zero external tooling — no ripgrep needed / 纯 Python，无外部依赖

## 📦 Install / 安装

Requires **Python 3.12+** and **git**. / 需要 Python 3.12+ 与 git。

```bash
git clone https://github.com/Aria-C1/0scan
cd 0scan
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e .          # 开发安装
# 或 pip install zeroscan（发布后）
```

## 🚀 Usage / 使用

### CLI

```bash
zeroscan scan https://github.com/owner/repo   # 扫描 GitHub 仓库
zeroscan scan .                               # 扫描本地目录
zeroscan scan demo                            # 离线演示
zeroscan scan demo --json                     # JSON 输出（CI 友好）
zeroscan scan demo --html report.html         # 生成 HTML 报告
zeroscan scan owner/repo --timeout 120        # 克隆超时（秒）
```

Exit codes / 退出码：`0` clean 干净 · `1` findings 有发现 · `2` target error 目标错误

### Web

```bash
zeroscan web                       # http://127.0.0.1:8080
zeroscan web --host 0.0.0.0        # 暴露给局域网（注意风险）
```

Enter `demo` in the form for an offline tour. / 在页面输入 `demo` 可离线体验。

## 🔍 Detection rules / 检测规则

| Type / 类型 | Pattern / 规则 |
|---|---|
| OpenAI Key | `sk-[A-Za-z0-9]{32,}` |
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| GitHub Token | `ghp_[A-Za-z0-9]{36}` |
| Google API Key | `AIza[0-9A-Za-z\-_]{35}` |
| Hardcoded Password | `password = '...'` / `password = "..."` (case-insensitive) |

Rules live in one place — `src/zeroscan/detectors.py`; filtering and limits in `src/zeroscan/config.py`. / 规则集中一处管理，便于扩展新的凭证类型。

## ⚠️ Limitations / 局限

- Regex-based: unconventional secrets (e.g. raw entropy strings) are out of scope for now; entropy scanning is on the roadmap. / 基于正则，暂不做熵分析（规划中）。
- Remote targets are GitHub HTTPS only, by design (SSRF safety). / 出于安全仅支持 GitHub https 地址。

## 🧱 Project layout / 项目结构

```
src/zeroscan/
├── config.py     # 过滤规则、占位符、性能护栏（唯一配置源）
├── detectors.py  # 检测器注册表 + 脱敏逻辑
├── scanner.py    # 纯 Python 扫描引擎
├── repo.py       # 目标获取：URL 白名单 / 克隆 / demo / 清理
├── report.py     # HTML / JSON 报告
├── cli.py        # 命令行入口
└── webapp.py     # Flask 应用
tests/            # pytest 测试套件
```

## 🛠️ Development / 开发

```bash
pip install -e ".[dev]"
pytest                 # 运行测试
```

Contributions welcome — new detectors, entropy analysis, and more report formats are good first issues. / 欢迎贡献：新增检测器、熵分析、更多报告格式都是不错的切入点。

## 📄 License / 许可证

MIT — see [LICENSE](LICENSE). Added by the rewrite; the maintainer's confirmation is noted in the corresponding PR. / MIT 许可证（本次重写新增，已在对应 PR 中请维护者确认）。

## ☕ Support / 赞助支持
如果你觉得这个工具对你有帮助，欢迎在爱发电请我喝杯可乐：
👉 https://afdian.com/a/Aria-C
