# Oscan - Mobile-First Secret Scanner / 手机端代码安检工具

🔥 **在线体验 (Live Demo):** [http://Aria1.pythonanywhere.com](http://Aria1.pythonanywhere.com) (输入 `demo` 即可无需配置直接体验 / Enter `demo` to try it offline)

## 🎯 为什么做这个？ (Why this project?)
现在的 AI 编程工具（如 Cursor、Bolt）让所有人都能轻松写出 App，但很多小白根本不懂代码，也不知道 GitHub 自带了安全扫描。
Oscan 的目标用户，就是用 AI 写代码，但看不懂代码的创作者。专业的扫漏工具输出全是红字警告，小白看了直接崩溃。所以 Oscan 致力于提供“保姆级”的代码安检报告，过滤海量误报，只告诉你最致命的危险在哪，并自动打码脱敏。

AI coding tools have made it incredibly easy to build apps, but many beginners lack coding knowledge and are unaware of built-in GitHub security scanning. Oscan is built for AI-assisted creators. Traditional scanners output overwhelming warnings. Oscan provides a "nanny-level" security report, filtering out noise, highlighting only the most critical risks, and automatically masking sensitive data.

## ✨ 核心功能 (Features)
- 🔑 **5类凭证检测 (5-Type Detection):** 识别 OpenAI / AWS / GitHub / Google 密钥及硬编码密码 (Detects API keys & hardcoded passwords)
- 🛡️ **全量脱敏 (Auto-masking):** 报告上下文同行打码，防二次泄漏 (Masks sensitive context lines)
- 🔇 **噪声过滤 (Noise Filtering):** 自动跳过占位符、测试文件、二进制大文件 (Skips placeholders, junk files & binaries)
- 💻 **双端入口 (Dual Interfaces):** 提供命令行 CLI (text/JSON/HTML) 与内置 Web UI (Provides CLI and Web UI)
- 🧪 **离线演示 (Offline Demo):** 输入 `demo` 即可无网体验 (Try it without network)
- 🛡️ **安全加固 (Hardened):** 强制 GitHub URL 白名单，临时目录安全清理 (GitHub URL allowlist & secure cleanup)
- 📦 **零外部依赖 (Zero external tools):** 纯 Python (3.12+) 构建，无需额外安装 ripgrep (Pure Python, no ripgrep needed)

## 🚀 本地安装与使用 (Install & Usage)
需要 Python 3.12+ 与 git (Requires Python 3.12+ and git):


git clone https://github.com/Aria-C1/0scan
cd 0scan
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e .

##CLI
zeroscan scan https://github.com/owner/repo    # 扫描 GitHub 仓库 (Scan repo)
zeroscan scan demo                             # 离线演示 (Offline demo)
zeroscan scan demo --json                      # JSON 格式输出 (JSON output)
zeroscan scan demo --html report.html          # 生成 HTML 报告 (HTML report)
                                               # 开启本地服务 (Runs on http://127.0.0.1:8080)
##Web UI
zeroscan web

##Project layout
src/zeroscan/
├── config.py       # 过滤规则与性能护栏 (Filtering rules & limits)
├── detectors.py    # 检测器注册表与脱敏 (Detectors & masking)
├── scanner.py      # 纯 Python 扫描引擎 (Scan engine)
├── repo.py         # URL 白名单/克隆/清理 (Target fetching & cleanup)
├── report.py       # HTML / JSON 报告 (Reports generation)
├── cli.py          # 命令行入口 (CLI entry)
└── webapp.py       # Flask 应用 (Flask app)
tests/              # pytest 测试套件 (Test suites)

##MIT License
