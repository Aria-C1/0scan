"""Flask Web 应用（保留旧 app.py 的功能与 demo 模式）。

安全修复：
- Web 输入经 fetch_repo 的 GitHub 白名单校验（修复任意 URL clone）；
- 报告经 Jinja2 自动转义渲染（修复 XSS）；
- 克隆在系统临时目录进行并由上下文管理器保证清理。
"""

from __future__ import annotations

from pathlib import Path

from flask import Flask, render_template, request

from .repo import RepoError, fetch_repo
from .scanner import Scanner

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def create_app() -> Flask:
    """创建并配置 0scan Web 应用（应用工厂模式，便于测试）。"""
    app = Flask(__name__, template_folder=str(_TEMPLATE_DIR))
    scanner = Scanner()

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/scan", methods=["POST"])
    def scan():
        raw = request.form.get("url", "")
        try:
            with fetch_repo(raw) as repo_dir:
                result = scanner.scan_path(
                    repo_dir, target_label=raw.strip() or "demo"
                )
        except RepoError as exc:
            return render_template("error.html", message=str(exc)), 400
        return render_template("report.html", result=result, web_mode=True)

    return app
