"""报告输出：HTML（Jinja2 自动转义）与 JSON。

修复旧版两个报告缺陷：
- XSS：旧版 f-string 拼 HTML，type/file/line 三类字段未转义，
  恶意文件名可注入脚本；现在全部经 Jinja2 自动转义；
- JSON 输出对齐旧 v4_engine 的结构化能力，供后续 CI/前端复用。
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .scanner import ScanResult

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(("html", "xml")),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_html(result: ScanResult, *, web_mode: bool = False) -> str:
    """渲染 HTML 报告。

    ``web_mode`` 为 True 时显示\"返回重新扫描\"按钮（Web 场景）。
    """
    return _env.get_template("report.html").render(result=result, web_mode=web_mode)


def render_json(result: ScanResult) -> str:
    """把扫描结果序列化为 JSON（发现均已脱敏）。"""
    return json.dumps(asdict(result), ensure_ascii=False, indent=2)


def write_html(result: ScanResult, path: str | Path, *, web_mode: bool = False) -> Path:
    """把 HTML 报告写入文件，返回文件路径。"""
    target = Path(path)
    target.write_text(render_html(result, web_mode=web_mode), encoding="utf-8")
    return target
