"""报告渲染测试：XSS 转义与脱敏回归。"""

from __future__ import annotations

import json

from zeroscan.report import render_html, render_json
from zeroscan.scanner import Finding, ScanResult

from conftest import OLD_EMOJIS, FAKE_OPENAI, FAKE_PASSWORD

_XSS_FILENAME = '<img src=x onerror="alert(1)">.py'


def _result_with_xss_filename() -> ScanResult:
    return ScanResult(
        target="https://github.com/user/repo",
        scanned_files=2,
        findings=[
            Finding(
                detector="Hardcoded Password",
                file=_XSS_FILENAME,
                line=3,
                masked_key="hunt****ter2",
                context='password = "hunt****ter2";',
            )
        ],
    )


def test_report_escapes_attacker_controlled_fields() -> None:
    """回归：旧版 file 字段未转义，恶意文件名可注入脚本。"""
    html = render_html(_result_with_xss_filename())
    assert "&lt;img" in html
    assert "<img" not in html.replace("<html", "").replace("</html", "")


def test_report_never_contains_full_secret() -> None:
    """回归：旧版上下文行泄露完整密钥。"""
    result = ScanResult(
        target="demo",
        findings=[
            Finding(
                detector="Hardcoded Password",
                file="a.py",
                line=1,
                masked_key="hunt****ter2",
                context='password = "hunt****ter2";',
            )
        ],
    )
    html = render_html(result)
    assert FAKE_OPENAI not in html
    assert FAKE_PASSWORD not in html
    assert "****" in html


def test_report_shows_error_panel_and_not_safe(tmp_path) -> None:
    result = ScanResult(target="x", errors=["boom.py: 读取失败"])
    html = render_html(result)
    assert "错误" in html
    assert "boom.py" in html
    assert "未发现高危" not in html  # 有错误时绝不给"安全"结论


def test_report_safe_when_clean() -> None:
    html = render_html(ScanResult(target="x"))
    assert "未发现高危" in html


def test_json_output_roundtrip() -> None:
    data = json.loads(render_json(_result_with_xss_filename()))
    assert data["findings"][0]["file"] == _XSS_FILENAME
    assert data["findings"][0]["masked_key"] == "hunt****ter2"
    assert FAKE_PASSWORD not in render_json(_result_with_xss_filename())


def test_report_uses_svg_icons_and_font_stack_without_emoji() -> None:
    """界面规范回归：SVG 图标 + Noto Sans 字体栈，禁用 emoji。"""
    scenarios = (
        ScanResult(target="x"),                          # 安全态
        _result_with_xss_filename(),                     # 有发现
        ScanResult(target="x", errors=["boom.py: 读取失败"]),  # 有错误
    )
    for result in scenarios:
        page = render_html(result)
        assert "<svg" in page
        assert '"Noto Sans"' in page
        assert "Microsoft YaHei" in page
        assert "PingFang SC" in page
        for emoji in OLD_EMOJIS:
            assert emoji not in page, f"页面不应再使用 emoji: {emoji}"
