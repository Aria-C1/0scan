"""Web 应用测试：首页、demo 扫描、非法输入。"""

from __future__ import annotations

import pytest

from zeroscan.webapp import create_app

from conftest import OLD_EMOJIS


@pytest.fixture
def client():
    app = create_app()
    app.testing = True
    return app.test_client()


def test_index_serves_form(client) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"0scan" in resp.data


def test_demo_scan_masks_all_secrets(client) -> None:
    """端到端回归：demo 模式报告中不得出现任何完整密钥。"""
    resp = client.post("/scan", data={"url": "demo"})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # 三条演示发现均已打码
    assert "sk-q****8765" in body
    assert "AKIA****MPLE" in body
    assert "supe****pass" in body
    # 完整密钥绝不出现（旧版缺陷：上下文明文泄露）
    assert "sk-qwertyuiopasdfghjklzxcvbnm098765" not in body
    assert "AKIAIOSFODNN7EXAMPLE" not in body
    assert "super_secret_admin_pass" not in body


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "https://gitlab.com/user/repo",
        "http://github.com/user/repo",
        "",
    ],
)
def test_unsafe_or_invalid_urls_rejected(url: str, client) -> None:
    resp = client.post("/scan", data={"url": url})
    assert resp.status_code == 400


def test_scan_is_post_only(client) -> None:
    assert client.get("/scan").status_code == 405


def test_all_pages_use_svg_icons_and_font_stack_without_emoji(client) -> None:
    """界面规范回归：三个页面（首页/报告/错误页）均使用 SVG 图标与
    Noto Sans 字体栈，不出现旧版 emoji。"""
    pages = (
        client.get("/").get_data(as_text=True),
        client.post("/scan", data={"url": "demo"}).get_data(as_text=True),
        client.post("/scan", data={"url": "file:///etc"}).get_data(as_text=True),
    )
    for page in pages:
        assert "<svg" in page
        assert '"Noto Sans"' in page
        assert "Microsoft YaHei" in page
        assert "PingFang SC" in page
        for emoji in OLD_EMOJIS:
            assert emoji not in page, f"页面不应再使用 emoji: {emoji}"
