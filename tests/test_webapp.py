"""Web 应用测试：首页、demo 扫描、非法输入。"""

from __future__ import annotations

import pytest

from zeroscan.webapp import create_app


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
