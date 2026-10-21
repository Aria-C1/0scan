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
    """端到端回归：demo 模式报告中不得出现任何完整密钥。

    POST /scan 为无 JS 回退路径：同步执行后 302 到报告页。
    """
    resp = client.post("/scan", data={"url": "demo"}, follow_redirects=True)
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
        client.post("/scan", data={"url": "demo"}, follow_redirects=True).get_data(as_text=True),
        client.post("/scan", data={"url": "file:///etc"}).get_data(as_text=True),
    )
    for page in pages:
        assert "<svg" in page
        assert '"Noto Sans"' in page
        assert "Microsoft YaHei" in page
        assert "PingFang SC" in page
        for emoji in OLD_EMOJIS:
            assert emoji not in page, f"页面不应再使用 emoji: {emoji}"


# ---- 异步任务流（v1.1）----

def _wait_done(client, job_id: str, timeout: float = 5.0) -> dict:
    import time as _time

    deadline = _time.time() + timeout
    while _time.time() < deadline:
        status = client.get(f"/api/status/{job_id}").get_json()
        if status["state"] in ("done", "error"):
            return status
        _time.sleep(0.05)
    raise AssertionError("任务超时未完成")


def test_async_scan_flow_with_downloads(client) -> None:
    created = client.post("/api/scan", json={"url": "demo"})
    assert created.status_code == 200
    job_id = created.get_json()["job_id"]

    status = _wait_done(client, job_id)
    assert status["state"] == "done"
    assert status["findings"] == 3

    report = client.get(f"/report/{job_id}")
    assert report.status_code == 200
    body = report.get_data(as_text=True)
    assert "sk-q****8765" in body
    assert "sk-qwertyuiopasdfghjklzxcvbnm098765" not in body
    # 工具栏（筛选/下载）只出现在 Web 报告
    assert "zsSearch" in body
    assert f"/api/report/{job_id}?format=json" in body

    as_json = client.get(f"/api/report/{job_id}?format=json")
    assert as_json.status_code == 200
    assert "attachment" in as_json.headers["Content-Disposition"]
    assert "sk-q****8765" in as_json.get_data(as_text=True)


def test_async_full_history_on_demo_is_skipped(client) -> None:
    """demo 非 git 仓库：full_history 请求不报错，正常产出报告。"""
    created = client.post("/api/scan", json={"url": "demo", "full_history": True})
    job_id = created.get_json()["job_id"]
    status = _wait_done(client, job_id)
    assert status["state"] == "done"


def test_history_listing_on_index(client) -> None:
    client.post("/api/scan", json={"url": "demo"})
    # 同步等待最近一条任务完成
    import time as _time

    deadline = _time.time() + 5
    while _time.time() < deadline:
        page = client.get("/").get_data(as_text=True)
        if "demo" in page and "查看报告" in page:
            break
        _time.sleep(0.05)
    else:
        raise AssertionError("首页历史列表未出现最近任务")
    assert "最近扫描" in page


def test_api_status_unknown_job(client) -> None:
    assert client.get("/api/status/never-exists").status_code == 404
    assert client.get("/report/never-exists").status_code == 404
    assert client.get("/api/report/never-exists").status_code == 404


def test_api_scan_rejects_unsafe_url(client) -> None:
    resp = client.post("/api/scan", json={"url": "https://gitlab.com/a/b"})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_sync_scan_with_full_history_demo(client) -> None:
    resp = client.post(
        "/scan", data={"url": "demo", "full_history": "1"}, follow_redirects=True
    )
    assert resp.status_code == 200
