"""密钥在线验证测试（全部 mock 网络，不发真实请求）。"""

from __future__ import annotations

import pytest

from zeroscan.report import render_html, render_json
from zeroscan.scanner import Finding, ScanResult, Scanner
from zeroscan.verify import verify, verify_findings

from conftest import FAKE_GITHUB, FAKE_OPENAI


@pytest.fixture
def mock_status(monkeypatch: pytest.MonkeyPatch):
    def install(status: int | None):
        monkeypatch.setattr(
            "zeroscan.verify._request_status", lambda url, scheme, secret: status
        )

    return install


@pytest.mark.parametrize(
    ("status", "expected"),
    [(200, "valid"), (401, "invalid"), (403, "invalid"), (500, "unknown"), (None, "unknown")],
)
def test_verify_status_mapping(mock_status, status, expected) -> None:
    mock_status(status)
    assert verify(FAKE_GITHUB, "GitHub Token") == expected


def test_verify_unsupported_detector_returns_empty(mock_status) -> None:
    mock_status(200)
    assert verify("whatever", "AWS Access Key") == ""


def test_verify_findings_marks_and_clears_raw(mock_status) -> None:
    mock_status(200)
    findings = [
        Finding(
            detector="GitHub Token", file="a.py", line=1,
            masked_key="ghp_****789a", context="k = 'ghp_****789a'",
            raw=FAKE_GITHUB,
        ),
        Finding(
            detector="OpenAI Key", file="a.py", line=2,
            masked_key="sk-1****wxyz", context="k = 'sk-1****wxyz'",
            raw=FAKE_OPENAI,
        ),
    ]
    verified = verify_findings(findings)
    assert [f.verification for f in verified] == ["valid", "valid"]
    assert all(f.raw == "" for f in verified)  # 验证后立即丢弃原始密钥


def test_raw_secret_never_leaks_into_outputs(tmp_path) -> None:
    """端到端：keep_raw 模式下，原始密钥不出现在任何输出里。"""
    (tmp_path / "leak.py").write_text(f'k = "{FAKE_GITHUB}"\n', encoding="utf-8")
    result = Scanner(keep_raw=True).scan_path(tmp_path)
    assert any(f.raw for f in result.findings)  # 内存中确实持有

    as_json = render_json(result)
    assert FAKE_GITHUB not in as_json
    assert '"raw"' not in as_json

    as_html = render_html(result)
    assert FAKE_GITHUB not in as_html
