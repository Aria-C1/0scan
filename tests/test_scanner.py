"""扫描引擎的单元测试。"""

from __future__ import annotations

from pathlib import Path

from zeroscan.config import ScanLimits
from zeroscan.scanner import Scanner

from conftest import FAKE_AWS, FAKE_OPENAI, FAKE_PASSWORD


def test_scan_finds_expected_secrets(repo: Path) -> None:
    result = Scanner().scan_path(repo, target_label="fixture")
    got = {(f.detector, f.file) for f in result.findings}
    assert got == {
        ("OpenAI Key", "app.py"),
        ("GitHub Token", "app.py"),
        ("AWS Access Key", "config.js"),
        ("Hardcoded Password", "config.js"),
    }


def test_same_secret_on_one_line_is_deduped(repo: Path) -> None:
    result = Scanner().scan_path(repo)
    openai_lines = [
        f.line for f in result.findings if f.detector == "OpenAI Key" and f.file == "app.py"
    ]
    assert openai_lines == [1, 3]  # 第 3 行两个相同密钥只计一次


def test_findings_are_masked_everywhere(repo: Path) -> None:
    """回归：报告字段（含上下文）一律不得出现完整密钥。"""
    result = Scanner().scan_path(repo)
    for finding in result.findings:
        blob = finding.masked_key + finding.context
        assert FAKE_OPENAI not in blob
        assert FAKE_PASSWORD not in blob
        assert FAKE_AWS not in blob
        assert "****" in finding.masked_key


def test_noise_is_excluded(repo: Path) -> None:
    result = Scanner().scan_path(repo)
    files = {f.file for f in result.findings}
    assert not any("node_modules" in f for f in files)
    assert "vendor.min.js" not in files
    assert "data.json" not in files
    assert "blob" not in files
    assert result.skipped_files == 3  # min.js / json / 二进制


def test_placeholder_file_yields_nothing(repo: Path) -> None:
    result = Scanner().scan_path(repo)
    assert all(f.file != "placeholder.py" for f in result.findings)


def test_scan_counts_scanned_files(repo: Path) -> None:
    result = Scanner().scan_path(repo)
    # app.py / config.js / placeholder.py（blob 与 json/min.js 已跳过）
    assert result.scanned_files == 3
    assert result.ok


def test_read_errors_are_recorded(tmp_path: Path) -> None:
    """损坏的符号链接必须记入 errors，绝不能静默当作\"安全\"。"""
    (tmp_path / "good.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "broken").symlink_to(tmp_path / "does-not-exist")
    result = Scanner().scan_path(tmp_path)
    assert result.scanned_files == 1
    assert not result.ok
    assert any("broken" in e for e in result.errors)


def test_oversized_file_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "big.py").write_text("x = 1\n" * 100, encoding="utf-8")
    limits = ScanLimits(max_file_bytes=10)
    result = Scanner(limits=limits).scan_path(tmp_path)
    assert result.findings == []
    assert result.skipped_files == 1


def test_result_is_deterministic(repo: Path) -> None:
    first = Scanner().scan_path(repo)
    second = Scanner().scan_path(repo)
    assert first.findings == second.findings


def test_entropy_finding_in_full_scan(tmp_path: Path) -> None:
    """端到端：无已知格式的高熵串以 medium 置信度入报告。"""
    from conftest import FAKE_ENTROPY

    (tmp_path / "notes.txt").write_text(
        f'session = "{FAKE_ENTROPY}"\n', encoding="utf-8"
    )
    result = Scanner().scan_path(tmp_path)
    assert [(f.detector, f.confidence) for f in result.findings] == [
        ("High-Entropy String", "medium")
    ]
