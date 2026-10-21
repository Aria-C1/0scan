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


def test_env_file_findings_flagged_and_pinned_first(tmp_path: Path) -> None:
    """.env 是泄露重灾区：标记高价值并置顶展示。"""
    from conftest import FAKE_OPENAI, FAKE_PASSWORD

    (tmp_path / "aaa.py").write_text(f'k = "{FAKE_OPENAI}"\n', encoding="utf-8")
    (tmp_path / ".env").write_text(
        f'DB_PASSWORD="{FAKE_PASSWORD}"\n', encoding="utf-8"
    )
    result = Scanner().scan_path(tmp_path)
    first = result.findings[0]
    assert first.file == ".env"
    assert first.high_value is True
    assert result.findings[-1].file == "aaa.py"
    assert result.findings[-1].high_value is False


def test_is_high_value_patterns() -> None:
    from zeroscan.scanner import is_high_value

    assert is_high_value(".env")
    assert is_high_value(".env.production")
    assert is_high_value("prod.env")
    assert is_high_value("id_rsa")
    assert is_high_value("ServerCredentials.yaml")
    assert not is_high_value("main.py")


def test_parallel_scan_matches_serial(tmp_path: Path) -> None:
    """并行与串行结果完全一致（排序保证确定性）。"""
    from zeroscan.config import ScanLimits
    from conftest import FAKE_OPENAI

    for i in range(80):
        (tmp_path / f"m{i:03d}.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "leak.py").write_text(f'k = "{FAKE_OPENAI}"\n', encoding="utf-8")

    serial = Scanner(limits=ScanLimits(scan_workers=1)).scan_path(tmp_path)
    parallel = Scanner(limits=ScanLimits(scan_workers=4)).scan_path(tmp_path)
    assert serial.findings == parallel.findings
    assert serial.scanned_files == parallel.scanned_files == 81


def test_utf16_files_are_scanned(tmp_path: Path) -> None:
    """带 BOM 与无 BOM 的 UTF-16 文件不应被当二进制跳过。"""
    (tmp_path / "bom.txt").write_text(
        'password = "hunter2hunter2hunter2"\n', encoding="utf-16"
    )
    (tmp_path / "nobom.txt").write_bytes(
        'password = "hunter2hunter2hunter2"\n'.encode("utf-16-le")
    )
    result = Scanner().scan_path(tmp_path)
    assert sorted(f.file for f in result.findings) == ["bom.txt", "nobom.txt"]
