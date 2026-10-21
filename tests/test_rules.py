"""自定义规则（zeroscan.toml）与误报白名单（.zeroscanignore）测试。"""

from __future__ import annotations

from pathlib import Path

import pytest

from zeroscan.detectors import DETECTORS
from zeroscan.rules import (
    RuleError,
    apply_ignore,
    load_custom_detectors,
    load_ignore_rules,
)
from zeroscan.scanner import Finding, Scanner

_CUSTOM_TOML = """
[[rule]]
id = "my-internal-token"
pattern = 'internal-[0-9a-f]{32}'
confidence = "high"

[[rule]]
id = "corp-db-password"
pattern = 'CORP_PASS_[A-Za-z0-9]{16}'
confidence = "medium"
"""


def _write_rules(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "zeroscan.toml"
    path.write_text(content, encoding="utf-8")
    return path


def test_custom_rules_loaded_and_applied(tmp_path: Path) -> None:
    rules = _write_rules(tmp_path, _CUSTOM_TOML)
    detectors = load_custom_detectors(rules)
    names = [d.name for d in detectors]
    assert "my-internal-token" in names
    assert "corp-db-password" in names
    # 自定义规则在熵值兜底之前
    assert names.index("my-internal-token") < names.index("High-Entropy String")
    assert names[-1] == "High-Entropy String"

    (tmp_path / "app.py").write_text(
        'token = "internal-' + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" + '"\n',
        encoding="utf-8",
    )
    result = Scanner(detectors=detectors).scan_path(tmp_path)
    hits = [f for f in result.findings if f.detector == "my-internal-token"]
    assert len(hits) == 1
    assert hits[0].confidence == "high"
    assert "internal" not in hits[0].context or "****" in hits[0].context


def test_invalid_regex_raises_rule_error(tmp_path: Path) -> None:
    rules = _write_rules(tmp_path, '[rust[rule]\nid = "x"\npattern = "["\n')
    with pytest.raises(RuleError):
        load_custom_detectors(rules)


def test_bad_confidence_rejected(tmp_path: Path) -> None:
    rules = _write_rules(
        tmp_path, '[[rule]]\nid = "x"\npattern = "abc"\nconfidence = "low"\n'
    )
    with pytest.raises(RuleError):
        load_custom_detectors(rules)


def test_missing_rule_file_raises(tmp_path: Path) -> None:
    with pytest.raises(RuleError):
        load_custom_detectors(tmp_path / "nope.toml")


def _finding(file: str, line: int) -> Finding:
    return Finding(
        detector="OpenAI Key", file=file, line=line,
        masked_key="sk-1****wxyz", context="k = 'sk-1****wxyz'",
    )


def _ignore_rules(tmp_path: Path, text: str):
    from zeroscan.rules import load_ignore_rules

    path = tmp_path / ".zeroscanignore"
    path.write_text(text, encoding="utf-8")
    return load_ignore_rules(path)


def test_ignore_file_glob_and_line_precision(tmp_path: Path) -> None:
    rules = _ignore_rules(
        tmp_path,
        "# 注释\n"
        "tests/fixtures/*\n"
        "docs/example.py:42\n",
    )
    assert apply_ignore(
        [_finding("tests/fixtures/leak.py", 1), _finding("src/app.py", 3)], rules
    ) == [_finding("src/app.py", 3)]
    # 行号不匹配时不豁免
    assert apply_ignore([_finding("docs/example.py", 43)], rules)
    # 行号精确匹配才豁免
    assert apply_ignore([_finding("docs/example.py", 42)], rules) == []


def test_scanner_applies_repo_ignore_file(tmp_path: Path) -> None:
    """仓库根目录的 .zeroscanignore 自动生效。"""
    from conftest import FAKE_OPENAI

    (tmp_path / "config.js").write_text(f'k = "{FAKE_OPENAI}"\n', encoding="utf-8")
    (tmp_path / "keep.py").write_text(
        'password = "hunter2hunter2hunter2"\n', encoding="utf-8"
    )
    (tmp_path / ".zeroscanignore").write_text("config.js\n", encoding="utf-8")
    result = Scanner().scan_path(tmp_path)
    assert [f.file for f in result.findings] == ["keep.py"]
