"""检测器与脱敏逻辑的单元测试。"""

from __future__ import annotations

import pytest

from zeroscan.detectors import DETECTORS, Detector, mask_value

from conftest import (
    FAKE_AWS,
    FAKE_GITHUB,
    FAKE_GOOGLE,
    FAKE_OPENAI,
    FAKE_PASSWORD,
)

_BY_NAME = {d.name: d for d in DETECTORS}


@pytest.mark.parametrize(
    ("name", "line"),
    [
        ("OpenAI Key", f'k = "{FAKE_OPENAI}"'),
        ("AWS Access Key", f"aws({FAKE_AWS})"),
        ("GitHub Token", f"token={FAKE_GITHUB}"),
        ("Google API Key", f"key: {FAKE_GOOGLE}"),
        ("Hardcoded Password", f'password = "{FAKE_PASSWORD}"'),
        # password 大小写不敏感、等号两侧无空格也应命中
        ("Hardcoded Password", f'PASSWORD="{FAKE_PASSWORD}"'),
    ],
)
def test_detector_matches(name: str, line: str) -> None:
    det = _BY_NAME[name]
    assert det.pattern.search(line), f"{name} 未命中: {line}"


def test_aws_key_is_case_sensitive() -> None:
    """小写 akia 前缀是误报来源，必须不命中。"""
    assert not _BY_NAME["AWS Access Key"].pattern.search("akiaabcdefghijklmnop")


def test_mask_value_rules() -> None:
    assert mask_value("12345678") == "****"  # 不过 8 位整体打码
    assert mask_value("123456789") == "1234****6789"


def test_password_mask_only_covers_value() -> None:
    """password 检测器掩码只作用于密码值，而不是整条赋值语句。"""
    det = _BY_NAME["Hardcoded Password"]
    match = det.pattern.search(f'password = "{FAKE_PASSWORD}";')
    assert match is not None
    assert det.value(match) == FAKE_PASSWORD
    assert det.masked_value(match) == "hunt****ter2"


def test_mask_line_keeps_syntax_masks_secret() -> None:
    det = _BY_NAME["Hardcoded Password"]
    masked = det.mask_line(f'password = "{FAKE_PASSWORD}";')
    assert FAKE_PASSWORD not in masked
    assert masked == 'password = "hunt****ter2";'


def test_mask_line_replaces_all_occurrences() -> None:
    det = _BY_NAME["OpenAI Key"]
    line = f'a = "{FAKE_OPENAI}"; b = "{FAKE_OPENAI}"'
    masked = det.mask_line(line)
    assert masked.count("****") == 2
    assert FAKE_OPENAI not in masked


def test_placeholder_rules() -> None:
    det = _BY_NAME["OpenAI Key"]
    assert det.is_placeholder("sk-your_api_key_here_0000000000000000")
    assert det.is_placeholder("test")
    assert not det.is_placeholder("qwertyuiopasdfghjklzxcvbnm098765")


def test_structured_keys_survive_weak_markers() -> None:
    """回归：随机密钥碰巧含 123456 等弱标记子串时不得被误杀。"""
    assert not _BY_NAME["GitHub Token"].is_placeholder(
        "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
    )
    # 自由文本密码仍需弱标记过滤
    pw = _BY_NAME["Hardcoded Password"]
    assert pw.is_placeholder("abc123456def")
    assert not pw.is_placeholder("correct-horse-battery")


def test_placeholder_substring_does_not_kill_real_key_on_same_line() -> None:
    """回归：旧版对整行做子串匹配导致误杀，现在只看密钥值。"""
    det = _BY_NAME["OpenAI Key"]
    match = det.pattern.search(f"// testing something\nvar k = '{FAKE_OPENAI}'")
    assert match is not None
    assert not det.is_placeholder(det.value(match))
