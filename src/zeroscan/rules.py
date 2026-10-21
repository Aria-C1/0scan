"""自定义规则（zeroscan.toml）与误报白名单（.zeroscanignore）。

zeroscan.toml —— 用户侧自定义检测规则（CLI ``--config`` 指定，
未指定时自动加载当前目录的 zeroscan.toml）::

    [[rule]]
    id = "my-internal-token"
    pattern = 'internal-[0-9a-f]{32}'
    confidence = "high"        # 可选：high（默认）/ medium

    [[rule]]
    id = "corp-db-password"
    pattern = 'CORP_PASS_[A-Za-z0-9]{16}'
    confidence = "medium"

自定义规则插入在内置规则之后、熵值兜底之前——用户规则比通用
启发式更具体，重叠时优先报告。

.zeroscanignore —— 被扫描仓库侧的白名单（仓库根目录自动生效）::

    # 整个文件/目录（fnmatch 通配符）
    tests/fixtures/*
    docs/examples/**
    # 精确到行
    docs/example.py:42
"""

from __future__ import annotations

import fnmatch
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .detectors import DETECTORS, Detector


class RuleError(Exception):
    """规则文件或白名单文件无效。"""


def load_custom_detectors(
    path: str | Path, base: tuple[Detector, ...] = DETECTORS
) -> tuple[Detector, ...]:
    """加载 zeroscan.toml 并合并进检测器列表（置于熵值兜底之前）。"""
    path = Path(path)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuleError(f"无法读取规则文件 {path}：{exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise RuleError(f"{path} 不是合法的 TOML：{exc}") from exc

    rules = data.get("rule", [])
    if not isinstance(rules, list):
        raise RuleError(f"{path}: [[rule]] 应为表数组")

    custom: list[Detector] = []
    for index, item in enumerate(rules, start=1):
        rule_id = item.get("id")
        pattern = item.get("pattern")
        if not rule_id or not isinstance(rule_id, str):
            raise RuleError(f"{path}: 第 {index} 条规则缺少字符串型 id")
        if not pattern or not isinstance(pattern, str):
            raise RuleError(f"{path}: 规则 {rule_id!r} 缺少字符串型 pattern")
        confidence = item.get("confidence", "high")
        if confidence not in ("high", "medium"):
            raise RuleError(f"{path}: 规则 {rule_id!r} confidence 只能是 high/medium")
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise RuleError(f"{path}: 规则 {rule_id!r} 正则无效：{exc}") from exc
        custom.append(Detector(name=rule_id, pattern=compiled, confidence=confidence))

    if not custom:
        return base
    # 内置规则 → 自定义规则 → 熵值兜底（base[-1] 必须保持最后）
    return tuple(base[:-1]) + tuple(custom) + (base[-1],)


@dataclass(frozen=True, slots=True)
class IgnoreRule:
    """一条白名单规则：文件通配（fnmatch），可精确到行。"""

    pattern: str
    line: int | None = None


def load_ignore_rules(path: str | Path) -> list[IgnoreRule]:
    """解析 .zeroscanignore（每行一条：glob 或 glob:line，# 注释）。"""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    rules: list[IgnoreRule] = []
    for raw in text.splitlines():
        entry = raw.strip()
        if not entry or entry.startswith("#"):
            continue
        file_part, _, line_part = entry.rpartition(":")
        if file_part and line_part.isdigit():
            rules.append(IgnoreRule(file_part, int(line_part)))
        else:
            rules.append(IgnoreRule(entry))
    return rules


def matches_ignore(finding, rules: list[IgnoreRule]) -> bool:
    """判断一条发现是否被白名单规则命中。"""
    for rule in rules:
        if not fnmatch.fnmatchcase(finding.file, rule.pattern):
            continue
        if rule.line is None or finding.line == rule.line:
            return True
    return False


def apply_ignore(findings: list, rules: list[IgnoreRule]) -> list:
    """过滤掉命中白名单的发现。"""
    if not rules:
        return findings
    return [f for f in findings if not matches_ignore(f, rules)]
