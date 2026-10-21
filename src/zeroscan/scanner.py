"""纯 Python 扫描引擎：遍历文件树，逐行匹配检测器。

相对旧版本（shell 调 ripgrep 再解析 stdout）的修复：
- 不再依赖外部 ripgrep，Termux 上零额外依赖；
- rg 的 stderr / 退出码被吞导致的"静默假阴性"不复存在——
  读取错误会记入 ``ScanResult.errors`` 并呈现在报告中，
  有错误时报告绝不给出"安全"结论；
- 不再解析 ``path:line:content`` 文本，天然支持含冒号的路径。

核心抽象 :class:`LineEngine` 负责单行匹配（占位符过滤、熵值门槛、
重叠抑制——同一处密钥只按最具体的规则报告一次），
工作区扫描与 Git 历史扫描共用该引擎。
"""

from __future__ import annotations

import fnmatch
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import (
    CONTEXT_MAX_CHARS,
    DEFAULT_LIMITS,
    EXCLUDED_DIRS,
    EXCLUDED_SUFFIXES,
    HIGH_VALUE_FILE_PATTERNS,
    IGNORE_FILE,
    ScanLimits,
)
from .detectors import DETECTORS, Detector, mask_value
from .rules import apply_ignore, load_ignore_rules

#: 读取多少字节用于嗅探二进制文件
_BINARY_SNIFF_BYTES = 8192


def is_high_value(filename: str) -> bool:
    """判断是否属于高价值文件（.env / 凭证 / 私钥等，小写匹配）。"""
    lowered = filename.lower()
    return any(fnmatch.fnmatchcase(lowered, pat) for pat in HIGH_VALUE_FILE_PATTERNS)


@dataclass(frozen=True, slots=True)
class Finding:
    """一条已脱敏的发现。"""

    detector: str
    file: str
    line: int
    masked_key: str
    context: str
    confidence: str = "high"
    high_value: bool = False
    commit: str = ""


@dataclass(slots=True)
class ScanResult:
    """一次扫描的完整结果。"""

    target: str
    scanned_files: int = 0
    skipped_files: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    @property
    def ok(self) -> bool:
        """扫描过程是否未发生任何错误（与是否有发现无关）。"""
        return not self.errors


@dataclass(frozen=True, slots=True)
class LineHit:
    """一行内的一个命中（已过滤占位符/熵值门槛，未与其他命中重叠）。"""

    detector: Detector
    value: str
    masked: str
    start: int
    end: int


class LineEngine:
    """单行匹配引擎：过滤 + 重叠抑制（按检测器顺序先到先得）。"""

    def __init__(self, detectors: tuple[Detector, ...] = DETECTORS) -> None:
        self.detectors = detectors

    def scan_line(self, line: str) -> list[LineHit]:
        hits: list[LineHit] = []
        covered: list[tuple[int, int]] = []
        for det in self.detectors:
            for match in det.pattern.finditer(line):
                value = det.value(match)
                if not value or det.is_placeholder(value):
                    continue
                if det.min_entropy is not None and not det.passes_entropy(value):
                    continue
                start, end = match.span(det.value_group)
                if any(start < c_end and end > c_start for c_start, c_end in covered):
                    continue  # 已被更具体的规则覆盖
                covered.append((start, end))
                hits.append(
                    LineHit(det, value, mask_value(value), start, end)
                )
        return hits


def build_context(line: str, hits: list[LineHit]) -> str:
    """把一行内全部命中的密钥值替换为打码形式，截断到展示上限。"""
    context = line
    for hit in sorted(hits, key=lambda h: h.start, reverse=True):
        context = context[: hit.start] + hit.masked + context[hit.end :]
    return context.strip()[:CONTEXT_MAX_CHARS]


@dataclass(slots=True)
class _FileOutcome:
    """单文件扫描产出（供主流程汇总）。"""

    rel: str
    scanned: int = 0
    skipped: int = 0
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


class Scanner:
    """对给定目录执行密钥扫描。"""

    def __init__(
        self,
        detectors: tuple[Detector, ...] = DETECTORS,
        limits: ScanLimits = DEFAULT_LIMITS,
    ) -> None:
        self.detectors = detectors
        self.limits = limits
        self._engine = LineEngine(detectors)

    def scan_path(self, root: Path, target_label: str | None = None) -> ScanResult:
        """扫描 ``root`` 目录，返回脱敏后的结果。"""
        root = Path(root)
        result = ScanResult(target=target_label or str(root))
        start = time.perf_counter()
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
            for name in sorted(filenames):
                outcome = self._scan_file(Path(dirpath) / name, root)
                if outcome.error is not None:
                    result.errors.append(outcome.error)
                else:
                    result.scanned_files += outcome.scanned
                    result.skipped_files += outcome.skipped
                    result.findings.extend(outcome.findings)
        ignore_rules = load_ignore_rules(root / IGNORE_FILE)
        if ignore_rules:
            result.findings = apply_ignore(result.findings, ignore_rules)
        result.findings.sort(key=_sort_key)
        result.elapsed_seconds = round(time.perf_counter() - start, 3)
        return result

    # ---- 内部实现 ----

    def _scan_file(self, path: Path, root: Path) -> _FileOutcome:
        rel = path.relative_to(root).as_posix()

        if path.name.endswith(".min.js") or path.suffix.lower() in EXCLUDED_SUFFIXES:
            return _FileOutcome(rel, skipped=1)
        try:
            if path.stat().st_size > self.limits.max_file_bytes:
                return _FileOutcome(rel, skipped=1)
            with path.open("rb") as fh:
                if b"\x00" in fh.read(_BINARY_SNIFF_BYTES):
                    return _FileOutcome(rel, skipped=1)
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return _FileOutcome(rel, error=f"{rel}: 读取失败 ({exc})")

        findings: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()
        high_value = is_high_value(path.name)
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(line) > self.limits.max_line_chars:
                continue
            hits = self._engine.scan_line(line)
            if not hits:
                continue
            context = build_context(line, hits)
            for hit in hits:
                key = (hit.detector.name, lineno, hit.masked)
                if key in seen:  # 同一行同一密钥去重
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        detector=hit.detector.name,
                        file=rel,
                        line=lineno,
                        masked_key=hit.masked,
                        context=context,
                        confidence=hit.detector.confidence,
                        high_value=high_value,
                    )
                )
        return _FileOutcome(rel, scanned=1, findings=findings)


def _sort_key(finding: Finding) -> tuple:
    """结果排序：高价值文件置顶，其余按文件 → 行号 → 检测器 → 密钥。"""
    return (
        not finding.high_value,
        finding.file,
        finding.line,
        finding.detector,
        finding.masked_key,
        finding.commit,
    )
