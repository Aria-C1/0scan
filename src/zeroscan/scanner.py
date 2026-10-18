"""纯 Python 扫描引擎：遍历文件树，逐行匹配检测器。

相对旧版本（shell 调 ripgrep 再解析 stdout）的修复：
- 不再依赖外部 ripgrep，Termux 上零额外依赖；
- rg 的 stderr / 退出码被吞导致的"静默假阴性"不复存在——
  读取错误会记入 ``ScanResult.errors`` 并呈现在报告中，
  有错误时报告绝不给出"安全"结论；
- 不再解析 ``path:line:content`` 文本，天然支持含冒号的路径。
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import (
    CONTEXT_MAX_CHARS,
    DEFAULT_LIMITS,
    EXCLUDED_DIRS,
    EXCLUDED_SUFFIXES,
    ScanLimits,
)
from .detectors import DETECTORS, Detector

#: 读取多少字节用于嗅探二进制文件
_BINARY_SNIFF_BYTES = 8192


@dataclass(frozen=True, slots=True)
class Finding:
    """一条已脱敏的发现。"""

    detector: str
    file: str
    line: int
    masked_key: str
    context: str


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


class Scanner:
    """对给定目录执行密钥扫描。"""

    def __init__(
        self,
        detectors: tuple[Detector, ...] = DETECTORS,
        limits: ScanLimits = DEFAULT_LIMITS,
    ) -> None:
        self.detectors = detectors
        self.limits = limits

    def scan_path(self, root: Path, target_label: str | None = None) -> ScanResult:
        """扫描 ``root`` 目录，返回脱敏后的结果。"""
        root = Path(root)
        result = ScanResult(target=target_label or str(root))
        start = time.perf_counter()
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
            for name in sorted(filenames):
                self._scan_file(Path(dirpath) / name, root, result)
        result.elapsed_seconds = round(time.perf_counter() - start, 3)
        return result

    # ---- 内部实现 ----

    def _scan_file(self, path: Path, root: Path, result: ScanResult) -> None:
        rel = path.relative_to(root).as_posix()

        if path.name.endswith(".min.js") or path.suffix.lower() in EXCLUDED_SUFFIXES:
            result.skipped_files += 1
            return
        try:
            if path.stat().st_size > self.limits.max_file_bytes:
                result.skipped_files += 1
                return
            with path.open("rb") as fh:
                if b"\x00" in fh.read(_BINARY_SNIFF_BYTES):
                    result.skipped_files += 1
                    return
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            result.errors.append(f"{rel}: 读取失败 ({exc})")
            return

        result.scanned_files += 1
        seen: set[tuple[str, int, str]] = set()
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(line) > self.limits.max_line_chars:
                continue
            for detector in self.detectors:
                for match in detector.pattern.finditer(line):
                    value = detector.value(match)
                    if not value or detector.is_placeholder(value):
                        continue
                    masked_key = detector.masked_value(match)
                    key = (detector.name, lineno, masked_key)
                    if key in seen:  # 同一行同一密钥去重
                        continue
                    seen.add(key)
                    context = detector.mask_line(line).strip()[:CONTEXT_MAX_CHARS]
                    result.findings.append(
                        Finding(detector.name, rel, lineno, masked_key, context)
                    )
