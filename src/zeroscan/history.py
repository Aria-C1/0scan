"""Git 历史扫描：逐提交检查新增行，找出"已删除"但仍留在历史里的密钥。

实现要点：
- 复用 :class:`LineEngine`（与工作区扫描同一套过滤/脱敏/重叠抑制）；
- ``git log -p -U0`` 零上下文输出，只取 ``+`` 开头的新增行；
- ``--pretty=format:@@@COMMIT@@@%H`` 打提交标记（argv 不能含 NUL，
  故不用 \\x00），内容行以 ``@@@COMMIT@@@`` 开头的概率可忽略；
- 同一密钥在多个提交出现只报告一次（记最近一次提交）。

密钥常在"删除泄露"提交后仍可从历史检出，这正是浅扫描的盲区。
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .config import DEFAULT_LIMITS, ScanLimits
from .detectors import DETECTORS, Detector
from .scanner import Finding, LineEngine, _sort_key, build_context, is_high_value

_COMMIT_MARKER = "@@@COMMIT@@@"
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")


def scan_history(
    repo_dir: Path,
    detectors: tuple[Detector, ...] = DETECTORS,
    limits: ScanLimits = DEFAULT_LIMITS,
) -> tuple[list[Finding], list[str]]:
    """扫描 ``repo_dir`` 的全部提交历史，返回（发现, 错误）。"""
    repo_dir = Path(repo_dir)
    if not (repo_dir / ".git").exists():
        return [], [f"{repo_dir}: 不是 git 仓库，跳过历史扫描"]

    cmd = [
        "git", "-C", str(repo_dir),
        "log", "-p", "--no-color", "-U0",
        f"--pretty=format:{_COMMIT_MARKER}%H",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            errors="replace", timeout=limits.clone_timeout * 10,
        )
    except FileNotFoundError:
        return [], ["未找到 git 命令，无法扫描历史"]
    except subprocess.TimeoutExpired:
        return [], ["历史扫描超时，已中止"]

    if proc.returncode != 0:
        stderr_lines = (proc.stderr or "").strip().splitlines()
        hint = stderr_lines[-1] if stderr_lines else "未知原因"
        return [], [f"git log 执行失败：{hint}"]

    engine = LineEngine(detectors)
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    commit = ""
    path = ""
    lineno = 0

    for line in proc.stdout.splitlines():
        if line.startswith(_COMMIT_MARKER):
            commit = line[len(_COMMIT_MARKER):][:8]
            continue
        if line.startswith("+++ b/"):
            path = line[6:]
            continue
        if line.startswith("--- "):
            continue
        hunk = _HUNK_RE.match(line)
        if hunk:
            lineno = int(hunk.group(1))
            continue
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            current_lineno = lineno
            lineno += 1
            if not path or len(content) > limits.max_line_chars:
                continue
            hits = engine.scan_line(content)
            if not hits:
                continue
            context = build_context(content, hits)
            high_value = is_high_value(Path(path).name)
            for hit in hits:
                key = (hit.detector.name, path, hit.masked)
                if key in seen:  # 同一密钥跨提交只报一次（最近提交）
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        detector=hit.detector.name,
                        file=path,
                        line=current_lineno,
                        masked_key=hit.masked,
                        context=context,
                        confidence=hit.detector.confidence,
                        high_value=high_value,
                        commit=commit,
                    )
                )

    findings.sort(key=_sort_key)
    return findings, []
