"""配置的唯一来源。

检测器（正则规则）在 detectors.py 中定义；
这里集中放置文件过滤、占位符过滤与性能护栏等全局配置，
替代旧版本中分散在 4 个脚本里的重复常量。
"""

from __future__ import annotations

from dataclasses import dataclass

# --- 目录黑名单：这些目录整体跳过 ---
EXCLUDED_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn",
    "node_modules", "vendor",
    ".venv", "venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    ".idea", ".vscode",
    "build", "dist", "target",
})

# --- 后缀黑名单：文档/锁文件/媒体/压缩包等噪声来源 ---
# 注意：".min.js" 是双后缀，在扫描器里单独判断。
EXCLUDED_SUFFIXES: frozenset[str] = frozenset({
    ".html", ".htm", ".md", ".rst", ".json",
    ".map", ".lock",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".pdf", ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pyc", ".pyo", ".class", ".jar", ".wasm",
    ".so", ".dylib", ".dll", ".exe", ".bin",
})

# --- 占位符过滤：密钥值命中这些规则的视为示例代码，不报告 ---
# 旧版本对整行内容做子串匹配，导致"行内含 test 就误杀整条真实密钥"；
# 现在只针对密钥值本身判断。
#: 值中包含即视为占位符
PLACEHOLDER_SUBSTRINGS: tuple[str, ...] = (
    "123456", "xxxxxx", "your_api_key", "your_", "placeholder",
)
#: 值完全相等才视为占位符（避免误杀真实密钥）
PLACEHOLDER_EXACT: frozenset[str] = frozenset({
    "test", "testing", "sample", "demo", "example", "example_key",
    "changeme", "dummy", "todo", "fixme", "xxx", "password", "secret",
})

#: 报告中展示的上下文最大长度（已脱敏）
CONTEXT_MAX_CHARS: int = 120


@dataclass(frozen=True, slots=True)
class ScanLimits:
    """性能与安全护栏。"""

    #: 单文件超过该大小则跳过（字节）
    max_file_bytes: int = 1_500_000
    #: 克隆下来的仓库超过该大小则报错（字节）
    max_repo_bytes: int = 300_000_000
    #: 超过该长度的行不做正则匹配（防御病态长行）
    max_line_chars: int = 2_000
    #: git clone 超时（秒）
    clone_timeout: int = 60


DEFAULT_LIMITS = ScanLimits()
