"""扫描目标的获取与校验。

相对旧版 app.py 的安全修复：
- URL 白名单：仅允许 ``https://github.com/<owner>/<repo>``，
  阻断 file://、内网地址、携带凭据的 URL、非 GitHub 站点等 SSRF 向量；
- 每次扫描使用独立的系统临时目录，异常时也保证清理，
  不再把含明文密钥的克隆遗留在项目目录中（旧版 temp_repo 的
  并发互删与残留问题一并解决）；
- demo 模式保留：离线生成演示文件，不走网络。
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from contextlib import contextmanager
from enum import Enum
from pathlib import Path
from typing import Iterator

from .config import DEFAULT_LIMITS, ScanLimits


class RepoError(Exception):
    """目标无法识别、校验失败或获取失败。"""


#: 仅接受 GitHub HTTPS 地址（可选 www 前缀、.git 后缀、末尾斜杠）
_GITHUB_URL_RE = re.compile(
    r"^https://(?:www\.)?github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+?(?:\.git)?/?$"
)


class TargetKind(Enum):
    DEMO = "demo"
    REMOTE = "remote"
    LOCAL = "local"


_DEMO_FILE = "leak_test.js"
_DEMO_CONTENT = (
    'const OPENAI_KEY = "sk-qwertyuiopasdfghjklzxcvbnm098765";\n'
    'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\n'
    'password = "super_secret_admin_pass";\n'
)


def classify_target(raw: str) -> tuple[TargetKind, str]:
    """把用户输入分类为 demo / GitHub 远程仓库 / 本地路径。

    :raises RepoError: 输入为空、URL 不在白名单内或本地路径不存在。
    """
    value = (raw or "").strip()
    if not value:
        raise RepoError("目标不能为空：支持 GitHub https 地址、本地路径或 demo。")
    if value.lower() == "demo":
        return TargetKind.DEMO, value
    if "://" in value or value.startswith("git@"):
        if _GITHUB_URL_RE.match(value):
            return TargetKind.REMOTE, value.rstrip("/")
        raise RepoError(
            "仅支持 https://github.com/<用户名>/<仓库名> 形式的地址，"
            "已拒绝非 GitHub 或不安全的 URL（file://、内网地址、"
            "携带凭据的 URL 等）。"
        )
    candidate = Path(value).expanduser()
    if candidate.exists():
        return TargetKind.LOCAL, str(candidate.resolve())
    raise RepoError(
        f"无法识别的目标 {value!r}："
        "请提供 GitHub https 地址、已存在的本地路径，或输入 demo 离线体验。"
    )


def clone_shallow(url: str, dest: Path, timeout: int, shallow: bool = True) -> None:
    """克隆 ``url`` 到 ``dest``（默认浅克隆），失败抛出带原因的 :class:`RepoError`。"""
    args = ["git", "clone"]
    if shallow:
        args += ["--depth", "1"]
    args += ["--single-branch", url, str(dest)]
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise RepoError("未找到 git 命令，请先安装 git。") from exc
    except subprocess.TimeoutExpired as exc:
        raise RepoError(f"克隆超时（超过 {timeout} 秒），已中止。") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        hint = detail[-1] if detail else "未知原因"
        raise RepoError(f"克隆失败：{hint}")


@contextmanager
def fetch_repo(
    raw_target: str,
    *,
    limits: ScanLimits = DEFAULT_LIMITS,
    full_history: bool = False,
) -> Iterator[Path]:
    """获取扫描目标，yield 一个可扫描的目录；退出时保证清理。

    ``full_history=True`` 时完整克隆（不截断深度），供历史扫描使用。
    """
    kind, value = classify_target(raw_target)

    if kind is TargetKind.LOCAL:
        yield Path(value)
        return

    with tempfile.TemporaryDirectory(prefix="zeroscan-") as tmp:
        repo_dir = Path(tmp) / "repo"
        if kind is TargetKind.DEMO:
            repo_dir.mkdir()
            (repo_dir / _DEMO_FILE).write_text(_DEMO_CONTENT, encoding="utf-8")
        else:
            clone_shallow(
                value, repo_dir, limits.clone_timeout, shallow=not full_history
            )
            used = _dir_size(repo_dir)
            if used > limits.max_repo_bytes:
                raise RepoError(
                    f"仓库体积约 {_human_size(used)}，超过"
                    f" {_human_size(limits.max_repo_bytes)} 上限，已中止扫描。"
                )
        yield repo_dir


def _dir_size(root: Path) -> int:
    total = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            try:
                total += (Path(dirpath) / name).stat().st_size
            except OSError:
                continue
    return total


def _human_size(size: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}PB"
