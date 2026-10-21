"""Git 历史扫描测试：被"删除"的密钥仍可从历史检出。"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from zeroscan.history import scan_history
from zeroscan.scanner import Scanner

from conftest import FAKE_OPENAI


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(cwd), *args],
        check=True, capture_output=True,
    )


def _commit_all(cwd: Path, message: str) -> None:
    _git(cwd, "add", "-A")
    _git(cwd, "-c", "user.name=zeroscan-test", "-c", "user.email=t@t.local",
         "commit", "-m", message)


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """含两个提交的仓库：先加入密钥，再删除（工作区已干净）。"""
    (tmp_path / "config.py").write_text(f'KEY = "{FAKE_OPENAI}"\n', encoding="utf-8")
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    _commit_all(tmp_path, "add secret")
    (tmp_path / "config.py").write_text("KEY = None\n", encoding="utf-8")
    _commit_all(tmp_path, "remove secret")
    return tmp_path


def test_worktree_clean_but_history_exposes_secret(git_repo: Path) -> None:
    """浅扫描看不到任何东西，历史扫描能找到被删除的密钥。"""
    assert Scanner().scan_path(git_repo).findings == []

    findings, errors = scan_history(git_repo)
    assert errors == []
    assert len(findings) == 1
    found = findings[0]
    assert found.detector == "OpenAI Key"
    assert found.file == "config.py"
    assert found.commit and len(found.commit) == 8
    assert FAKE_OPENAI not in found.masked_key + found.context
    assert "****" in found.masked_key


def test_history_dedupes_across_commits(tmp_path: Path) -> None:
    """同一文件同一密钥出现在多个提交中，只报告一次（最近提交）。"""
    (tmp_path / "a.py").write_text(f'x = "{FAKE_OPENAI}"\n', encoding="utf-8")
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    _commit_all(tmp_path, "1")
    (tmp_path / "a.py").write_text(
        f'# moved\nx = "{FAKE_OPENAI}"\n', encoding="utf-8"
    )
    _commit_all(tmp_path, "2")

    findings, _ = scan_history(tmp_path)
    assert len(findings) == 1
    assert findings[0].file == "a.py"


def test_history_on_non_git_dir(tmp_path: Path) -> None:
    findings, errors = scan_history(tmp_path)
    assert findings == []
    assert errors and "不是 git 仓库" in errors[0]


def test_fetch_repo_full_history_clone_args(monkeypatch: pytest.MonkeyPatch) -> None:
    """full_history=True 时不再浅克隆（通过拦截 git 命令验证参数）。"""
    from zeroscan.repo import fetch_repo

    captured: dict[str, list[str]] = {}

    class _Proc:
        returncode = 0
        stderr = ""

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _Proc()

    monkeypatch.setattr("zeroscan.repo.subprocess.run", fake_run)
    with fetch_repo("https://github.com/user/repo", full_history=True):
        assert "--depth" not in captured["cmd"]
    with fetch_repo("https://github.com/user/repo"):
        assert "--depth" in captured["cmd"]
