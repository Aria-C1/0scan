"""目标分类、URL 白名单与获取流程的测试。"""

from __future__ import annotations

from pathlib import Path

import pytest

from zeroscan.repo import RepoError, TargetKind, classify_target, fetch_repo


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/user/repo",
        "https://github.com/user/repo.git",
        "https://www.github.com/user/repo",
        "https://github.com/user/repo/",
    ],
)
def test_github_https_urls_accepted(url: str) -> None:
    kind, value = classify_target(url)
    assert kind is TargetKind.REMOTE
    assert not value.endswith("/")


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",                      # 本地文件协议
        "http://github.com/user/repo",             # 非 https
        "https://gitlab.com/user/repo",            # 非 GitHub
        "ssh://git@github.com/user/repo",          # ssh 协议
        "git@github.com:user/repo.git",            # scp 语法
        "https://user:pass@github.com/user/repo",  # 携带凭据
        "https://github.com/user/repo/extra",      # 多余路径段
        "https://192.168.1.1/x.git",               # 内网地址
        "ftp://github.com/user/repo",              # 其他协议
        "demo 模式以外的随意文字！",
        "",
        "   ",
    ],
)
def test_disallowed_targets_rejected(url: str) -> None:
    with pytest.raises(RepoError):
        classify_target(url)


def test_demo_and_local_targets(tmp_path: Path) -> None:
    assert classify_target("Demo")[0] is TargetKind.DEMO
    assert classify_target(str(tmp_path))[0] is TargetKind.LOCAL
    with pytest.raises(RepoError):
        classify_target("/no/such/path/exists")


def test_fetch_demo_creates_and_cleans_up() -> None:
    with fetch_repo("demo") as repo_dir:
        assert (repo_dir / "leak_test.js").is_file()
        captured = repo_dir
    assert not captured.exists()  # 退出上下文即清理


def test_fetch_local_yields_path_itself(tmp_path: Path) -> None:
    with fetch_repo(str(tmp_path)) as repo_dir:
        assert repo_dir == tmp_path.resolve()


def test_fetch_rejects_unsafe_url_before_any_clone() -> None:
    with pytest.raises(RepoError), fetch_repo("file:///etc") as _:
        pass
