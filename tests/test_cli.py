"""CLI 冒烟测试：确保入口模块可导入、各子命令可解析。

背景：曾有一次编辑事故让 cli.py 出现语法错误，而其余测试套件
不导入 cli 模块从而漏检——此文件专职兜底。
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys

def _module_imports_cleanly() -> bool:
    for name in ("zeroscan.cli", "zeroscan.webapp", "zeroscan.__main__"):
        spec = importlib.util.find_spec(name)
        assert spec is not None, f"{name} 缺失"
    return True


def test_cli_module_importable() -> None:
    assert _module_imports_cleanly()


def test_cli_help_and_version_run() -> None:
    for args in (["--version"], ["scan", "--help"], ["web", "--help"]):
        proc = subprocess.run(
            [sys.executable, "-m", "zeroscan", *args],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, f"{args} 失败: {proc.stderr}"
        assert proc.stdout.strip()


def test_cli_scan_demo_smoke() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "zeroscan", "scan", "demo"],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 1  # demo 有发现
    assert "sk-q****8765" in proc.stdout
    assert "sk-qwertyuiopasdfghjklzxcvbnm098765" not in proc.stdout


def test_cli_scan_bad_target_exit_code() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "zeroscan", "scan", "/no/such/path"],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 2
    assert "❌" in proc.stderr
