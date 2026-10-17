"""0scan —— 面向手机（Termux）与桌面的密钥泄露扫描器。

包名使用 zeroscan（"0scan" 以数字开头，无法作为 Python 标识符导入）。

公共 API：
- :class:`Scanner` / :class:`ScanResult` / :class:`Finding` —— 扫描引擎
- :func:`fetch_repo` / :class:`RepoError` —— 目标获取与校验
- :func:`render_html` / :func:`render_json` —— 报告输出
- :func:`create_app` —— Flask Web 应用
"""

from __future__ import annotations

__version__ = "1.0.0"

from .detectors import DETECTORS, Detector, mask_value
from .repo import RepoError, TargetKind, classify_target, fetch_repo
from .report import render_html, render_json, write_html
from .scanner import Finding, ScanResult, Scanner
from .webapp import create_app

__all__ = [
    "__version__",
    # 引擎
    "Scanner",
    "ScanResult",
    "Finding",
    # 检测器
    "DETECTORS",
    "Detector",
    "mask_value",
    # 目标获取
    "RepoError",
    "TargetKind",
    "classify_target",
    "fetch_repo",
    # 报告
    "render_html",
    "render_json",
    "write_html",
    # Web
    "create_app",
]
