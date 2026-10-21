"""命令行接口：``zeroscan scan`` 与 ``zeroscan web``。

退出码约定（便于 CI / 脚本集成）：
- 0：扫描完成且未发现风险
- 1：扫描完成但发现风险
- 2：目标获取或校验失败
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .detectors import DETECTORS, Detector
from .history import scan_history
from .repo import RepoError, fetch_repo
from .report import render_json, write_html, write_sarif
from .rules import RuleError, load_custom_detectors
from .scanner import Scanner
from .config import RULES_FILE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zeroscan",
        description="0scan：面向手机与桌面的密钥泄露扫描器（发现均已脱敏）。",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="扫描 GitHub 仓库 / 本地路径 / demo")
    scan_p.add_argument("target", help="GitHub https 地址、本地路径，或 demo（离线演示）")
    scan_p.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    scan_p.add_argument("--html", metavar="PATH", help="同时生成 HTML 报告文件")
    scan_p.add_argument("--sarif", metavar="PATH", help="同时生成 SARIF 报告（GitHub Code Scanning）")
    scan_p.add_argument("--config", metavar="PATH", help="自定义规则文件 zeroscan.toml（默认自动加载当前目录）")
    scan_p.add_argument("--full-history", action="store_true", help="完整克隆并扫描全部提交历史（较慢）")
    scan_p.add_argument("--timeout", type=int, default=60, help="克隆超时秒数（默认 60）")
    scan_p.set_defaults(func=cmd_scan)

    web_p = sub.add_parser("web", help="启动 Web 界面")
    web_p.add_argument("--host", default="127.0.0.1", help="监听地址（默认仅本机）")
    web_p.add_argument("--port", type=int, default=8080, help="监听端口（默认 8080）")
    web_p.set_defaults(func=cmd_web)

    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    detectors = _resolve_detectors(args.config)
    if detectors is None:
        return 2
    scanner = Scanner(detectors=detectors)
    try:
        with fetch_repo(args.target, full_history=args.full_history) as repo_dir:
            result = scanner.scan_path(repo_dir, target_label=args.target.strip())
            if args.full_history and (repo_dir / ".git").is_dir():
                history_findings, history_errors = scan_history(
                    repo_dir, scanner.detectors, scanner.limits
                )
                result.findings.extend(history_findings)
                result.errors.extend(history_errors)
    except RepoError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(render_json(result))
    else:
        _print_summary(result)

    if args.html:
        path = write_html(result, args.html)
        print(f"📄 HTML 报告已生成：{path}")
    if args.sarif:
        path = write_sarif(result, args.sarif)
        print(f"📄 SARIF 报告已生成：{path}")

    return 1 if result.findings else 0


def _resolve_detectors(config_arg: str | None) -> tuple[Detector, ...] | None:
    """合并自定义规则；--config 优先，否则尝试当前目录 zeroscan.toml。"""
    path = Path(config_arg) if config_arg else Path(RULES_FILE)
    if not path.exists():
        return DETECTORS
    try:
        detectors = load_custom_detectors(path)
    except RuleError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return None
    print(f"已加载自定义规则 {len(detectors) - len(DETECTORS)} 条（{path}）")
    return detectors


def _print_summary(result) -> None:
    print(f"🎯 扫描完成：{result.scanned_files} 个文件，耗时 {result.elapsed_seconds}s")
    for err in result.errors:
        print(f"⚠️ 错误：{err}")
    if not result.findings:
        if result.ok:
            print("✅ 未发现高危硬编码密钥或密码。")
        else:
            print("⚠️ 存在扫描错误，本次结果不构成\"安全\"结论。")
        return
    print(f"⚠️ 共发现 {len(result.findings)} 处潜在风险：")
    for item in result.findings:
        where = f"{item.file}:{item.line}"
        if item.commit:
            where += f" @ {item.commit}"
        print(f"  [{item.detector}] {where}")
        print(f"    凭证: {item.masked_key}")
        print(f"    {item.context}")


def cmd_web(args: argparse.Namespace) -> int:
    from .webapp import create_app

    app = create_app()
    if args.host in ("0.0.0.0", "::"):
        print("⚠️ 正在监听所有网卡，任何同一网络的人都能访问，请确认你了解风险。")
    print(f"🚀 0scan Web 界面已启动：http://{args.host}:{args.port} （Ctrl+C 退出）")
    app.run(host=args.host, port=args.port, debug=False)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)  # type: ignore[return-value]
