"""密钥在线验证（opt-in，默认关闭，需显式 ``--verify``）。

设计原则：
- 仅向确定无害的只读端点发起验证（GitHub ``/user``、OpenAI ``/models``）；
- 原始密钥只存在于内存（``Finding.raw``，不参与序列化/渲染），
  验证完成后立即清空，输出只包含状态（valid/invalid/unknown）；
- 网络异常记为 unknown，绝不把"连不上"当成"密钥无效"。
"""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import replace

from .scanner import Finding

#: 检测器名 → (只读验证端点, Authorization 方案)
_VERIFIERS: dict[str, tuple[str, str]] = {
    "GitHub Token": ("https://api.github.com/user", "Bearer"),
    "OpenAI Key": ("https://api.openai.com/v1/models", "Bearer"),
}

_TIMEOUT_SECONDS = 10


def _request_status(url: str, scheme: str, secret: str) -> int | None:
    """发起只读验证请求，返回 HTTP 状态码；网络错误返回 None。"""
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"{scheme} {secret}",
            "User-Agent": "zeroscan-verify",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, OSError, TimeoutError):
        return None


def verify_secret(raw: str, detector: str) -> str:
    """验证密钥：valid / invalid / unknown；不可验证的检测器返回空串。"""
    entry = _VERIFIERS.get(detector)
    if entry is None or not raw:
        return ""
    url, scheme = entry
    status = _request_status(url, scheme, raw)
    if status == 200:
        return "valid"
    if status in (401, 403):
        return "invalid"
    return "unknown"


def verify_findings(findings: list[Finding]) -> list[Finding]:
    """对支持验证的发现逐条验证，并立即丢弃原始密钥。"""
    verified: list[Finding] = []
    for finding in findings:
        status = verify_secret(finding.raw, finding.detector)
        verified.append(replace(finding, verification=status, raw=""))
    return verified
