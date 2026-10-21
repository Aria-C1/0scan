"""检测器注册表：每类凭证一条编译好的正则与配套脱敏逻辑。

相对旧版本的关键修复：
- 每个检测器声明 ``value_group``，掩码只作用于真正的密钥值，
  而不是整个 ``password = "..."`` 赋值语句；
- 脱敏同样应用于报告的上下文行（``mask_line``），
  杜绝旧版本"密钥字段打了码、上下文却泄露完整密钥"的缺陷；
- 密钥格式类检测保持大小写敏感（AWS/GitHub Key 混入小写即误报），
  仅关键字类用局部 ``(?i)`` 做大小写不敏感匹配。

检测器顺序即优先级：具体的厂商格式在前，通用赋值在后；
同一行内发生重叠时，先匹配者保留、后者抑制（例如 ``sk-ant-`` 密钥
只报告为 Anthropic Key，而不会被更宽泛的 OpenAI/熵值规则重复报告）。
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .config import PLACEHOLDER_EXACT, PLACEHOLDER_SUBSTRINGS, WEAK_PLACEHOLDER_SUBSTRINGS


def mask_value(value: str) -> str:
    """保留首尾各 4 位，中间打码；过短的值整体打码。"""
    if len(value) > 8:
        return f"{value[:4]}****{value[-4:]}"
    return "****"


def shannon_entropy(value: str) -> float:
    """计算字符的 Shannon 熵（比特/字符）。"""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def passes_entropy_gate(value: str, threshold: float) -> bool:
    """熵值门槛 + 启发式：需同时含字母与数字，避免误报普通长单词。"""
    if not any(c.isdigit() for c in value):
        return False
    if not any(c.isalpha() for c in value):
        return False
    return shannon_entropy(value) >= threshold


@dataclass(frozen=True, slots=True)
class Detector:
    """一类凭证的检测规则。"""

    #: 展示名（出现在报告中）
    name: str
    #: 编译后的正则
    pattern: re.Pattern[str]
    #: 捕获真正密钥值的分组编号（0 = 整个匹配）
    value_group: int = 0
    #: 是否为结构化密钥（格式本身即强证据，如 sk-/AKIA/ghp_）。
    #: 结构化密钥不做弱标记占位符过滤，避免随机值碰巧含
    #: "123456" 等子串时被误杀；自由文本（密码）仍需弱标记过滤。
    structured: bool = True
    #: 置信度：high = 已知厂商格式；medium = 通用赋值/熵值启发式
    confidence: str = "high"
    #: 熵值门槛（仅熵值检测器使用）
    min_entropy: float | None = None

    def value(self, match: re.Match[str]) -> str:
        return match.group(self.value_group)

    def masked_value(self, match: re.Match[str]) -> str:
        return mask_value(self.value(match))

    def is_placeholder(self, value: str) -> bool:
        """判断密钥值是否是示例/占位符（避免把教程代码当泄露）。"""
        lowered = value.lower()
        if lowered in PLACEHOLDER_EXACT:
            return True
        if any(token in lowered for token in PLACEHOLDER_SUBSTRINGS):
            return True
        if not self.structured:
            return any(token in lowered for token in WEAK_PLACEHOLDER_SUBSTRINGS)
        return False

    def passes_entropy(self, value: str) -> bool:
        """熵值检测器专用门槛：熵值 + 字母数字启发式。"""
        assert self.min_entropy is not None
        return passes_entropy_gate(value, self.min_entropy)

    def mask_line(self, line: str) -> str:
        """把一行内命中的所有密钥值替换为打码形式（其余内容原样保留）。"""
        masked = line
        for match in reversed(list(self.pattern.finditer(line))):
            start, end = match.span(self.value_group)
            masked = masked[:start] + mask_value(self.value(match)) + masked[end:]
        return masked


#: 内置检测器（单一事实来源，CLI / Web / 测试共用）。
#: 顺序 = 优先级：厂商格式 → 通用赋值 → 熵值兜底（必须最后）。
DETECTORS: tuple[Detector, ...] = (
    # ---- 私钥文件头（多行 PEM 的首行，单行即可判定）----
    Detector(
        name="Private Key (PEM/PGP)",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"
        ),
    ),
    # ---- 厂商格式（high）----
    Detector(
        name="Anthropic Key",
        pattern=re.compile(r"sk-ant-(?:api|admin)[0-9]*-[A-Za-z0-9_-]{24,}"),
    ),
    Detector(
        name="OpenAI Key",
        pattern=re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{32,}"),
    ),
    Detector(
        name="AWS Access Key",
        pattern=re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    ),
    Detector(
        name="GitHub Token",
        pattern=re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ),
    Detector(
        name="GitLab Token",
        pattern=re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),
    ),
    Detector(
        name="Google API Key",
        pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    ),
    Detector(
        name="Slack Token",
        pattern=re.compile(r"xox[baprse]-[0-9A-Za-z-]{10,}"),
    ),
    Detector(
        name="Stripe Secret Key",
        pattern=re.compile(r"(?:sk|rk)_live_[0-9a-zA-Z]{20,}"),
    ),
    Detector(
        name="SendGrid API Key",
        pattern=re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    ),
    Detector(
        name="Twilio API Key",
        pattern=re.compile(r"SK[0-9a-fA-F]{32}"),
    ),
    Detector(
        name="Mailgun API Key",
        pattern=re.compile(r"key-[0-9a-zA-Z]{32}"),
    ),
    Detector(
        name="npm Token",
        pattern=re.compile(r"npm_[A-Za-z0-9]{36}"),
    ),
    Detector(
        name="PyPI Token",
        pattern=re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}"),
    ),
    Detector(
        name="Shopify Token",
        pattern=re.compile(r"shp(?:at|ca|ss|pa|oa)_[a-fA-F0-9]{32}"),
    ),
    Detector(
        name="Telegram Bot Token",
        pattern=re.compile(r"[0-9]{8,10}:AA[A-Za-z0-9_-]{33}"),
    ),
    Detector(
        name="Facebook Access Token",
        pattern=re.compile(r"EAACEdEose0cBA[A-Za-z0-9]{10,}"),
    ),
    Detector(
        name="JWT",
        pattern=re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    ),
    Detector(
        name="Database URL Password",
        pattern=re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)"
            r"://[^\s:'\"@/]*:([^@\s'\"]+)@[^\s'\"]+"
        ),
        value_group=1,
    ),
    # ---- 通用赋值（medium；兼容 .env 无引号 / yaml 冒号风格）----
    Detector(
        name="Hardcoded Password",
        pattern=re.compile(
            r"""(?i)\b[\w.\-]*password[\w.\-]*\s*[:=]\s*["']?"""
            r"""([A-Za-z0-9][^$"'`\s()\[\]{};,+]{3,})["']?"""
        ),
        value_group=1,
        structured=False,
        confidence="medium",
    ),
    Detector(
        name="Generic API Key",
        pattern=re.compile(
            r"""(?i)\b[\w.\-]*(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token"""
            r"""|client[_-]?secret|secret[_-]?key|app[_-]?secret)[\w.\-]*\s*[:=]\s*["']?"""
            r"""([A-Za-z0-9][A-Za-z0-9_\-+/=.]{15,})["']?"""
        ),
        value_group=1,
        structured=False,
        confidence="medium",
    ),
    # ---- 熵值兜底（必须最后；见 scanner 的重叠抑制）----
    Detector(
        name="High-Entropy String",
        pattern=re.compile(r"[A-Za-z0-9+/_=-]{20,}"),
        structured=False,
        confidence="medium",
        min_entropy=4.5,
    ),
)
