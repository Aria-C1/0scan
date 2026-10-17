"""检测器注册表：每类凭证一条编译好的正则与配套脱敏逻辑。

相对旧版本的关键修复：
- 每个检测器声明 ``value_group``，掩码只作用于真正的密钥值，
  而不是整个 ``password = "..."`` 赋值语句；
- 脱敏同样应用于报告的上下文行（``mask_line``），
  杜绝旧版本"密钥字段打了码、上下文却泄露完整密钥"的缺陷；
- 密钥格式类检测保持大小写敏感（AWS/GitHub Key 混入小写即误报），
  仅 password 关键字用局部 ``(?i)`` 做大小写不敏感匹配。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .config import PLACEHOLDER_EXACT, PLACEHOLDER_SUBSTRINGS


def mask_value(value: str) -> str:
    """保留首尾各 4 位，中间打码；过短的值整体打码。"""
    if len(value) > 8:
        return f"{value[:4]}****{value[-4:]}"
    return "****"


@dataclass(frozen=True, slots=True)
class Detector:
    """一类凭证的检测规则。"""

    #: 展示名（出现在报告中）
    name: str
    #: 编译后的正则
    pattern: re.Pattern[str]
    #: 捕获真正密钥值的分组编号（0 = 整个匹配）
    value_group: int = 0

    def value(self, match: re.Match[str]) -> str:
        return match.group(self.value_group)

    def masked_value(self, match: re.Match[str]) -> str:
        return mask_value(self.value(match))

    def is_placeholder(self, value: str) -> bool:
        """判断密钥值是否是示例/占位符（避免把教程代码当泄露）。"""
        lowered = value.lower()
        if lowered in PLACEHOLDER_EXACT:
            return True
        return any(token in lowered for token in PLACEHOLDER_SUBSTRINGS)

    def mask_line(self, line: str) -> str:
        """把一行内命中的所有密钥值替换为打码形式（其余内容原样保留）。"""
        masked = line
        for match in reversed(list(self.pattern.finditer(line))):
            start, end = match.span(self.value_group)
            masked = masked[:start] + mask_value(self.value(match)) + masked[end:]
        return masked


#: 内置检测器（单一事实来源，CLI / Web / 测试共用）
DETECTORS: tuple[Detector, ...] = (
    Detector(
        name="OpenAI Key",
        pattern=re.compile(r"sk-[A-Za-z0-9]{32,}"),
    ),
    Detector(
        name="AWS Access Key",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
    Detector(
        name="GitHub Token",
        pattern=re.compile(r"ghp_[A-Za-z0-9]{36}"),
    ),
    Detector(
        name="Google API Key",
        pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    ),
    Detector(
        name="Hardcoded Password",
        pattern=re.compile(r"""(?i)\bpassword\b\s*=\s*['"]([^$'"\s][^'"]*)['"]"""),
        value_group=1,
    ),
)
