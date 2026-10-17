"""测试共用：伪造密钥常量与扫描目标仓库 fixture。

所有密钥均为编造的假密钥，仅用于测试检测规则本身。
"""

from __future__ import annotations

from pathlib import Path

import pytest

#: 32 位字母数字，满足 sk-[A-Za-z0-9]{32,}
FAKE_OPENAI = "sk-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"
#: AKIA + 16 位大写
FAKE_AWS = "AKIAABCDEFGHIJKLMNOP"
#: ghp_ + 36 位字母数字
FAKE_GITHUB = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
#: AIza + 35 位
FAKE_GOOGLE = "AIza" + "A" * 35
FAKE_PASSWORD = "hunter2hunter2hunter2"

ALL_FAKE_SECRETS = (FAKE_OPENAI, FAKE_AWS, FAKE_GITHUB, FAKE_GOOGLE, FAKE_PASSWORD)

#: 旧版界面使用过的 emoji，重设计后页面中不得再出现
OLD_EMOJIS = (
    "🛡️", "📁", "🔑", "⬅️", "⚠", "✅", "😢", "🚀", "🎯", "📄", "👀", "💡", "⚠️",
)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """构造一个包含真实命中、占位符与各类排除项的迷你仓库。"""
    (tmp_path / "app.py").write_text(
        f'OPENAI_KEY = "{FAKE_OPENAI}"\n'
        f'GITHUB_TOKEN = "{FAKE_GITHUB}"\n'
        f'var a = "{FAKE_OPENAI}", b = "{FAKE_OPENAI}";  # 同一行重复应去重\n',
        encoding="utf-8",
    )
    (tmp_path / "config.js").write_text(
        f'const AWS_KEY = "{FAKE_AWS}";\n'
        f'password = "{FAKE_PASSWORD}";\n',
        encoding="utf-8",
    )
    # 占位符：不应产生任何发现
    (tmp_path / "placeholder.py").write_text(
        'password = "test"\n'
        f'password = "abc123456def"\n'
        f'OPENAI = "sk-your_api_key_0000000000000000000000"\n',
        encoding="utf-8",
    )
    # 各类排除项：不应被扫描
    (tmp_path / "vendor.min.js").write_text(
        f'k="{FAKE_OPENAI}"', encoding="utf-8"
    )
    (tmp_path / "data.json").write_text(
        f'{{"password": "{FAKE_PASSWORD}"}}', encoding="utf-8"
    )
    (tmp_path / "node_modules" / "dep").mkdir(parents=True)
    (tmp_path / "node_modules" / "dep" / "x.py").write_text(
        f'AWS = "{FAKE_AWS}"', encoding="utf-8"
    )
    (tmp_path / "blob").write_bytes(b"\x00\x01\x02" + FAKE_AWS.encode())
    return tmp_path
