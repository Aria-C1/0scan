import subprocess
import re

# 1. 升级敏感词库：加入真实的 API Key 格式
patterns = [
    r"sk-[a-zA-Z0-9]{32,}", # OpenAI 密钥
    r"AKIA[0-9A-Z]{16}",    # AWS 密钥
    r"AIza[0-9A-Za-z\-_]{35}", # Google API Key
    r"ghp_[a-zA-Z0-9]{36}", # GitHub Token
    r"password\s*=\s*['\"].+['\"]" # 真正的硬编码密码（排除空的）
]

# 2. 白名单：忽略正常文件，减少误报
exclude_files = [".min.js", ".html", ".md", ".json", "package-lock.json", "test", "example"]

print("👀 启动 0scan V4 高级扫描...")
print("正在搜索高危格式和硬编码凭证...\n")

found_issues = 0

for pattern in patterns:
    # 组装命令，只搜索当前目录
    cmd = ["rg", "-i", pattern, "."]
    for f in exclude_files:
        cmd.extend(["--glob", "!" + f])
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        found_issues += 1
        lines = result.stdout.strip().split('\n')
        for line in lines:
            if len(line) > 100: line = line[:100] + "..."
            # 极其聪明的打码：只打码真实密钥，保留普通单词
            safe_line = re.sub(r'(sk-|AKIA|ghp_|AIza)[a-zA-Z0-9_\-]{6,}', r'\1****************', line)
            print(safe_line)

if found_issues == 0:
    print("✅ 完美！未发现高危硬编码或密钥泄露。")
else:
    print(f"\n⚠️ 扫描结束，共发现 {found_issues} 类潜在风险。请务必检查！")
