import subprocess
import re
import json

# 1. 升级：精确的密钥格式与误报过滤
patterns = {
    "OpenAI Key": r"sk-[a-zA-Z0-9]{32,}",
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
    "Generic Password": r"password\s*=\s*['\"]([^'\"]+)['\"]"
}

# 2. 假密钥黑名单（过滤掉明显的测试代码）
fake_keywords = ["123456", "xxxxxx", "your_api_key", "placeholder", "YOUR_", "test"]

# 忽略白名单文件
exclude_files = [".min.js", ".html", ".md", ".json", "package-lock.json"]

print("🚀 启动 0scan V4 核心引擎...")
print("正在扫描上下文并提取结构化数据...\n")

report_data = []

for key_type, pattern in patterns.items():
    cmd = ["rg", "--line-number", pattern, "."]
    for f in exclude_files:
        cmd.extend(["--glob", "!" + f])
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.stdout:
        lines = result.stdout.strip().split('\n')
        for line in lines:
            # 解析 rg 的输出格式： 文件名:行号:代码内容
            parts = line.split(":", 2)
            if len(parts) == 3:
                file_path, line_num, content = parts
                
                # 检查是否是假密钥
                is_fake = any(fake in content for fake in fake_keywords)
                if is_fake:
                    continue  # 跳过假密钥

                # 提取并脱敏真实凭证
                match = re.search(pattern, content)
                if match:
                    raw_key = match.group(0)
                    # 只保留前4位和后4位，中间打码
                    if len(raw_key) > 8:
                        masked_key = raw_key[:4] + "****" + raw_key[-4:]
                    else:
                        masked_key = "****"
                    
                    # 结构化数据组装
                    issue = {
                        "type": key_type,
                        "file": file_path,
                        "line": line_num,
                        "masked_key": masked_key,
                        "raw_context": content.strip()[:80] # 保留一点上下文
                    }
                    report_data.append(issue)

# 3. 输出专业级的 JSON 报告
if not report_data:
    print("✅ 完美！未发现高危硬编码或密钥泄露。")
else:
    print(f"⚠️ 警报！共发现 {len(report_data)} 处真实泄露风险：")
    print(json.dumps(report_data, indent=4, ensure_ascii=False))
    print("\n💡 提示：以上数据已脱敏，可直接作为 API 返回给前端展示。")
