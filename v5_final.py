import subprocess
import re
import html

patterns = {
    "OpenAI Key": r"sk-[a-zA-Z0-9]{32,}",
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
    "Hardcoded Password": r"password\s*=\s*['\"]([^${\s][^'\"]*)['\"]"
}
fake_keywords = ["123456", "xxxxxx", "your_api_key", "placeholder", "YOUR_", "test"]
exclude_files = [".min.js", ".html", ".md", ".json", "package-lock.json"]

print("🚀 启动 0scan V5 扫描引擎...")
report_data = []

for key_type, pattern in patterns.items():
    cmd = ["rg", "--line-number", pattern, "."]
    for f in exclude_files:
        cmd.extend(["--glob", "!" + f])
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        for line in result.stdout.strip().split('\n'):
            parts = line.split(":", 2)
            if len(parts) == 3:
                file_path, line_num, content = parts
                if any(fake in content.lower() for fake in fake_keywords):
                    continue
                
                match = re.search(pattern, content)
                if match:
                    raw_key = match.group(0)
                    masked_key = raw_key[:4] + "****" + raw_key[-4:] if len(raw_key) > 8 else "****"
                    report_data.append({
                        "type": key_type,
                        "file": file_path,
                        "line": line_num,
                        "masked_key": masked_key,
                        "raw_context": content.strip()[:80]
                    })

html_content = """
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>0scan V5 安全报告</title>
<style>
    body { font-family: sans-serif; background: #f4f4f9; padding: 20px; }
    .card { background: white; border-left: 5px solid #ff4757; padding: 15px; margin-bottom: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
    .safe { border-left: 5px solid #2ed573; text-align: center; padding: 40px; }
    .tag { background: #ffe0e0; color: #ff4757; padding: 2px 8px; border-radius: 3px; font-weight: bold; font-size: 12px; }
    pre { background: #2f3542; color: #dfe4ea; padding: 10px; border-radius: 5px; overflow-x: auto; font-size: 12px; }
    .btn { display: inline-block; background: #2f3542; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-bottom: 20px; font-size: 14px; }
</style></head><body>
<a href="http://localhost:8080" class="btn">⬅️ 返回首页</a>
<h1>🛡️ 0scan 代码安检报告</h1>
"""

if not report_data:
    html_content += "<div class='card safe'><h2>✅ 完美！未发现高危硬编码或密钥泄露。</h2></div>"
else:
    html_content += f"<p>共发现 <strong>{len(report_data)}</strong> 处潜在风险：</p>"
    for item in report_data:
        html_content += f"""
        <div class='card'>
            <span class='tag'>{item['type']}</span>
            <p>📁 文件: <code>{item['file']}</code> (第 {item['line']} 行)</p>
            <p>🔑 提取凭证: <strong>{html.escape(item['masked_key'])}</strong></p>
            <pre>{html.escape(item['raw_context'])}</pre>
        </div>
        """

html_content += "</body></html>"

with open("v5_report.html", "w", encoding="utf-8") as f:
    f.write(html_content)

print(f"✅ 扫描完成！共发现 {len(report_data)} 处风险。")
print("📄 报告已生成：v5_report.html")
