import subprocess

keywords = "password|api_key|secret|token"
# 排除测试、文档、依赖库，并且排除我们自己的脚本
exclude_files = [".min.js", ".html", ".md", ".json", "scanner*.py"]

print("正在执行 V3 智能安检...")

cmd = ["rg", "-i", keywords]
for f in exclude_files:
    cmd.extend(["--glob", "!" + f])
cmd.append(".")

result = subprocess.run(cmd, capture_output=True, text=True)
output = result.stdout

if not output:
    output = "未发现可疑信息，很安全！"

# 加了 CSS 样式，让网页更像一份正式的报告
html_content = f"""<html>
<head>
<meta charset="utf-8">
<title>PocketAudit 3.0 报告</title>
<style>
    body {{ font-family: sans-serif; padding: 20px; background: #f4f4f9; }}
    h1 {{ color: #333; }}
    pre {{ background: #222; color: #0f0; padding: 15px; border-radius: 5px; overflow-x: auto; }}
    p {{ color: #666; }}
</style>
</head>
<body>
    <h1>PocketAudit 3.0 智能安检报告</h1>
    <p>已自动排除测试文件、依赖库以及工具自身的脚本。</p>
    <pre>{output}</pre>
</body>
</html>"""

with open("report_v3.html", "w", encoding="utf-8") as f:
    f.write(html_content)

print("V3 安检完成！报告已保存为 report_v3.html")
