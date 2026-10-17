from flask import Flask, render_template, request
import subprocess, os, shutil, re, html

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    if os.path.exists('temp_repo'):
        shutil.rmtree('temp_repo')
        
    # 🌟 极客作弊码：输入 demo 直接本地生成漏洞，不走网络
    if url.strip().lower() == "demo":
        os.makedirs('temp_repo', exist_ok=True)
        with open('temp_repo/leak_test.js', 'w') as f:
            f.write('const OPENAI_KEY = "sk-qwertyuiopasdfghjklzxcvbnm098765";\n')
            f.write('const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\n')
            f.write('password = "super_secret_admin_pass";\n')
    else:
        try:
            print(f"\n--- 正在尝试下载: {url} ---")
            subprocess.run(['git', 'clone', '--depth', '1', url, 'temp_repo'], check=True, capture_output=True, timeout=60)
        except Exception as e:
            return "<h2>下载失败</h2><p>请检查网址或网络。</p><a href='/'>返回首页</a>"

    patterns = {
        "OpenAI Key": r"sk-[a-zA-Z0-9]{32,}",
        "AWS Key": r"AKIA[0-9A-Z]{16}",
        "Hardcoded Password": r"password\s*=\s*['\"]([^${\s][^'\"]*)['\"]"
    }
    fake_keywords = ["123456", "xxxxxx", "your_api_key", "placeholder", "YOUR_", "test"]
    exclude_files = [".min.js", ".html", ".md", ".json", "package-lock.json"]
    
    report_data = []
    for key_type, pattern in patterns.items():
        cmd = ["rg", "--line-number", pattern, "."]
        for f in exclude_files:
            cmd.extend(["--glob", "!" + f])
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd='temp_repo')
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
                            "type": key_type, "file": file_path, "line": line_num,
                            "masked_key": masked_key, "raw_context": content.strip()[:80]
                        })
    shutil.rmtree('temp_repo')
    
    html_content = """
    <html><head><meta charset="utf-8"><title>0scan 报告</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #f4f4f9; padding: 20px; }
        .card { background: white; border-left: 5px solid #ff4757; padding: 15px; margin-bottom: 15px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.05); }
        .safe { border-left: 5px solid #2ed573; text-align: center; padding: 40px; }
        .tag { background: #ffe0e0; color: #ff4757; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; }
        pre { background: #1a1a1a; color: #dfe4ea; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; }
        .btn { display: inline-block; background: #1a1a1a; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin-bottom: 20px; font-weight: 600; }
    </style></head><body>
    <a href="/" class="btn">返回重新扫描</a>
    <h1>0scan 代码安检</h1>
    """
    if not report_data:
        html_content += "<div class='card safe'><h2>完美！未发现高危硬编码或密钥泄露。</h2></div>"
    else:
        html_content += f"<p>共发现 <strong>{len(report_data)}</strong> 处潜在风险：</p>"
        for item in report_data:
            html_content += f"""
            <div class='card'>
                <span class='tag'>{item['type']}</span>
                <p>文件: <code>{item['file']}</code> (第 {item['line']} 行)</p>
                <p>提取凭证: <strong>{html.escape(item['masked_key'])}</strong></p>
                <pre>{html.escape(item['raw_context'])}</pre>
            </div>
            """
    html_content += "</body></html>"
    return html_content

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
