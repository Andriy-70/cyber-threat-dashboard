import requests
import datetime
import os

def fetch_cves():
    """
    Отримуємо дані з GitHub Advisory Database. 
    Це надійне джерело, яке включає CVE та вразливості в оупенсорс проектах.
    """
    url = "https://api.github.com/advisories"
    headers = {
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'Cyber-Intel-Dashboard-App'
    }
    
    print(f"[*] Fetching security advisories from GitHub...")
    try:
        # Запитуємо останні 30 вразливостей
        r = requests.get(url, headers=headers, params={'per_page': 30}, timeout=15)
        r.raise_for_status()
        advisories = r.json()
        
        formatted_data = []
        for adv in advisories:
            # Форматуємо дані під наш дизайн
            severity = adv.get('severity', 'UNKNOWN').upper()
            score = adv.get('cvss', {}).get('score', 'N/A')
            
            formatted_data.append({
                'id': adv.get('cve_id') or adv.get('ghsa_id'),
                'title': adv.get('summary', 'No summary available'),
                'description': adv.get('description', 'No detailed description available.'),
                'severity': severity,
                'score': score,
                'url': adv.get('html_url'),
                'published': adv.get('published_at', '').split('T')[0]
            })
        
        print(f"[+] Successfully retrieved {len(formatted_data)} items.")
        return formatted_data
    except Exception as e:
        print(f"[!] Error fetching data: {e}")
        return []

def generate_html(data):
    """
    Генеруємо сучасний UI на основі отриманих даних.
    """
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    rows = ""
    
    for item in data:
        # Кольори для різних рівнів загрози
        color = "#8b949e" # Default grey
        if item['severity'] == "CRITICAL": color = "#ff4d4d"
        elif item['severity'] == "HIGH": color = "#ffa500"
        elif item['severity'] == "MEDIUM": color = "#ffeb3b"
        elif item['severity'] == "LOW": color = "#3fb950"

        rows += f"""
        <div class="card">
            <div class="card-header">
                <span class="cve-id">{item['id']}</span>
                <span class="severity" style="background: {color}22; color: {color}; border: 1px solid {color}">
                    {item['severity']} {item['score']}
                </span>
            </div>
            <div class="card-title">{item['title']}</div>
            <div class="card-body">{item['description'][:350]}...</div>
            <div class="card-footer">
                <span>Published: {item['published']}</span>
                <a href="{item['url']}" target="_blank">Full Report →</a>
            </div>
        </div>
        """

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cyber Intel Dashboard</title>
        <style>
            :root {{
                --bg: #0d1117;
                --card-bg: #161b22;
                --text: #c9d1d9;
                --accent: #58a6ff;
                --border: #30363d;
            }}
            body {{
                background-color: var(--bg);
                color: var(--text);
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
                margin: 0;
                padding: 20px;
                display: flex;
                flex-direction: column;
                align-items: center;
            }}
            .container {{ max-width: 1000px; width: 100%; }}
            header {{
                width: 100%;
                padding: 40px 0;
                border-bottom: 1px solid var(--border);
                margin-bottom: 30px;
            }}
            h1 {{ margin: 0; font-size: 32px; color: #f0f6fc; }}
            .status {{ font-size: 14px; color: #8b949e; margin-top: 10px; }}
            .grid {{ display: grid; gap: 20px; grid-template-columns: 1fr; }}
            .card {{
                background: var(--card-bg);
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 24px;
                transition: border-color 0.2s;
            }}
            .card:hover {{ border-color: #8b949e; }}
            .card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }}
            .cve-id {{ font-family: monospace; font-size: 16px; color: var(--accent); font-weight: bold; }}
            .severity {{
                font-size: 10px;
                padding: 2px 8px;
                border-radius: 12px;
                font-weight: 600;
            }}
            .card-title {{ font-size: 18px; font-weight: 600; margin-bottom: 10px; color: #f0f6fc; }}
            .card-body {{ font-size: 14px; line-height: 1.5; color: #8b949e; margin-bottom: 20px; }}
            .card-footer {{ 
                display: flex; 
                justify-content: space-between; 
                align-items: center;
                padding-top: 15px;
                border-top: 1px solid var(--border);
                font-size: 12px;
                color: #484f58;
            }}
            .card-footer a {{ color: var(--accent); text-decoration: none; font-weight: 500; }}
            footer {{ margin-top: 60px; padding: 20px; font-size: 12px; color: #484f58; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🛡️ Cyber Threat Intelligence</h1>
                <div class="status">● GitHub Security Advisory Feed • Updated: {now} UTC</div>
            </header>
            <div class="grid">
                {rows if rows else "<p>Searching for active threats...</p>"}
            </div>
            <footer>
                &copy; 2026 Automated Security Dashboard • Powered by GitHub Actions
            </footer>
        </div>
    </body>
    </html>
    """
    with open("docs/index.html", "w", encoding="utf-8") as f:
        f.write(html)

if __name__ == "__main__":
    advisories = fetch_cves()
    generate_html(advisories)
    print(f"[*] Build complete. {len(advisories)} items processed.")