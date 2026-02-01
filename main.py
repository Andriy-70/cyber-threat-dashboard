import requests
import datetime
import os

def fetch_cves():
    # Беремо дані за останні 5 днів
    date_limit = (datetime.datetime.now() - datetime.timedelta(days=5)).isoformat()
    url = f"https://services.nist.gov/rest/json/cves/2.0/?pubStartDate={date_limit}"
    
    try:
        r = requests.get(url, timeout=15)
        return r.json().get('vulnerabilities', [])
    except Exception as e:
        print(f"Error fetching data: {e}")
        return []

def generate_html(vulnerabilities):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    rows = ""
    
    for v in vulnerabilities:
        cve = v.get('cve', {})
        cve_id = cve.get('id', 'N/A')
        
        # Отримуємо опис
        descriptions = cve.get('descriptions', [])
        desc = "No description available."
        for d in descriptions:
            if d.get('lang') == 'en':
                desc = d.get('value', desc)
                break
        
        # Спроба дістати рівень загрози (Severity)
        metrics = cve.get('metrics', {})
        cvss = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
        base_score = cvss.get('baseScore', 'N/A')
        severity = cvss.get('baseSeverity', 'UNKNOWN').upper()

        # Колір залежно від загрози
        color = "#00d4ff" # Default blue
        if severity == "CRITICAL": color = "#ff4d4d"
        elif severity == "HIGH": color = "#ffa500"
        elif severity == "MEDIUM": color = "#ffeb3b"

        rows += f"""
        <div class="card">
            <div class="card-header">
                <span class="cve-id">{cve_id}</span>
                <span class="severity" style="background: {color}22; color: {color}; border: 1px solid {color}">{severity} {base_score}</span>
            </div>
            <div class="card-body">{desc[:300]}...</div>
            <div class="card-footer">
                <a href="https://nvd.nist.gov/vuln/detail/{cve_id}" target="_blank">View Details →</a>
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
                --bg: #0b0e14;
                --card-bg: #151921;
                --text: #e0e6ed;
                --accent: #00d4ff;
                --border: #2d333f;
            }}
            body {{
                background-color: var(--bg);
                color: var(--text);
                font-family: 'Inter', -apple-system, sans-serif;
                margin: 0;
                padding: 20px;
                display: flex;
                flex-direction: column;
                align-items: center;
            }}
            .container {{ max-width: 900px; width: 100%; }}
            header {{
                width: 100%;
                padding: 40px 0;
                text-align: left;
                border-bottom: 1px solid var(--border);
                margin-bottom: 30px;
            }}
            h1 {{ margin: 0; font-size: 28px; letter-spacing: -0.5px; color: var(--accent); }}
            .status {{ font-size: 14px; color: #8892b0; margin-top: 10px; }}
            .grid {{ display: grid; gap: 20px; grid-template-columns: 1fr; }}
            .card {{
                background: var(--card-bg);
                border: 1px solid var(--border);
                border-radius: 12px;
                padding: 20px;
                transition: transform 0.2s;
            }}
            .card:hover {{ transform: translateY(-3px); border-color: var(--accent); }}
            .card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
            .cve-id {{ font-weight: bold; font-size: 18px; color: var(--accent); }}
            .severity {{
                font-size: 11px;
                padding: 4px 10px;
                border-radius: 20px;
                font-weight: 800;
                text-transform: uppercase;
            }}
            .card-body {{ font-size: 15px; line-height: 1.6; color: #b0b8c4; }}
            .card-footer {{ margin-top: 20px; font-size: 13px; }}
            .card-footer a {{ color: var(--accent); text-decoration: none; font-weight: 600; }}
            footer {{ margin-top: 50px; padding: 20px; font-size: 12px; color: #4b5563; }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🛡️ Cyber Threat Intelligence</h1>
                <div class="status">Live Feed • Last sync: {now} UTC • Sources: NVD NIST</div>
            </header>
            <div class="grid">
                {rows if rows else "<p>No critical threats found in the last 5 days.</p>"}
            </div>
            <footer>
                &copy; 2026 Automated Security Feed • Built by Andriy-70
            </footer>
        </div>
    </body>
    </html>
    """
    with open("docs/index.html", "w", encoding="utf-8") as f:
        f.write(html)

if __name__ == "__main__":
    data = fetch_cves()
    generate_html(data)