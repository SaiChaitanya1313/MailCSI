from datetime import datetime


def export_html(result):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"mailcsi_report_{timestamp}.html"

    h = result["headers"]
    ind = result["indicators"]
    mitre_list = result.get("mitre", ["N/A"])

    verdict_color = "#cc0000" if "HIGH" in result["risk_level"] else \
                     "#cc8800" if "MEDIUM" in result["risk_level"] else \
                     "#888800" if "LOW" in result["risk_level"] else "#008800"

    def list_block(title, items):
        if not items:
            return ""
        rows = "".join(f"<li>{i}</li>" for i in items)
        return f"<h3>{title}</h3><ul>{rows}</ul>"

    url_rows = ""
    for url in result.get("urls", []):
        vt = result["url_results"].get(url, {})
        if "error" in vt:
            status = f"UNKNOWN ({vt['error']})"
            color = "#888"
        elif vt.get("malicious", 0) >= 1:
            status = f"MALICIOUS ({vt['malicious']}/{vt.get('total', 0)} engines)"
            color = "#cc0000"
        elif vt.get("malicious", 0) >= 1 or vt.get("suspicious", 0) >= 1:
            status = "SUSPICIOUS"
            color = "#cc8800"
        else:
            status = "CLEAN"
            color = "#008800"
        url_rows += f'<tr><td style="color:{color}; font-weight:bold;">{status}</td><td>{url}</td></tr>'

    hash_rows = ""
    for hsh in result.get("hashes", []):
        res = result["hash_results"].get(hsh, {})
        htype = res.get("hash_type", "?")
        if "error" in res:
            status = f"UNKNOWN ({res['error']})"
            color = "#888"
        elif res.get("malicious", 0) >= 3:
            status = f"MALICIOUS ({res['malicious']}/{res.get('total', 0)} engines)"
            color = "#cc0000"
        elif res.get("malicious", 0) >= 1:
            status = "SUSPICIOUS"
            color = "#cc8800"
        else:
            status = "CLEAN"
            color = "#008800"
        hash_rows += f'<tr><td>{htype}</td><td style="color:{color}; font-weight:bold;">{status}</td><td style="word-break:break-all;">{hsh}</td></tr>'

    mitre_html = "".join(f"<li>{t}</li>" for t in mitre_list)

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>MailCSI Report</title>
<style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 30px; color: #222; }}
    .container {{ max-width: 900px; margin: auto; background: #fff; border-radius: 8px; padding: 30px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
    h1 {{ color: #1a1a2e; border-bottom: 3px solid #1a1a2e; padding-bottom: 10px; }}
    h2 {{ color: #1a1a2e; margin-top: 30px; }}
    h3 {{ color: #444; margin-bottom: 5px; }}
    .verdict {{ font-size: 1.3em; font-weight: bold; color: {verdict_color}; padding: 15px; background: #fafafa; border-left: 5px solid {verdict_color}; border-radius: 4px; }}
    .meta-table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    .meta-table td {{ padding: 8px; border-bottom: 1px solid #eee; vertical-align: top; }}
    .meta-table td:first-child {{ font-weight: bold; width: 180px; color: #555; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    table td, table th {{ padding: 8px; border-bottom: 1px solid #eee; text-align: left; font-size: 0.9em; }}
    th {{ background: #1a1a2e; color: #fff; }}
    ul {{ margin-top: 5px; }}
    .score-badge {{ display: inline-block; background: {verdict_color}; color: white; padding: 5px 15px; border-radius: 20px; font-weight: bold; }}
    .footer {{ margin-top: 30px; font-size: 0.8em; color: #999; text-align: center; }}
</style>
</head>
<body>
<div class="container">
    <h1>🛡️ MailCSI — Phishing Analysis Report</h1>

    <div class="verdict">{result['risk_level']}</div>
    <p>Risk Score: <span class="score-badge">{result['score']}</span></p>

    <h2>Email Metadata</h2>
    <table class="meta-table">
        <tr><td>From</td><td>{h.get('From', 'N/A')}</td></tr>
        <tr><td>To</td><td>{h.get('To', 'N/A')}</td></tr>
        <tr><td>Subject</td><td>{h.get('Subject', 'N/A')}</td></tr>
        <tr><td>Date</td><td>{h.get('Date', 'N/A')}</td></tr>
        <tr><td>Reply-To</td><td>{h.get('Reply-To', 'N/A')}</td></tr>
        <tr><td>Return-Path</td><td>{h.get('Return-Path', 'N/A')}</td></tr>
        <tr><td>Originating IP</td><td>{result.get('originating_ip', 'N/A')}</td></tr>
    </table>

    <h2>MITRE ATT&CK Mapping</h2>
    <ul>{mitre_html}</ul>

    <h2>Phishing Indicators</h2>
    {list_block("Header Spoofing", ind.get("spoofing", []))}
    {list_block("Urgency Keywords", ind.get("urgency_keywords", []))}
    {list_block("Suspicious Subject Terms", ind.get("suspicious_subject", []))}
    {list_block("Link Text Mismatches", ind.get("link_mismatches", []))}
    {list_block("Suspicious Attachments", ind.get("suspicious_attachments", []))}
    {list_block("Shortened URLs", ind.get("shortened_urls", []))}

    <h2>URLs Found ({len(result.get('urls', []))})</h2>
    <table>
        <tr><th>Verdict</th><th>URL</th></tr>
        {url_rows if url_rows else "<tr><td colspan='2'>None found</td></tr>"}
    </table>

    <h2>File Hashes Found ({len(result.get('hashes', []))})</h2>
    <table>
        <tr><th>Type</th><th>Verdict</th><th>Hash</th></tr>
        {hash_rows if hash_rows else "<tr><td colspan='3'>None found</td></tr>"}
    </table>

    <div class="footer">Generated by MailCSI — Phishing Email Analyzer</div>
</div>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"✅ HTML report saved to: {filename}")
    return filename