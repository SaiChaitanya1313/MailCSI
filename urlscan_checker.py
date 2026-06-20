import requests
import time


def urlscan_submit_and_check(url, api_key):
    """Submit a URL to URLScan.io and retrieve the scan result."""
    if not api_key or api_key == "your_urlscan_api_key_here":
        return {"error": "URLScan API key not configured"}

    headers = {"API-Key": api_key, "Content-Type": "application/json"}

    try:
        submit = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={"url": url, "visibility": "public"},
            timeout=10
        )
    except requests.RequestException as e:
        return {"error": f"URLScan submit failed: {str(e)}"}

    if submit.status_code != 200:
        try:
            error_detail = submit.json().get("message", submit.text[:200])
        except:
            error_detail = submit.text[:200]
        return {"error": f"URLScan submit error {submit.status_code}: {error_detail}"}

    data = submit.json()
    result_url = data.get("api")
    screenshot_url = data.get("screenshot")
    report_url = data.get("result")

    if not result_url:
        return {"error": "URLScan did not return a result URL"}

    # Poll for completion (scans usually take 10-20s)
    for _ in range(4):
        time.sleep(8)
        try:
            r = requests.get(result_url, timeout=10)
        except requests.RequestException:
            continue

        if r.status_code == 200:
            result_data = r.json()
            verdicts = result_data.get("verdicts", {}).get("overall", {})
            page = result_data.get("page", {})
            return {
                "malicious": verdicts.get("malicious", False),
                "score": verdicts.get("score", 0),
                "categories": verdicts.get("categories", []),
                "final_url": page.get("url", url),
                "ip": page.get("ip", "?"),
                "country": page.get("country", "?"),
                "screenshot": screenshot_url,
                "report": report_url
            }

    return {"error": "URLScan analysis timed out", "report": report_url}