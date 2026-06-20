import re
import requests
import time
import base64
import ipaddress
import csv
import json
import os
from datetime import datetime
from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, URLSCAN_API_KEY
from header_parser import parse_headers, extract_originating_ip, check_spoofing, extract_sender_domain
from phish_detector import (
    check_urgency_keywords, check_suspicious_subject,
    check_suspicious_attachments, check_link_text_mismatch,
    calculate_risk_score
)
from urlscan_checker import urlscan_submit_and_check
from mitre_mapper import map_mitre
from html_report import export_html


# Separate thresholds per IOC type — URLs are higher-confidence signals even with
# fewer engine hits, while hashes/IPs are more prone to noisy single-engine false positives.
VT_URL_THRESHOLD = 1
VT_HASH_THRESHOLD = 3
VT_IP_THRESHOLD = 3


# ─────────────────────────────────────────────
#  EXTRACT URLS, HASHES, DOMAINS FROM EMAIL BODY
# ─────────────────────────────────────────────

def extract_urls(text):
    url_pattern = r"https?://[^\s\>\<\"\'\)]+"
    return list(set(re.findall(url_pattern, text)))


def extract_hashes(text):
    """Extract MD5/SHA1/SHA256 hashes from email body."""
    hash_pattern = r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b"
    return list(set(re.findall(hash_pattern, text)))


def detect_hash_type(h):
    if len(h) == 32:
        return "MD5"
    elif len(h) == 40:
        return "SHA1"
    elif len(h) == 64:
        return "SHA256"
    return "UNKNOWN"


def extract_domain_from_url(url):
    match = re.match(r"^https?://([^/?\#]+)", url, re.IGNORECASE)
    if match:
        return match.group(1).split(":")[0]
    return None


# ─────────────────────────────────────────────
#  URL SHORTENER DETECTION & RESOLUTION
# ─────────────────────────────────────────────

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
    "tiny.cc", "lnkd.in", "bl.ink", "shorte.st", "soo.gd",
    "clck.ru", "v.gd", "qr.ae", "adf.ly"
}


def is_shortened_url(url):
    domain = extract_domain_from_url(url)
    return domain and domain.lower() in KNOWN_SHORTENERS


def resolve_shortened_url(url):
    """Follow redirects to find the real destination of a shortened URL.
    Returns None if the shortener is dead/invalid (resolves back to itself)."""
    try:
        r = requests.head(url, allow_redirects=True, timeout=10)
        if r.url.rstrip("/") != url.rstrip("/"):
            return r.url
    except requests.RequestException:
        pass

    # Some shorteners block HEAD requests, or HEAD didn't redirect — try GET
    try:
        r = requests.get(url, allow_redirects=True, timeout=10, stream=True)
        r.close()
        if r.url.rstrip("/") != url.rstrip("/"):
            return r.url
    except requests.RequestException:
        pass

    # Either it errored out, or it resolved back to the same URL (dead/invalid shortcode)
    return None


# ─────────────────────────────────────────────
#  VIRUSTOTAL CHECKS
# ─────────────────────────────────────────────

def vt_check_url(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    base = "https://www.virustotal.com/api/v3"

    try:
        post = requests.post(
            f"{base}/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )
    except requests.RequestException as e:
        return {"error": str(e)}

    if post.status_code not in (200, 201):
        return {"error": f"VT submit error {post.status_code}"}

    analysis_id = post.json().get("data", {}).get("id", "")
    if not analysis_id:
        return {"error": "No analysis ID returned"}

    for _ in range(5):
        time.sleep(5)
        try:
            result = requests.get(f"{base}/analyses/{analysis_id}", headers=headers, timeout=15)
        except requests.RequestException as e:
            return {"error": str(e)}

        if result.status_code == 200:
            attrs = result.json().get("data", {}).get("attributes", {})
            if attrs.get("status") == "completed":
                stats = attrs.get("stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "total": sum(stats.values())
                }

    return {"error": "VT analysis timed out"}


def vt_check_ip(ip):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers, timeout=10
        )
    except requests.RequestException as e:
        return {"error": str(e)}

    if r.status_code == 200:
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total": sum(stats.values())
        }
    return {"error": f"VT error {r.status_code}"}


def vt_check_hash(file_hash):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers=headers, timeout=10
        )
    except requests.RequestException as e:
        return {"error": str(e)}

    if r.status_code == 200:
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total": sum(stats.values())
        }
    elif r.status_code == 404:
        return {"error": "Hash not found in VirusTotal"}
    return {"error": f"VT error {r.status_code}"}


def abuseipdb_check(ip):
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
    except requests.RequestException as e:
        return {"error": str(e)}

    if r.status_code == 200:
        data = r.json()["data"]
        return {
            "abuse_score": data["abuseConfidenceScore"],
            "total_reports": data["totalReports"],
            "country": data.get("countryCode", "?"),
            "isp": data.get("isp", "?")
        }
    return {"error": f"AbuseIPDB error {r.status_code}"}


def is_private_ip(ip):
    try:
        obj = ipaddress.IPv4Address(ip)
        return obj.is_private or obj.is_loopback or obj.is_multicast or obj.is_reserved or obj.is_link_local
    except:
        return True


# ─────────────────────────────────────────────
#  ANALYZE EMAIL
# ─────────────────────────────────────────────

def analyze_email(raw_email, use_urlscan=False):
    print("\n[*] Parsing headers...")
    headers = parse_headers(raw_email)
    originating_ip = extract_originating_ip(raw_email)
    spoofing = check_spoofing(headers)

    print("[*] Extracting URLs and hashes...")
    urls = extract_urls(raw_email)
    hashes = extract_hashes(raw_email)

    print("[*] Running phishing indicator checks...")
    urgency = check_urgency_keywords(raw_email)
    subject_flags = check_suspicious_subject(headers.get("Subject", ""))
    attachments = check_suspicious_attachments(raw_email)
    link_mismatches = check_link_text_mismatch(raw_email)

    # VT + URLScan check URLs
    malicious_urls = []
    url_results = {}
    urlscan_results = {}
    shortened_resolutions = {}
    unresolved_shorteners = []

    if urls:
        print(f"[*] Checking {len(urls)} URL(s) against VirusTotal...")
        for url in urls:
            check_url = url

            # If shortened, resolve it first
            if is_shortened_url(url):
                print(f"    [!] Shortened URL detected: {url} — resolving...")
                resolved = resolve_shortened_url(url)
                if resolved:
                    shortened_resolutions[url] = resolved
                    check_url = resolved
                    print(f"        → Resolved to: {resolved}")
                else:
                    # Could not resolve — treat as suspicious by default, do NOT
                    # fall back to checking the meaningless short link itself
                    shortened_resolutions[url] = "Could not resolve"
                    unresolved_shorteners.append(url)
                    url_results[url] = {"error": "Shortener could not be resolved — treated as suspicious"}
                    continue

            result = vt_check_url(check_url)
            url_results[url] = result
            if "error" not in result and result.get("malicious", 0) >= VT_URL_THRESHOLD:
                malicious_urls.append(url)

            if use_urlscan:
                print(f"    [*] Scanning with URLScan.io: {check_url}...")
                us_result = urlscan_submit_and_check(check_url, URLSCAN_API_KEY)
                urlscan_results[url] = us_result

            time.sleep(5)

    # VT check hashes
    hash_results = {}
    malicious_hashes = []
    if hashes:
        print(f"[*] Checking {len(hashes)} hash(es) against VirusTotal...")
        for h in hashes:
            result = vt_check_hash(h)
            result["hash_type"] = detect_hash_type(h)
            hash_results[h] = result
            if "error" not in result and result.get("malicious", 0) >= VT_HASH_THRESHOLD:
                malicious_hashes.append(h)
            time.sleep(5)

    # VT + AbuseIPDB check originating IP
    malicious_ips = []
    ip_result = {}
    if originating_ip and not is_private_ip(originating_ip):
        print(f"[*] Checking originating IP: {originating_ip}...")
        ip_vt = vt_check_ip(originating_ip)
        ip_abuse = abuseipdb_check(originating_ip)
        ip_result = {"vt": ip_vt, "abuse": ip_abuse}
        if ip_vt.get("malicious", 0) >= VT_IP_THRESHOLD or ip_abuse.get("abuse_score", 0) >= 25:
            malicious_ips.append(originating_ip)
        time.sleep(5)

    indicators = {
        "urgency_keywords": urgency,
        "suspicious_subject": subject_flags,
        "spoofing": spoofing,
        "link_mismatches": link_mismatches,
        "suspicious_attachments": attachments,
        "malicious_urls": malicious_urls,
        "malicious_ips": malicious_ips,
        "malicious_hashes": malicious_hashes,
        "shortened_urls": list(shortened_resolutions.keys()),
        "unresolved_shorteners": unresolved_shorteners
    }

    score, risk_level = calculate_risk_score(indicators)
    mitre = map_mitre(indicators)

    return {
        "headers": headers,
        "originating_ip": originating_ip,
        "ip_result": ip_result,
        "urls": urls,
        "url_results": url_results,
        "urlscan_results": urlscan_results,
        "hashes": hashes,
        "hash_results": hash_results,
        "shortened_resolutions": shortened_resolutions,
        "indicators": indicators,
        "score": score,
        "risk_level": risk_level,
        "mitre": mitre
    }


# ─────────────────────────────────────────────
#  PRINT REPORT
# ─────────────────────────────────────────────

def print_report(result):
    h = result["headers"]
    ind = result["indicators"]

    print("\n" + "="*60)
    print("  MailCSI — PHISHING ANALYSIS REPORT")
    print("="*60)

    print("\n  [EMAIL HEADERS]")
    for field in ["From", "To", "Subject", "Date", "Reply-To", "Return-Path", "X-Originating-IP"]:
        if field in h:
            print(f"  {field:<20}: {h[field]}")

    if result["originating_ip"]:
        print(f"\n  Originating IP  : {result['originating_ip']}")
        if result["ip_result"]:
            vt = result["ip_result"].get("vt", {})
            abuse = result["ip_result"].get("abuse", {})
            if "error" not in vt:
                print(f"  VT Malicious    : {vt.get('malicious', 0)} / {vt.get('total', 0)}")
            if "error" not in abuse:
                print(f"  Abuse Score     : {abuse.get('abuse_score', 0)}% ({abuse.get('total_reports', 0)} reports) [{abuse.get('country', '?')}]")

    print("\n  [PHISHING INDICATORS]")

    if ind["spoofing"]:
        print("\n  ⚠️  Header Spoofing:")
        for s in ind["spoofing"]:
            print(f"     • {s}")

    if ind["urgency_keywords"]:
        print(f"\n  ⚠️  Urgency Keywords ({len(ind['urgency_keywords'])} found):")
        print(f"     {', '.join(ind['urgency_keywords'][:8])}")

    if ind["suspicious_subject"]:
        print(f"\n  ⚠️  Suspicious Subject Terms: {', '.join(ind['suspicious_subject'])}")

    if ind["link_mismatches"]:
        print(f"\n  ⚠️  Link Text Mismatches:")
        for m in ind["link_mismatches"]:
            print(f"     • {m}")

    if ind["suspicious_attachments"]:
        print(f"\n  ⚠️  Suspicious Attachment Types: {', '.join(ind['suspicious_attachments'])}")

    if result.get("shortened_resolutions"):
        print(f"\n  ⚠️  Shortened URLs Detected:")
        for short, resolved in result["shortened_resolutions"].items():
            flag = "  (UNRESOLVED — treated as suspicious)" if resolved == "Could not resolve" else ""
            print(f"     • {short} → {resolved}{flag}")

    if result["urls"]:
        print(f"\n  [URLs FOUND — {len(result['urls'])}]")
        for url in result["urls"]:
            vt = result["url_results"].get(url, {})
            if "error" in vt:
                status = f"⚪ UNKNOWN ({vt['error']})"
            elif vt.get("malicious", 0) >= VT_URL_THRESHOLD:
                status = f"🔴 MALICIOUS ({vt['malicious']}/{vt['total']} engines)"
            elif vt.get("suspicious", 0) >= 1:
                status = f"🟡 SUSPICIOUS (low-confidence engine hits)"
            else:
                status = f"🟢 CLEAN"
            print(f"     {status} — {url}")

            us = result.get("urlscan_results", {}).get(url)
            if us and "error" not in us:
                verdict = "🔴 MALICIOUS" if us.get("malicious") else "🟢 Not flagged"
                print(f"        URLScan: {verdict} (score: {us.get('score', 0)}) | Final URL: {us.get('final_url', '?')}")
                if us.get("report"):
                    print(f"        Report: {us['report']}")
            elif us and "error" in us:
                print(f"        URLScan: ⚪ {us['error']}")

    if result.get("hashes"):
        print(f"\n  [FILE HASHES FOUND — {len(result['hashes'])}]")
        for h in result["hashes"]:
            res = result["hash_results"].get(h, {})
            htype = res.get("hash_type", "UNKNOWN")
            if "error" in res:
                status = f"⚪ UNKNOWN ({res['error']})"
            elif res.get("malicious", 0) >= VT_HASH_THRESHOLD:
                status = f"🔴 MALICIOUS ({res['malicious']}/{res['total']} engines)"
            elif res.get("malicious", 0) >= 1:
                status = f"🟡 SUSPICIOUS (low-confidence engine hits)"
            else:
                status = f"🟢 CLEAN"
            print(f"     [{htype}] {status} — {h}")

    if not any([ind["spoofing"], ind["urgency_keywords"], ind["suspicious_subject"],
                ind["link_mismatches"], ind["suspicious_attachments"],
                ind["malicious_urls"], ind["malicious_ips"], ind["malicious_hashes"]]):
        print("  No significant indicators found.")

    print("\n" + "-"*60)
    print(f"  RISK SCORE : {result['score']}")
    print(f"  VERDICT    : {result['risk_level']}")
    print(f"  MITRE ATT&CK: {', '.join(result.get('mitre', ['N/A']))}")
    print("="*60 + "\n")


# ─────────────────────────────────────────────
#  EXPORT
# ─────────────────────────────────────────────

def export_report(result):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"mailcsi_report_{timestamp}.json"

    export = {
        "timestamp": timestamp,
        "from": result["headers"].get("From", ""),
        "subject": result["headers"].get("Subject", ""),
        "originating_ip": result["originating_ip"],
        "risk_score": result["score"],
        "verdict": result["risk_level"],
        "mitre": result.get("mitre", ["N/A"]),
        "indicators": result["indicators"],
        "urls_checked": result["url_results"],
        "urlscan_results": result.get("urlscan_results", {}),
        "hashes_checked": result["hash_results"]
    }

    with open(filename, "w") as f:
        json.dump(export, f, indent=2)

    print(f"✅ Report saved to: {filename}")


# ─────────────────────────────────────────────
#  INPUT MODES
# ─────────────────────────────────────────────

def get_email_from_paste():
    print("\nPaste the raw email below.")
    print("When done, type END on a new line and press Enter:\n")
    lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)
    return "\n".join(lines)


def get_email_from_file(filepath):
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return None
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    print("\n==============================")
    print("   MailCSI — Phishing Analyzer")
    print("==============================")
    print("1. Paste raw email")
    print("2. Load from .eml file")
    print("==============================")

    choice = input("Select mode (1/2): ").strip()

    if choice == "1":
        raw_email = get_email_from_paste()
    elif choice == "2":
        filepath = input("Enter path to .eml file: ").strip()
        raw_email = get_email_from_file(filepath)
        if not raw_email:
            return
    else:
        print("Invalid choice.")
        return

    if not raw_email.strip():
        print("No email content provided.")
        return

    use_urlscan = input("Also scan URLs with URLScan.io? (slower, y/n): ").strip().lower() == "y"

    result = analyze_email(raw_email, use_urlscan=use_urlscan)
    print_report(result)

    save = input("Export report to JSON? (y/n): ").strip().lower()
    if save == "y":
        export_report(result)

    save_html = input("Export report to HTML? (y/n): ").strip().lower()
    if save_html == "y":
        export_html(result)


if __name__ == "__main__":
    main()