import re
import ipaddress


def parse_headers(raw_email):
    """Extract key headers from raw email text."""
    headers = {}

    fields = [
        "From", "To", "Subject", "Date", "Reply-To",
        "Return-Path", "Message-ID", "X-Originating-IP",
        "Received", "X-Mailer", "MIME-Version", "Content-Type"
    ]

    for field in fields:
        pattern = rf"^{field}:\s*(.+?)(?=\n\S|\Z)"
        match = re.search(pattern, raw_email, re.MULTILINE | re.IGNORECASE | re.DOTALL)
        if match:
            headers[field] = match.group(1).strip().replace("\n", " ").replace("\r", "")

    return headers


def extract_sender_domain(from_header):
    """Extract domain from From header."""
    match = re.search(r"@([\w\.\-]+)", from_header or "")
    return match.group(1).lower() if match else None


def extract_originating_ip(raw_email):
    """Extract originating IP from X-Originating-IP or first Received header."""
    # Try X-Originating-IP first
    match = re.search(r"X-Originating-IP:\s*([\d\.]+)", raw_email, re.IGNORECASE)
    if match:
        return match.group(1)

    # Fall back to first external IP in Received headers
    received_ips = re.findall(
        r"Received:.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        raw_email, re.IGNORECASE
    )
    for ip in received_ips:
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved):
                return ip
        except:
            continue

    return None


def check_spoofing(headers):
    """Check for common spoofing indicators in headers."""
    indicators = []

    from_header = headers.get("From", "")
    reply_to = headers.get("Reply-To", "")
    return_path = headers.get("Return-Path", "")

    from_domain = extract_sender_domain(from_header)
    reply_domain = extract_sender_domain(reply_to)
    return_domain = extract_sender_domain(return_path)

    # Mismatch between From and Reply-To
    if from_domain and reply_domain and from_domain != reply_domain:
        indicators.append(f"Reply-To domain mismatch: From={from_domain}, Reply-To={reply_domain}")

    # Mismatch between From and Return-Path
    if from_domain and return_domain and from_domain != return_domain:
        indicators.append(f"Return-Path domain mismatch: From={from_domain}, Return-Path={return_domain}")

    # Display name spoofing — name says legit brand but email domain isn't the real one
    legit_brand_domains = {
        "paypal": ["paypal.com"],
        "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com"],
        "google": ["google.com", "gmail.com"],
        "apple": ["apple.com", "icloud.com"],
        "amazon": ["amazon.com"],
        "netflix": ["netflix.com"],
        "bank of america": ["bankofamerica.com"],
    }

    for brand, real_domains in legit_brand_domains.items():
        if brand in from_header.lower():
            if from_domain and not any(from_domain.lower() == d or from_domain.lower().endswith("." + d) for d in real_domains):
                indicators.append(f"Display name spoofing: '{brand}' in name but domain is '{from_domain}' (not an official {brand} domain)")

    return indicators