import re


# ─────────────────────────────────────────────
#  URGENCY / SOCIAL ENGINEERING KEYWORDS
# ─────────────────────────────────────────────

URGENCY_KEYWORDS = [
    "urgent", "immediately", "account suspended", "verify now",
    "click here", "confirm your", "unusual activity", "limited time",
    "act now", "your account has been", "will be suspended",
    "unauthorized access", "security alert", "login attempt",
    "update your information", "verify your identity", "expires",
    "final notice", "last chance", "within 24 hours", "within 48 hours"
]

SUSPICIOUS_SUBJECTS = [
    "account", "verify", "suspended", "alert", "security",
    "unusual", "confirm", "update", "password", "urgent",
    "action required", "important", "notification"
]

SUSPICIOUS_ATTACHMENT_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".vbs", ".js", ".jar",
    ".zip", ".rar", ".7z", ".iso", ".ps1", ".scr", ".hta"
]


# ─────────────────────────────────────────────
#  KEYWORD ANALYSIS
# ─────────────────────────────────────────────

def check_urgency_keywords(text):
    """Find urgency/manipulation keywords in email body."""
    found = []
    text_lower = text.lower()
    for keyword in URGENCY_KEYWORDS:
        if keyword in text_lower:
            found.append(keyword)
    return found


def check_suspicious_subject(subject):
    """Check if subject contains phishing-related terms."""
    found = []
    subject_lower = (subject or "").lower()
    for term in SUSPICIOUS_SUBJECTS:
        if term in subject_lower:
            found.append(term)
    return found


def check_suspicious_attachments(raw_email):
    """Detect suspicious attachment types."""
    found = []
    for ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS:
        if ext in raw_email.lower():
            found.append(ext)
    return found


def check_link_text_mismatch(raw_email):
    """Detect links where display text doesn't match the actual URL."""
    mismatches = []
    # Pattern: <a href="url">display text</a>
    pattern = r'<a\s+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
    matches = re.findall(pattern, raw_email, re.IGNORECASE)
    for href, text in matches:
        text = text.strip()
        # If display text looks like a URL but doesn't match href
        if re.match(r"https?://", text) and text.rstrip("/") != href.rstrip("/"):
            mismatches.append(f"Display: '{text}' → Actual: '{href}'")
    return mismatches


# ─────────────────────────────────────────────
#  SCORING
# ─────────────────────────────────────────────

def calculate_risk_score(indicators: dict) -> tuple:
    """
    Score the email based on all indicators.
    Returns (score, risk_level)
    """
    score = 0

    score += len(indicators.get("urgency_keywords", [])) * 5
    score += len(indicators.get("suspicious_subject", [])) * 5
    score += len(indicators.get("spoofing", [])) * 20
    score += len(indicators.get("link_mismatches", [])) * 15
    score += len(indicators.get("suspicious_attachments", [])) * 20
    score += len(indicators.get("malicious_urls", [])) * 30
    score += len(indicators.get("malicious_ips", [])) * 25
    score += len(indicators.get("shortened_urls", [])) * 10
    score += len(indicators.get("unresolved_shorteners", [])) * 15
    score += len(indicators.get("malicious_hashes", [])) * 30

    if score >= 80:
        level = "🔴 HIGH RISK — LIKELY PHISHING"
    elif score >= 40:
        level = "🟡 MEDIUM RISK — SUSPICIOUS"
    elif score >= 10:
        level = "🟠 LOW RISK — REVIEW RECOMMENDED"
    else:
        level = "🟢 CLEAN — NO SIGNIFICANT INDICATORS"

    return score, level