def map_mitre(indicators):
    """Map detected indicators to relevant MITRE ATT&CK techniques."""
    techniques = []

    if indicators.get("suspicious_attachments"):
        techniques.append("T1566.001 - Spearphishing Attachment")

    if (
        indicators.get("malicious_urls")
        or indicators.get("link_mismatches")
        or indicators.get("shortened_urls")
        or indicators.get("unresolved_shorteners")
    ):
        techniques.append("T1566.002 - Spearphishing Link")

    if indicators.get("spoofing"):
        techniques.append("T1656 - Impersonation")

    if indicators.get("urgency_keywords") or indicators.get("suspicious_subject"):
        techniques.append("T1598 - Phishing for Information")

    if indicators.get("malicious_ips"):
        techniques.append("T1071 - Application Layer Protocol")

    if indicators.get("malicious_hashes"):
        techniques.append("T1204.002 - Malicious File")

    return techniques if techniques else ["N/A"]