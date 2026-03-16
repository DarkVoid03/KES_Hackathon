"""
Response Generator — maps threat severity + type to actionable recommendations.
"""

RECOMMENDATIONS = {
    ("Critical", "nlp"):      "Delete this email immediately. Do not click any links or download attachments. Report to your IT security team and change your password if you interacted with it.",
    ("Critical", "url"):      "Block this URL at the firewall immediately. Do not visit this site. Report to your threat intelligence team. Check if any users accessed it in the past 24 hours.",
    ("Critical", "anomaly"):  "Freeze this user account immediately. Trigger step-up authentication. Review all actions taken in this session. Escalate to the security operations team.",
    ("Critical", "deepfake"): "Do not act on instructions given in this media. Verify the identity of the person through a separate trusted channel before proceeding.",
    ("Likely Malicious", "nlp"):  "Quarantine this email. Do not click links. Forward to security team for review.",
    ("Likely Malicious", "url"):  "Do not visit this URL. Flag for security review. Check DNS block lists.",
    ("Likely Malicious", "anomaly"): "Require additional authentication for this user. Monitor session activity closely.",
    ("Suspicious", "nlp"):   "Treat this message with caution. Verify the sender through a separate channel before responding.",
    ("Suspicious", "url"):   "Verify this URL with a trusted source before clicking. Check the domain reputation.",
    ("Suspicious", "anomaly"): "Monitor this user session. No immediate action required unless additional signals appear.",
}

DEFAULT_RECOMMENDATIONS = {
    "Critical":         "Take immediate protective action. Isolate the threat and contact your security team.",
    "Likely Malicious": "Exercise extreme caution. Do not engage with this content without security team approval.",
    "Suspicious":       "Verify through independent channels before taking action.",
    "Clean":            "No action required. Continue normal operations.",
}


def build_recommendation(severity: str, active_detectors: list) -> str:
    for det in active_detectors:
        key = (severity, det)
        if key in RECOMMENDATIONS:
            return RECOMMENDATIONS[key]
    return DEFAULT_RECOMMENDATIONS.get(severity, "Review this alert with your security team.")
