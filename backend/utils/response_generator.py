"""
SentinelAI — utils/response_generator.py
Maps severity level to recommended analyst action strings.
"""

_ACTIONS: dict[str, str] = {
    "CRITICAL": (
        "Quarantine email immediately. Block sender domain at email gateway. "
        "Notify affected user. Escalate to SOC Tier 2 within 15 minutes."
    ),
    "HIGH": (
        "Quarantine email and block sender domain. "
        "Notify affected user and request confirmation of any actions taken. "
        "Log incident for Tier 1 review."
    ),
    "MEDIUM": (
        "Flag email for analyst review. "
        "Monitor for follow-on suspicious activity from the same sender. "
        "No immediate quarantine required."
    ),
    "LOW": (
        "Log event. Continue passive monitoring. "
        "No user notification required at this time."
    ),
    "INFO": (
        "Retain for audit log. No action required."
    ),
}


def recommend_action(severity: str) -> str:
    return _ACTIONS.get(severity.upper(), "Manual review recommended.")