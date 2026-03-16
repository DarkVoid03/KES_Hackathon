"""
SentinelAI — utils/mitre_mapper.py
Maps detector signals to MITRE ATT&CK tactics and techniques.
"""

from typing import Any

# Simple rule-based mapping — expand as needed
_RULES = [
    {
        "condition": lambda active, flags: "url_detector" in active and any(
            f in flags for f in ["lookalike_domain", "newly_registered_domain"]
        ),
        "tactic": "Initial Access",
        "technique": "T1566.002",
        "technique_name": "Spearphishing Link",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
    },
    {
        "condition": lambda active, flags: "nlp_detector" in active and any(
            f in flags for f in ["credential_request", "authority_impersonation"]
        ),
        "tactic": "Credential Access",
        "technique": "T1598",
        "technique_name": "Phishing for Information",
        "url": "https://attack.mitre.org/techniques/T1598/",
    },
    {
        "condition": lambda active, flags: "anomaly_detector" in active and any(
            f in flags for f in ["off_hours_send", "unusual_sender_domain"]
        ),
        "tactic": "Defense Evasion",
        "technique": "T1036",
        "technique_name": "Masquerading",
        "url": "https://attack.mitre.org/techniques/T1036/",
    },
    {
        "condition": lambda active, flags: "deepfake_detector" in active,
        "tactic": "Initial Access",
        "technique": "T1566",
        "technique_name": "Phishing (Deepfake-assisted)",
        "url": "https://attack.mitre.org/techniques/T1566/",
    },
]

_DEFAULT = {
    "tactic": "Unknown",
    "technique": "T0000",
    "technique_name": "Undetermined",
    "url": "https://attack.mitre.org/",
}


def map_mitre_tactic(detector_results: dict[str, Any], fusion_result: dict) -> dict:
    active = fusion_result.get("active_detectors", [])

    # Collect all flags across detectors
    all_flags: list[str] = []
    for result in detector_results.values():
        all_flags.extend(result.get("flags", []))

    for rule in _RULES:
        try:
            if rule["condition"](active, all_flags):
                return {
                    "tactic": rule["tactic"],
                    "technique": rule["technique"],
                    "technique_name": rule["technique_name"],
                    "url": rule["url"],
                }
        except Exception:
            continue

    return _DEFAULT