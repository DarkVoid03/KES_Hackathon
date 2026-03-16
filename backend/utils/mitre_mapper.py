"""
MITRE ATT&CK Mapper — maps detected threat types to MITRE tactic IDs.
"""

MITRE_MAP = {
    "nlp":      {"id": "T1566",   "name": "Phishing",                       "tactic": "Initial Access"},
    "url":      {"id": "T1583.001", "name": "Acquire Infrastructure: Domains","tactic": "Resource Development"},
    "deepfake": {"id": "T1656",   "name": "Impersonation",                  "tactic": "Defense Evasion"},
    "anomaly":  {"id": "T1078",   "name": "Valid Accounts",                 "tactic": "Persistence"},
    "injection":{"id": "T1059",   "name": "Command and Scripting Interpreter","tactic": "Execution"},
}


def map_to_mitre(active_detectors: list) -> list:
    results = []
    for det in active_detectors:
        if det in MITRE_MAP:
            entry = MITRE_MAP[det]
            results.append(f"{entry['id']} — {entry['name']} ({entry['tactic']})")
    return results if results else ["T1000 — Unknown Threat"]
