"""
URL Detector — Lexical feature extraction + LightGBM classifier.
Falls back to rule-based scoring if no trained model is found.
"""

import re
import math
import os
import joblib
import numpy as np
from urllib.parse import urlparse

# High-risk TLDs frequently abused by attackers
HIGH_RISK_TLDS = {
    ".xyz", ".top", ".club", ".online", ".site", ".icu", ".buzz",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".rest"
}

# Suspicious keywords commonly seen in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "verify", "account", "update", "confirm",
    "banking", "paypal", "amazon", "apple", "microsoft", "google",
    "signin", "password", "credential", "support", "help-center"
]


class URLDetector:

    def __init__(self):
        self._model = None
        model_path = "models/url_lgbm.pkl"
        if os.path.exists(model_path):
            self._model = joblib.load(model_path)

    def predict(self, url: str) -> dict:
        features = self.extract_features(url)
        feature_vector = list(features.values())

        if self._model:
            prob = float(self._model.predict_proba([feature_vector])[0][1])
            confidence = 0.88
        else:
            prob = self._rule_based_score(features)
            confidence = 0.65

        return {
            "score": prob,
            "confidence": confidence,
            "features": features,
            "top_risk_signals": self._top_signals(features),
            "detector": "url_lexical",
        }

    # ── Feature Extraction ─────────────────────────────────────────────────
    def extract_features(self, url: str) -> dict:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        full = url.lower()

        return {
            "url_length":          len(url),
            "hostname_length":     len(hostname),
            "path_length":         len(path),
            "num_dots":            url.count("."),
            "num_hyphens":         url.count("-"),
            "num_digits":          sum(c.isdigit() for c in url),
            "num_special_chars":   sum(not c.isalnum() and c not in "/:.-_" for c in url),
            "has_at_symbol":       int("@" in url),
            "has_double_slash":    int("//" in path),
            "has_ip_address":      int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', hostname))),
            "subdomain_depth":     max(0, len(hostname.split(".")) - 2),
            "path_entropy":        self._entropy(path),
            "hostname_entropy":    self._entropy(hostname),
            "url_entropy":         self._entropy(url),
            "digit_ratio":         sum(c.isdigit() for c in url) / max(len(url), 1),
            "is_https":            int(url.startswith("https")),
            "tld_risk":            self._tld_risk(hostname),
            "suspicious_keyword":  int(any(kw in full for kw in SUSPICIOUS_KEYWORDS)),
            "has_hex_chars":       int(bool(re.search(r'%[0-9a-fA-F]{2}', url))),
            "num_query_params":    len(parsed.query.split("&")) if parsed.query else 0,
        }

    def _entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        return round(-sum(f/len(s) * math.log2(f/len(s)) for f in freq.values()), 3)

    def _tld_risk(self, hostname: str) -> int:
        for tld in HIGH_RISK_TLDS:
            if hostname.endswith(tld):
                return 1
        return 0

    def _rule_based_score(self, features: dict) -> float:
        score = 0.0
        if features["url_length"] > 75:           score += 0.10
        if features["num_dots"] > 4:              score += 0.10
        if features["has_ip_address"]:            score += 0.20
        if features["tld_risk"]:                  score += 0.20
        if features["suspicious_keyword"]:        score += 0.15
        if features["path_entropy"] > 3.5:        score += 0.10
        if features["subdomain_depth"] > 2:       score += 0.10
        if features["has_at_symbol"]:             score += 0.15
        if features["digit_ratio"] > 0.2:         score += 0.10
        return min(score, 0.95)

    def _top_signals(self, features: dict) -> list:
        """Return top 5 features that indicate maliciousness."""
        signals = []
        if features["has_ip_address"]:         signals.append("IP address used as hostname")
        if features["tld_risk"]:               signals.append("High-risk TLD detected")
        if features["suspicious_keyword"]:     signals.append("Suspicious brand keyword in URL")
        if features["url_entropy"] > 4.0:      signals.append(f"High URL entropy: {features['url_entropy']}")
        if features["num_dots"] > 4:           signals.append(f"Excessive subdomains: {features['subdomain_depth']}")
        if features["has_at_symbol"]:          signals.append("@ symbol used to mask real hostname")
        if features["url_length"] > 75:        signals.append(f"Abnormally long URL: {features['url_length']} chars")
        return signals[:5]
