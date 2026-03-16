"""
NLP Detector — Phishing email & prompt injection classifier.
Uses RoBERTa-base via HuggingFace Inference API (no local GPU required).
Falls back to a TF-IDF + LightGBM model if API is unavailable.
"""

import os
import re
import requests
import lightgbm as lgb
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib

HF_API_URL = "https://api-inference.huggingface.co/models/ealvaradob/bert-finetuned-phishing"
HF_TOKEN = os.getenv("HF_TOKEN", "")

# Urgency / social-engineering signal words
URGENCY_WORDS = [
    "urgent", "immediately", "suspended", "verify", "confirm", "expire",
    "limited", "action required", "click here", "act now", "account locked",
    "unusual activity", "security alert", "password", "update your"
]

# Known prompt injection patterns
INJECTION_PATTERNS = [
    r"ignore (previous|all|above) instructions",
    r"disregard (your|the) (system|previous)",
    r"you are now",
    r"act as (a|an)",
    r"new instructions:",
    r"forget (everything|what)",
    r"do not follow",
    r"override (your|the)",
    r"jailbreak",
    r"DAN mode",
]


class NLPDetector:

    def __init__(self):
        self._fallback_model = None
        self._fallback_vectorizer = None
        self._load_fallback()

    def _load_fallback(self):
        """Load fallback TF-IDF + LightGBM model if saved artefact exists."""
        model_path = "models/nlp_fallback.pkl"
        vec_path = "models/nlp_vectorizer.pkl"
        if os.path.exists(model_path) and os.path.exists(vec_path):
            self._fallback_model = joblib.load(model_path)
            self._fallback_vectorizer = joblib.load(vec_path)

    def predict(self, content: str, metadata: dict, mode: str = "phishing") -> dict:
        if mode == "injection":
            return self._detect_injection(content)
        return self._detect_phishing(content, metadata)

    # ── Phishing Detection ─────────────────────────────────────────────────
    def _detect_phishing(self, content: str, metadata: dict) -> dict:
        # Try HuggingFace API first
        hf_result = self._call_hf_api(content)

        if hf_result:
            score = hf_result["score"]
            confidence = min(hf_result["score"] + 0.05, 1.0)
        elif self._fallback_model:
            score = self._fallback_predict(content)
            confidence = 0.75
        else:
            # Rule-based fallback (always works)
            score = self._rule_based_score(content)
            confidence = 0.6

        top_tokens = self._extract_suspicious_tokens(content)
        header_evidence = self._analyse_headers(metadata)
        urgency_score = self._urgency_score(content)

        return {
            "score": score,
            "confidence": confidence,
            "top_tokens": top_tokens,
            "urgency_score": urgency_score,
            "header_evidence": header_evidence,
            "detector": "nlp_phishing",
        }

    def _call_hf_api(self, text: str) -> dict | None:
        """Call HuggingFace Inference API for phishing classification."""
        if not HF_TOKEN:
            return None
        try:
            headers = {"Authorization": f"Bearer {HF_TOKEN}"}
            payload = {"inputs": text[:512]}   # Truncate for API limit
            response = requests.post(HF_API_URL, headers=headers, json=payload, timeout=5)
            if response.status_code == 200:
                results = response.json()
                if isinstance(results, list) and len(results) > 0:
                    # Find the phishing/malicious label
                    for item in results[0]:
                        if item["label"].lower() in ("phishing", "malicious", "label_1", "1"):
                            return {"score": item["score"]}
        except Exception:
            pass
        return None

    def _fallback_predict(self, content: str) -> float:
        vec = self._fallback_vectorizer.transform([content])
        prob = self._fallback_model.predict_proba(vec)[0][1]
        return float(prob)

    def _rule_based_score(self, content: str) -> float:
        """Simple heuristic scoring — always available as last resort."""
        lower = content.lower()
        score = 0.0
        matched = sum(1 for w in URGENCY_WORDS if w in lower)
        score += min(matched * 0.08, 0.5)
        if re.search(r'https?://[^\s]+', content):
            score += 0.1
        if re.search(r'[0-9a-zA-Z]{20,}', content):
            score += 0.05
        return min(score, 0.95)

    def _extract_suspicious_tokens(self, content: str) -> list:
        lower = content.lower()
        return [w for w in URGENCY_WORDS if w in lower][:8]

    def _urgency_score(self, content: str) -> float:
        lower = content.lower()
        matches = sum(1 for w in URGENCY_WORDS if w in lower)
        return round(min(matches / 5.0, 1.0), 2)

    def _analyse_headers(self, metadata: dict) -> dict:
        """Parse SPF/DKIM/DMARC signals from email metadata."""
        return {
            "spf": metadata.get("spf", "unknown"),
            "dkim": metadata.get("dkim", "unknown"),
            "dmarc": metadata.get("dmarc", "unknown"),
            "sender_domain_age": metadata.get("sender_domain_age", "unknown"),
        }

    # ── Prompt Injection Detection ─────────────────────────────────────────
    def _detect_injection(self, content: str) -> dict:
        lower = content.lower()
        matched_patterns = []
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, lower):
                matched_patterns.append(pattern)

        base_score = min(len(matched_patterns) * 0.25, 0.95)
        confidence = 0.85 if matched_patterns else 0.6

        return {
            "score": base_score,
            "confidence": confidence,
            "matched_patterns": matched_patterns,
            "pattern_count": len(matched_patterns),
            "detector": "nlp_injection",
        }
