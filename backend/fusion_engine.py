"""
SentinelAI — fusion_engine.py
Weighted risk aggregation with co-occurrence multiplier.

Formula: R = Σ(wᵢ × scoreᵢ × confᵢ) × co_occurrence_multiplier
Weights:  nlp=0.35, url=0.30, deepfake=0.20, anomaly=0.15
Co-occurrence:
    1.5× if nlp + url both trigger
    1.8× if 3+ modules trigger
"""

from typing import Any

# Module weights (must sum to 1.0)
WEIGHTS: dict[str, float] = {
    "nlp_detector": 0.35,
    "url_detector": 0.30,
    "deepfake_detector": 0.20,
    "anomaly_detector": 0.15,
}

# Trigger threshold — score above this counts as "triggered"
TRIGGER_THRESHOLD = 0.40

# Severity bands
SEVERITY_BANDS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0,  "INFO"),
]


class FusionEngine:

    def aggregate(self, detector_results: dict[str, Any]) -> dict:
        """
        Accepts the orchestrator output dict and returns:
        {
            "risk_score": int (0-100),
            "severity": str,
            "active_detectors": list[str],
            "raw_weighted_sum": float,
            "multiplier": float,
            "per_module": dict
        }
        """
        weighted_sum = 0.0
        per_module: dict[str, dict] = {}
        active_detectors: list[str] = []

        for module, result in detector_results.items():
            score = float(result.get("score", 0.0))
            confidence = float(result.get("confidence", 0.0))
            weight = WEIGHTS.get(module, 0.10)   # fallback weight for unknown modules

            contribution = weight * score * confidence
            weighted_sum += contribution

            per_module[module] = {
                "score": round(score, 4),
                "confidence": round(confidence, 4),
                "weight": weight,
                "contribution": round(contribution, 4),
                "triggered": score >= TRIGGER_THRESHOLD,
            }

            if score >= TRIGGER_THRESHOLD:
                active_detectors.append(module)

        # Co-occurrence multiplier
        multiplier = self._co_occurrence_multiplier(active_detectors)

        raw_risk = weighted_sum * multiplier
        risk_score = min(100, int(round(raw_risk * 100)))

        severity = self._severity(risk_score)

        return {
            "risk_score": risk_score,
            "severity": severity,
            "active_detectors": active_detectors,
            "raw_weighted_sum": round(weighted_sum, 4),
            "multiplier": multiplier,
            "per_module": per_module,
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _co_occurrence_multiplier(active: list[str]) -> float:
        nlp_on = "nlp_detector" in active
        url_on = "url_detector" in active
        if len(active) >= 3:
            return 1.8
        if nlp_on and url_on:
            return 1.5
        return 1.0

    @staticmethod
    def _severity(score: int) -> str:
        for threshold, label in SEVERITY_BANDS:
            if score >= threshold:
                return label
        return "INFO"