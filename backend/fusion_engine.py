"""
Fusion Engine — combines detector outputs into a single composite risk score.
Formula: R = Σ(wᵢ × scoreᵢ × confᵢ) × co_occurrence_multiplier
"""

WEIGHTS = {
    "nlp":      0.35,
    "url":      0.30,
    "deepfake": 0.20,
    "anomaly":  0.15,
}

SEVERITY_BANDS = [
    (81, 100, "Critical"),
    (61, 80,  "Likely Malicious"),
    (31, 60,  "Suspicious"),
    (0,  30,  "Clean"),
]


class FusionEngine:

    def fuse(self, detector_results: dict) -> dict:
        """
        Accepts a dict of {detector_name: {score, confidence, ...}}
        Returns composite risk score and severity band.
        """
        if not detector_results:
            return {"risk_score": 0, "severity": "Clean", "active_detectors": []}

        weighted_sum = 0.0
        total_weight = 0.0
        active_detectors = []

        for name, result in detector_results.items():
            if "error" in result:
                continue
            score = result.get("score", 0.0)
            confidence = result.get("confidence", 1.0)
            weight = WEIGHTS.get(name, 0.1)

            # Low-confidence predictions contribute at half weight
            effective_confidence = confidence if confidence >= 0.6 else confidence * 0.5

            weighted_sum += weight * score * effective_confidence
            total_weight += weight

            if score > 0.3:
                active_detectors.append(name)

        if total_weight == 0:
            raw_score = 0.0
        else:
            raw_score = weighted_sum / total_weight

        # Co-occurrence multiplier
        multiplier = self._co_occurrence_multiplier(active_detectors)
        final_score = min(100, int(raw_score * 100 * multiplier))

        severity = self._get_severity(final_score)

        return {
            "risk_score": final_score,
            "severity": severity,
            "active_detectors": active_detectors,
            "raw_weighted_score": round(raw_score, 4),
            "co_occurrence_multiplier": multiplier,
        }

    def _co_occurrence_multiplier(self, active: list) -> float:
        if len(active) >= 3:
            return 1.8
        if "nlp" in active and "url" in active:
            return 1.5
        return 1.0

    def _get_severity(self, score: int) -> str:
        for lo, hi, label in SEVERITY_BANDS:
            if lo <= score <= hi:
                return label
        return "Clean"
