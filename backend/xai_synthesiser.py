"""
XAI Synthesiser — generates human-readable explanations for detections.
Uses GPT-4o-mini for natural language briefs; template fallback if API unavailable.
"""

import os
import json
import requests

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

SEVERITY_DESCRIPTIONS = {
    "Critical":          "This input exhibits strong indicators of a malicious cyber threat.",
    "Likely Malicious":  "This input has multiple characteristics commonly associated with cyber attacks.",
    "Suspicious":        "This input contains some unusual patterns that warrant caution.",
    "Clean":             "No significant threat indicators were found in this input.",
}

ACTION_TEMPLATES = {
    "nlp":      "The text contains persuasive or deceptive language patterns consistent with phishing.",
    "url":      "The URL has structural characteristics associated with malicious domains.",
    "deepfake": "The media shows artifacts consistent with AI-generated or manipulated content.",
    "anomaly":  "The behaviour pattern deviates significantly from normal user activity.",
}


class XAISynthesiser:

    def explain(self, input_content: str, detector_results: dict, fusion_result: dict) -> dict:
        """
        Generates a structured explanation combining:
        - Per-module evidence summaries
        - An LLM-generated (or template) natural language brief
        """
        evidence = self._build_evidence(detector_results)
        brief = self._generate_brief(input_content, detector_results, fusion_result, evidence)

        return {
            "brief": brief,
            "evidence": evidence,
        }

    def _build_evidence(self, detector_results: dict) -> dict:
        evidence = {}

        for name, result in detector_results.items():
            if "error" in result or result.get("score", 0) < 0.1:
                continue

            entry = {
                "score_percent": int(result.get("score", 0) * 100),
                "confidence_percent": int(result.get("confidence", 0) * 100),
            }

            if name == "nlp":
                entry["top_tokens"] = result.get("top_tokens", [])
                entry["urgency_score"] = result.get("urgency_score", 0)
                entry["header_evidence"] = result.get("header_evidence", {})
                entry["matched_patterns"] = result.get("matched_patterns", [])

            elif name == "url":
                entry["top_risk_signals"] = result.get("top_risk_signals", [])
                entry["features"] = {
                    k: v for k, v in result.get("features", {}).items()
                    if k in ("url_length", "subdomain_depth", "path_entropy",
                             "tld_risk", "has_ip_address", "suspicious_keyword")
                }

            elif name == "anomaly":
                entry["deviation_summary"] = result.get("deviation_summary", [])

            elif name == "deepfake":
                entry["frame_score"] = result.get("frame_score", 0)
                entry["audio_score"] = result.get("audio_score", 0)

            evidence[name] = entry

        return evidence

    def _generate_brief(self, content: str, detector_results: dict,
                        fusion_result: dict, evidence: dict) -> str:
        """Try LLM; fall back to template if API unavailable."""
        if OPENAI_API_KEY:
            llm_brief = self._call_openai(content, fusion_result, evidence)
            if llm_brief:
                return llm_brief

        return self._template_brief(fusion_result, evidence)

    def _call_openai(self, content: str, fusion_result: dict, evidence: dict) -> str | None:
        try:
            evidence_text = json.dumps(evidence, indent=2)
            prompt = f"""You are a cybersecurity analyst explaining a threat detection to a non-technical user.

Risk Score: {fusion_result['risk_score']}/100 ({fusion_result['severity']})
Detectors triggered: {', '.join(fusion_result['active_detectors'])}
Evidence summary:
{evidence_text}

Write exactly 3 sentences:
1. What was detected and how serious it is.
2. The most important technical evidence (in plain language).
3. What the user should do right now.

Use simple, clear language. Do not use jargon."""

            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}",
                         "Content-Type": "application/json"},
                json={
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 200,
                    "temperature": 0.3,
                },
                timeout=6
            )
            if response.status_code == 200:
                return response.json()["choices"][0]["message"]["content"].strip()
        except Exception:
            pass
        return None

    def _template_brief(self, fusion_result: dict, evidence: dict) -> str:
        severity = fusion_result.get("severity", "Unknown")
        score = fusion_result.get("risk_score", 0)
        active = fusion_result.get("active_detectors", [])

        sentence1 = SEVERITY_DESCRIPTIONS.get(severity, "Analysis complete.")

        signals = []
        for det in active:
            if det in evidence:
                if det == "nlp" and evidence[det].get("top_tokens"):
                    signals.append(f"suspicious language ({', '.join(evidence[det]['top_tokens'][:3])})")
                elif det == "url" and evidence[det].get("top_risk_signals"):
                    signals.append(evidence[det]["top_risk_signals"][0].lower())
                elif det == "anomaly" and evidence[det].get("deviation_summary"):
                    signals.append(evidence[det]["deviation_summary"][0].lower())

        sentence2 = f"Key indicators: {'; '.join(signals)}." if signals else \
                    f"The system assigned a risk score of {score}/100 based on {len(active)} detection module(s)."

        if score >= 81:
            sentence3 = "Do not interact with this content. Report it to your security team immediately."
        elif score >= 61:
            sentence3 = "Exercise extreme caution. Verify the source independently before taking any action."
        elif score >= 31:
            sentence3 = "Proceed with caution and verify the legitimacy of this content before engaging."
        else:
            sentence3 = "No immediate action required, but remain vigilant."

        return f"{sentence1} {sentence2} {sentence3}"
