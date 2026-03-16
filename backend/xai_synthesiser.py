"""
SentinelAI — xai_synthesiser.py
Builds per-module evidence cards and generates a plain-English threat brief.
Uses GPT-4o-mini if OPENAI_API_KEY is set; otherwise falls back to a template.
"""

import os
import asyncio
import requests
from typing import Any

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_URL = "https://api.openai.com/v1/chat/completions"


class XAISynthesiser:

    def build_evidence_cards(self, detector_results: dict[str, Any]) -> list[dict]:
        """
        Converts raw detector output dicts into clean evidence cards for the frontend.
        Each card is guaranteed to have: module, score, confidence, flags.
        Extra keys are passed through as-is.
        """
        cards = []
        for module, result in detector_results.items():
            if result.get("stub"):
                # Don't surface stub results as evidence
                continue

            card = {
                "module": module,
                "score": round(float(result.get("score", 0.0)), 4),
                "confidence": round(float(result.get("confidence", 0.0)), 4),
                "flags": result.get("flags", []),
            }

            # Pass through any extra keys the detector returns
            for key in result:
                if key not in ("score", "confidence", "flags", "stub", "module"):
                    card[key] = result[key]

            cards.append(card)

        # Sort highest-score first
        cards.sort(key=lambda c: c["score"], reverse=True)
        return cards

    async def generate_brief(
        self,
        input_type: str,
        fusion_result: dict,
        evidence: list[dict],
        content_preview: str = "",
    ) -> str:
        """
        Returns a 3-sentence plain-English threat brief.
        Tries GPT-4o-mini first; falls back to template on any failure.
        """
        if OPENAI_API_KEY:
            try:
                brief = await asyncio.to_thread(
                    self._call_openai, input_type, fusion_result, evidence, content_preview
                )
                if brief:
                    return brief
            except Exception as e:
                print(f"[xai] OpenAI call failed: {e} — using template fallback")

        return self._template_brief(input_type, fusion_result, evidence)

    # ── OpenAI call (sync, runs in thread) ───────────────────────────────────

    def _call_openai(
        self,
        input_type: str,
        fusion_result: dict,
        evidence: list[dict],
        content_preview: str,
    ) -> str:
        severity = fusion_result["severity"]
        risk_score = fusion_result["risk_score"]
        active = ", ".join(fusion_result["active_detectors"]) or "none"
        flags = []
        for card in evidence:
            flags.extend(card.get("flags", []))
        flags_str = ", ".join(set(flags)) or "none detected"

        prompt = (
            f"You are a senior SOC analyst writing a concise threat brief.\n"
            f"Input type: {input_type}\n"
            f"Risk score: {risk_score}/100  Severity: {severity}\n"
            f"Detectors triggered: {active}\n"
            f"Top signal flags: {flags_str}\n"
            f"Content preview (first 300 chars): {content_preview[:300]}\n\n"
            f"Write exactly 3 sentences in plain English:\n"
            f"1. What was detected and why it is suspicious.\n"
            f"2. The likely attacker intent or technique.\n"
            f"3. The immediate recommended response.\n"
            f"Do not use bullet points or headers."
        )

        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 200,
            "temperature": 0.3,
        }
        resp = requests.post(OPENAI_URL, headers=headers, json=payload, timeout=10)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()

    # ── Template fallback ─────────────────────────────────────────────────────

    @staticmethod
    def _template_brief(
        input_type: str,
        fusion_result: dict,
        evidence: list[dict],
    ) -> str:
        severity = fusion_result["severity"]
        risk_score = fusion_result["risk_score"]
        active = fusion_result["active_detectors"]

        # Collect top flags across all modules
        all_flags: list[str] = []
        for card in evidence:
            all_flags.extend(card.get("flags", []))
        top_flags = list(dict.fromkeys(all_flags))[:3]  # deduplicate, keep order
        flags_text = (
            f"Key signals include: {', '.join(top_flags)}." if top_flags
            else "No specific flags were surfaced."
        )

        modules_text = (
            f"{', '.join(active)} detector(s) triggered"
            if active
            else "No detectors triggered"
        )

        severity_action = {
            "CRITICAL": "Immediate quarantine and SOC Tier 2 escalation are required.",
            "HIGH":     "Quarantine the content and notify the affected user promptly.",
            "MEDIUM":   "Flag for analyst review and monitor for follow-on activity.",
            "LOW":      "Log the event and continue passive monitoring.",
            "INFO":     "No immediate action required; retain for audit purposes.",
        }

        action = severity_action.get(severity, "Review and assess manually.")

        return (
            f"Analysis of this {input_type} input produced a risk score of {risk_score}/100 "
            f"({severity}), with {modules_text}. "
            f"{flags_text} "
            f"{action}"
        )