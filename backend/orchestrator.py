"""
SentinelAI — orchestrator.py
Detects input type and dispatches to the correct detectors in parallel.
"""

import asyncio
from typing import Any

# ── Detector imports — wrapped in try/except so the app boots even if
#    Person 1's models aren't ready yet (stubs kick in automatically).
try:
    from detectors.nlp_detector import NLPDetector
    _nlp = NLPDetector()
    NLP_READY = True
except Exception as e:
    print(f"[orchestrator] nlp_detector not ready: {e}")
    NLP_READY = False

try:
    from detectors.url_detector import URLDetector
    _url = URLDetector()
    URL_READY = True
except Exception as e:
    print(f"[orchestrator] url_detector not ready: {e}")
    URL_READY = False

try:
    from detectors.anomaly_detector import AnomalyDetector
    _anomaly = AnomalyDetector()
    ANOMALY_READY = True
except Exception as e:
    print(f"[orchestrator] anomaly_detector not ready: {e}")
    ANOMALY_READY = False

try:
    from detectors.deepfake_detector import DeepfakeDetector
    _deepfake = DeepfakeDetector()
    DEEPFAKE_READY = True
except Exception as e:
    print(f"[orchestrator] deepfake_detector not ready: {e}")
    DEEPFAKE_READY = False


# ── Stub results — returned when a detector module isn't loaded ───────────────
def _stub(name: str) -> dict:
    return {
        "score": 0.0,
        "confidence": 0.0,
        "flags": [],
        "stub": True,
        "module": name,
    }


class Orchestrator:
    """
    Routes input to the correct detector(s) and gathers results in parallel.

    Integration contract (Person 1):
        nlp.predict(content, metadata, mode)  → {"score": float, "confidence": float, ...}
        url.predict(url)                       → {"score": float, "confidence": float, ...}
        anomaly.predict(log_list)              → {"score": float, "confidence": float, ...}
        deepfake.predict(content, metadata)    → {"score": float, "confidence": float, ...}
    """

    async def dispatch(
        self, input_type: str, content: str, metadata: dict
    ) -> dict[str, Any]:
        """
        Returns dict of { detector_name: result_dict }.
        Detectors run concurrently via asyncio.gather.
        """
        tasks: dict[str, Any] = {}

        if input_type in ("email", "text", "prompt"):
            tasks["nlp_detector"] = self._run_nlp(content, metadata, mode=input_type)
            tasks["anomaly_detector"] = self._run_anomaly(content, metadata)

        if input_type == "url":
            tasks["url_detector"] = self._run_url(content)
            tasks["nlp_detector"] = self._run_nlp(content, metadata, mode="url")

        if input_type == "email":
            # Emails often contain URLs — extract and scan them too
            urls = self._extract_urls(content)
            if urls:
                tasks["url_detector"] = self._run_url(urls[0])

        if input_type == "deepfake":
            tasks["deepfake_detector"] = self._run_deepfake(content, metadata)

        # Default fallback — always run NLP if nothing matched
        if not tasks:
            tasks["nlp_detector"] = self._run_nlp(content, metadata, mode="text")

        # Run all tasks in parallel
        keys = list(tasks.keys())
        results_list = await asyncio.gather(*tasks.values(), return_exceptions=True)

        results: dict[str, Any] = {}
        for key, result in zip(keys, results_list):
            if isinstance(result, Exception):
                print(f"[orchestrator] {key} raised: {result}")
                results[key] = _stub(key)
            else:
                results[key] = result

        return results

    # ── Internal runner helpers ───────────────────────────────────────────────
    # Each wraps a sync detector call in asyncio.to_thread so it doesn't
    # block the event loop. If the detector isn't loaded, return a stub.

    async def _run_nlp(self, content: str, metadata: dict, mode: str) -> dict:
        if not NLP_READY:
            return _stub("nlp_detector")
        return await asyncio.to_thread(_nlp.predict, content, metadata, mode)

    async def _run_url(self, url: str) -> dict:
        if not URL_READY:
            return _stub("url_detector")
        return await asyncio.to_thread(_url.predict, url)

    async def _run_anomaly(self, content: str, metadata: dict) -> dict:
        if not ANOMALY_READY:
            return _stub("anomaly_detector")
        log_list = metadata.get("logs", [content])
        return await asyncio.to_thread(_anomaly.predict, log_list)

    async def _run_deepfake(self, content: str, metadata: dict) -> dict:
        if not DEEPFAKE_READY:
            return _stub("deepfake_detector")
        return await asyncio.to_thread(_deepfake.predict, content, metadata)

    # ── URL extraction utility ────────────────────────────────────────────────
    @staticmethod
    def _extract_urls(text: str) -> list[str]:
        import re
        pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
        return re.findall(pattern, text)