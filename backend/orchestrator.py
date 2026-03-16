"""
Orchestrator — detects input type and fans out to relevant detectors in parallel.
"""

import asyncio
from detectors.nlp_detector import NLPDetector
from detectors.url_detector import URLDetector
from detectors.anomaly_detector import AnomalyDetector

# Lazy-load deepfake detector (heavy model) only if needed
_deepfake_detector = None


def _get_deepfake_detector():
    global _deepfake_detector
    if _deepfake_detector is None:
        from detectors.deepfake_detector import DeepfakeDetector
        _deepfake_detector = DeepfakeDetector()
    return _deepfake_detector


class Orchestrator:
    def __init__(self):
        self.nlp = NLPDetector()
        self.url = URLDetector()
        self.anomaly = AnomalyDetector()

    async def dispatch(self, input_type: str, content: str, metadata: dict) -> dict:
        """
        Determines which detectors to invoke and runs them concurrently.
        Returns a dict of detector name -> result.
        """
        tasks = {}

        if input_type in ("email", "text"):
            tasks["nlp"] = self._run_nlp(content, metadata)
            # Also check for embedded URLs in email body
            urls = self._extract_urls(content)
            if urls:
                tasks["url"] = self._run_url(urls[0])   # Analyse first URL found

        elif input_type == "url":
            tasks["url"] = self._run_url(content)

        elif input_type == "prompt":
            tasks["nlp"] = self._run_nlp(content, metadata, mode="injection")

        # Run all tasks concurrently
        results = {}
        if tasks:
            completed = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for key, result in zip(tasks.keys(), completed):
                if isinstance(result, Exception):
                    results[key] = {"score": 0.0, "error": str(result)}
                else:
                    results[key] = result

        return results

    async def _run_nlp(self, content: str, metadata: dict, mode: str = "phishing") -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.nlp.predict, content, metadata, mode)

    async def _run_url(self, url: str) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.url.predict, url)

    async def _run_anomaly(self, log_data: list) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.anomaly.predict, log_data)

    def _extract_urls(self, text: str) -> list:
        """Simple URL extractor — replace with regex in production."""
        import re
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)
