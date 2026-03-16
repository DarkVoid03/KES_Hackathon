"""
SentinelAI — main.py
FastAPI application entry point.
"""

import uuid
import asyncio
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from orchestrator import Orchestrator
from fusion_engine import FusionEngine
from xai_synthesiser import XAISynthesiser
from utils.mitre_mapper import map_mitre_tactic
from utils.response_generator import recommend_action

# ── App init ──────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SentinelAI",
    description="Hybrid multi-threat cyber defense platform",
    version="0.1.0",
)

# ── CORS — allow all origins for hackathon ────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Singletons ────────────────────────────────────────────────────────────────
orchestrator = Orchestrator()
fusion = FusionEngine()
xai = XAISynthesiser()

# ── In-memory incident log (swap for DB later) ────────────────────────────────
incident_log: list[dict] = []


# ── Request / Response schemas ────────────────────────────────────────────────
class AnalyseRequest(BaseModel):
    type: str                        # "email" | "url" | "prompt" | "text"
    content: str
    metadata: Optional[dict] = {}


class URLRequest(BaseModel):
    url: str
    metadata: Optional[dict] = {}


class FeedbackRequest(BaseModel):
    verdict: str                     # "true_positive" | "false_positive" | "escalate"
    analyst_note: Optional[str] = ""


# ── Shared analysis pipeline ──────────────────────────────────────────────────
async def run_analysis(input_type: str, content: str, metadata: dict) -> dict:
    incident_id = str(uuid.uuid4())[:8].upper()
    timestamp = datetime.now(timezone.utc).isoformat()

    # 1. Orchestrate — parallel detector dispatch
    detector_results = await orchestrator.dispatch(input_type, content, metadata)

    # 2. Fuse — weighted risk aggregation
    fusion_result = fusion.aggregate(detector_results)

    # 3. XAI — evidence cards + threat brief
    evidence = xai.build_evidence_cards(detector_results)
    threat_brief = await xai.generate_brief(
        input_type, fusion_result, evidence, content
    )

    # 4. MITRE + recommended action
    mitre_tactic = map_mitre_tactic(detector_results, fusion_result)
    recommended_action = recommend_action(fusion_result["severity"])

    response = {
        "incident_id": incident_id,
        "timestamp": timestamp,
        "risk_score": fusion_result["risk_score"],
        "severity": fusion_result["severity"],
        "detectors_triggered": fusion_result["active_detectors"],
        "threat_brief": threat_brief,
        "evidence": evidence,
        "mitre_tactic": mitre_tactic,
        "recommended_action": recommended_action,
        # Internal — not exposed to frontend but stored in log
        "_detector_raw": detector_results,
        "_fusion_detail": fusion_result,
    }

    # Store in incident log
    incident_log.append(response)
    return response


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "0.1.0",
    }


@app.post("/analyse")
async def analyse(req: AnalyseRequest):
    return await run_analysis(req.type, req.content, req.metadata or {})


@app.post("/analyse/url")
async def analyse_url(req: URLRequest):
    return await run_analysis("url", req.url, req.metadata or {})


@app.post("/analyse/file")
async def analyse_file(file: UploadFile = File(...)):
    if not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported.")
    raw = await file.read()
    content = raw.decode("utf-8", errors="ignore")
    return await run_analysis("email", content, {"filename": file.filename})


@app.get("/incidents")
async def get_incidents():
    # Strip internal keys before returning
    clean = [
        {k: v for k, v in inc.items() if not k.startswith("_")}
        for inc in incident_log
    ]
    return {"total": len(clean), "incidents": clean}


@app.post("/feedback/{incident_id}")
async def post_feedback(incident_id: str, feedback: FeedbackRequest):
    match = next(
        (inc for inc in incident_log if inc.get("incident_id") == incident_id),
        None,
    )
    if not match:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")
    match["_feedback"] = {
        "verdict": feedback.verdict,
        "analyst_note": feedback.analyst_note,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }
    return {"status": "accepted", "incident_id": incident_id}


# ── MOCK endpoint — unblocks Person 3 immediately ────────────────────────────
@app.post("/analyse/mock")
async def analyse_mock():
    """
    Returns hardcoded realistic JSON so the frontend team can build
    the UI without waiting for real models. Shape is identical to /analyse.
    """
    await asyncio.sleep(0.4)   # Simulate realistic latency
    return {
        "incident_id": "A3F9C1B2",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_score": 87,
        "severity": "CRITICAL",
        "detectors_triggered": ["nlp_detector", "url_detector", "anomaly_detector"],
        "threat_brief": (
            "This email exhibits strong indicators of a spear-phishing campaign "
            "targeting credential harvesting. The embedded URL resolves to a newly "
            "registered domain mimicking a corporate login portal. Immediate quarantine "
            "and user notification are advised."
        ),
        "evidence": [
            {
                "module": "nlp_detector",
                "score": 0.91,
                "confidence": 0.88,
                "flags": ["urgency_language", "authority_impersonation", "credential_request"],
                "top_tokens": ["verify your account", "immediate action", "suspended"],
            },
            {
                "module": "url_detector",
                "score": 0.84,
                "confidence": 0.92,
                "flags": ["newly_registered_domain", "lookalike_domain", "no_https"],
                "urls_analysed": ["http://secure-login-corporate.xyz/auth"],
            },
            {
                "module": "anomaly_detector",
                "score": 0.72,
                "confidence": 0.79,
                "flags": ["off_hours_send", "unusual_sender_domain"],
                "anomaly_type": "behavioral",
            },
        ],
        "mitre_tactic": {
            "tactic": "Initial Access",
            "technique": "T1566.001",
            "technique_name": "Spearphishing Attachment",
            "url": "https://attack.mitre.org/techniques/T1566/001/",
        },
        "recommended_action": "Quarantine email, block sender domain, notify user, escalate to SOC Tier 2.",
    }