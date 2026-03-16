"""
SentinelAI — Hybrid Multi-Threat Cyber Defense Platform
FastAPI Backend Entry Point
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Literal
import uvicorn
import uuid
from datetime import datetime

from orchestrator import Orchestrator
from fusion_engine import FusionEngine
from xai_synthesiser import XAISynthesiser
from utils.response_generator import build_recommendation
from utils.mitre_mapper import map_to_mitre

# ── App Setup ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="SentinelAI API",
    description="Hybrid Multi-Threat Cyber Defense Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # Tighten in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory incident log (replace with SQLite for persistence)
incident_log = []

# Singletons — loaded once at startup
orchestrator = Orchestrator()
fusion_engine = FusionEngine()
xai_synthesiser = XAISynthesiser()


# ── Pydantic Models ────────────────────────────────────────────────────────
class AnalyseRequest(BaseModel):
    type: Literal["email", "url", "prompt", "text"]
    content: str
    metadata: Optional[dict] = None   # e.g. {"sender": "...", "subject": "..."}


class FeedbackRequest(BaseModel):
    verdict: Literal["true_positive", "false_positive"]
    analyst_note: Optional[str] = None


# ── Endpoints ──────────────────────────────────────────────────────────────
@app.get("/health")
def health_check():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.post("/analyse")
async def analyse(req: AnalyseRequest):
    """
    Main analysis endpoint.
    Accepts email/URL/prompt text and returns full threat analysis with XAI.
    """
    try:
        # 1. Route input to relevant detectors
        detector_results = await orchestrator.dispatch(
            input_type=req.type,
            content=req.content,
            metadata=req.metadata or {}
        )

        # 2. Fuse results into composite risk score
        fusion_result = fusion_engine.fuse(detector_results)

        # 3. Generate explanation
        explanation = xai_synthesiser.explain(
            input_content=req.content,
            detector_results=detector_results,
            fusion_result=fusion_result
        )

        # 4. Map to MITRE ATT&CK and build action recommendation
        mitre = map_to_mitre(fusion_result["active_detectors"])
        action = build_recommendation(fusion_result["severity"], fusion_result["active_detectors"])

        # 5. Build response and log incident
        incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:4].upper()}"
        response = {
            "incident_id": incident_id,
            "timestamp": datetime.utcnow().isoformat(),
            "risk_score": fusion_result["risk_score"],
            "severity": fusion_result["severity"],
            "detectors_triggered": fusion_result["active_detectors"],
            "threat_brief": explanation["brief"],
            "evidence": explanation["evidence"],
            "mitre_tactic": mitre,
            "recommended_action": action,
        }
        incident_log.append({**response, "input_type": req.type, "analyst_verdict": None})

        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyse/url")
async def analyse_url(url: str):
    """Shortcut endpoint for direct URL analysis."""
    return await analyse(AnalyseRequest(type="url", content=url))


@app.post("/analyse/file")
async def analyse_file(file: UploadFile = File(...)):
    """
    File upload endpoint — handles .eml email files.
    Reads file content and routes to /analyse.
    """
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    return await analyse(AnalyseRequest(type="email", content=text))


@app.get("/incidents")
def get_incidents(limit: int = 50):
    """Returns the last N incidents from the log."""
    return {"incidents": incident_log[-limit:][::-1]}


@app.post("/feedback/{incident_id}")
def submit_feedback(incident_id: str, req: FeedbackRequest):
    """Analyst feedback for active learning loop."""
    for inc in incident_log:
        if inc["incident_id"] == incident_id:
            inc["analyst_verdict"] = req.verdict
            inc["analyst_note"] = req.analyst_note
            return {"status": "updated", "incident_id": incident_id}
    raise HTTPException(status_code=404, detail="Incident not found")


# ── Dev Entry Point ────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
