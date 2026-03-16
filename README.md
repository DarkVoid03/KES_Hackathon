# 🛡️ SentinelAI — Hybrid Multi-Threat Cyber Defense Platform

> **IndiaNext Hackathon 2026 · K.E.S. Shroff College, Mumbai · March 16–17, 2026**

---

## What Is SentinelAI?

SentinelAI is a unified cybersecurity platform that uses multiple AI/ML models working together to detect, analyse, and **explain** modern cyber threats in real time. It does not just tell you something is dangerous — it shows you *why*, using plain language any user can understand.

The platform covers six of the most critical AI-driven threat categories of 2026:

| Threat | What It Detects |
|--------|----------------|
| 📧 Phishing Email / Message | Credential-harvesting emails, urgency manipulation, spoofed senders |
| 🔗 Malicious URL | Suspicious links, newly registered domains, C2 infrastructure |
| 🎭 Deepfake Audio / Video | Synthetic faces, voice clones, lip-sync anomalies |
| 💉 Prompt Injection | Adversarial instructions hidden in AI system inputs |
| 👤 Behaviour Anomaly | Unusual login patterns, insider threats, compromised accounts |
| 🤖 AI-Generated Content | LLM-generated disinformation, synthetic scam content |

---

## Why SentinelAI Exists

Cyber attackers today use the same AI tools that defenders use. A phishing email written by an LLM has no grammar mistakes. A deepfake video of a CEO is indistinguishable to the human eye. Prompt injection attacks silently hijack AI agents. Traditional security tools, built on keyword matching and known signatures, cannot keep up.

SentinelAI fights AI-driven attacks with AI-driven defence. More importantly, it solves the trust problem: every detection comes with a clear explanation — what was found, why it matters, how confident the system is, and what to do next.

---

## How It Works — The Big Picture

```
User submits input (email / URL / video / log / prompt)
              ↓
        API Gateway
     (validates & routes)
              ↓
        Orchestrator
   (detects type, fans out)
    ↙    ↓      ↓     ↘
  NLP   URL  Deepfake  Anomaly
  Model Score Detector  Engine
    ↘    ↓      ↓     ↙
       Fusion Engine
   (combines all scores)
              ↓
      XAI Synthesiser
  (generates explanation)
              ↓
     Risk Score + Action
              ↓
      Security Dashboard
   (displays everything clearly)
```

Each detector is a specialist. The Fusion Engine is the judge. The XAI Synthesiser is the translator — it turns technical scores into plain English.

---

## Core Features

### 1. Multi-Threat Detection
A single platform handles all six threat types. Submit an email that contains a suspicious URL — the system analyses both simultaneously and combines the risk.

### 2. Explainable AI (XAI) — The Central Feature
Every detection is backed by evidence:
- **Highlighted tokens** — the exact words in an email that triggered suspicion
- **Feature importance charts** — which URL characteristics looked malicious
- **Grad-CAM heatmaps** — which region of a video frame showed deepfake artifacts
- **Natural language brief** — a 3-sentence summary any non-technical user can read

### 3. Composite Risk Scoring
Risk is not binary. SentinelAI produces a 0–100 score with four severity bands:
- 🟢 0–30: Clean
- 🟡 31–60: Suspicious
- 🟠 61–80: Likely Malicious
- 🔴 81–100: Critical — immediate action required

When multiple threats are detected together (e.g., phishing email + malicious URL in the same session), the score is boosted to reflect the coordinated nature of the attack.

### 4. Actionable Recommendations
The platform does not just flag threats — it tells the user what to do: quarantine the email, block the URL, freeze the account, trigger multi-factor authentication, or escalate to a security team.

### 5. SOC-Style Incident Dashboard
A security operations centre (SOC) style interface shows an incident queue, lets analysts mark verdicts (true/false positive), tracks alert history, and auto-generates incident reports.

---

## Technology Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| ML / NLP | PyTorch + HuggingFace Transformers | State-of-art phishing & injection detection without training from scratch |
| Tabular ML | LightGBM + scikit-learn | Fast, accurate URL scoring; natively supports SHAP explanations |
| Anomaly Detection | Isolation Forest (sklearn) | Unsupervised — no labelled anomaly data needed |
| Deepfake Detection | EfficientNet-B0 + LSTM | Pre-trained on ImageNet; fine-tuned on FaceForensics++ dataset |
| XAI | SHAP + Grad-CAM + GPT-4o-mini | Industry-standard explainability; LLM generates human-readable summaries |
| Backend | FastAPI (Python) | Async, high-performance, automatic API docs |
| Frontend | React + TailwindCSS + Recharts | Fast development; rich visualisation components |
| Deployment | Railway.app (backend) + Vercel (frontend) | Free tier; auto-deploy from GitHub; live link for judges |

---

## Project Structure

```
sentinelai/
├── backend/
│   ├── main.py                    # FastAPI app entry point
│   ├── orchestrator.py            # Input router and task dispatcher
│   ├── fusion_engine.py           # Weighted risk aggregation
│   ├── xai_synthesiser.py         # SHAP + Grad-CAM + LLM explanation
│   ├── detectors/
│   │   ├── nlp_detector.py        # Phishing / prompt injection (RoBERTa)
│   │   ├── url_detector.py        # URL scoring (LightGBM + lexical features)
│   │   ├── deepfake_detector.py   # Video/audio (EfficientNet + LSTM)
│   │   └── anomaly_detector.py    # Behaviour anomaly (Isolation Forest)
│   ├── models/                    # Saved model artefacts (.pkl, .pt)
│   ├── data/                      # Sample datasets and test fixtures
│   ├── utils/
│   │   ├── feature_extractor.py   # Shared feature engineering utilities
│   │   ├── mitre_mapper.py        # Maps threat type to MITRE ATT&CK tactic
│   │   └── response_generator.py  # Builds mitigation recommendation
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── components/
│   │   │   ├── InputPanel.jsx     # File upload / text input / URL input
│   │   │   ├── RiskGauge.jsx      # Animated 0-100 risk score gauge
│   │   │   ├── EvidenceCard.jsx   # Per-module explanation accordion
│   │   │   ├── ThreatBrief.jsx    # LLM-generated natural language summary
│   │   │   ├── IncidentLog.jsx    # SOC-style alert history table
│   │   │   └── ActionPanel.jsx    # Recommended next steps
│   │   ├── api/
│   │   │   └── sentinelApi.js     # Axios client for backend endpoints
│   │   └── index.css
│   ├── package.json
│   └── vite.config.js
├── notebooks/
│   ├── train_phishing_model.ipynb
│   ├── train_url_model.ipynb
│   └── test_xai_outputs.ipynb
├── .env.example
├── docker-compose.yml
└── README.md
```

---

## Setup & Running Locally

### Prerequisites
- Python 3.10+
- Node.js 18+
- Git

### Backend Setup
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

The app will be live at `http://localhost:5173`. The API runs at `http://localhost:8000`.

### Environment Variables
Copy `.env.example` to `.env` and fill in:
```
OPENAI_API_KEY=your_key_here       # For GPT-4o-mini XAI summaries
VIRUSTOTAL_API_KEY=your_key_here   # Optional: URL enrichment
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/analyse` | Submit any input for full threat analysis |
| POST | `/analyse/email` | Direct email analysis endpoint |
| POST | `/analyse/url` | Direct URL analysis endpoint |
| POST | `/analyse/behaviour` | Submit login log CSV for anomaly detection |
| GET | `/incidents` | Retrieve incident log |
| POST | `/feedback/{incident_id}` | Mark true/false positive |
| GET | `/health` | System health check |

### Sample Request
```json
POST /analyse
{
  "type": "email",
  "content": "Dear User, Your account has been suspended. Click here immediately: http://paypa1-secure.xyz/verify"
}
```

### Sample Response
```json
{
  "risk_score": 91,
  "severity": "Critical",
  "detectors_triggered": ["nlp", "url"],
  "threat_brief": "This email exhibits strong phishing characteristics. The sender domain does not match PayPal's official domain, and the link points to a site registered 2 days ago with high lexical entropy. Immediate deletion is recommended.",
  "evidence": {
    "nlp": {
      "score": 0.94,
      "top_tokens": ["suspended", "immediately", "verify", "paypa1"],
      "header_verdict": "SPF FAIL, DKIM missing"
    },
    "url": {
      "score": 0.89,
      "domain_age_days": 2,
      "entropy": 4.7,
      "top_features": ["digit_substitution", "low_domain_age", "high_path_entropy"]
    }
  },
  "mitre_tactic": "T1566 - Phishing",
  "recommended_action": "Delete email immediately. Do not click any links. Report to IT security team.",
  "incident_id": "INC-20260316-0042"
}
```

---

## The XAI Difference

Most security tools say: **"This is malicious."**

SentinelAI says: **"This is malicious — because the sender domain was registered 2 days ago, the email uses urgency language ('suspended', 'immediately'), the link domain substitutes '1' for 'l' in 'paypal', and the SPF record fails verification. Confidence: 94%."**

That difference is why SentinelAI exists.

---

## Dataset Credits
- PhishTank / URLHaus (abuse.ch) — URL threat intelligence
- SpamAssassin Public Corpus — phishing email samples
- FaceForensics++ — deepfake video detection
- CICIDS-2017 — network behaviour anomaly
- Deepset Prompt Injection Dataset (HuggingFace) — injection samples

---

## Team

Built at IndiaNext Hackathon 2026 | K.E.S. Shroff College, Mumbai

---

*Build something that matters. Outthink the algorithm.*
