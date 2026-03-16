// ── ThreatBrief ────────────────────────────────────────────────────────────
export function ThreatBrief({ brief, mitre }) {
    return (
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-5 space-y-3">
        <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wide">🤖 AI Threat Brief</h3>
        <p className="text-sm text-gray-200 leading-relaxed">{brief}</p>
        {mitre && mitre.length > 0 && (
          <div className="flex flex-wrap gap-2 pt-1">
            {mitre.map((t, i) => (
              <span key={i} className="bg-blue-900/40 border border-blue-700 text-blue-300 text-xs px-2 py-1 rounded">
                🎯 {t}
              </span>
            ))}
          </div>
        )}
      </div>
    );
  }
  
  // ── EvidenceCard ────────────────────────────────────────────────────────────
  import { useState } from "react";
  
  const DETECTOR_LABELS = {
    nlp:      { label: "NLP Phishing Detector",    icon: "📧" },
    url:      { label: "URL Intelligence Engine",  icon: "🔗" },
    deepfake: { label: "Deepfake Analyser",         icon: "🎭" },
    anomaly:  { label: "Behaviour Anomaly Engine",  icon: "👤" },
  };
  
  export function EvidenceCard({ evidence }) {
    const [open, setOpen] = useState(null);
  
    if (!evidence || Object.keys(evidence).length === 0) return null;
  
    return (
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-5 space-y-3">
        <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wide">🔬 Detection Evidence</h3>
        {Object.entries(evidence).map(([det, data]) => {
          const meta = DETECTOR_LABELS[det] || { label: det, icon: "⚙️" };
          const isOpen = open === det;
          return (
            <div key={det} className="border border-gray-700 rounded-lg overflow-hidden">
              <button
                onClick={() => setOpen(isOpen ? null : det)}
                className="w-full flex items-center justify-between px-4 py-3 bg-gray-800 hover:bg-gray-750 text-sm"
              >
                <span className="font-medium text-gray-200">{meta.icon} {meta.label}</span>
                <div className="flex items-center gap-3">
                  <ScoreBadge score={data.score_percent} />
                  <span className="text-gray-400 text-xs">{isOpen ? "▲" : "▼"}</span>
                </div>
              </button>
              {isOpen && (
                <div className="px-4 py-3 bg-gray-900 space-y-2 text-sm text-gray-300">
                  <p className="text-xs text-gray-500">Confidence: {data.confidence_percent}%</p>
  
                  {data.top_tokens?.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 mb-1">Suspicious Tokens:</p>
                      <div className="flex flex-wrap gap-1">
                        {data.top_tokens.map(t => (
                          <span key={t} className="bg-red-900/40 border border-red-700 text-red-300 text-xs px-2 py-0.5 rounded">{t}</span>
                        ))}
                      </div>
                    </div>
                  )}
  
                  {data.top_risk_signals?.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 mb-1">Risk Signals:</p>
                      <ul className="space-y-1">
                        {data.top_risk_signals.map((s, i) => <li key={i} className="text-xs text-orange-300">⚠ {s}</li>)}
                      </ul>
                    </div>
                  )}
  
                  {data.deviation_summary?.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 mb-1">Behaviour Deviations:</p>
                      <ul className="space-y-1">
                        {data.deviation_summary.map((s, i) => <li key={i} className="text-xs text-yellow-300">⚡ {s}</li>)}
                      </ul>
                    </div>
                  )}
  
                  {data.matched_patterns?.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 mb-1">Injection Patterns Matched:</p>
                      <ul className="space-y-1">
                        {data.matched_patterns.map((p, i) => <li key={i} className="text-xs text-purple-300 font-mono">• {p}</li>)}
                      </ul>
                    </div>
                  )}
  
                  {data.header_evidence && Object.keys(data.header_evidence).length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 mb-1">Email Header Analysis:</p>
                      <div className="grid grid-cols-2 gap-1">
                        {Object.entries(data.header_evidence).map(([k, v]) => (
                          <span key={k} className={`text-xs px-2 py-0.5 rounded ${v === "FAIL" || v === "missing" ? "bg-red-900/40 text-red-300" : "bg-green-900/40 text-green-300"}`}>
                            {k.toUpperCase()}: {v}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  }
  
  function ScoreBadge({ score }) {
    const color = score >= 80 ? "text-red-400" : score >= 60 ? "text-orange-400" : score >= 30 ? "text-yellow-400" : "text-green-400";
    return <span className={`text-sm font-bold ${color}`}>{score}%</span>;
  }
  
  // ── ActionPanel ─────────────────────────────────────────────────────────────
  export function ActionPanel({ action, incidentId }) {
    return (
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-5 space-y-3">
        <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wide">⚡ Recommended Action</h3>
        <p className="text-sm text-gray-200 leading-relaxed">{action}</p>
        <p className="text-xs text-gray-500">Incident ID: <span className="font-mono text-gray-400">{incidentId}</span></p>
      </div>
    );
  }
  