import { useState } from "react";
import InputPanel from "./components/InputPanel";
import RiskGauge from "./components/RiskGauge";
import ThreatBrief from "./components/ThreatBrief";
import EvidenceCard from "./components/EvidenceCard";
import ActionPanel from "./components/ActionPanel";
import IncidentLog from "./components/IncidentLog";
import { analyseInput } from "./api/sentinelApi";

export default function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState("analyse");

  const handleAnalyse = async (inputData) => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await analyseInput(inputData);
      setResult(data);
    } catch (err) {
      setError(err.message || "Analysis failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-white font-sans">
      {/* Header */}
      <header className="border-b border-gray-800 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center text-lg">🛡️</div>
          <div>
            <h1 className="text-lg font-bold text-white">SentinelAI</h1>
            <p className="text-xs text-gray-400">Hybrid Multi-Threat Cyber Defense Platform</p>
          </div>
        </div>
        <div className="flex gap-2">
          {["analyse", "incidents"].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${
                activeTab === tab
                  ? "bg-blue-600 text-white"
                  : "bg-gray-800 text-gray-400 hover:text-white"
              }`}
            >
              {tab === "analyse" ? "Analyse Threat" : "Incident Log"}
            </button>
          ))}
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8">
        {activeTab === "analyse" ? (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Left column: Input */}
            <div className="space-y-4">
              <InputPanel onAnalyse={handleAnalyse} loading={loading} />
              {error && (
                <div className="bg-red-900/30 border border-red-700 rounded-lg p-4 text-red-300 text-sm">
                  ⚠️ {error}
                </div>
              )}
            </div>

            {/* Right column: Results */}
            <div className="space-y-4">
              {loading && (
                <div className="bg-gray-900 border border-gray-700 rounded-xl p-8 flex flex-col items-center gap-4">
                  <div className="w-10 h-10 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
                  <p className="text-gray-400 text-sm">Analysing threat...</p>
                </div>
              )}

              {result && !loading && (
                <>
                  <RiskGauge score={result.risk_score} severity={result.severity} />
                  <ThreatBrief brief={result.threat_brief} mitre={result.mitre_tactic} />
                  <EvidenceCard evidence={result.evidence} />
                  <ActionPanel action={result.recommended_action} incidentId={result.incident_id} />
                </>
              )}

              {!result && !loading && (
                <div className="bg-gray-900 border border-dashed border-gray-700 rounded-xl p-8 text-center text-gray-500 text-sm">
                  Submit an input to see the threat analysis
                </div>
              )}
            </div>
          </div>
        ) : (
          <IncidentLog />
        )}
      </main>
    </div>
  );
}
