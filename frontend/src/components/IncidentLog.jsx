// IncidentLog.jsx
import { useEffect, useState } from "react";
import { getIncidents, submitFeedback } from "../api/sentinelApi";

const SEVERITY_COLORS = {
  "Critical":          "text-red-400 bg-red-900/20",
  "Likely Malicious":  "text-orange-400 bg-orange-900/20",
  "Suspicious":        "text-yellow-400 bg-yellow-900/20",
  "Clean":             "text-green-400 bg-green-900/20",
};

export default function IncidentLog() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getIncidents()
      .then(data => setIncidents(data.incidents || []))
      .catch(() => setIncidents([]))
      .finally(() => setLoading(false));
  }, []);

  const handleFeedback = async (id, verdict) => {
    await submitFeedback(id, verdict);
    setIncidents(prev =>
      prev.map(inc => inc.incident_id === id ? { ...inc, analyst_verdict: verdict } : inc)
    );
  };

  if (loading) return <div className="text-gray-400 py-8 text-center">Loading incidents...</div>;

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold text-white">📋 Incident Log</h2>
      {incidents.length === 0 ? (
        <div className="text-gray-500 text-sm text-center py-12 border border-dashed border-gray-700 rounded-xl">
          No incidents yet. Analyse a threat to see it here.
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-gray-700">
          <table className="w-full text-sm">
            <thead className="bg-gray-800 text-gray-400 text-xs uppercase">
              <tr>
                {["Incident ID", "Type", "Score", "Severity", "Time", "Verdict", "Actions"].map(h => (
                  <th key={h} className="px-4 py-3 text-left">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {incidents.map(inc => (
                <tr key={inc.incident_id} className="bg-gray-900 hover:bg-gray-850">
                  <td className="px-4 py-3 font-mono text-xs text-gray-400">{inc.incident_id}</td>
                  <td className="px-4 py-3 text-gray-300 capitalize">{inc.input_type}</td>
                  <td className="px-4 py-3 font-bold text-white">{inc.risk_score}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_COLORS[inc.severity] || "text-gray-400"}`}>
                      {inc.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-400 text-xs">
                    {new Date(inc.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="px-4 py-3 text-xs">
                    {inc.analyst_verdict ? (
                      <span className={inc.analyst_verdict === "true_positive" ? "text-red-400" : "text-green-400"}>
                        {inc.analyst_verdict === "true_positive" ? "✓ True Positive" : "✗ False Positive"}
                      </span>
                    ) : (
                      <span className="text-gray-600">Pending</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {!inc.analyst_verdict && (
                      <div className="flex gap-1">
                        <button onClick={() => handleFeedback(inc.incident_id, "true_positive")}
                          className="text-xs px-2 py-1 bg-red-900/30 border border-red-700 text-red-300 rounded hover:bg-red-900/50">
                          TP
                        </button>
                        <button onClick={() => handleFeedback(inc.incident_id, "false_positive")}
                          className="text-xs px-2 py-1 bg-green-900/30 border border-green-700 text-green-300 rounded hover:bg-green-900/50">
                          FP
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
