/**
 * RiskGauge — animated 0-100 risk score display with severity colour band.
 */
export default function RiskGauge({ score, severity }) {
    const getColor = () => {
      if (score >= 81) return { bg: "bg-red-900/30",   border: "border-red-600",   text: "text-red-400",   ring: "stroke-red-500" };
      if (score >= 61) return { bg: "bg-orange-900/30",border: "border-orange-600",text: "text-orange-400",ring: "stroke-orange-500" };
      if (score >= 31) return { bg: "bg-yellow-900/30",border: "border-yellow-600",text: "text-yellow-400",ring: "stroke-yellow-500" };
      return              { bg: "bg-green-900/30",  border: "border-green-600",  text: "text-green-400",  ring: "stroke-green-500" };
    };
  
    const c = getColor();
    // SVG arc calculation
    const radius = 52;
    const circumference = Math.PI * radius;  // half circle
    const progress = ((100 - score) / 100) * circumference;
  
    const severityEmoji = { Critical: "🔴", "Likely Malicious": "🟠", Suspicious: "🟡", Clean: "🟢" };
  
    return (
      <div className={`${c.bg} border ${c.border} rounded-xl p-5`}>
        <div className="flex items-center justify-between mb-3">
          <span className="text-sm font-medium text-gray-300">Risk Score</span>
          <span className={`text-sm font-bold ${c.text}`}>
            {severityEmoji[severity] || "⚪"} {severity}
          </span>
        </div>
  
        <div className="flex items-center gap-6">
          {/* SVG Semi-circle gauge */}
          <svg width="130" height="70" viewBox="0 0 130 70">
            {/* Background track */}
            <path
              d="M 10 65 A 52 52 0 0 1 120 65"
              fill="none"
              stroke="#374151"
              strokeWidth="10"
              strokeLinecap="round"
            />
            {/* Animated progress arc */}
            <path
              d="M 10 65 A 52 52 0 0 1 120 65"
              fill="none"
              className={c.ring}
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={progress}
              style={{ transition: "stroke-dashoffset 0.8s ease" }}
            />
            {/* Score text */}
            <text x="65" y="62" textAnchor="middle" className="fill-white" fontSize="22" fontWeight="bold">
              {score}
            </text>
          </svg>
  
          {/* Severity band legend */}
          <div className="flex flex-col gap-1 text-xs">
            {[
              { label: "Critical",         range: "81–100", color: "text-red-400" },
              { label: "Likely Malicious", range: "61–80",  color: "text-orange-400" },
              { label: "Suspicious",       range: "31–60",  color: "text-yellow-400" },
              { label: "Clean",            range: "0–30",   color: "text-green-400" },
            ].map(b => (
              <div key={b.label} className={`flex gap-2 ${b.label === severity ? "font-bold" : "opacity-50"}`}>
                <span className={b.color}>{b.range}</span>
                <span className="text-gray-400">{b.label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }
  