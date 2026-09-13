interface Props {
  score: number;
  label?: string;
}

export function SeverityGauge({ score, label }: Props) {
  const clamped = Math.max(0, Math.min(100, score));
  const angle = (clamped / 100) * 180;
  const tone = clamped >= 85 ? "critical" : clamped >= 70 ? "high" : clamped >= 45 ? "medium" : "low";
  return (
    <div className={`gauge ${tone}`}>
      <svg viewBox="0 0 120 72" role="img" aria-label={`Risk ${clamped}`}>
        <path
          d="M10 62 A50 50 0 0 1 110 62"
          fill="none"
          stroke="currentColor"
          strokeWidth="8"
          opacity="0.18"
        />
        <path
          d="M10 62 A50 50 0 0 1 110 62"
          fill="none"
          stroke="currentColor"
          strokeWidth="8"
          strokeDasharray={`${(angle / 180) * 157} 157`}
          strokeLinecap="round"
        />
        <text x="60" y="58" textAnchor="middle">
          {clamped}
        </text>
      </svg>
      <span>{label ?? "risk"}</span>
    </div>
  );
}
