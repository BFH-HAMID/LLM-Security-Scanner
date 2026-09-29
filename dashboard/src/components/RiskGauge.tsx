import { GRADE_COLOR, riskColor } from "@/lib/format";

const BAND_LABEL: Record<string, string> = {
  minimal: "Minimal risk",
  low: "Low risk",
  moderate: "Moderate risk",
  high: "High risk",
  critical: "Critical risk",
};

/** Half-circle gauge: 0 (safe) on the left, 100 (critical) on the right. */
export function RiskGauge({ score, grade, band }: { score: number; grade: string; band?: string }) {
  const radius = 80;
  const half = Math.PI * radius;
  const frac = Math.min(1, Math.max(0, score / 100));
  const arc = "M 20 100 A 80 80 0 0 1 180 100";
  return (
    <div className="flex flex-col items-center">
      <svg
        viewBox="0 0 200 122"
        className="w-full max-w-[260px]"
        role="img"
        aria-label={`Risk score ${Math.round(score)} out of 100, grade ${grade}`}
      >
        <path d={arc} fill="none" stroke="#e2e8f0" strokeWidth={16} strokeLinecap="round" />
        {frac > 0 ? (
          <path
            d={arc}
            fill="none"
            stroke={riskColor(score)}
            strokeWidth={16}
            strokeLinecap="round"
            strokeDasharray={`${frac * half} ${half}`}
          />
        ) : null}
        <text x="100" y="92" textAnchor="middle" fontSize="42" fontWeight="700" fill="#0f172a">
          {Math.round(score)}
        </text>
        <text x="100" y="112" textAnchor="middle" fontSize="11" fill="#64748b">
          out of 100
        </text>
      </svg>
      <div className="mt-1 flex items-center gap-2">
        <span
          className="inline-flex size-9 items-center justify-center rounded-lg text-lg font-bold text-white"
          style={{ backgroundColor: GRADE_COLOR[grade] ?? "#64748b" }}
        >
          {grade}
        </span>
        <span className="text-sm font-medium text-slate-700">{BAND_LABEL[band ?? ""] ?? band ?? ""}</span>
      </div>
    </div>
  );
}
