"use client";

import clsx from "clsx";
import { categoryLabel, pct, riskColor } from "@/lib/format";
import type { ScoreCard } from "@/lib/types";
import { Chip } from "./ui";

export function CategoryTable({
  score,
  active,
  onSelect,
}: {
  score: ScoreCard;
  active?: string;
  onSelect: (category: string) => void;
}) {
  const rows = Object.values(score.categories);
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px]">
        <thead className="border-b border-slate-100 bg-slate-50/60">
          <tr>
            <th className="th">Category</th>
            <th className="th">OWASP LLM Top 10</th>
            <th className="th">Attack success rate (95% CI)</th>
            <th className="th text-right">Succeeded</th>
            <th className="th text-right">Risk</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {rows.map((c) => (
            <tr
              key={c.category}
              onClick={() => onSelect(c.category)}
              className={clsx("cursor-pointer hover:bg-slate-50", active === c.category && "bg-red-50/50")}
            >
              <td className="td font-medium">
                <button type="button" className="text-left hover:text-brand-700" onClick={() => onSelect(c.category)}>
                  {c.title || categoryLabel(c.category)}
                </button>
              </td>
              <td className="td">
                <div className="flex flex-wrap gap-1">
                  {c.owasp.map((o) => (
                    <Chip key={o}>{o}</Chip>
                  ))}
                </div>
              </td>
              <td className="td">
                <div className="flex items-center gap-3">
                  <div className="h-2 w-28 overflow-hidden rounded-full bg-slate-200" aria-hidden>
                    <div className="h-full rounded-full" style={{ width: `${c.asr * 100}%`, backgroundColor: riskColor(c.asr * 100) }} />
                  </div>
                  <span className="w-10 font-semibold tabular-nums">{pct(c.asr)}</span>
                  <span className="text-xs text-slate-500 tabular-nums">
                    {c.total ? `${pct(c.ci_low)} to ${pct(c.ci_high)}` : "no verdicts"}
                  </span>
                </div>
              </td>
              <td className="td text-right tabular-nums">
                <span className={c.failed ? "font-semibold text-red-600" : "text-slate-500"}>{c.failed}</span>
                <span className="text-slate-400"> / {c.total}</span>
              </td>
              <td className="td text-right font-semibold tabular-nums" style={{ color: riskColor(c.risk) }}>
                {Math.round(c.risk)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
