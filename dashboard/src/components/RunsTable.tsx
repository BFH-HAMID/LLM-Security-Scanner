"use client";

import clsx from "clsx";
import { ChevronRight } from "lucide-react";
import Link from "next/link";
import { duration, isActive, riskColor, targetLabel, timeAgo, dateTime } from "@/lib/format";
import type { RunSummary } from "@/lib/types";
import { Chip, GradeBadge, ProgressBar, StatusBadge } from "./ui";

export function RiskBar({ score, grade }: { score: number | null; grade: string | null }) {
  if (score === null) return <span className="text-slate-400">-</span>;
  return (
    <div className="flex items-center gap-3">
      <div className="h-2 w-24 overflow-hidden rounded-full bg-slate-200" aria-hidden>
        <div className="h-full rounded-full" style={{ width: `${Math.max(3, score)}%`, backgroundColor: riskColor(score) }} />
      </div>
      <span className="w-8 text-sm font-semibold tabular-nums">{Math.round(score)}</span>
      <GradeBadge grade={grade} size="sm" />
    </div>
  );
}

export function RunsTable({
  runs,
  selected,
  onToggle,
}: {
  runs: RunSummary[];
  selected: string[];
  onToggle: (id: string) => void;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[860px]">
        <thead className="border-b border-slate-100 bg-slate-50/60">
          <tr>
            <th className="th w-10" aria-label="Select" />
            <th className="th">Run</th>
            <th className="th">Status</th>
            <th className="th">Risk score</th>
            <th className="th text-right">Successful attacks</th>
            <th className="th pl-10">Started</th>
            <th className="th text-right">Duration</th>
            <th className="th w-8" aria-label="Open" />
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {runs.map((r) => {
            const isSel = selected.includes(r.id);
            return (
              <tr key={r.id} className={clsx("transition-colors hover:bg-slate-50", isSel && "bg-red-50/40")}>
                <td className="td">
                  <input
                    type="checkbox"
                    checked={isSel}
                    onChange={() => onToggle(r.id)}
                    aria-label={`Select run ${r.name ?? r.id.slice(0, 8)} for comparison`}
                    className="size-4 rounded border-slate-300 accent-red-600"
                  />
                </td>
                <td className="td">
                  <Link href={`/runs/${r.id}`} className="font-medium text-slate-900 no-underline hover:text-brand-700">
                    {r.name || targetLabel(r.target)}
                  </Link>
                  <div className="mt-0.5 flex items-center gap-2 text-xs text-slate-500">
                    <Chip>{r.target.type}</Chip>
                    <span className="truncate">{targetLabel(r.target)}</span>
                    <span className="font-mono text-slate-400">{r.id.slice(0, 8)}</span>
                  </div>
                </td>
                <td className="td min-w-36">
                  <StatusBadge status={r.status} />
                  {isActive(r.status) ? (
                    <div className="mt-2 w-28">
                      <ProgressBar done={r.progress.done} total={r.progress.total} />
                      <div className="mt-1 text-[11px] text-slate-500 tabular-nums">
                        {r.progress.done}/{r.progress.total || "?"}
                      </div>
                    </div>
                  ) : null}
                  {r.status === "failed" && r.error ? (
                    <div className="mt-1 max-w-56 truncate text-xs text-red-700" title={r.error}>
                      {r.error}
                    </div>
                  ) : null}
                </td>
                <td className="td">
                  <RiskBar score={r.risk_score} grade={r.grade} />
                </td>
                <td className={clsx("td text-right tabular-nums", r.findings > 0 ? "font-semibold text-red-600" : "text-slate-500")}>
                  {r.status === "queued" ? "-" : r.findings}
                </td>
                <td className="td pl-10 whitespace-nowrap text-slate-600" title={dateTime(r.created_at)}>
                  {timeAgo(r.created_at)}
                </td>
                <td className="td text-right whitespace-nowrap text-slate-600 tabular-nums">
                  {r.status === "queued" ? "-" : duration(r.duration_s)}
                </td>
                <td className="td">
                  <Link href={`/runs/${r.id}`} aria-label="Open run" className="text-slate-400 hover:text-slate-700">
                    <ChevronRight className="size-4" />
                  </Link>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
