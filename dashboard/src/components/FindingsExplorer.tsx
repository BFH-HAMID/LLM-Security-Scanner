"use client";

import clsx from "clsx";
import { ChevronRight, X } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { api, useApi } from "@/lib/api";
import { SEVERITIES, categoryLabel, mutatorLabel } from "@/lib/format";
import type { ResultStatus } from "@/lib/types";
import { Card, CardHeader, Chip, EmptyState, ErrorBanner, SeverityBadge, Spinner, StatusBadge } from "./ui";

const PAGE = 25;
const STATUS_CHOICES: { value: ResultStatus | ""; label: string }[] = [
  { value: "fail", label: "Attack succeeded" },
  { value: "pass", label: "Resisted" },
  { value: "inconclusive", label: "Inconclusive" },
  { value: "error", label: "Errors" },
  { value: "", label: "All" },
];

export interface Focus {
  status?: string;
  category?: string;
  probe?: string;
  mutator?: string;
}

export function FindingsExplorer({
  runId,
  categories,
  mutators,
  focus,
  onFocusChange,
  live,
}: {
  runId: string;
  categories: string[];
  mutators: string[];
  focus: Focus;
  onFocusChange: (f: Focus) => void;
  live: boolean;
}) {
  const [severity, setSeverity] = useState("");
  const [page, setPage] = useState(0);
  const status = focus.status ?? "fail";

  // Any filter change goes back to the first page.
  useEffect(() => setPage(0), [status, focus.category, focus.probe, focus.mutator, severity]);

  const key = `results:${runId}:${status}:${focus.category}:${focus.probe}:${focus.mutator}:${severity}:${page}`;
  const results = useApi(
    key,
    () =>
      api.results(runId, {
        status,
        category: focus.category,
        probe_id: focus.probe,
        mutator: focus.mutator,
        severity,
        limit: PAGE,
        offset: page * PAGE,
      }),
    () => (live ? 3000 : false),
  );
  const items = results.data?.items ?? [];
  const total = results.data?.total ?? 0;
  const set = (patch: Focus) => onFocusChange({ ...focus, ...patch });

  return (
    <Card>
      <CardHeader
        title="Findings"
        subtitle="Every attack the scanner ran. Open one to read the transcript, the evidence and the fix."
      />
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-100 px-5 py-3">
        <div className="inline-flex overflow-hidden rounded-lg border border-slate-300" role="group" aria-label="Result filter">
          {STATUS_CHOICES.map((c) => (
            <button
              key={c.value}
              type="button"
              aria-pressed={status === c.value}
              onClick={() => set({ status: c.value })}
              className={clsx(
                "px-3 py-1.5 text-xs font-medium",
                status === c.value ? "bg-slate-900 text-white" : "bg-white text-slate-600 hover:bg-slate-50",
              )}
            >
              {c.label}
            </button>
          ))}
        </div>
        <select className="input w-auto py-1.5 text-xs" value={focus.category ?? ""} onChange={(e) => set({ category: e.target.value || undefined })} aria-label="Category">
          <option value="">All categories</option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {categoryLabel(c)}
            </option>
          ))}
        </select>
        <select className="input w-auto py-1.5 text-xs" value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        {mutators.length > 1 ? (
          <select className="input w-auto py-1.5 text-xs" value={focus.mutator ?? ""} onChange={(e) => set({ mutator: e.target.value || undefined })} aria-label="Mutator">
            <option value="">All mutators</option>
            {mutators.map((m) => (
              <option key={m} value={m}>
                {mutatorLabel(m)}
              </option>
            ))}
          </select>
        ) : null}
        {focus.probe ? (
          <button type="button" onClick={() => set({ probe: undefined })} className="inline-flex items-center gap-1 rounded-full bg-slate-900 px-3 py-1 text-xs text-white">
            Probe {focus.probe} <X className="size-3" aria-label="Clear probe filter" />
          </button>
        ) : null}
        <span className="ml-auto text-xs text-slate-500">
          {total} result{total === 1 ? "" : "s"}
        </span>
      </div>

      <ErrorBanner error={results.error} title="Could not load findings" />
      {results.loading && !results.data ? (
        <Spinner label="Loading findings" />
      ) : items.length ? (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[820px]">
            <thead className="border-b border-slate-100 bg-slate-50/60">
              <tr>
                <th className="th">Severity</th>
                <th className="th">Probe</th>
                <th className="th">Category</th>
                <th className="th">Mutator</th>
                <th className="th">Result</th>
                <th className="th w-8" aria-label="Open" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {items.map((r) => (
                <tr key={r.id} className="hover:bg-slate-50">
                  <td className="td">
                    <SeverityBadge severity={r.severity} />
                  </td>
                  <td className="td max-w-md">
                    <Link href={`/runs/${runId}/findings/${r.id}`} className="font-medium text-slate-900 no-underline hover:text-brand-700">
                      <span className="mr-1.5 font-mono text-xs text-slate-500">{r.probe_id}</span>
                      {r.probe_name}
                    </Link>
                    {r.reason ? <div className="mt-0.5 truncate text-xs text-slate-500">{r.reason}</div> : null}
                  </td>
                  <td className="td">
                    <div className="text-slate-700">{categoryLabel(r.category)}</div>
                    <div className="mt-0.5 flex gap-1">
                      {r.owasp.map((o) => (
                        <Chip key={o}>{o}</Chip>
                      ))}
                    </div>
                  </td>
                  <td className="td font-mono text-xs text-slate-600">{mutatorLabel(r.mutator)}</td>
                  <td className="td">
                    <StatusBadge status={r.status} kind="result" />
                  </td>
                  <td className="td">
                    <Link href={`/runs/${runId}/findings/${r.id}`} aria-label="Open finding" className="text-slate-400 hover:text-slate-700">
                      <ChevronRight className="size-4" />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        live && !total ? (
          <EmptyState title="Waiting for results">Findings appear here as soon as the scan produces them.</EmptyState>
        ) : (
          <EmptyState title={status === "fail" ? "No successful attacks match these filters" : "No results match these filters"}>
            {status === "fail" ? "That is good news for this selection. Switch to “Resisted” to see what was tried." : "Try widening the filters."}
          </EmptyState>
        )
      )}

      {total > PAGE ? (
        <div className="flex items-center justify-between border-t border-slate-100 px-5 py-3 text-sm text-slate-600">
          <button type="button" className="btn-secondary py-1" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
            Previous
          </button>
          <span>
            {page * PAGE + 1}-{Math.min(total, (page + 1) * PAGE)} of {total}
          </span>
          <button type="button" className="btn-secondary py-1" disabled={(page + 1) * PAGE >= total} onClick={() => setPage((p) => p + 1)}>
            Next
          </button>
        </div>
      ) : null}
    </Card>
  );
}
