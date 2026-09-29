"use client";

import { Ban, ChevronDown, Download, GitCompareArrows, Star, Trash2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { api } from "@/lib/api";
import { dateTime, duration, isActive, targetLabel } from "@/lib/format";
import type { RunDetail, TargetRecord } from "@/lib/types";
import { Chip, PageHeader, StatusBadge } from "./ui";

const FORMATS = [
  ["html", "HTML report"],
  ["pdf", "PDF report"],
  ["json", "JSON (full data)"],
  ["sarif", "SARIF (code scanning)"],
  ["md", "Markdown"],
] as const;

export function ExportMenu({ runId, disabled }: { runId: string; disabled?: boolean }) {
  return (
    <details className="group relative">
      <summary
        className={`btn-secondary list-none ${disabled ? "pointer-events-none opacity-50" : "cursor-pointer"} [&::-webkit-details-marker]:hidden`}
      >
        <Download className="size-4" aria-hidden /> Export <ChevronDown className="size-3.5 transition group-open:rotate-180" aria-hidden />
      </summary>
      <div className="absolute right-0 z-30 mt-2 w-56 overflow-hidden rounded-xl border border-slate-200 bg-white py-1 shadow-lg">
        {FORMATS.map(([fmt, label]) => (
          <a
            key={fmt}
            href={api.reportUrl(runId, fmt)}
            className="block px-4 py-2 text-sm text-slate-700 no-underline hover:bg-slate-50"
          >
            {label}
          </a>
        ))}
      </div>
    </details>
  );
}

export function RunHeader({
  run,
  target,
  onChanged,
}: {
  run: RunDetail;
  target: TargetRecord | undefined;
  onChanged: () => void;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const isBaseline = !!target && target.baseline_run_id === run.id;

  const act = async (fn: () => Promise<unknown>, then?: () => void) => {
    setBusy(true);
    setError(undefined);
    try {
      await fn();
      (then ?? onChanged)();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const compareHref = target?.baseline_run_id && !isBaseline ? `/compare?a=${target.baseline_run_id}&b=${run.id}` : `/compare?b=${run.id}`;

  return (
    <>
      <PageHeader
        title={run.name || targetLabel(run.target)}
        subtitle={
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <StatusBadge status={run.status} />
            <Chip>{run.target.type}</Chip>
            <span>{targetLabel(run.target)}</span>
            {run.target.url || run.target.base_url ? <span className="font-mono text-xs">{run.target.url ?? run.target.base_url}</span> : null}
            <span title={dateTime(run.created_at)}>{dateTime(run.started_at ?? run.created_at)}</span>
            {run.finished_at ? <span>took {duration(run.duration_s)}</span> : null}
            <span className="font-mono text-xs text-slate-400">{run.id}</span>
            {isBaseline ? (
              <span className="inline-flex items-center gap-1 text-amber-700">
                <Star className="size-3.5 fill-amber-400 text-amber-500" aria-hidden /> baseline for this target
              </span>
            ) : null}
          </span>
        }
        actions={
          <>
            {isActive(run.status) ? (
              <button type="button" className="btn-danger" disabled={busy} onClick={() => act(() => api.cancelRun(run.id))}>
                <Ban className="size-4" aria-hidden /> Cancel run
              </button>
            ) : null}
            {run.target_id && run.score && !isActive(run.status) ? (
              isBaseline ? (
                <button type="button" className="btn-secondary" disabled={busy} onClick={() => act(() => api.clearBaseline(run.target_id!))}>
                  <Star className="size-4" aria-hidden /> Clear baseline
                </button>
              ) : (
                <button type="button" className="btn-secondary" disabled={busy} onClick={() => act(() => api.setBaseline(run.target_id!, run.id))}>
                  <Star className="size-4" aria-hidden /> Set as baseline
                </button>
              )
            ) : null}
            {run.score ? (
              <Link href={compareHref} className="btn-secondary no-underline">
                <GitCompareArrows className="size-4" aria-hidden /> Compare
              </Link>
            ) : null}
            <ExportMenu runId={run.id} disabled={!run.score} />
            <button
              type="button"
              className="btn-danger"
              disabled={busy || isActive(run.status)}
              title={isActive(run.status) ? "Cancel the run first" : "Delete this run and its findings"}
              onClick={() => {
                if (confirm("Delete this run and all of its findings? This cannot be undone.")) {
                  void act(() => api.deleteRun(run.id), () => router.push("/"));
                }
              }}
            >
              <Trash2 className="size-4" aria-hidden />
              <span className="sr-only">Delete run</span>
            </button>
          </>
        }
      />
      {error ? <p className="-mt-3 mb-4 text-sm text-red-700">{error}</p> : null}
    </>
  );
}
