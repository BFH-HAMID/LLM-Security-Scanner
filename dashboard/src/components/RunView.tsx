"use client";

import { CheckCircle2, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { useRef, useState } from "react";
import { CategoryTable } from "@/components/CategoryTable";
import { FindingsExplorer, type Focus } from "@/components/FindingsExplorer";
import { Heatmap, HeatmapLegend } from "@/components/Heatmap";
import { RiskGauge } from "@/components/RiskGauge";
import { RunHeader } from "@/components/RunHeader";
import { ScanSettings } from "@/components/ScanSettings";
import { CategoryRadar, MutatorChart, SeverityChart, seriesFromScore } from "@/components/charts";
import { Card, CardHeader, ErrorBanner, NoteBanner, ProgressBar, Spinner, Stat } from "@/components/ui";
import { api, useApi } from "@/lib/api";
import { isActive, pct } from "@/lib/format";

export function RunView() {
  const { id } = useParams<{ id: string }>();
  const search = useSearchParams();
  const findingsRef = useRef<HTMLDivElement>(null);
  const [onlyFailing, setOnlyFailing] = useState(false);
  const [focus, setFocus] = useState<Focus>({
    status: search.get("status") ?? undefined,
    category: search.get("category") ?? undefined,
    probe: search.get("probe") ?? undefined,
    mutator: search.get("mutator") ?? undefined,
  });

  const run = useApi(`run:${id}`, () => api.run(id), (r) => (isActive(r.status) ? 1500 : false));
  const targets = useApi("targets", api.targets);
  const r = run.data;
  const done = !!r && !isActive(r.status);
  const heat = useApi(r?.score && done ? `heat:${id}` : null, () => api.heatmap(id));
  const target = targets.data?.find((t) => t.id === r?.target_id);
  // Only ask when the target has a baseline that is a different run (otherwise the API answers 404).
  const hasBaseline = !!target?.baseline_run_id && target.baseline_run_id !== id;
  const baseline = useApi(r?.score && done && hasBaseline ? `baseline:${id}:${target?.baseline_run_id}` : null, () => api.baselineCheck(id).catch(() => null));

  const jump = (f: Focus) => {
    setFocus((cur) => ({ ...cur, ...f }));
    findingsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  if (run.error && !r) return <ErrorBanner error={run.error} title="Could not load this run" />;
  if (!r) return <Spinner label="Loading run" />;
  const score = r.score;

  return (
    <div className="space-y-6">
      <nav className="text-sm text-slate-500" aria-label="Breadcrumb">
        <Link href="/" className="hover:text-slate-900">
          Runs
        </Link>{" "}
        / <span className="text-slate-900">{r.name || r.target.name}</span>
      </nav>
      <RunHeader run={r} target={target} onChanged={() => { run.reload(); targets.reload(); }} />

      {isActive(r.status) ? (
        <Card className="px-5 py-4">
          <div className="mb-2 flex items-center justify-between text-sm">
            <span className="font-medium">{r.status === "queued" ? "Waiting for a worker" : "Scanning"}</span>
            <span className="text-slate-500 tabular-nums">
              {r.progress.done} / {r.progress.total || "?"} attacks · {r.findings} succeeded so far
            </span>
          </div>
          <ProgressBar done={r.progress.done} total={r.progress.total} className="h-2.5" />
        </Card>
      ) : null}
      {r.status === "failed" ? <ErrorBanner error={r.error ?? "The run failed."} title="This run failed" /> : null}
      {r.status === "cancelled" ? <p className="rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-600">This run was cancelled; results are partial.</p> : null}
      {baseline.data ? (
        <div
          role="status"
          className={`flex items-start gap-3 rounded-xl border px-4 py-3 text-sm ${baseline.data.ok ? "border-emerald-200 bg-emerald-50 text-emerald-900" : "border-red-200 bg-red-50 text-red-900"}`}
        >
          {baseline.data.ok ? <CheckCircle2 className="mt-0.5 size-4" aria-hidden /> : <ShieldAlert className="mt-0.5 size-4" aria-hidden />}
          <div>
            <span className="font-semibold">
              {baseline.data.ok
                ? "No regression against this target’s baseline."
                : `${baseline.data.regressions.length} regression${baseline.data.regressions.length === 1 ? "" : "s"} against this target’s baseline.`}
            </span>{" "}
            Risk score {baseline.data.risk_before.toFixed(0)} to {baseline.data.risk_after.toFixed(0)} (increases up to {baseline.data.tolerance.toFixed(0)} points are tolerated);{" "}
            {baseline.data.improvements} attack{baseline.data.improvements === 1 ? "" : "s"} newly resisted.
            {!baseline.data.ok ? (
              <ul className="mt-1 list-disc pl-5">
                {baseline.data.regressions.slice(0, 5).map((x) => (
                  <li key={x.key}>
                    <button type="button" className="underline" onClick={() => jump({ probe: x.probe_id, mutator: x.mutator, status: "fail" })}>
                      {x.probe_id} {x.probe_name}
                    </button>{" "}
                    ({x.mutator}): {x.reason}
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        </div>
      ) : null}
      <NoteBanner notes={r.notes} />

      {score ? (
        <>
          <div className="grid gap-6 lg:grid-cols-[minmax(0,320px)_1fr]">
            <Card className="flex flex-col items-center justify-center px-5 py-6">
              <RiskGauge score={score.risk_score} grade={score.grade} band={score.band} />
              <p className="mt-3 text-center text-xs text-slate-500">
                Severity-weighted attack success, never lower than the worst confirmed finding.{" "}
                <span className="whitespace-nowrap">Lower is better.</span>
              </p>
            </Card>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
              <Stat label="Attack success rate" value={pct(score.asr)} hint={`${pct(score.weighted_asr)} severity-weighted`} tone={score.asr >= 0.25 ? "bad" : undefined} />
              <Stat label="Attacks succeeded" value={score.failed} hint={`of ${score.passed + score.failed} conclusive`} tone={score.failed ? "bad" : "good"} />
              <Stat label="Attacks resisted" value={score.passed} tone="good" />
              <Stat label="Highest severity hit" value={score.highest_severity_failed ?? "none"} tone={score.highest_severity_failed ? "bad" : "good"} />
              <Stat label="Inconclusive" value={score.inconclusive} hint="judge abstained" tone={score.inconclusive ? "warn" : undefined} />
              <Stat label="Errors" value={score.errors} hint="excluded from ASR" tone={score.errors ? "warn" : undefined} />
            </div>
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <Card>
              <CardHeader title="Attack success by category" subtitle="Share of attacks that worked, per attack family." />
              <div className="px-2 pb-3">
                <CategoryRadar series={[seriesFromScore("Attack success", "#dc2626", score)]} />
              </div>
            </Card>
            <Card>
              <CardHeader title="Severity breakdown" subtitle="Where the successful attacks sit by severity." />
              <div className="px-2 pb-3">
                <SeverityChart score={score} height={300} />
              </div>
            </Card>
          </div>

          {Object.keys(score.mutators).length > 1 ? (
            <Card>
              <CardHeader title="Which obfuscations get through" subtitle="Attack success rate when the same payloads are re-encoded by each mutator." />
              <div className="px-2 pb-3">
                <MutatorChart score={score} />
              </div>
            </Card>
          ) : null}

          <Card>
            <CardHeader title="Categories" subtitle="Click a row to list its findings. Intervals are 95% Wilson confidence bounds." />
            <CategoryTable score={score} active={focus.category} onSelect={(c) => jump({ category: c })} />
          </Card>

          <Card>
            <CardHeader
              title="Pass / fail heatmap"
              subtitle="Every probe against every mutator. Click a cell to see that attack."
              actions={
                <label className="flex items-center gap-2 text-xs text-slate-600">
                  <input type="checkbox" checked={onlyFailing} onChange={(e) => setOnlyFailing(e.target.checked)} className="size-3.5 accent-red-600" />
                  Only probes with a successful attack
                </label>
              }
            />
            <div className="px-5 pt-3">
              <HeatmapLegend />
            </div>
            <div className="px-3 pb-4 pt-2">
              {heat.data ? (
                <Heatmap
                  data={heat.data}
                  onlyFailing={onlyFailing}
                  selected={focus.probe && focus.mutator ? { probe: focus.probe, mutator: focus.mutator } : null}
                  onSelect={(probe, mutator) => jump({ probe, mutator, status: "" })}
                />
              ) : heat.error ? (
                <ErrorBanner error={heat.error} />
              ) : (
                <Spinner label="Loading heatmap" />
              )}
            </div>
          </Card>
        </>
      ) : null}

      <div ref={findingsRef} id="findings" className="scroll-mt-6">
        <FindingsExplorer
          runId={id}
          categories={score ? Object.keys(score.categories) : []}
          mutators={score ? Object.keys(score.mutators) : []}
          focus={focus}
          onFocusChange={setFocus}
          live={isActive(r.status)}
        />
      </div>

      {score ? <ScanSettings run={r} /> : null}
    </div>
  );
}
