"use client";

import clsx from "clsx";
import { ArrowDownRight, ArrowRight, ArrowUpRight, ArrowLeftRight, Equal } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect } from "react";
import { api, useApi } from "@/lib/api";
import { categoryLabel, mutatorLabel, pct, timeAgo } from "@/lib/format";
import type { Comparison, KeyChange, RunSummary } from "@/lib/types";
import { CategoryRadar, seriesFromScore } from "./charts";
import { Card, CardHeader, EmptyState, ErrorBanner, GradeBadge, PageHeader, SeverityBadge, Spinner, Stat } from "./ui";

const VERDICT = {
  better: { label: "Improved", tone: "border-emerald-200 bg-emerald-50 text-emerald-900", Icon: ArrowDownRight },
  worse: { label: "Regressed", tone: "border-red-200 bg-red-50 text-red-900", Icon: ArrowUpRight },
  mixed: { label: "Mixed", tone: "border-amber-200 bg-amber-50 text-amber-900", Icon: ArrowLeftRight },
  unchanged: { label: "No change", tone: "border-slate-200 bg-white text-slate-800", Icon: Equal },
} as const;

const label = (r: RunSummary) =>
  `${r.name || r.target.name} · ${timeAgo(r.created_at)} · risk ${r.risk_score != null ? Math.round(r.risk_score) : "?"} ${r.grade ?? ""}`;

function ChangeTable({ title, tone, rows, runId, empty }: { title: string; tone: string; rows: KeyChange[]; runId: string; empty: string }) {
  return (
    <Card>
      <CardHeader title={<span className={tone}>{title}</span>} subtitle={`${rows.length} attack${rows.length === 1 ? "" : "s"}`} />
      {rows.length ? (
        <div className="max-h-96 overflow-auto">
          <table className="w-full min-w-[640px]">
            <thead className="sticky top-0 border-b border-slate-100 bg-slate-50">
              <tr>
                <th className="th">Severity</th>
                <th className="th">Probe</th>
                <th className="th">Mutator</th>
                <th className="th text-right">Success rate</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((c) => (
                <tr key={c.key} className="hover:bg-slate-50">
                  <td className="td"><SeverityBadge severity={c.severity} /></td>
                  <td className="td">
                    <Link
                      href={`/runs/${runId}?probe=${c.probe_id}&mutator=${encodeURIComponent(c.mutator)}&status=#findings`}
                      className="font-medium text-slate-900 no-underline hover:text-brand-700"
                    >
                      <span className="mr-1.5 font-mono text-xs text-slate-500">{c.probe_id}</span>
                      {c.probe_name}
                    </Link>
                    <div className="text-xs text-slate-500">{categoryLabel(c.category)}</div>
                  </td>
                  <td className="td font-mono text-xs">{mutatorLabel(c.mutator)}</td>
                  <td className="td text-right tabular-nums">
                    {pct(c.fail_rate_before)} <ArrowRight className="mx-1 inline size-3 text-slate-400" aria-hidden /> {pct(c.fail_rate_after)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="px-5 py-6 text-sm text-slate-500">{empty}</p>
      )}
    </Card>
  );
}

function Result({ c, a, b }: { c: Comparison; a: string; b: string }) {
  const ra = useApi(`run:${a}`, () => api.run(a));
  const rb = useApi(`run:${b}`, () => api.run(b));
  const v = VERDICT[c.verdict];
  const delta = c.risk_delta;
  return (
    <div className="space-y-6">
      <div className={clsx("flex flex-wrap items-center gap-x-6 gap-y-3 rounded-xl border px-5 py-4", v.tone)} role="status">
        <v.Icon className="size-7 shrink-0" aria-hidden />
        <div className="min-w-0 flex-1">
          <div className="text-lg font-semibold">{v.label}</div>
          <div className="text-sm opacity-80">
            {c.verdict === "better" && "Attacks that used to succeed are now resisted, and none newly succeed."}
            {c.verdict === "worse" && "Attacks that used to be resisted now succeed, and none were fixed."}
            {c.verdict === "mixed" && "Some attacks were fixed while others newly succeed."}
            {c.verdict === "unchanged" && "The same attacks succeed in both runs."}
          </div>
        </div>
        <div className="flex items-center gap-3 text-2xl font-semibold tabular-nums">
          <GradeBadge grade={c.grade_a} /> {c.risk_a.toFixed(0)} <ArrowRight className="size-5 opacity-60" aria-hidden /> {c.risk_b.toFixed(0)} <GradeBadge grade={c.grade_b} />
          <span className="text-sm font-medium opacity-80">({delta > 0 ? "+" : ""}{delta.toFixed(1)})</span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Newly succeeding" value={c.regressions.length} tone={c.regressions.length ? "bad" : "good"} hint="resisted in A, succeeds in B" />
        <Stat label="Fixed" value={c.fixed.length} tone={c.fixed.length ? "good" : undefined} hint="succeeded in A, resisted in B" />
        <Stat label="Still succeeding" value={c.still_failing.length} tone={c.still_failing.length ? "warn" : "good"} />
        <Stat label="New / removed probes" value={`${c.new_probes.length} / ${c.removed_probes.length}`} hint="not comparable" />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader title="Attack success by category" subtitle="Run A in grey, run B in red." />
          <div className="px-2 pb-3">
            {ra.data?.score && rb.data?.score ? (
              <CategoryRadar
                series={[seriesFromScore("Run A", "#64748b", ra.data.score), seriesFromScore("Run B", "#dc2626", rb.data.score)]}
              />
            ) : (
              <Spinner />
            )}
          </div>
        </Card>
        <Card>
          <CardHeader title="Category changes" />
          <table className="w-full">
            <thead className="border-b border-slate-100 bg-slate-50/60">
              <tr>
                <th className="th">Category</th>
                <th className="th text-right">A</th>
                <th className="th text-right">B</th>
                <th className="th text-right">Change</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {c.categories.map((d) => (
                <tr key={d.category}>
                  <td className="td">{d.title || categoryLabel(d.category)}</td>
                  <td className="td text-right tabular-nums">{pct(d.asr_a)}</td>
                  <td className="td text-right tabular-nums">{pct(d.asr_b)}</td>
                  <td className={clsx("td text-right font-semibold tabular-nums", d.delta > 0.005 ? "text-red-600" : d.delta < -0.005 ? "text-emerald-600" : "text-slate-400")}>
                    {d.delta > 0 ? "+" : ""}
                    {(d.delta * 100).toFixed(0)} pts
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>

      <ChangeTable title="Newly succeeding attacks" tone="text-red-700" rows={c.regressions} runId={b} empty="No attack that was resisted in A succeeds in B." />
      <ChangeTable title="Fixed" tone="text-emerald-700" rows={c.fixed} runId={a} empty="Nothing that succeeded in A is resisted in B." />
      <ChangeTable title="Still succeeding" tone="text-amber-700" rows={c.still_failing} runId={b} empty="No attack succeeds in both runs." />
    </div>
  );
}

export function CompareView() {
  const router = useRouter();
  const params = useSearchParams();
  const runs = useApi("runs:compare", () => api.runs({ limit: 100 }));
  const usable = (runs.data?.items ?? []).filter((r) => r.risk_score !== null && (r.status === "completed" || r.status === "cancelled"));

  // Default to the two newest comparable runs of the same target.
  const a = params.get("a") ?? "";
  const b = params.get("b") ?? "";
  useEffect(() => {
    if (!runs.data || (a && b)) return;
    const newest = b ? usable.find((r) => r.id === b) : usable.find((r) => r.id !== a);
    const before = a ? usable.find((r) => r.id === a) : usable.find((r) => r.id !== newest?.id && r.target_id === newest?.target_id) ?? usable.find((r) => r.id !== newest?.id);
    if (newest && before) router.replace(`/compare?a=${before.id}&b=${newest.id}`);
  }, [runs.data]);

  const set = (na: string, nb: string) => router.replace(`/compare?a=${na}&b=${nb}`);
  const cmp = useApi(a && b && a !== b ? `compare:${a}:${b}` : null, () => api.compare(a, b));

  return (
    <>
      <PageHeader title="Compare runs" subtitle="What newly succeeds, what got fixed, and how the risk score moved between two scans." />
      <Card className="mb-6 px-5 py-4">
        <div className="grid items-end gap-4 md:grid-cols-[1fr_auto_1fr]">
          {(["a", "b"] as const).map((side, i) => (
            <div key={side} className={i === 1 ? "md:col-start-3" : ""}>
              <label className="label" htmlFor={`run-${side}`}>{side === "a" ? "Run A (before)" : "Run B (after)"}</label>
              <select id={`run-${side}`} className="input" value={side === "a" ? a : b} onChange={(e) => (side === "a" ? set(e.target.value, b) : set(a, e.target.value))}>
                <option value="">Choose a run…</option>
                {usable.map((r) => (
                  <option key={r.id} value={r.id}>{label(r)}</option>
                ))}
              </select>
            </div>
          ))}
          <button type="button" className="btn-secondary md:col-start-2 md:row-start-1" onClick={() => set(b, a)} disabled={!a || !b} title="Swap A and B">
            <ArrowLeftRight className="size-4" aria-hidden /> Swap
          </button>
        </div>
      </Card>

      <ErrorBanner error={runs.error ?? cmp.error} title="Could not compare" />
      {a && b && a === b ? <EmptyState title="Choose two different runs">Comparing a run with itself has nothing to show.</EmptyState> : null}
      {!a || !b ? (
        runs.loading ? <Spinner /> : usable.length < 2 ? (
          <EmptyState title="You need two finished runs to compare">Start another scan (for example after changing your system prompt or guardrails) and come back.</EmptyState>
        ) : <Spinner label="Choosing runs" />
      ) : cmp.data ? (
        <Result c={cmp.data} a={a} b={b} />
      ) : cmp.loading ? (
        <Spinner label="Comparing" />
      ) : null}
    </>
  );
}
