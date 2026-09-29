"use client";

import { GitCompareArrows, Plus, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { RunsTable } from "@/components/RunsTable";
import { Card, EmptyState, ErrorBanner, PageHeader, Spinner, Stat } from "@/components/ui";
import { api, useApi } from "@/lib/api";
import { isActive } from "@/lib/format";

const PAGE = 20;
const STATUSES = ["", "running", "queued", "completed", "failed", "cancelled"];

export default function RunsPage() {
  const router = useRouter();
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<string[]>([]);

  const runs = useApi(
    `runs:${status}:${page}`,
    () => api.runs({ status, limit: PAGE, offset: page * PAGE }),
    (d) => (d.items.some((r) => isActive(r.status)) ? 2500 : false),
  );

  const items = runs.data?.items ?? [];
  const total = runs.data?.total ?? 0;
  const active = items.filter((r) => isActive(r.status)).length;
  const latest = items.find((r) => r.status === "completed");
  const toggle = (id: string) =>
    setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : s.length >= 2 ? [s[1]!, id] : [...s, id]));

  const compare = () => {
    // A is the older run ("before"), B the newer one ("after").
    const [a, b] = items
      .filter((r) => selected.includes(r.id))
      .sort((x, y) => x.created_at.localeCompare(y.created_at));
    if (a && b) router.push(`/compare?a=${a.id}&b=${b.id}`);
  };

  return (
    <>
      <PageHeader
        title="Runs"
        subtitle="Every scan, newest first. Select two runs to see what changed between them."
        actions={
          <>
            <button type="button" className="btn-secondary" disabled={selected.length !== 2} onClick={compare}>
              <GitCompareArrows className="size-4" aria-hidden /> Compare selected
            </button>
            <Link href="/config" className="btn-primary no-underline">
              <Plus className="size-4" aria-hidden /> New scan
            </Link>
          </>
        }
      />

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Total runs" value={runs.data ? total : "-"} />
        <Stat label="Running now" value={runs.data ? active : "-"} tone={active ? "warn" : undefined} />
        <Stat
          label="Latest risk score"
          value={latest?.risk_score != null ? `${Math.round(latest.risk_score)} · ${latest.grade}` : "-"}
          hint={latest ? (latest.name ?? latest.target.name) : undefined}
          tone={latest?.risk_score != null && latest.risk_score >= 50 ? "bad" : undefined}
        />
        <Stat
          label="Successful attacks (latest)"
          value={latest ? latest.findings : "-"}
          tone={latest && latest.findings > 0 ? "bad" : latest ? "good" : undefined}
        />
      </div>

      <ErrorBanner error={runs.error} title="Could not load runs" />

      <Card>
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 px-5 py-3">
          <label className="flex items-center gap-2 text-sm text-slate-600">
            Status
            <select
              className="input w-auto py-1.5"
              value={status}
              onChange={(e) => {
                setStatus(e.target.value);
                setPage(0);
                setSelected([]);
              }}
            >
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s || "All"}
                </option>
              ))}
            </select>
          </label>
          <span className="text-xs text-slate-500">
            {selected.length ? `${selected.length}/2 selected · ` : ""}
            {total} run{total === 1 ? "" : "s"}
          </span>
        </div>

        {runs.loading && !runs.data ? (
          <Spinner label="Loading runs" />
        ) : items.length ? (
          <RunsTable runs={items} selected={selected} onToggle={toggle} />
        ) : (
          <EmptyState
            icon={<ShieldCheck className="size-10" />}
            title={status ? `No ${status} runs` : "No scans yet"}
            action={
              status ? undefined : (
                <Link href="/config" className="btn-primary no-underline">
                  <Plus className="size-4" aria-hidden /> Start your first scan
                </Link>
              )
            }
          >
            {status
              ? "Try another status filter."
              : "Point llmscan at a chat endpoint, RAG app or agent you are authorised to test. The built-in demo app is a safe place to start."}
          </EmptyState>
        )}

        {total > PAGE ? (
          <div className="flex items-center justify-between border-t border-slate-100 px-5 py-3 text-sm text-slate-600">
            <button type="button" className="btn-secondary py-1" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
              Previous
            </button>
            <span>
              Page {page + 1} of {Math.ceil(total / PAGE)}
            </span>
            <button type="button" className="btn-secondary py-1" disabled={(page + 1) * PAGE >= total} onClick={() => setPage((p) => p + 1)}>
              Next
            </button>
          </div>
        ) : null}
      </Card>
    </>
  );
}
