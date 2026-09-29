"use client";

import clsx from "clsx";
import { Play, Plus, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import { ScanForm } from "@/components/ScanForm";
import { TargetForm } from "@/components/TargetForm";
import { Card, CardHeader, Chip, ErrorBanner, PageHeader, Spinner } from "@/components/ui";
import { api, useApi } from "@/lib/api";
import { emptyDraft, emptyScan, fromConfig, isPublicUrl, toConfig, toScan, type ScanDraft, type TargetDraft } from "@/lib/drafts";
import { timeAgo } from "@/lib/format";
import type { TargetRecord } from "@/lib/types";

const NEW = "new";

export default function ConfigPage() {
  const router = useRouter();
  const meta = useApi("meta", api.meta);
  const targets = useApi("targets", api.targets);
  const probes = useApi("probes", () => api.probes());

  const [selected, setSelected] = useState<string>(NEW);
  const [draft, setDraft] = useState<TargetDraft>(() => ({ ...emptyDraft("demo"), name: "Demo app (weak)" }));
  const [scan, setScan] = useState<ScanDraft>(emptyScan);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const saved = targets.data ?? [];
  const current = saved.find((t) => t.id === selected);

  const choose = (t: TargetRecord | null) => {
    setError(undefined);
    if (t) {
      setSelected(t.id);
      setDraft(fromConfig(t.name, t.config));
    } else {
      setSelected(NEW);
      setDraft(emptyDraft("demo"));
    }
  };

  // Land on the newest saved target so re-running a scan is one click away (first load only).
  const initialised = useRef(false);
  useEffect(() => {
    if (initialised.current || !targets.data) return;
    initialised.current = true;
    const newest = targets.data[0];
    if (newest) {
      setSelected(newest.id);
      setDraft(fromConfig(newest.name, newest.config));
    }
  }, [targets.data]);

  const url = draft.type === "http" ? draft.url : draft.type === "demo" ? "" : draft.baseUrl;
  const publicTarget = isPublicUrl(url);
  const missingAck = publicTarget && !scan.acknowledged;

  const selectedProbes = useMemo(() => {
    const list = probes.data ?? [];
    const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 } as Record<string, number>;
    let picked = list.filter((p) => (!scan.categories.length || scan.categories.includes(p.category)) && (!scan.minSeverity || rank[p.severity]! >= rank[scan.minSeverity]!));
    if (scan.maxProbes) picked = picked.slice(0, Number(scan.maxProbes));
    return picked;
  }, [probes.data, scan.categories, scan.minSeverity, scan.maxProbes]);
  const variants = (scan.includeOriginal ? 1 : 0) + scan.mutators.length;
  const attempts = selectedProbes.length * variants * scan.repeats;

  const start = async () => {
    setBusy(true);
    setError(undefined);
    try {
      if (!draft.name.trim()) throw new Error("Give the target a name so you can find its runs later.");
      const config = toConfig(draft);
      let target: TargetRecord;
      if (current) target = await api.updateTarget(current.id, { name: draft.name.trim(), config });
      else target = await api.createTarget(draft.name.trim(), config);
      const run = await api.createRun({
        target_id: target.id,
        name: scan.name.trim() || undefined,
        scan: toScan(scan),
        authorization: { acknowledged: scan.acknowledged, note: scan.authNote, contact: scan.authContact },
      });
      router.push(`/runs/${run.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      targets.reload();
      setBusy(false);
    }
  };

  const remove = async (t: TargetRecord) => {
    if (!confirm(`Delete target “${t.name}”? Its past runs are kept.`)) return;
    try {
      await api.deleteTarget(t.id);
      if (selected === t.id) choose(null);
      targets.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <>
      <PageHeader title="New scan" subtitle="Choose what to attack, which attacks to run and how gently. Targets are saved so you can re-scan and compare later." />
      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_340px]">
        <div className="space-y-6">
          <Card>
            <CardHeader
              title="Saved targets"
              actions={
                <button type="button" className="btn-secondary py-1.5" onClick={() => choose(null)}>
                  <Plus className="size-4" aria-hidden /> New target
                </button>
              }
            />
            <div className="flex flex-wrap gap-2 px-5 py-4">
              {targets.loading && !targets.data ? <Spinner label="Loading targets" /> : null}
              {!targets.loading && !saved.length ? <p className="text-sm text-slate-500">No saved targets yet. Fill in the form below; it is saved when you start the scan.</p> : null}
              {saved.map((t) => (
                <div
                  key={t.id}
                  className={clsx("group flex items-center gap-2 rounded-lg border py-1.5 pr-1.5 pl-3 text-sm", selected === t.id ? "border-brand-600 bg-brand-50" : "border-slate-300 bg-white")}
                >
                  <button type="button" className="text-left" onClick={() => choose(t)}>
                    <span className="font-medium">{t.name}</span>
                    <span className="ml-2 text-xs text-slate-500">
                      <Chip>{t.type}</Chip> {timeAgo(t.updated_at)}
                    </span>
                  </button>
                  <button type="button" className="rounded p-1 text-slate-400 hover:bg-red-50 hover:text-red-600" onClick={() => remove(t)} aria-label={`Delete ${t.name}`}>
                    <Trash2 className="size-3.5" />
                  </button>
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <CardHeader title="1. Target" subtitle={current ? `Editing “${current.name}”. Changes are saved when you start the scan.` : "A new target. It is saved when you start the scan."} />
            <div className="px-5 py-5">
              <TargetForm draft={draft} onChange={setDraft} editing={!!current} />
            </div>
          </Card>

          <Card>
            <CardHeader title="2. Scan options" />
            <div className="px-5 py-5">
              <ScanForm scan={scan} onChange={setScan} meta={meta.data} publicTarget={publicTarget} />
            </div>
          </Card>
        </div>

        <aside className="xl:sticky xl:top-6 xl:self-start">
          <Card>
            <CardHeader title="Summary" />
            <dl className="space-y-3 px-5 py-4 text-sm">
              <div className="flex justify-between gap-3"><dt className="text-slate-500">Target</dt><dd className="truncate text-right font-medium">{draft.name || "-"}</dd></div>
              <div className="flex justify-between gap-3"><dt className="text-slate-500">Probes</dt><dd className="font-medium tabular-nums">{probes.data ? selectedProbes.length : "-"}</dd></div>
              <div className="flex justify-between gap-3"><dt className="text-slate-500">Variants per probe</dt><dd className="font-medium tabular-nums">{variants}</dd></div>
              <div className="flex justify-between gap-3"><dt className="text-slate-500">Attempts</dt><dd className="font-medium tabular-nums">up to {attempts || "-"}</dd></div>
              <div className="flex justify-between gap-3"><dt className="text-slate-500">Rate limit</dt><dd className="font-medium">{scan.rps ? `${scan.rps}/s` : publicTarget ? "2/s (public default)" : "unlimited"}</dd></div>
              <div className="flex justify-between gap-3"><dt className="text-slate-500">Scope</dt><dd className={clsx("font-medium", publicTarget && "text-amber-700")}>{draft.type === "demo" ? "built-in demo" : publicTarget ? "public host" : "local / private"}</dd></div>
            </dl>
            <div className="space-y-3 border-t border-slate-100 px-5 py-4">
              <input className="input" placeholder="Run name (optional)" value={scan.name} onChange={(e) => setScan({ ...scan, name: e.target.value })} aria-label="Run name" />
              <button type="button" className="btn-primary w-full" disabled={busy || missingAck || (!!probes.data && attempts === 0)} onClick={start}>
                <Play className="size-4" aria-hidden /> {busy ? "Starting…" : "Start scan"}
              </button>
              {missingAck ? <p className="text-xs text-amber-700">Confirm your authorisation to scan a public host.</p> : null}
              <ErrorBanner error={error} title="Could not start the scan" />
            </div>
          </Card>
        </aside>
      </div>
    </>
  );
}
