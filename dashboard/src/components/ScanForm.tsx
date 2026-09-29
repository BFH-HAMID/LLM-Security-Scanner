"use client";

import clsx from "clsx";
import { ShieldAlert } from "lucide-react";
import { SEVERITIES, categoryLabel } from "@/lib/format";
import type { ScanDraft } from "@/lib/drafts";
import type { Meta } from "@/lib/types";

const ETHICS = "https://github.com/BFH-HAMID/LLM-Security-Scanner/blob/main/docs/ETHICS.md";

function Toggle({ on, onClick, children, title }: { on: boolean; onClick: () => void; children: React.ReactNode; title?: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={on}
      title={title}
      className={clsx(
        "rounded-full border px-3 py-1 text-xs font-medium transition",
        on ? "border-brand-600 bg-brand-50 text-brand-700" : "border-slate-300 bg-white text-slate-600 hover:bg-slate-50",
      )}
    >
      {children}
    </button>
  );
}

const num = "input";

export function ScanForm({
  scan,
  onChange,
  meta,
  publicTarget,
}: {
  scan: ScanDraft;
  onChange: (s: ScanDraft) => void;
  meta: Meta | undefined;
  publicTarget: boolean;
}) {
  const set = <K extends keyof ScanDraft>(key: K, value: ScanDraft[K]) => onChange({ ...scan, [key]: value });
  const toggle = (key: "categories" | "mutators", value: string) =>
    set(key, scan[key].includes(value) ? scan[key].filter((x) => x !== value) : [...scan[key], value]);

  return (
    <div className="space-y-8">
      <section aria-labelledby="sel">
        <h3 id="sel" className="mb-1 text-sm font-semibold text-slate-900">Probe selection</h3>
        <p className="mb-3 text-xs text-slate-500">Leave everything unselected to run the whole library.</p>
        <div className="flex flex-wrap gap-2">
          {meta?.categories.map((c) => (
            <Toggle key={c.key} on={scan.categories.includes(c.key)} onClick={() => toggle("categories", c.key)} title={c.description}>
              {categoryLabel(c.key)} <span className="opacity-60">({c.probes})</span>
            </Toggle>
          ))}
        </div>
        <div className="mt-4 grid gap-4 sm:grid-cols-3">
          <div>
            <label className="label">Minimum severity</label>
            <select className="input" value={scan.minSeverity} onChange={(e) => set("minSeverity", e.target.value)}>
              <option value="">Any</option>
              {SEVERITIES.filter((s) => s !== "info").map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="label">Max probes</label>
            <input className={num} type="number" min={1} placeholder="no limit" value={scan.maxProbes} onChange={(e) => set("maxProbes", e.target.value)} />
          </div>
          <div>
            <label className="label">Repeats per attack</label>
            <input className={num} type="number" min={1} max={50} value={scan.repeats} onChange={(e) => set("repeats", Math.max(1, Number(e.target.value) || 1))} />
          </div>
        </div>
      </section>

      <section aria-labelledby="mut">
        <h3 id="mut" className="mb-1 text-sm font-semibold text-slate-900">Mutators</h3>
        <p className="mb-3 text-xs text-slate-500">Re-send every attack in disguise (encoded, translated, role-played) to see whether your filters only catch the plain version.</p>
        <div className="flex flex-wrap gap-2">
          {meta?.mutators.map((m) => (
            <Toggle key={m.name} on={scan.mutators.includes(m.name)} onClick={() => toggle("mutators", m.name)} title={m.description}>
              {m.name}
            </Toggle>
          ))}
        </div>
        <label className="mt-3 flex items-center gap-2 text-sm text-slate-700">
          <input type="checkbox" className="size-4 accent-red-600" checked={scan.includeOriginal} onChange={(e) => set("includeOriginal", e.target.checked)} />
          Also run the plain, unmodified prompts
        </label>
      </section>

      <section aria-labelledby="rate">
        <h3 id="rate" className="mb-1 text-sm font-semibold text-slate-900">Rate limits and judging</h3>
        <p className="mb-3 text-xs text-slate-500">Be kind to shared systems. Public targets default to 2 requests per second.</p>
        <div className="grid gap-4 sm:grid-cols-4">
          <div>
            <label className="label">Requests / second</label>
            <input className={num} type="number" min={0.1} step={0.1} placeholder="default" value={scan.rps} onChange={(e) => set("rps", e.target.value)} />
          </div>
          <div>
            <label className="label">Concurrency</label>
            <input className={num} type="number" min={1} max={64} value={scan.concurrency} onChange={(e) => set("concurrency", Math.max(1, Number(e.target.value) || 1))} />
          </div>
          <div>
            <label className="label">Retries</label>
            <input className={num} type="number" min={0} max={10} value={scan.retries} onChange={(e) => set("retries", Math.max(0, Number(e.target.value) || 0))} />
          </div>
          <div>
            <label className="label">Timeout (s)</label>
            <input className={num} type="number" min={1} placeholder="default" value={scan.timeout} onChange={(e) => set("timeout", e.target.value)} />
          </div>
          <div>
            <label className="label">Judge</label>
            <select className="input" value={scan.judgeMode} onChange={(e) => set("judgeMode", e.target.value as ScanDraft["judgeMode"])}>
              <option value="auto">Auto</option>
              <option value="llm">LLM judge</option>
              <option value="heuristic">Heuristic only</option>
              <option value="off">Rules only</option>
            </select>
          </div>
          {scan.judgeMode === "llm" ? (
            <div className="sm:col-span-2">
              <label className="label">Judge model</label>
              <input className="input font-mono" placeholder="ollama:llama3.1" value={scan.judgeTarget} onChange={(e) => set("judgeTarget", e.target.value)} />
            </div>
          ) : null}
          <div>
            <label className="label">Seed</label>
            <input className={num} type="number" placeholder="random" value={scan.seed} onChange={(e) => set("seed", e.target.value)} />
          </div>
        </div>
        <label className="mt-3 flex items-center gap-2 text-sm text-slate-700">
          <input type="checkbox" className="size-4 accent-red-600" checked={scan.redact} onChange={(e) => set("redact", e.target.checked)} />
          Mask secrets and PII in stored transcripts
        </label>
      </section>

      <section aria-labelledby="auth" className={clsx("rounded-xl border px-4 py-4", publicTarget ? "border-amber-300 bg-amber-50" : "border-slate-200 bg-slate-50/60")}>
        <h3 id="auth" className="mb-1 flex items-center gap-2 text-sm font-semibold text-slate-900">
          <ShieldAlert className="size-4 text-amber-600" aria-hidden /> Authorisation
        </h3>
        <p className="mb-3 text-xs text-slate-600">
          {publicTarget
            ? "This target is on a public host. llmscan only tests systems you own or are explicitly authorised to test."
            : "This target looks local or private. Public hosts require an explicit acknowledgement."}{" "}
          <a href={ETHICS} target="_blank" rel="noreferrer" className="underline">Read the policy</a>.
        </p>
        <label className="flex items-start gap-2 text-sm text-slate-800">
          <input type="checkbox" className="mt-0.5 size-4 accent-red-600" checked={scan.acknowledged} onChange={(e) => set("acknowledged", e.target.checked)} />
          <span>I own this system or have written authorisation to test it.</span>
        </label>
        {scan.acknowledged ? (
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <div>
              <label className="label">Basis of authorisation</label>
              <input className="input" placeholder="e.g. our staging deployment; ticket SEC-142" value={scan.authNote} onChange={(e) => set("authNote", e.target.value)} />
            </div>
            <div>
              <label className="label">Contact</label>
              <input className="input" placeholder="security@example.com" value={scan.authContact} onChange={(e) => set("authContact", e.target.value)} />
            </div>
          </div>
        ) : null}
      </section>
    </div>
  );
}
