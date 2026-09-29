"use client";

import { Check, Copy, ExternalLink } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { DetectionList, EvidenceList, Remediation } from "@/components/Evidence";
import { Transcript, ToolCallView } from "@/components/Transcript";
import { Badge, Card, CardHeader, Chip, ErrorBanner, PageHeader, SeverityBadge, Spinner, StatusBadge } from "@/components/ui";
import { api, useApi } from "@/lib/api";
import { categoryLabel, mutatorLabel } from "@/lib/format";
import type { ResultDetail } from "@/lib/types";

function reproduceCommand(r: ResultDetail, seed: unknown): string {
  const parts = ["llmscan run <your-config.yaml>", `-p ${r.probe_id}`];
  if (r.mutator !== "none") parts.push(`-m ${r.mutator}`, "--no-original");
  if (seed != null) parts.push(`--seed ${String(seed)}`);
  return parts.join(" ");
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="btn-secondary px-2 py-1 text-xs"
      onClick={() => {
        void navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
    >
      {copied ? <Check className="size-3.5" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

export function FindingView() {
  const { id, resultId } = useParams<{ id: string; resultId: string }>();
  const result = useApi(`result:${id}:${resultId}`, () => api.result(id, resultId));
  const run = useApi(`run:${id}`, () => api.run(id));
  const meta = useApi("meta", api.meta);
  const r = result.data;
  const probe = useApi(r ? `probe:${r.probe_id}` : null, () => api.probe(r!.probe_id).catch(() => null));

  if (result.error && !r) return <ErrorBanner error={result.error} title="Could not load this finding" />;
  if (!r) return <Spinner label="Loading finding" />;

  const needles = [...r.evidence, ...r.detections.flatMap((d) => d.evidence)].map((e) => e.matched ?? "");
  const cmd = reproduceCommand(r, run.data?.scan.seed);
  const failed = r.status === "fail";
  const extraTools = r.tool_calls.filter((c) => !r.transcript.some((m) => m.tool_calls.some((t) => t.id && t.id === c.id)));

  return (
    <div className="space-y-6">
      <nav className="text-sm text-slate-500" aria-label="Breadcrumb">
        <Link href="/" className="hover:text-slate-900">Runs</Link> /{" "}
        <Link href={`/runs/${id}`} className="hover:text-slate-900">{run.data?.name || run.data?.target.name || id.slice(0, 8)}</Link> /{" "}
        <span className="text-slate-900">{r.probe_id}</span>
      </nav>

      <PageHeader
        title={
          <>
            <span className="mr-2 font-mono text-lg text-slate-500">{r.probe_id}</span>
            {r.probe_name}
          </>
        }
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <StatusBadge status={r.status} kind="result" />
            <SeverityBadge severity={r.severity} />
            <Badge className="bg-white text-slate-700 ring-slate-300">{categoryLabel(r.category)}</Badge>
            <Badge className="bg-white font-mono text-slate-700 ring-slate-300">mutator: {mutatorLabel(r.mutator)}</Badge>
            <span className="text-xs">{r.latency_ms.toFixed(0)} ms · confidence {(r.confidence * 100).toFixed(0)}%</span>
          </span>
        }
      />

      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
        <span className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs font-semibold tracking-wide text-slate-500 uppercase">OWASP</span>
          {r.owasp.map((o) => (
            <Chip key={o} title={meta.data?.owasp.items[o]}>
              {o}
              {meta.data?.owasp.items[o] ? <span className="ml-1 font-sans text-slate-500">{meta.data.owasp.items[o]}</span> : null}
            </Chip>
          ))}
        </span>
        <span className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs font-semibold tracking-wide text-slate-500 uppercase">MITRE ATLAS</span>
          {r.atlas.map((a) => (
            <a key={a} href={`https://atlas.mitre.org/techniques/${a}`} target="_blank" rel="noreferrer" className="no-underline">
              <Chip title={meta.data?.atlas.techniques[a]} className="hover:bg-slate-200">
                {a}
                {meta.data?.atlas.techniques[a] ? <span className="ml-1 font-sans text-slate-500">{meta.data.atlas.techniques[a]}</span> : null}
                <ExternalLink className="ml-1 size-3 text-slate-400" aria-hidden />
              </Chip>
            </a>
          ))}
        </span>
      </div>

      {r.status === "pass" ? (
        <p className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900">The target resisted this attack. The guidance below is general hardening advice for this class of attack.</p>
      ) : null}
      {r.error ? <ErrorBanner error={r.error} title="The attempt errored" /> : null}

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <Card>
          <CardHeader title="Transcript" subtitle="Exactly what was sent and what came back. Matched evidence is highlighted." />
          <div className="px-5 py-4">
            <Transcript messages={r.transcript} needles={needles} />
            {extraTools.map((c, i) => (
              <ToolCallView key={i} call={c} needles={needles} />
            ))}
          </div>
        </Card>

        <div className="space-y-6">
          <Card>
            <CardHeader title={failed ? "Why it was flagged" : "What the detectors saw"} subtitle={r.reason || undefined} />
            <div className="space-y-3 px-5 py-4">
              {r.detections.length ? <DetectionList detections={r.detections} /> : <EvidenceList evidence={r.evidence} />}
              {!r.detections.length && !r.evidence.length ? <p className="text-sm text-slate-500">No detector produced evidence for this attempt.</p> : null}
            </div>
          </Card>

          <Card>
            <CardHeader title="Suggested fix" />
            <div className="px-5 py-4">
              {r.remediation ? <Remediation text={r.remediation} /> : <p className="text-sm text-slate-500">This probe has no remediation text.</p>}
            </div>
          </Card>

          <Card>
            <CardHeader title="About this probe" />
            <div className="space-y-3 px-5 py-4 text-sm">
              {probe.data?.description ? <p className="text-slate-700">{probe.data.description}</p> : null}
              <div className="flex flex-wrap gap-1.5">
                {r.tags.map((t) => (
                  <Chip key={t}>#{t}</Chip>
                ))}
              </div>
              {r.source_file ? <p className="font-mono text-xs text-slate-500">{r.source_file}</p> : null}
              <div>
                <div className="mb-1 flex items-center justify-between">
                  <span className="text-xs font-semibold tracking-wide text-slate-500 uppercase">Reproduce</span>
                  <CopyButton text={cmd} />
                </div>
                <pre className="overflow-x-auto rounded-lg bg-slate-900 px-3 py-2 font-mono text-xs text-slate-100">{cmd}</pre>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
