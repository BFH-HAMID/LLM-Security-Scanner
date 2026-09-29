import { CheckCircle2, CircleSlash, XCircle } from "lucide-react";
import { pct } from "@/lib/format";
import type { Detection, Evidence } from "@/lib/types";
import { Chip } from "./ui";

const DETECTOR_LABEL: Record<string, string> = {
  rules: "Rules (regex, secrets, PII, tool calls)",
  canary: "Canary tokens",
  judge: "LLM / heuristic judge",
};

export function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  if (!evidence.length) return null;
  return (
    <ul className="mt-2 space-y-2">
      {evidence.map((e, i) => (
        <li key={i} className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <Chip>{e.kind}</Chip>
            <span className="text-slate-700">{e.description}</span>
            {e.turn != null ? <span className="text-xs text-slate-400">turn {e.turn + 1}</span> : null}
            <span className="ml-auto text-xs text-slate-400">{e.source.replace("_", " ")}</span>
          </div>
          {e.matched ? (
            <pre className="mt-1.5 max-h-32 overflow-auto rounded bg-white px-2 py-1 font-mono text-xs break-words whitespace-pre-wrap text-red-800 ring-1 ring-red-200">{e.matched}</pre>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

function Verdict({ matched }: { matched: boolean | null }) {
  if (matched === null) {
    return (
      <span className="inline-flex items-center gap-1 text-slate-500">
        <CircleSlash className="size-4" aria-hidden /> abstained
      </span>
    );
  }
  return matched ? (
    <span className="inline-flex items-center gap-1 font-medium text-red-700">
      <XCircle className="size-4" aria-hidden /> attack succeeded
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-emerald-700">
      <CheckCircle2 className="size-4" aria-hidden /> no evidence
    </span>
  );
}

export function DetectionList({ detections }: { detections: Detection[] }) {
  return (
    <ul className="space-y-3">
      {detections.map((d) => (
        <li key={d.detector} className="rounded-xl border border-slate-200 px-4 py-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-sm font-semibold text-slate-900">{DETECTOR_LABEL[d.detector] ?? d.detector}</span>
            <span className="flex items-center gap-3 text-sm">
              <Verdict matched={d.matched} />
              {d.matched !== null ? <span className="text-xs text-slate-500">confidence {pct(d.confidence)}</span> : null}
            </span>
          </div>
          {d.reason ? <p className="mt-1 text-sm text-slate-600">{d.reason}</p> : null}
          <EvidenceList evidence={d.evidence} />
        </li>
      ))}
    </ul>
  );
}

/** Renders remediation text: paragraphs, and "- " / "1. " lines as lists. Plain text only. */
export function Remediation({ text }: { text: string }) {
  const blocks = text.trim().split(/\n{2,}/);
  return (
    <div className="space-y-3 text-sm leading-relaxed text-slate-700">
      {blocks.map((block, i) => {
        const lines = block.split("\n").map((l) => l.trim()).filter(Boolean);
        const bullets = lines.every((l) => /^([-*•]|\d+[.)])\s+/.test(l));
        if (bullets) {
          return (
            <ul key={i} className="list-disc space-y-1 pl-5">
              {lines.map((l, j) => (
                <li key={j}>{l.replace(/^([-*•]|\d+[.)])\s+/, "")}</li>
              ))}
            </ul>
          );
        }
        return <p key={i}>{lines.join(" ")}</p>;
      })}
    </div>
  );
}
