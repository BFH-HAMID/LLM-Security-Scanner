import type { ResultStatus, RunStatus, Severity } from "./types";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_STYLE: Record<string, string> = {
  critical: "bg-red-100 text-red-800 ring-red-600/20",
  high: "bg-orange-100 text-orange-800 ring-orange-600/20",
  medium: "bg-amber-100 text-amber-800 ring-amber-600/20",
  low: "bg-sky-100 text-sky-800 ring-sky-600/20",
  info: "bg-slate-100 text-slate-700 ring-slate-500/20",
};

export const SEVERITY_COLOR: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#0284c7",
  info: "#94a3b8",
};

export const STATUS_STYLE: Record<ResultStatus | RunStatus, string> = {
  fail: "bg-red-100 text-red-800 ring-red-600/20",
  pass: "bg-emerald-100 text-emerald-800 ring-emerald-600/20",
  inconclusive: "bg-amber-100 text-amber-800 ring-amber-600/20",
  error: "bg-slate-200 text-slate-700 ring-slate-500/20",
  queued: "bg-slate-100 text-slate-700 ring-slate-500/20",
  running: "bg-blue-100 text-blue-800 ring-blue-600/20",
  completed: "bg-emerald-100 text-emerald-800 ring-emerald-600/20",
  failed: "bg-red-100 text-red-800 ring-red-600/20",
  cancelled: "bg-slate-100 text-slate-600 ring-slate-500/20",
};

/** Result-status labels: "fail" means the *attack succeeded*, which reads backwards to newcomers. */
export const RESULT_LABEL: Record<ResultStatus, string> = {
  fail: "attack succeeded",
  pass: "resisted",
  inconclusive: "inconclusive",
  error: "error",
};

export const GRADE_COLOR: Record<string, string> = {
  A: "#059669",
  B: "#65a30d",
  C: "#d97706",
  D: "#ea580c",
  F: "#dc2626",
};

export function riskColor(score: number): string {
  if (score < 10) return GRADE_COLOR.A!;
  if (score < 25) return GRADE_COLOR.B!;
  if (score < 50) return GRADE_COLOR.C!;
  if (score < 75) return GRADE_COLOR.D!;
  return GRADE_COLOR.F!;
}

export const pct = (x: number, digits = 0): string => `${(x * 100).toFixed(digits)}%`;

export function titleCase(s: string): string {
  return s.replace(/[_-]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function duration(seconds: number): string {
  if (!seconds || seconds < 0.05) return "<0.1s";
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return m < 60 ? `${m}m ${s}s` : `${Math.floor(m / 60)}h ${m % 60}m`;
}

export function timeAgo(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "-";
  const s = Math.max(0, (now - new Date(iso).getTime()) / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  if (s < 86400 * 14) return `${Math.round(s / 86400)} d ago`;
  return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function targetLabel(t: { type?: string; name?: string; url?: string; base_url?: string; model?: string; level?: string; surface?: string }): string {
  if (t.type === "demo") return `demo app (${t.level ?? "weak"} / ${t.surface ?? "chat"})`;
  return t.name || t.model || t.url || t.base_url || "target";
}

export const isActive = (s: RunStatus): boolean => s === "queued" || s === "running";

/** `a=b` per line -> object; blank lines ignored. */
export function parseKeyValues(text: string, sep = ":"): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const i = line.indexOf(sep);
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
}

export const lines = (text: string): string[] =>
  text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

export const CATEGORY_SHORT: Record<string, string> = {
  prompt_injection: "Direct injection",
  indirect_injection: "Indirect injection",
  jailbreak: "Jailbreaks",
  system_prompt_extraction: "Prompt extraction",
  sensitive_data_leakage: "Data leakage",
  insecure_output_handling: "Output handling",
  excessive_agency: "Excessive agency",
};

export const categoryLabel = (key: string): string => CATEGORY_SHORT[key] ?? titleCase(key);

export const mutatorLabel = (m: string): string => (m === "none" ? "Plain" : m);
