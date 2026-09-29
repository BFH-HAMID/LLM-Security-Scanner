import { dateTime } from "@/lib/format";
import type { RunDetail } from "@/lib/types";
import { Card, CardHeader } from "./ui";

const list = (v: unknown, empty: string): string => (Array.isArray(v) && v.length ? v.join(", ") : empty);

export function ScanSettings({ run }: { run: RunDetail }) {
  const scan = run.scan as Record<string, unknown>;
  const sum = run.summary as Record<string, unknown>;
  const judge = (scan.judge as { mode?: string; target?: string } | undefined) ?? {};
  const auth = run.authorization;
  const rows: [string, string][] = [
    ["Probes run", String(sum.probes ?? "-")],
    ["Categories", list(scan.categories, "all")],
    ["Mutators", list(sum.mutators ?? scan.mutators, "none (plain prompts only)")],
    ["Repeats per attack", String(scan.repeats ?? 1)],
    ["Seed", scan.seed == null ? "random" : String(scan.seed)],
    ["Judge", judge.target ? `${judge.mode} (${judge.target})` : (judge.mode ?? String(sum.judge ?? "auto"))],
    ["Concurrency", String(scan.concurrency ?? "-")],
    ["Rate limit", scan.rps ? `${scan.rps} req/s` : "default"],
    ["Canaries", Array.isArray(sum.canaries) && sum.canaries.length ? sum.canaries.join(", ") : "-"],
    ["Scope", auth ? `${auth.scope}${auth.host ? ` (${auth.host})` : ""}` : "-"],
    ["Authorisation", auth ? `${auth.acknowledged ? "acknowledged" : "not acknowledged"} via ${auth.via}${auth.note ? `: ${auth.note}` : ""}` : "-"],
    ["Recorded", auth ? dateTime(auth.recorded_at) : "-"],
  ];
  return (
    <Card>
      <CardHeader title="Scan settings" subtitle="Everything needed to reproduce this run." />
      <dl className="grid gap-x-8 gap-y-3 px-5 py-4 text-sm sm:grid-cols-2 lg:grid-cols-3">
        {rows.map(([k, v]) => (
          <div key={k}>
            <dt className="text-xs font-medium text-slate-500">{k}</dt>
            <dd className="mt-0.5 break-words text-slate-900">{v}</dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}
