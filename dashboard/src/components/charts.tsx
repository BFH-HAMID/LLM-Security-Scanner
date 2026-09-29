"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { SEVERITIES, categoryLabel, mutatorLabel, riskColor } from "@/lib/format";
import type { ScoreCard } from "@/lib/types";

const CATEGORY_ORDER = [
  "prompt_injection",
  "indirect_injection",
  "jailbreak",
  "system_prompt_extraction",
  "sensitive_data_leakage",
  "insecure_output_handling",
  "excessive_agency",
];

const legend = (value: string) => <span className="text-slate-600">{value}</span>;

const TIP = { borderRadius: 10, border: "1px solid #e2e8f0", fontSize: 12, boxShadow: "0 4px 12px rgb(0 0 0 / 0.08)" };

export interface RadarSeries {
  name: string;
  color: string;
  /** category key -> attack success rate, 0..1 */
  values: Record<string, number>;
}

export function seriesFromScore(name: string, color: string, score: ScoreCard): RadarSeries {
  return { name, color, values: Object.fromEntries(Object.values(score.categories).map((c) => [c.category, c.asr])) };
}

/** Attack success rate per category. Falls back to bars when fewer than three axes exist. */
export function CategoryRadar({ series, height = 300 }: { series: RadarSeries[]; height?: number }) {
  const keys = CATEGORY_ORDER.filter((k) => series.some((s) => k in s.values));
  const data = keys.map((k) => ({
    key: k,
    label: categoryLabel(k),
    ...Object.fromEntries(series.map((s) => [s.name, Math.round((s.values[k] ?? 0) * 100)])),
  }));
  if (keys.length < 3) {
    return (
      <ResponsiveContainer width="100%" height={Math.max(120, keys.length * 60)}>
        <BarChart data={data} layout="vertical" margin={{ left: 16, right: 24 }}>
          <XAxis type="number" domain={[0, 100]} tickFormatter={(v) => `${v}%`} />
          <YAxis type="category" dataKey="label" width={120} />
          <Tooltip contentStyle={TIP} formatter={(v) => `${v}%`} />
          {series.map((s) => (
            <Bar key={s.name} dataKey={s.name} fill={s.color} radius={4} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    );
  }
  return (
    <ResponsiveContainer width="100%" height={height}>
      <RadarChart data={data} outerRadius="68%" margin={{ top: 8, right: 44, bottom: 8, left: 44 }}>
        <PolarGrid stroke="#e2e8f0" />
        <PolarAngleAxis dataKey="label" tick={{ fontSize: 12, fill: "#475569" }} />
        <PolarRadiusAxis
          angle={90}
          domain={[0, 100]}
          tickCount={5}
          tickFormatter={(v: number) => (v === 100 || v === 0 ? "" : `${v}%`)}
          tick={{ fontSize: 10, fill: "#94a3b8" }}
          axisLine={false}
        />
        {series.map((s) => (
          <Radar
            key={s.name}
            name={s.name}
            dataKey={s.name}
            stroke={s.color}
            fill={s.color}
            fillOpacity={series.length > 1 ? 0.18 : 0.3}
            strokeWidth={2}
            isAnimationActive={false}
          />
        ))}
        <Tooltip contentStyle={TIP} formatter={(v) => `${v}% of attacks succeeded`} />
        {series.length > 1 ? <Legend wrapperStyle={{ fontSize: 12 }} formatter={legend} /> : null}
      </RadarChart>
    </ResponsiveContainer>
  );
}

/** Attempts per severity, split into "attack succeeded" and "resisted". */
export function SeverityChart({ score, height = 260 }: { score: ScoreCard; height?: number }) {
  const data = SEVERITIES.filter((s) => score.severities[s]?.total).map((s) => {
    const c = score.severities[s]!;
    return { severity: s, failed: c.failed, resisted: c.total - c.failed };
  });
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -12 }}>
        <CartesianGrid vertical={false} stroke="#f1f5f9" />
        <XAxis dataKey="severity" tick={{ fontSize: 12, fill: "#475569" }} tickLine={false} />
        <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
        <Tooltip contentStyle={TIP} cursor={{ fill: "#f8fafc" }} />
        <Legend wrapperStyle={{ fontSize: 12 }} formatter={legend} />
        <Bar dataKey="failed" name="Attack succeeded" stackId="a" fill="#dc2626" isAnimationActive={false} />
        <Bar dataKey="resisted" name="Resisted" stackId="a" fill="#a7f3d0" radius={[4, 4, 0, 0]} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  );
}

/** Which obfuscations get past the defences: ASR per mutator, highest first. */
export function MutatorChart({ score }: { score: ScoreCard }) {
  const data = Object.values(score.mutators)
    .filter((m) => m.total > 0)
    .sort((a, b) => b.asr - a.asr)
    .map((m) => ({ name: mutatorLabel(m.mutator), asr: Math.round(m.asr * 100), failed: m.failed, total: m.total }));
  return (
    <ResponsiveContainer width="100%" height={Math.max(160, data.length * 30 + 40)}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 28, top: 4, bottom: 4 }}>
        <CartesianGrid horizontal={false} stroke="#f1f5f9" />
        <XAxis type="number" domain={[0, 100]} tickFormatter={(v) => `${v}%`} tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} />
        <YAxis type="category" dataKey="name" width={92} tick={{ fontSize: 12, fill: "#475569" }} tickLine={false} />
        <Tooltip
          contentStyle={TIP}
          cursor={{ fill: "#f8fafc" }}
          formatter={(v, _n, item) => [`${v}% (${item.payload.failed}/${item.payload.total})`, "Attack success"]}
        />
        <Bar dataKey="asr" radius={[0, 4, 4, 0]} isAnimationActive={false}>
          {data.map((d) => (
            <Cell key={d.name} fill={riskColor(d.asr)} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

/** Grouped bars: ASR of run A vs run B for every category. */
export function CategoryDeltaChart({
  rows,
  labelA,
  labelB,
}: {
  rows: { category: string; asr_a: number; asr_b: number }[];
  labelA: string;
  labelB: string;
}) {
  const data = rows.map((r) => ({ label: categoryLabel(r.category), [labelA]: Math.round(r.asr_a * 100), [labelB]: Math.round(r.asr_b * 100) }));
  return (
    <ResponsiveContainer width="100%" height={280}>
      <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -12 }}>
        <CartesianGrid vertical={false} stroke="#f1f5f9" />
        <XAxis dataKey="label" tick={{ fontSize: 11, fill: "#475569" }} tickLine={false} interval={0} />
        <YAxis domain={[0, 100]} tickFormatter={(v) => `${v}%`} tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
        <Tooltip contentStyle={TIP} cursor={{ fill: "#f8fafc" }} formatter={(v) => `${v}%`} />
        <Legend wrapperStyle={{ fontSize: 12 }} formatter={legend} />
        <Bar dataKey={labelA} fill="#94a3b8" radius={[4, 4, 0, 0]} isAnimationActive={false} />
        <Bar dataKey={labelB} fill="#dc2626" radius={[4, 4, 0, 0]} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  );
}
