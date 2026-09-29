"use client";

import clsx from "clsx";
import { Fragment, useMemo } from "react";
import { SEVERITY_COLOR, categoryLabel, mutatorLabel } from "@/lib/format";
import type { HeatCell, Heatmap as HeatmapData } from "@/lib/types";

const CELL: Record<string, string> = {
  fail: "bg-red-500 hover:ring-red-700",
  pass: "bg-emerald-200 hover:ring-emerald-500",
  inconclusive: "bg-amber-300 hover:ring-amber-600",
  error: "bg-slate-300 hover:ring-slate-500",
};

function cellTitle(probe: string, mutator: string, cell: HeatCell | undefined): string {
  if (!cell) return `${probe} x ${mutator}: not run`;
  const verdict = { fail: "attack succeeded", pass: "resisted", inconclusive: "inconclusive", error: "error" }[cell.status];
  return `${probe} x ${mutator}: ${verdict}${cell.total > 1 ? ` (${cell.failed}/${cell.total} repeats succeeded)` : ""}`;
}

export function Heatmap({
  data,
  onSelect,
  selected,
  onlyFailing,
}: {
  data: HeatmapData;
  onSelect: (probeId: string, mutator: string) => void;
  selected?: { probe: string; mutator: string } | null;
  onlyFailing?: boolean;
}) {
  const rows = useMemo(
    () => (onlyFailing ? data.rows.filter((r) => Object.values(r.cells).some((c) => c.status === "fail")) : data.rows),
    [data.rows, onlyFailing],
  );
  const groups = useMemo(() => {
    const out: { category: string; rows: typeof rows }[] = [];
    for (const r of rows) {
      const last = out[out.length - 1];
      if (last && last.category === r.category) last.rows.push(r);
      else out.push({ category: r.category, rows: [r] });
    }
    return out;
  }, [rows]);

  const roomy = data.mutators.length <= 6;
  const cellSize = roomy ? "h-5 w-14" : "size-5";

  if (!rows.length) {
    return <p className="px-5 py-10 text-center text-sm text-slate-500">No attack succeeded against any probe: nothing to show.</p>;
  }
  return (
    <div className="max-h-[560px] overflow-auto">
      <table className="border-separate border-spacing-0 text-xs">
        <thead>
          <tr>
            <th className="sticky top-0 left-0 z-20 bg-white px-3 py-2 text-left font-semibold text-slate-500">Probe</th>
            {data.mutators.map((m) => (
              <th key={m} className="sticky top-0 z-10 bg-white px-1 pb-2 align-bottom">
                {roomy ? (
                  <div className="mx-auto w-14 truncate text-center font-medium text-slate-600" title={m}>
                    {mutatorLabel(m)}
                  </div>
                ) : (
                  <div className="mx-auto h-24 w-5 [writing-mode:vertical-rl] rotate-180 text-left font-medium whitespace-nowrap text-slate-600">
                    {mutatorLabel(m)}
                  </div>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {groups.map((g) => (
            <Fragment key={g.category}>
              <tr>
                <td colSpan={data.mutators.length + 1} className="sticky left-0 bg-slate-50 px-3 py-1.5 text-[11px] font-semibold tracking-wide text-slate-500 uppercase">
                  {categoryLabel(g.category)}
                </td>
              </tr>
              {g.rows.map((r) => (
                <tr key={r.probe_id}>
                  <th
                    scope="row"
                    className="sticky left-0 z-10 w-[380px] max-w-[380px] truncate bg-white px-3 py-[3px] text-left font-normal text-slate-700"
                    title={`${r.probe_id} ${r.probe_name} (${r.severity})`}
                  >
                    <span className="mr-2 inline-block size-2 rounded-full align-middle" style={{ backgroundColor: SEVERITY_COLOR[r.severity] }} />
                    <span className="font-mono text-[11px] text-slate-500">{r.probe_id}</span> {r.probe_name}
                  </th>
                  {data.mutators.map((m) => {
                    const cell = r.cells[m];
                    const active = selected?.probe === r.probe_id && selected.mutator === m;
                    return (
                      <td key={m} className="p-[2px] text-center">
                        {cell ? (
                          <button
                            type="button"
                            onClick={() => onSelect(r.probe_id, m)}
                            title={cellTitle(r.probe_id, m, cell)}
                            aria-label={cellTitle(r.probe_id, m, cell)}
                            className={clsx(
                              "block rounded-[5px] ring-2 ring-transparent transition",
                              cellSize,
                              CELL[cell.status],
                              active && "ring-slate-900",
                            )}
                          />
                        ) : (
                          <span className={clsx("block rounded-[5px] border border-dashed border-slate-200", cellSize)} title={cellTitle(r.probe_id, m, undefined)} />
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function HeatmapLegend() {
  const items = [
    ["bg-red-500", "Attack succeeded"],
    ["bg-emerald-200", "Resisted"],
    ["bg-amber-300", "Inconclusive"],
    ["bg-slate-300", "Error"],
  ];
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-600">
      {items.map(([c, l]) => (
        <span key={l} className="inline-flex items-center gap-1.5">
          <span className={clsx("size-3 rounded-[4px]", c)} /> {l}
        </span>
      ))}
      <span className="inline-flex items-center gap-1.5">
        <span className="size-3 rounded-[4px] border border-dashed border-slate-300" /> Not run
      </span>
    </div>
  );
}
