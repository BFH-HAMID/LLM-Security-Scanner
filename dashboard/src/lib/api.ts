"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type {
  BaselineCheck,
  Comparison,
  Health,
  Heatmap,
  Meta,
  ProbeDetail,
  ProbeListItem,
  ResultDetail,
  ResultList,
  RunDetail,
  RunList,
  TargetRecord,
} from "./types";

/** Every call goes through the dashboard's own server, which adds the API key. */
const BASE = "/api/llmscan";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

function errorMessage(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      // FastAPI validation errors: [{loc: [...], msg: "..."}]
      return detail
        .map((d) => {
          const loc = Array.isArray(d?.loc) ? d.loc.filter((x: unknown) => x !== "body").join(".") : "";
          return loc ? `${loc}: ${d?.msg}` : String(d?.msg ?? d);
        })
        .join("; ");
    }
  }
  return fallback;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    ...init,
    headers: { Accept: "application/json", ...(init?.body ? { "Content-Type": "application/json" } : {}) },
    cache: "no-store",
  });
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let body: unknown = undefined;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    /* not JSON */
  }
  if (!res.ok) throw new ApiError(res.status, errorMessage(body, `${res.status} ${res.statusText}`));
  return body as T;
}

const qs = (params: Record<string, string | number | boolean | undefined | null>): string => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
};

const json = (method: string, body?: unknown): RequestInit => ({
  method,
  body: body === undefined ? undefined : JSON.stringify(body),
});

export interface ResultQuery {
  status?: string;
  category?: string;
  severity?: string;
  probe_id?: string;
  mutator?: string;
  limit?: number;
  offset?: number;
}

export const api = {
  health: () => request<Health>("/health"),
  meta: () => request<Meta>("/meta"),
  runs: (q: { status?: string; target_id?: string; limit?: number; offset?: number } = {}) =>
    request<RunList>(`/runs${qs(q)}`),
  run: (id: string) => request<RunDetail>(`/runs/${id}`),
  createRun: (body: Record<string, unknown>) => request<RunDetail>("/runs", json("POST", body)),
  cancelRun: (id: string) => request<RunDetail>(`/runs/${id}/cancel`, json("POST")),
  deleteRun: (id: string) => request<void>(`/runs/${id}`, json("DELETE")),
  results: (id: string, q: ResultQuery = {}) => request<ResultList>(`/runs/${id}/results${qs({ ...q })}`),
  result: (id: string, resultId: string) => request<ResultDetail>(`/runs/${id}/results/${resultId}`),
  heatmap: (id: string) => request<Heatmap>(`/runs/${id}/heatmap`),
  baselineCheck: (id: string) => request<BaselineCheck>(`/runs/${id}/baseline-check`),
  compare: (a: string, b: string) => request<Comparison>(`/compare${qs({ a, b })}`),
  targets: () => request<TargetRecord[]>("/targets"),
  createTarget: (name: string, config: Record<string, unknown>) =>
    request<TargetRecord>("/targets", json("POST", { name, config })),
  updateTarget: (id: string, body: { name?: string; config?: Record<string, unknown> }) =>
    request<TargetRecord>(`/targets/${id}`, json("PUT", body)),
  deleteTarget: (id: string) => request<void>(`/targets/${id}`, json("DELETE")),
  setBaseline: (targetId: string, runId: string) =>
    request<TargetRecord>(`/targets/${targetId}/baseline`, json("PUT", { run_id: runId })),
  clearBaseline: (targetId: string) => request<void>(`/targets/${targetId}/baseline`, json("DELETE")),
  probes: (q: { category?: string } = {}) => request<ProbeListItem[]>(`/probes${qs(q)}`),
  probe: (id: string) => request<ProbeDetail>(`/probes/${id}`),
  reportUrl: (id: string, format: "json" | "html" | "pdf" | "sarif" | "md") =>
    `${BASE}/runs/${id}/report?format=${format}`,
};

export interface Query<T> {
  data?: T;
  error?: ApiError;
  loading: boolean;
  reload: () => void;
}

/**
 * Tiny data hook: fetch on mount / key change, optionally poll.
 * `refresh(data)` returns the delay in ms before the next poll, or a falsy value to stop.
 */
export function useApi<T>(
  key: string | null,
  fetcher: () => Promise<T>,
  refresh?: (data: T) => number | false | undefined,
): Query<T> {
  const [state, setState] = useState<{ data?: T; error?: ApiError; loading: boolean }>({ loading: key !== null });
  const [tick, setTick] = useState(0);
  const fetcherRef = useRef(fetcher);
  const refreshRef = useRef(refresh);
  useEffect(() => {
    fetcherRef.current = fetcher;
    refreshRef.current = refresh;
  });

  useEffect(() => {
    if (key === null) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let failures = 0;
    const load = async () => {
      try {
        const data = await fetcherRef.current();
        if (cancelled) return;
        failures = 0;
        setState({ data, loading: false });
        const next = refreshRef.current?.(data);
        if (next) timer = setTimeout(load, next);
      } catch (e) {
        if (cancelled) return;
        failures += 1;
        setState((s) => ({ ...s, error: e instanceof ApiError ? e : new ApiError(0, String(e)), loading: false }));
        if (refreshRef.current && failures < 5) timer = setTimeout(load, 2000 * failures);
      }
    };
    setState((s) => ({ ...s, loading: s.data === undefined, error: undefined }));
    void load();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [key, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { ...state, reload };
}
