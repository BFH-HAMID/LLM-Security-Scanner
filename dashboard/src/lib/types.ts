/** Shapes returned by the llmscan REST API (see api/schemas.py and scanner/models.py). */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ResultStatus = "pass" | "fail" | "error" | "inconclusive";
export type RunStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface Progress {
  done: number;
  total: number;
}

export interface TargetSummary {
  type: string;
  name: string;
  url?: string;
  base_url?: string;
  model?: string;
  level?: string;
  surface?: string;
  method?: string;
}

export interface RunSummary {
  id: string;
  name: string | null;
  status: RunStatus;
  target_id: string | null;
  target: TargetSummary;
  risk_score: number | null;
  grade: string | null;
  findings: number;
  progress: Progress;
  error: string | null;
  duration_s: number;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface Counter {
  total: number;
  failed: number;
}

export interface CategoryScore {
  category: string;
  title: string;
  total: number;
  passed: number;
  failed: number;
  errors: number;
  inconclusive: number;
  asr: number;
  weighted_asr: number;
  ci_low: number;
  ci_high: number;
  risk: number;
  by_severity: Record<string, Counter>;
  owasp: string[];
  atlas: string[];
}

export interface MutatorScore {
  mutator: string;
  total: number;
  failed: number;
  asr: number;
}

export interface ScoreCard {
  risk_score: number;
  grade: string;
  band: string;
  asr: number;
  weighted_asr: number;
  total: number;
  passed: number;
  failed: number;
  errors: number;
  inconclusive: number;
  highest_severity_failed: Severity | null;
  categories: Record<string, CategoryScore>;
  severities: Record<string, Counter>;
  mutators: Record<string, MutatorScore>;
  owasp: Record<string, Counter>;
}

export interface Authorization {
  acknowledged: boolean;
  scope: string;
  host: string | null;
  via: string;
  note: string;
  contact: string;
  recorded_at: string;
}

export interface RunDetail extends RunSummary {
  score: ScoreCard | null;
  notes: string[];
  authorization: Authorization | null;
  scan: Record<string, unknown>;
  summary: Record<string, unknown>;
}

export interface RunList {
  items: RunSummary[];
  total: number;
}

export interface Evidence {
  detector: string;
  kind: string;
  description: string;
  matched: string | null;
  start: number | null;
  end: number | null;
  source: "response" | "tool_call" | "transcript";
  turn: number | null;
  confidence: number;
}

export interface ToolCall {
  name: string;
  arguments: Record<string, unknown>;
  id: string | null;
  result: unknown;
  blocked: boolean;
}

export interface Message {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  tool_calls: ToolCall[];
  name: string | null;
  tool_call_id: string | null;
}

export interface Detection {
  detector: string;
  matched: boolean | null;
  confidence: number;
  reason: string;
  evidence: Evidence[];
  meta: Record<string, unknown>;
}

export interface ResultItem {
  id: string;
  probe_id: string;
  probe_name: string;
  category: string;
  severity: Severity;
  owasp: string[];
  atlas: string[];
  tags: string[];
  mutator: string;
  repeat: number;
  status: ResultStatus;
  confidence: number;
  reason: string;
  evidence: Evidence[];
  latency_ms: number;
  error: string | null;
  started_at: string;
  source_file: string | null;
}

export interface ResultDetail extends ResultItem {
  transcript: Message[];
  response_text: string;
  tool_calls: ToolCall[];
  detections: Detection[];
  remediation: string;
  meta: Record<string, unknown>;
}

export interface ResultList {
  items: ResultItem[];
  total: number;
}

export interface HeatCell {
  status: ResultStatus;
  failed: number;
  total: number;
}

export interface HeatRow {
  probe_id: string;
  probe_name: string;
  category: string;
  severity: Severity;
  cells: Record<string, HeatCell>;
}

export interface Heatmap {
  mutators: string[];
  rows: HeatRow[];
}

export interface KeyChange {
  key: string;
  probe_id: string;
  probe_name: string;
  mutator: string;
  category: string;
  severity: Severity;
  before: string;
  after: string;
  fail_rate_before: number;
  fail_rate_after: number;
}

export interface CategoryDelta {
  category: string;
  title: string;
  asr_a: number;
  asr_b: number;
  risk_a: number;
  risk_b: number;
  delta: number;
}

export interface Comparison {
  a_id: string;
  b_id: string;
  a_name: string;
  b_name: string;
  risk_a: number;
  risk_b: number;
  grade_a: string;
  grade_b: string;
  risk_delta: number;
  verdict: "better" | "worse" | "mixed" | "unchanged";
  categories: CategoryDelta[];
  regressions: KeyChange[];
  fixed: KeyChange[];
  still_failing: KeyChange[];
  new_probes: string[];
  removed_probes: string[];
}

export interface RegressionItem {
  key: string;
  probe_id: string;
  probe_name: string;
  mutator: string;
  severity: Severity;
  reason: string;
  fail_rate_before: number | null;
  fail_rate_after: number;
}

export interface BaselineCheck {
  ok: boolean;
  risk_before: number;
  risk_after: number;
  risk_delta: number;
  tolerance: number;
  regressions: RegressionItem[];
  improvements: number;
  message: string;
}

export interface TargetRecord {
  id: string;
  name: string;
  type: string;
  config: Record<string, unknown>;
  baseline_run_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface CategoryMeta {
  key: string;
  title: string;
  description: string;
  owasp: string[];
  atlas: string[];
  probes: number;
}

export interface Meta {
  version: string;
  categories: CategoryMeta[];
  severities: Severity[];
  mutators: { name: string; description: string }[];
  owasp: { edition: string; items: Record<string, string> };
  atlas: { version: string; techniques: Record<string, string>; mitigations: Record<string, string> };
}

export interface ProbeListItem {
  id: string;
  name: string;
  category: string;
  severity: Severity;
  kind: string;
  owasp: string[];
  atlas: string[];
  tags: string[];
  description: string;
}

export interface ProbeDetail extends ProbeListItem {
  spec: Record<string, unknown>;
  remediation: string;
}

export interface Health {
  status: string;
  version: string;
  queue: string;
}
