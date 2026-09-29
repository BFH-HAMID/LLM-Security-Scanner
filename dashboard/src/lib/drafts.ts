import { lines, parseKeyValues } from "./format";

export type TargetType = "demo" | "http" | "openai" | "anthropic" | "ollama";

export const TYPE_LABEL: Record<TargetType, string> = {
  demo: "Built-in demo app",
  http: "HTTP chat endpoint",
  openai: "OpenAI-compatible API",
  anthropic: "Anthropic API",
  ollama: "Ollama",
};

export const TYPE_HELP: Record<TargetType, string> = {
  demo: "A deliberately vulnerable app that runs inside the scanner. Safe, offline, and a good way to see what a report looks like.",
  http: "Your own chatbot, RAG app or agent behind any HTTP endpoint. Describe the request with a template.",
  openai: "A model behind the OpenAI chat-completions API: OpenAI, Azure, vLLM, LiteLLM, LM Studio and others.",
  anthropic: "A Claude model through the Anthropic Messages API.",
  ollama: "A local model served by Ollama. Point it at your own instance.",
};

export interface TargetDraft {
  type: TargetType;
  name: string;
  // http
  url: string;
  method: string;
  headers: string;
  authType: "none" | "bearer" | "basic" | "header";
  authToken: string;
  authUser: string;
  authPass: string;
  authHeader: string;
  authValue: string;
  body: string;
  responsePath: string;
  toolCallsPath: string;
  // model endpoints
  baseUrl: string;
  model: string;
  apiKey: string;
  // demo
  level: string;
  surface: string;
  // what the scanner should look for
  systemPrompt: string;
  canaries: string;
  fragments: string;
  sensitive: string;
}

const BASE_URLS: Record<string, string> = {
  openai: "https://api.openai.com/v1",
  anthropic: "https://api.anthropic.com",
  ollama: "http://localhost:11434",
};

export function emptyDraft(type: TargetType = "demo"): TargetDraft {
  return {
    type,
    name: "",
    url: "",
    method: "POST",
    headers: "",
    authType: "none",
    authToken: "",
    authUser: "",
    authPass: "",
    authHeader: "",
    authValue: "",
    body: '{\n  "message": "{{prompt}}"\n}',
    responsePath: "$.reply",
    toolCallsPath: "",
    baseUrl: BASE_URLS[type] ?? "",
    model: "",
    apiKey: "",
    level: "weak",
    surface: "chat",
    systemPrompt: "",
    canaries: "",
    fragments: "",
    sensitive: "",
  };
}

export function parseCanaries(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  lines(text).forEach((line, i) => {
    const eq = line.indexOf("=");
    if (eq > 0) out[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
    else out[i === 0 ? "canary" : `canary_${i + 1}`] = line;
  });
  return out;
}

/** Form state -> the JSON the API expects. Throws an Error with a readable message on bad input. */
export function toConfig(d: TargetDraft): Record<string, unknown> {
  const cfg: Record<string, unknown> = { type: d.type, name: d.name.trim() };
  const put = (key: string, value: unknown) => {
    if (value !== undefined && value !== "" && !(Array.isArray(value) && !value.length)) cfg[key] = value;
  };
  switch (d.type) {
    case "demo":
      cfg.level = d.level;
      cfg.surface = d.surface;
      break;
    case "http": {
      if (!d.url.trim()) throw new Error("The endpoint URL is required.");
      cfg.url = d.url.trim();
      cfg.method = d.method;
      const headers = parseKeyValues(d.headers);
      if (Object.keys(headers).length) cfg.headers = headers;
      if (d.authType === "bearer") cfg.auth = { type: "bearer", token: d.authToken };
      if (d.authType === "basic") cfg.auth = { type: "basic", username: d.authUser, password: d.authPass };
      if (d.authType === "header") cfg.auth = { type: "header", header: d.authHeader, value: d.authValue };
      try {
        cfg.body = JSON.parse(d.body);
      } catch {
        throw new Error("The request body template must be valid JSON, for example {\"message\": \"{{prompt}}\"}.");
      }
      put("response_path", d.responsePath.trim());
      put("tool_calls_path", d.toolCallsPath.trim());
      break;
    }
    case "openai":
    case "anthropic":
    case "ollama":
      if (!d.model.trim()) throw new Error("The model name is required.");
      cfg.model = d.model.trim();
      put("base_url", d.baseUrl.trim());
      if (d.type !== "ollama") put("api_key", d.apiKey);
      break;
  }
  if (d.type !== "demo") {
    put("system_prompt", d.systemPrompt);
    const canaries = parseCanaries(d.canaries);
    if (Object.keys(canaries).length) cfg.canaries = canaries;
    put("system_prompt_fragments", lines(d.fragments));
    put("known_sensitive", lines(d.sensitive));
  }
  return cfg;
}

const str = (v: unknown): string => (typeof v === "string" ? v : "");
const strList = (v: unknown): string => (Array.isArray(v) ? v.map(String).join("\n") : "");

/** Saved target -> form state (secrets arrive masked and are sent back unchanged). */
export function fromConfig(name: string, cfg: Record<string, unknown>): TargetDraft {
  const type = (str(cfg.type) || "http") as TargetType;
  const d = emptyDraft(type);
  const auth = (cfg.auth ?? {}) as Record<string, unknown>;
  const canaries = cfg.canaries && typeof cfg.canaries === "object" ? (cfg.canaries as Record<string, string>) : {};
  return {
    ...d,
    name,
    url: str(cfg.url),
    method: str(cfg.method) || "POST",
    headers: Object.entries((cfg.headers ?? {}) as Record<string, string>).map(([k, v]) => `${k}: ${v}`).join("\n"),
    authType: (str(auth.type) || "none") as TargetDraft["authType"],
    authToken: str(auth.token),
    authUser: str(auth.username),
    authPass: str(auth.password),
    authHeader: str(auth.header),
    authValue: str(auth.value),
    body: cfg.body === undefined ? d.body : JSON.stringify(cfg.body, null, 2),
    responsePath: str(cfg.response_path) || d.responsePath,
    toolCallsPath: str(cfg.tool_calls_path),
    baseUrl: str(cfg.base_url) || d.baseUrl,
    model: str(cfg.model),
    apiKey: str(cfg.api_key),
    level: str(cfg.level) || "weak",
    surface: str(cfg.surface) || "chat",
    systemPrompt: str(cfg.system_prompt),
    canaries: Object.entries(canaries).map(([k, v]) => `${k}=${v}`).join("\n"),
    fragments: strList(cfg.system_prompt_fragments),
    sensitive: strList(cfg.known_sensitive),
  };
}

const PRIVATE_SUFFIXES = [".local", ".internal", ".localhost", ".lan", ".home.arpa", ".test", ".example", ".invalid"];

/** Mirrors scanner/scope.py classify_host: the server stays authoritative, this only warns early. */
export function isPublicUrl(raw: string): boolean {
  try {
    const host = new URL(raw).hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (!host || host === "localhost" || host === "0.0.0.0" || host.endsWith(".localhost")) return false;
    const v4 = host.match(/^(\d+)\.(\d+)\.\d+\.\d+$/);
    if (v4) {
      const [a, b] = [Number(v4[1]), Number(v4[2])];
      return !(a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254));
    }
    if (host.includes(":")) return !(host === "::1" || /^f[cd]/.test(host) || host.startsWith("fe80"));
    if (!host.includes(".")) return false; // single-label names: docker/k8s services, intranet hosts
    return !PRIVATE_SUFFIXES.some((suffix) => host.endsWith(suffix));
  } catch {
    return false;
  }
}

export interface ScanDraft {
  name: string;
  categories: string[];
  minSeverity: string;
  mutators: string[];
  includeOriginal: boolean;
  repeats: number;
  maxProbes: string;
  rps: string;
  concurrency: number;
  retries: number;
  timeout: string;
  seed: string;
  judgeMode: "auto" | "heuristic" | "llm" | "off";
  judgeTarget: string;
  redact: boolean;
  acknowledged: boolean;
  authNote: string;
  authContact: string;
}

export const emptyScan = (): ScanDraft => ({
  name: "",
  categories: [],
  minSeverity: "",
  mutators: [],
  includeOriginal: true,
  repeats: 1,
  maxProbes: "",
  rps: "",
  concurrency: 4,
  retries: 3,
  timeout: "",
  seed: "",
  judgeMode: "auto",
  judgeTarget: "",
  redact: false,
  acknowledged: false,
  authNote: "",
  authContact: "",
});

export function toScan(s: ScanDraft): Record<string, unknown> {
  const out: Record<string, unknown> = {
    categories: s.categories,
    mutators: s.mutators,
    include_original: s.includeOriginal,
    repeats: s.repeats,
    concurrency: s.concurrency,
    retries: s.retries,
    redact: s.redact,
    judge: { mode: s.judgeMode, ...(s.judgeMode === "llm" ? { target: s.judgeTarget.trim() } : {}) },
  };
  if (s.minSeverity) out.min_severity = s.minSeverity;
  if (s.maxProbes) out.max_probes = Number(s.maxProbes);
  if (s.rps) out.rps = Number(s.rps);
  if (s.timeout) out.timeout = Number(s.timeout);
  if (s.seed) out.seed = Number(s.seed);
  return out;
}
