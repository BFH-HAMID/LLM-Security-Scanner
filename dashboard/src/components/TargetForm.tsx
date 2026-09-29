"use client";

import clsx from "clsx";
import { TYPE_HELP, TYPE_LABEL, type TargetDraft, type TargetType } from "@/lib/drafts";
import { emptyDraft } from "@/lib/drafts";
import type { ReactNode } from "react";

function Field({ label, hint, children, wide }: { label: string; hint?: ReactNode; children: ReactNode; wide?: boolean }) {
  return (
    <div className={wide ? "sm:col-span-2" : undefined}>
      <label className="label">{label}</label>
      {children}
      {hint ? <p className="mt-1 text-xs text-slate-500">{hint}</p> : null}
    </div>
  );
}

const TYPES = Object.keys(TYPE_LABEL) as TargetType[];

export function TargetForm({ draft, onChange, editing }: { draft: TargetDraft; onChange: (d: TargetDraft) => void; editing: boolean }) {
  const set = <K extends keyof TargetDraft>(key: K, value: TargetDraft[K]) => onChange({ ...draft, [key]: value });
  const t = draft.type;

  return (
    <div className="space-y-5">
      <div>
        <span className="label">What are you testing?</span>
        <div className="grid grid-cols-2 gap-2 lg:grid-cols-5" role="radiogroup" aria-label="Target type">
          {TYPES.map((type) => (
            <button
              key={type}
              type="button"
              role="radio"
              aria-checked={t === type}
              disabled={editing && t !== type}
              onClick={() => onChange({ ...emptyDraft(type), name: draft.name })}
              className={clsx(
                "rounded-lg border px-3 py-2 text-left text-sm font-medium transition",
                t === type ? "border-brand-600 bg-brand-50 text-brand-700 ring-1 ring-brand-600" : "border-slate-300 bg-white text-slate-700 hover:bg-slate-50",
                editing && t !== type && "cursor-not-allowed opacity-40",
              )}
            >
              {TYPE_LABEL[type]}
            </button>
          ))}
        </div>
        <p className="mt-2 text-xs text-slate-500">{TYPE_HELP[t]}</p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name" hint="Shown in run lists and reports." wide>
          <input className="input" value={draft.name} onChange={(e) => set("name", e.target.value)} placeholder="Acme support bot (staging)" required />
        </Field>

        {t === "demo" ? (
          <>
            <Field label="Defences" hint="weak = no protection; hardened = input + output filters, tool allow-list.">
              <select className="input" value={draft.level} onChange={(e) => set("level", e.target.value)}>
                {["weak", "medium", "hardened"].map((v) => (
                  <option key={v}>{v}</option>
                ))}
              </select>
            </Field>
            <Field label="Surface" hint="chat, a RAG assistant with documents, or an agent with tools.">
              <select className="input" value={draft.surface} onChange={(e) => set("surface", e.target.value)}>
                {["chat", "rag", "agent"].map((v) => (
                  <option key={v}>{v}</option>
                ))}
              </select>
            </Field>
          </>
        ) : null}

        {t === "http" ? (
          <>
            <Field label="Endpoint URL" wide>
              <input className="input font-mono" value={draft.url} onChange={(e) => set("url", e.target.value)} placeholder="http://localhost:8080/chat" />
            </Field>
            <Field label="Method">
              <select className="input" value={draft.method} onChange={(e) => set("method", e.target.value)}>
                {["POST", "PUT", "PATCH", "GET"].map((v) => (
                  <option key={v}>{v}</option>
                ))}
              </select>
            </Field>
            <Field label="Reply path (JSONPath)" hint="Where the answer text sits in the response, e.g. $.choices[0].message.content">
              <input className="input font-mono" value={draft.responsePath} onChange={(e) => set("responsePath", e.target.value)} />
            </Field>
            <Field label="Request body (JSON template)" hint="Placeholders: {{prompt}}, {{messages}}, {{system}}, {{conversation_id}}" wide>
              <textarea className="input h-28 font-mono text-xs" spellCheck={false} value={draft.body} onChange={(e) => set("body", e.target.value)} />
            </Field>
            <Field label="Extra headers" hint="One per line: Name: value" wide>
              <textarea className="input h-16 font-mono text-xs" spellCheck={false} value={draft.headers} onChange={(e) => set("headers", e.target.value)} placeholder="X-Tenant: staging" />
            </Field>
            <Field label="Authentication">
              <select className="input" value={draft.authType} onChange={(e) => set("authType", e.target.value as TargetDraft["authType"])}>
                <option value="none">None</option>
                <option value="bearer">Bearer token</option>
                <option value="basic">Basic (user / password)</option>
                <option value="header">Custom header</option>
              </select>
            </Field>
            {draft.authType === "bearer" ? (
              <Field label="Token" hint="Stored on the server and masked afterwards.">
                <input className="input font-mono" type="password" autoComplete="off" value={draft.authToken} onChange={(e) => set("authToken", e.target.value)} />
              </Field>
            ) : null}
            {draft.authType === "basic" ? (
              <>
                <Field label="Username">
                  <input className="input" value={draft.authUser} onChange={(e) => set("authUser", e.target.value)} autoComplete="off" />
                </Field>
                <Field label="Password">
                  <input className="input" type="password" value={draft.authPass} onChange={(e) => set("authPass", e.target.value)} autoComplete="off" />
                </Field>
              </>
            ) : null}
            {draft.authType === "header" ? (
              <>
                <Field label="Header name">
                  <input className="input font-mono" value={draft.authHeader} onChange={(e) => set("authHeader", e.target.value)} placeholder="X-API-Key" />
                </Field>
                <Field label="Header value">
                  <input className="input font-mono" type="password" value={draft.authValue} onChange={(e) => set("authValue", e.target.value)} autoComplete="off" />
                </Field>
              </>
            ) : null}
            <Field label="Tool calls path (optional)" hint="JSONPath to tool/function calls in the reply, so agent probes can see them.">
              <input className="input font-mono" value={draft.toolCallsPath} onChange={(e) => set("toolCallsPath", e.target.value)} placeholder="$.tool_calls" />
            </Field>
          </>
        ) : null}

        {t === "openai" || t === "anthropic" || t === "ollama" ? (
          <>
            <Field label="Base URL" hint={t === "openai" ? "Include /v1 for OpenAI-compatible servers." : undefined}>
              <input className="input font-mono" value={draft.baseUrl} onChange={(e) => set("baseUrl", e.target.value)} />
            </Field>
            <Field label="Model">
              <input className="input font-mono" value={draft.model} onChange={(e) => set("model", e.target.value)} placeholder={t === "ollama" ? "llama3.1" : t === "anthropic" ? "claude-…" : "gpt-4o-mini"} />
            </Field>
            {t !== "ollama" ? (
              <Field label="API key" hint="Stored on the server and masked afterwards. Leave empty for endpoints that need no key (e.g. a local vLLM)." wide>
                <input className="input font-mono" type="password" autoComplete="off" value={draft.apiKey} onChange={(e) => set("apiKey", e.target.value)} />
              </Field>
            ) : null}
          </>
        ) : null}
      </div>

      {t !== "demo" ? (
        <details className="rounded-lg border border-slate-200 bg-slate-50/60 px-4 py-3" open={!!(draft.canaries || draft.fragments || draft.sensitive || draft.systemPrompt)}>
          <summary className="cursor-pointer text-sm font-semibold text-slate-800">Detection context (recommended)</summary>
          <p className="mt-2 text-xs text-slate-600">
            Plant secrets in your <em>test</em> deployment, then list them here. Any response that reveals one is reported as a leak, with certainty rather than guesswork.
          </p>
          <div className="mt-3 grid gap-4 sm:grid-cols-2">
            <Field label="Canary tokens" hint="One per line: name=value, e.g. system=CANARY-9f3a…">
              <textarea className="input h-20 font-mono text-xs" spellCheck={false} value={draft.canaries} onChange={(e) => set("canaries", e.target.value)} />
            </Field>
            <Field label="System prompt fragments" hint="Distinctive phrases from your real system prompt (one per line).">
              <textarea className="input h-20 text-xs" spellCheck={false} value={draft.fragments} onChange={(e) => set("fragments", e.target.value)} />
            </Field>
            <Field label="Known sensitive values" hint="Seeded PII, keys or documents that must never appear.">
              <textarea className="input h-20 font-mono text-xs" spellCheck={false} value={draft.sensitive} onChange={(e) => set("sensitive", e.target.value)} />
            </Field>
            {t === "openai" || t === "anthropic" || t === "ollama" ? (
              <Field label="Test-time system prompt" hint="Sent with every request. Use {{canary}} to embed the first canary.">
                <textarea className="input h-20 text-xs" spellCheck={false} value={draft.systemPrompt} onChange={(e) => set("systemPrompt", e.target.value)} />
              </Field>
            ) : null}
          </div>
        </details>
      ) : null}
    </div>
  );
}
