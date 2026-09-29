import clsx from "clsx";
import { Wrench } from "lucide-react";
import type { Message, ToolCall } from "@/lib/types";

const ROLE_LABEL: Record<Message["role"], string> = {
  system: "System prompt",
  user: "Attacker",
  assistant: "Target",
  tool: "Tool result",
};

const ROLE_STYLE: Record<Message["role"], string> = {
  system: "border border-dashed border-slate-300 bg-slate-50 text-slate-600",
  user: "bg-slate-100 text-slate-900",
  assistant: "border border-slate-200 bg-white text-slate-900 shadow-sm",
  tool: "bg-slate-900 font-mono text-xs text-slate-100",
};

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Wrap every occurrence of the given strings in <mark>. Text only: nothing is ever parsed as HTML. */
export function Highlight({ text, needles }: { text: string; needles: string[] }) {
  const parts = [...new Set(needles.filter((n) => n && n.length >= 2))].sort((a, b) => b.length - a.length).map(escapeRegExp);
  if (!parts.length) return <>{text}</>;
  const pieces = text.split(new RegExp(`(${parts.join("|")})`, "gi"));
  return (
    <>
      {pieces.map((p, i) =>
        i % 2 ? (
          <mark key={i} className="rounded bg-red-200 px-0.5 font-semibold text-red-900">
            {p}
          </mark>
        ) : (
          <span key={i}>{p}</span>
        ),
      )}
    </>
  );
}

export function ToolCallView({ call, needles }: { call: ToolCall; needles: string[] }) {
  const args = JSON.stringify(call.arguments, null, 2);
  return (
    <div className={clsx("mt-2 rounded-lg border px-3 py-2 font-mono text-xs", call.blocked ? "border-slate-200 bg-slate-50 text-slate-600" : "border-red-200 bg-red-50 text-red-900")}>
      <div className="mb-1 flex items-center gap-1.5 font-sans font-semibold">
        <Wrench className="size-3.5" aria-hidden />
        {call.name}
        {call.blocked ? <span className="rounded bg-slate-200 px-1.5 text-[10px] font-medium text-slate-700">blocked by the app’s guard</span> : <span className="rounded bg-red-200 px-1.5 text-[10px] font-medium text-red-900">attempted</span>}
      </div>
      <pre className="break-words whitespace-pre-wrap">
        <Highlight text={args} needles={needles} />
      </pre>
    </div>
  );
}

export function Transcript({ messages, needles }: { messages: Message[]; needles: string[] }) {
  return (
    <ol className="space-y-3" aria-label="Conversation transcript">
      {messages.map((m, i) => (
        <li key={i} className={clsx("flex", m.role === "assistant" ? "justify-end" : "justify-start")}>
          <div className={clsx("max-w-[94%] min-w-[40%] rounded-2xl px-4 py-3 text-sm", ROLE_STYLE[m.role])}>
            <div className="mb-1 flex items-center gap-2 text-[11px] font-semibold tracking-wide uppercase opacity-70">
              {ROLE_LABEL[m.role]}
              {m.name ? <span className="normal-case">({m.name})</span> : null}
              <span className="ml-auto font-normal normal-case opacity-70">turn {Math.floor(i / 2) + 1}</span>
            </div>
            <div className="max-h-96 overflow-y-auto break-words whitespace-pre-wrap">
              {m.content ? <Highlight text={m.content} needles={m.role === "user" || m.role === "system" ? [] : needles} /> : <em className="opacity-60">(empty)</em>}
            </div>
            {m.tool_calls.map((c, j) => (
              <ToolCallView key={j} call={c} needles={needles} />
            ))}
          </div>
        </li>
      ))}
    </ol>
  );
}
