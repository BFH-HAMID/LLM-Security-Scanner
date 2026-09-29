import clsx from "clsx";
import { AlertTriangle, Loader2 } from "lucide-react";
import type { ReactNode } from "react";
import { GRADE_COLOR, RESULT_LABEL, SEVERITY_STYLE, STATUS_STYLE } from "@/lib/format";
import type { ResultStatus, RunStatus } from "@/lib/types";

export function Card({ className, children }: { className?: string; children: ReactNode }) {
  return <section className={clsx("card", className)}>{children}</section>;
}

export function CardHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 px-5 py-4">
      <div>
        <h2 className="text-sm font-semibold text-slate-900">{title}</h2>
        {subtitle ? <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p> : null}
      </div>
      {actions}
    </div>
  );
}

export function Badge({ className, children, title }: { className?: string; children: ReactNode; title?: string }) {
  return (
    <span
      title={title}
      className={clsx(
        "inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ring-inset",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  return <Badge className={SEVERITY_STYLE[severity] ?? SEVERITY_STYLE.info}>{severity}</Badge>;
}

export function StatusBadge({ status, kind = "run" }: { status: RunStatus | ResultStatus; kind?: "run" | "result" }) {
  const label = kind === "result" ? RESULT_LABEL[status as ResultStatus] ?? status : status;
  return (
    <Badge className={STATUS_STYLE[status]}>
      {status === "running" ? <Loader2 className="size-3 animate-spin" aria-hidden /> : null}
      {label}
    </Badge>
  );
}

export function GradeBadge({ grade, size = "md" }: { grade: string | null; size?: "sm" | "md" | "lg" }) {
  if (!grade) return <span className="text-slate-400">-</span>;
  return (
    <span
      className={clsx(
        "inline-flex items-center justify-center rounded-lg font-bold text-white",
        size === "sm" && "size-6 text-xs",
        size === "md" && "size-8 text-sm",
        size === "lg" && "size-12 text-2xl",
      )}
      style={{ backgroundColor: GRADE_COLOR[grade] ?? "#64748b" }}
      title={`Grade ${grade}`}
    >
      {grade}
    </span>
  );
}

export function Chip({ children, title, className }: { children: ReactNode; title?: string; className?: string }) {
  return (
    <span
      title={title}
      className={clsx(
        "inline-flex items-center rounded-full bg-slate-100 px-2 py-0.5 font-mono text-[11px] text-slate-700",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: "bad" | "good" | "warn" }) {
  return (
    <div className="card px-4 py-3">
      <div className="text-xs font-medium text-slate-500">{label}</div>
      <div
        className={clsx(
          "mt-1 text-2xl font-semibold tabular-nums",
          tone === "bad" && "text-red-600",
          tone === "good" && "text-emerald-600",
          tone === "warn" && "text-amber-600",
        )}
      >
        {value}
      </div>
      {hint ? <div className="mt-0.5 text-xs text-slate-500">{hint}</div> : null}
    </div>
  );
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-sm text-slate-500" role="status">
      <Loader2 className="size-4 animate-spin" aria-hidden /> {label}...
    </div>
  );
}

export function ErrorBanner({ error, title = "Something went wrong" }: { error: { message: string } | string | undefined; title?: string }) {
  if (!error) return null;
  const message = typeof error === "string" ? error : error.message;
  return (
    <div role="alert" className="flex gap-3 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
      <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div>
        <div className="font-semibold">{title}</div>
        <div className="mt-0.5 break-words">{message}</div>
      </div>
    </div>
  );
}

export function NoteBanner({ notes }: { notes: string[] }) {
  if (!notes.length) return null;
  return (
    <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
      <div className="mb-1 flex items-center gap-2 font-semibold">
        <AlertTriangle className="size-4" aria-hidden /> Coverage notes
      </div>
      <ul className="list-disc space-y-1 pl-5">
        {notes.map((n) => (
          <li key={n}>{n}</li>
        ))}
      </ul>
    </div>
  );
}

export function EmptyState({ icon, title, children, action }: { icon?: ReactNode; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 px-6 py-14 text-center">
      {icon ? <div className="text-slate-300">{icon}</div> : null}
      <h3 className="text-base font-semibold text-slate-900">{title}</h3>
      {children ? <p className="max-w-md text-sm text-slate-500">{children}</p> : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="mb-6 flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        <h1 className="truncate text-2xl font-semibold tracking-tight text-slate-900">{title}</h1>
        {subtitle ? <div className="mt-1 text-sm text-slate-500">{subtitle}</div> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  );
}

export function ProgressBar({ done, total, className }: { done: number; total: number; className?: string }) {
  const frac = total ? Math.min(1, done / total) : 0;
  return (
    <div
      className={clsx("h-1.5 w-full overflow-hidden rounded-full bg-slate-200", className)}
      role="progressbar"
      aria-valuenow={done}
      aria-valuemax={total}
    >
      <div className="h-full rounded-full bg-blue-500 transition-all" style={{ width: `${frac * 100}%` }} />
    </div>
  );
}
