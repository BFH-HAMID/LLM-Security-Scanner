"use client";

import clsx from "clsx";
import { GitCompareArrows, ListChecks, Plus, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { api, useApi } from "@/lib/api";

const NAV = [
  { href: "/", label: "Runs", icon: ListChecks, match: (p: string) => p === "/" || p.startsWith("/runs") },
  { href: "/config", label: "New scan", icon: Plus, match: (p: string) => p.startsWith("/config") },
  { href: "/compare", label: "Compare", icon: GitCompareArrows, match: (p: string) => p.startsWith("/compare") },
];

const ETHICS = "https://github.com/BFH-HAMID/LLM-Security-Scanner/blob/main/docs/ETHICS.md";

function ApiStatus() {
  const { data, error } = useApi("health", api.health, () => 15000);
  const ok = data?.status === "ok" && !error;
  return (
    <div className="flex items-center gap-2 text-xs text-slate-400" title={error ? error.message : `queue: ${data?.queue ?? "?"}`}>
      <span className={clsx("size-2 rounded-full", data === undefined && !error ? "bg-slate-500" : ok ? "bg-emerald-400" : "bg-red-500")} />
      {error ? "API unreachable" : data ? `API ${data.version} · ${data.queue}` : "connecting"}
    </div>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col bg-slate-950 px-4 py-5 text-slate-200 md:flex">
        <Link href="/" className="mb-8 flex items-center gap-2.5 px-2 text-white no-underline">
          <span className="flex size-8 items-center justify-center rounded-lg bg-brand-600">
            <ShieldAlert className="size-5" aria-hidden />
          </span>
          <span className="text-base font-semibold tracking-tight">llmscan</span>
        </Link>
        <nav className="flex flex-1 flex-col gap-1" aria-label="Main">
          {NAV.map(({ href, label, icon: Icon, match }) => (
            <Link
              key={href}
              href={href}
              aria-current={match(pathname) ? "page" : undefined}
              className={clsx(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium no-underline transition-colors",
                match(pathname) ? "bg-slate-800 text-white" : "text-slate-400 hover:bg-slate-900 hover:text-white",
              )}
            >
              <Icon className="size-4" aria-hidden /> {label}
            </Link>
          ))}
        </nav>
        <div className="space-y-3 border-t border-slate-800 px-2 pt-4">
          <ApiStatus />
          <p className="text-[11px] leading-snug text-slate-500">
            Authorised testing only. Scan systems you own or have written permission to test.{" "}
            <a href={ETHICS} target="_blank" rel="noreferrer" className="text-slate-300 underline">
              Ethics policy
            </a>
          </p>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex items-center justify-between bg-slate-950 px-4 py-3 text-white md:hidden">
          <Link href="/" className="flex items-center gap-2 font-semibold no-underline">
            <ShieldAlert className="size-5 text-brand-500" aria-hidden /> llmscan
          </Link>
          <nav className="flex gap-4 text-sm" aria-label="Main">
            {NAV.map(({ href, label }) => (
              <Link key={href} href={href} className="no-underline opacity-80 hover:opacity-100">
                {label}
              </Link>
            ))}
          </nav>
        </div>
        <main className="mx-auto w-full max-w-[1280px] flex-1 px-4 py-6 sm:px-8 sm:py-8">{children}</main>
      </div>
    </div>
  );
}
