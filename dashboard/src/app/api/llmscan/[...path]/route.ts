import type { NextRequest } from "next/server";

/**
 * Server-side proxy to the llmscan API.
 *
 * The browser never sees the API key: it is read from LLMSCAN_API_KEY here and attached to the
 * upstream request. Because the key is powerful, the proxy is deliberately narrow:
 *   - only the endpoints the dashboard uses are reachable (no key or project administration),
 *   - state-changing requests must be same-origin (CSRF protection),
 *   - path segments cannot climb out of /api/v1.
 */
export const dynamic = "force-dynamic";

const ALLOWED_ROOTS = new Set(["health", "meta", "me", "probes", "targets", "runs", "compare"]);
const PASS_THROUGH_HEADERS = ["content-type", "content-disposition", "content-security-policy", "cache-control"];

const apiUrl = () => (process.env.LLMSCAN_API_URL ?? "http://localhost:8000").replace(/\/+$/, "");

const problem = (status: number, detail: string) => Response.json({ detail }, { status });

function crossSite(req: NextRequest): boolean {
  const site = req.headers.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") return true;
  const origin = req.headers.get("origin");
  if (origin) {
    try {
      return new URL(origin).host !== req.headers.get("host");
    } catch {
      return true;
    }
  }
  return false;
}

async function forward(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }): Promise<Response> {
  const key = process.env.LLMSCAN_API_KEY;
  if (!key) {
    return problem(500, "The dashboard is not configured: set LLMSCAN_API_KEY on the dashboard server.");
  }
  const { path } = await ctx.params;
  if (!path.length || !ALLOWED_ROOTS.has(path[0]!) || path.some((p) => p === "." || p === ".." || p.includes("/"))) {
    return problem(404, "Not found");
  }
  const mutating = req.method !== "GET" && req.method !== "HEAD";
  if (mutating && crossSite(req)) return problem(403, "Cross-site request refused");

  const url = `${apiUrl()}/api/v1/${path.map(encodeURIComponent).join("/")}${req.nextUrl.search}`;
  const headers = new Headers({ "X-API-Key": key, Accept: req.headers.get("accept") ?? "application/json" });
  const contentType = req.headers.get("content-type");
  if (contentType) headers.set("content-type", contentType);

  let upstream: Response;
  try {
    upstream = await fetch(url, {
      method: req.method,
      headers,
      body: mutating ? await req.arrayBuffer() : undefined,
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(120_000),
    });
  } catch {
    return problem(502, `Cannot reach the scanner API at ${apiUrl()}. Is it running?`);
  }

  const out = new Headers();
  for (const name of PASS_THROUGH_HEADERS) {
    const value = upstream.headers.get(name);
    if (value) out.set(name, value);
  }
  out.set("cache-control", "no-store");
  return new Response(upstream.status === 204 ? null : upstream.body, { status: upstream.status, headers: out });
}

export { forward as GET, forward as POST, forward as PUT, forward as PATCH, forward as DELETE };
