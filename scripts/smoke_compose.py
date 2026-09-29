#!/usr/bin/env python3
"""End-to-end smoke test of a running stack (standard library only).

    python scripts/smoke_compose.py --key "$LLMSCAN_API_KEY"

Checks, in order: API health, dashboard page, dashboard proxy, then a real scan of the built-in
demo target through the job queue (in Compose: Redis -> Celery worker -> Postgres), read back
through both the API and the dashboard. Exits non-zero with a reason on the first failure.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def call(
    url: str, *, key: str | None = None, body: dict | None = None, method: str | None = None
) -> tuple[int, bytes]:
    headers = {"Accept": "application/json"}
    if key:
        headers["X-API-Key"] = key
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def step(label: str, ok: bool, detail: str = "") -> None:
    print(("PASS " if ok else "FAIL ") + label + (f"  ({detail})" if detail else ""), flush=True)
    if not ok:
        sys.exit(1)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--dashboard", default="http://127.0.0.1:3000")
    ap.add_argument("--key", required=True)
    ap.add_argument("--timeout", type=int, default=240, help="seconds to wait for the scan")
    ap.add_argument(
        "--expect-queue", default="", help="fail unless the API reports this queue (e.g. celery)"
    )
    ap.add_argument(
        "--dashboard-auth", default="", help="user:password if DASHBOARD_PASSWORD is set"
    )
    args = ap.parse_args()
    api = args.api.rstrip("/") + "/api/v1"

    status, body = call(f"{api}/health")
    health = json.loads(body) if status == 200 else {}
    step(
        "API is healthy",
        status == 200 and health.get("status") == "ok",
        f"queue={health.get('queue')}",
    )
    if args.expect_queue:
        step(f"API runs jobs through {args.expect_queue}", health.get("queue") == args.expect_queue)

    status, _ = call(f"{api}/runs")
    step("API rejects requests without a key", status == 401)

    status, body = call(f"{api}/me", key=args.key)
    step("API accepts the configured key", status == 200 and json.loads(body)["is_admin"] is True)

    status, body = call(f"{args.dashboard.rstrip('/')}/")
    if args.dashboard_auth:
        step("dashboard demands a password when one is set", status == 401)
    else:
        step("dashboard serves its pages", status == 200 and b"llmscan" in body)

    tid = call(
        f"{api}/targets",
        key=args.key,
        body={"name": "smoke", "config": {"type": "demo", "level": "weak", "surface": "chat"}},
    )
    step("create a target", tid[0] == 201, str(tid[0]))
    target_id = json.loads(tid[1])["id"]

    status, body = call(
        f"{api}/runs",
        key=args.key,
        body={
            "target_id": target_id,
            "name": "smoke test",
            "scan": {"seed": 1, "categories": ["prompt_injection", "system_prompt_extraction"]},
        },
    )
    step("start a run", status == 202, str(status))
    run = json.loads(body)

    deadline = time.time() + args.timeout
    while time.time() < deadline:
        run = json.loads(call(f"{api}/runs/{run['id']}", key=args.key)[1])
        if run["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(1)
    step(
        "the run finishes",
        run["status"] == "completed",
        f"status={run['status']} error={run.get('error')}",
    )
    step(
        "the weak demo app is found vulnerable",
        run["findings"] >= 10 and run["risk_score"] >= 40,
        f"findings={run['findings']} risk={run['risk_score']}",
    )

    status, body = call(f"{api}/runs/{run['id']}/report?format=sarif", key=args.key)
    step("SARIF export works", status == 200 and json.loads(body)["version"] == "2.1.0")

    status, body = call(
        f"{api}/runs/{run['id']}/results?status=fail&limit=1&include_transcript=true", key=args.key
    )
    first = json.loads(body)["items"][0]
    step(
        "findings carry a transcript, evidence and a fix",
        bool(first["transcript"] and first["evidence"] and first["remediation"]),
    )

    if not args.dashboard_auth:
        status, body = call(f"{args.dashboard.rstrip('/')}/api/llmscan/runs/{run['id']}")
        step(
            "the dashboard proxy reads the run with its own key",
            status == 200 and json.loads(body)["id"] == run["id"],
        )
        status, _ = call(f"{args.dashboard.rstrip('/')}/api/llmscan/keys")
        step("the dashboard proxy does not expose key administration", status == 404)

    call(f"{api}/runs/{run['id']}", key=args.key, method="DELETE")
    call(f"{api}/targets/{target_id}", key=args.key, method="DELETE")
    print("\nAll smoke checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
