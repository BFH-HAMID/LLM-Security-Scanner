#!/usr/bin/env python3
"""Fill a running llmscan API with demo runs so the dashboard has something to show.

    python scripts/seed_demo.py --api http://localhost:8000 --key $LLMSCAN_API_KEY

It scans the built-in vulnerable demo app at three defence levels (weak, medium, hardened), with and
without mutators, then marks the hardened run as the baseline. Everything runs in-process on the API
server: no external system is contacted.
"""

from __future__ import annotations

import argparse
import sys
import time

import httpx

TARGETS = [
    ("Acme support bot - weak prompt", {"type": "demo", "level": "weak", "surface": "chat"}),
    ("Acme support bot - filtered", {"type": "demo", "level": "medium", "surface": "chat"}),
    ("Acme support bot - hardened", {"type": "demo", "level": "hardened", "surface": "chat"}),
    ("Acme ops agent - tools enabled", {"type": "demo", "level": "medium", "surface": "agent"}),
]


def wait(client: httpx.Client, run_id: str, timeout: float = 300) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        run = client.get(f"/runs/{run_id}").raise_for_status().json()
        if run["status"] in ("completed", "failed", "cancelled"):
            return run
        time.sleep(0.4)
    raise TimeoutError(run_id)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--api", default="http://localhost:8000", help="API base URL")
    ap.add_argument("--key", required=True, help="API key (X-API-Key)")
    ap.add_argument("--force", action="store_true", help="seed even if runs already exist")
    args = ap.parse_args()

    with httpx.Client(
        base_url=args.api.rstrip("/") + "/api/v1", headers={"X-API-Key": args.key}, timeout=60
    ) as client:
        if (
            not args.force
            and client.get("/runs", params={"limit": 1}).raise_for_status().json()["total"]
        ):
            print("The API already has runs; use --force to add more.")
            return 0
        ids: dict[str, str] = {}
        for name, config in TARGETS:
            tid = (
                client.post("/targets", json={"name": name, "config": config})
                .raise_for_status()
                .json()["id"]
            )
            ids[name] = tid

        plan = [
            (TARGETS[0][0], "weak: plain prompts", {"seed": 1}),
            (
                TARGETS[0][0],
                "weak: with encodings",
                {"seed": 1, "mutators": ["base64", "rot13", "roleplay"]},
            ),
            (TARGETS[1][0], "filtered: plain prompts", {"seed": 1}),
            (
                TARGETS[1][0],
                "filtered: with encodings",
                {"seed": 1, "mutators": ["base64", "rot13", "roleplay"]},
            ),
            (
                TARGETS[3][0],
                "agent: tool abuse",
                {"seed": 1, "categories": ["excessive_agency", "indirect_injection"]},
            ),
            (TARGETS[2][0], "hardened: plain prompts", {"seed": 1}),
            (
                TARGETS[2][0],
                "hardened: with encodings",
                {"seed": 1, "mutators": ["base64", "rot13", "roleplay"]},
            ),
        ]
        hardened = None
        for target, label, scan in plan:
            run = (
                client.post("/runs", json={"target_id": ids[target], "name": label, "scan": scan})
                .raise_for_status()
                .json()
            )
            done = wait(client, run["id"])
            print(
                f"{label:28} {done['status']:10} risk {done['risk_score']} grade {done['grade']} findings {done['findings']}"
            )
            if label == "hardened: plain prompts":
                hardened = (ids[target], done["id"])
        if hardened:
            client.put(
                f"/targets/{hardened[0]}/baseline", json={"run_id": hardened[1]}
            ).raise_for_status()
            print("Marked the hardened run as that target's baseline.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
