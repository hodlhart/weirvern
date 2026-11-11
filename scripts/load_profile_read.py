#!/usr/bin/env python3
"""Read-only console load profile.

It drives the same read routes an operator uses, concurrently, and records latency and errors.
It does not write a setting, a rule or a row. Run it against a running deployment:

    WEIRVERN_BASE=http://127.0.0.1:30088 WEIRVERN_TOKEN_FILE=/path/to/token \
        python3 scripts/load_profile_read.py --seconds 120 --workers 8
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

PATHS = (
    "/api/health",
    "/api/anomalies?limit=50",
    "/api/findings?limit=50",
    "/api/settings",
    "/api/update",
)


def one(base: str, token: str, path: str) -> tuple[str, float, int]:
    req = urllib.request.Request(base.rstrip("/") + path, headers={"X-Weirvern-Token": token})
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - operator-supplied URL
            body = resp.read()
            return path, (time.perf_counter() - started) * 1000.0, 200 if body else resp.status
    except urllib.error.HTTPError as exc:
        return path, (time.perf_counter() - started) * 1000.0, exc.code
    except Exception:  # noqa: BLE001 - a failed sample is data
        return path, (time.perf_counter() - started) * 1000.0, 0


def pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * q))))
    return ordered[idx]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", default=os.environ.get("WEIRVERN_BASE", "http://127.0.0.1:30088"))
    ap.add_argument("--token-file", default=os.environ.get("WEIRVERN_TOKEN_FILE"))
    ap.add_argument("--seconds", type=int, default=120)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    if not args.token_file:
        ap.error("--token-file or WEIRVERN_TOKEN_FILE is required")
    token = Path(args.token_file).read_text().strip()

    samples: dict[str, list[float]] = {p: [] for p in PATHS}
    errors: dict[str, int] = {p: 0 for p in PATHS}
    started = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        while time.time() - started < args.seconds:
            futures = [pool.submit(one, args.base, token, p) for p in PATHS]
            for fut in as_completed(futures):
                path, ms, code = fut.result()
                samples[path].append(ms)
                if code != 200:
                    errors[path] += 1

    report = {
        "base": args.base,
        "seconds": args.seconds,
        "workers": args.workers,
        "paths": {
            p: {
                "n": len(samples[p]),
                "errors": errors[p],
                "p50_ms": round(statistics.median(samples[p]), 1) if samples[p] else None,
                "p95_ms": round(pct(samples[p], 0.95), 1) if samples[p] else None,
                "p99_ms": round(pct(samples[p], 0.99), 1) if samples[p] else None,
            }
            for p in PATHS
        },
    }
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n")
    return 1 if any(v["errors"] for v in report["paths"].values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
