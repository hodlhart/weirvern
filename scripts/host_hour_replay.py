"""Replay the host-hour engine against a reference it can actually use.

WHY THIS EXISTS
===============

The eval gate seeds five hours. A per-host reference needs fourteen days, so every host-hour
run so far has ended in `no-reference` -- honest, and useless for judging the decision unit.
The roadmap's exit criteria (twenty episodes a day, precision on the top twenty, canary recall)
cannot be applied to an engine that abstains on everything.

This script builds the missing half: it seeds a benign history BEFORE the attack window, builds
the reference from that history alone, then seeds the usual attack window and replays the hour
engine over it. What comes out is the first episodes/day number the hour engine has ever had,
next to the window engine's measured 1449.6.

WHAT IT CANNOT TELL YOU
=======================

The history is synthetic and benign by construction, so the reference is cleaner than any real
one. Precision here is against the seed's own attack labels -- the same caveat the scorecard
carries. And episodes are episodes: a run of two or more anomalous hours. A single anomalous
hour is deliberately not counted, here as in the engine.

USAGE
=====

    python scripts/host_hour_replay.py --days 14 --window-hours 5 --budget 20

Needs a ClickHouse it may truncate (the throwaway one the eval harness uses), not the box.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import importlib.util  # noqa: E402

from weirvern import db  # noqa: E402
from weirvern.config import Settings  # noqa: E402
from weirvern.models import host_hour  # noqa: E402

_SPEC = importlib.util.spec_from_file_location(
    "wv_eval", os.path.join(os.path.dirname(os.path.abspath(__file__)), "eval_detection.py"))
assert _SPEC is not None and _SPEC.loader is not None
EVAL = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(EVAL)

TABLES = ("flows", "flows_window", "host_hour_features", "host_reference_stats",
          "host_reference_samples", "host_hour_scores")


def seed_history(client, days: int, devices: int, seed: int, end: datetime) -> int:
    """Benign background only: no scanner, no beacon, no exfiltration, no scenarios.

    Generated and inserted one day at a time so a fortnight of history does not have to exist
    in memory at once.
    """
    from weirvern.ingester import map_flow
    from weirvern.tools.demo_flows import generate

    total = 0
    for day in range(days):
        day_start = int((end - timedelta(days=days - day)).timestamp())
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "history.jsonl")
            generate(type("A", (), {
                "minutes": 1440, "devices": devices, "output": out, "seed": seed + day,
                "scanner": False, "scan_ports": 0, "beacon": False, "exfil": False,
                "new_scenarios": False, "attack_start_minute": 0, "start": day_start,
            })())
            rows = []
            with open(out) as fh:
                for line in fh:
                    if line.strip():
                        rows.append(map_flow(json.loads(line)))
        for i in range(0, len(rows), 20_000):
            chunk = rows[i:i + 20_000]
            client.insert("weirvern.flows", [list(r.values()) for r in chunk],
                          column_names=list(chunk[0].keys()))
        total += len(rows)
        print(f"  history day {day + 1}/{days}: {len(rows)} flows", flush=True)
    return total


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=14, help="days of benign reference history")
    ap.add_argument("--window-hours", type=int, default=5, help="attack window to replay")
    ap.add_argument("--budget", type=float, default=20.0, help="episodes per day")
    ap.add_argument("--devices", type=int, default=12)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--keep", action="store_true", help="leave the tables in place")
    args = ap.parse_args()

    client = db.connect(Settings(), retries=3, delay_s=1)
    db.apply_schema(client, Settings())
    if not args.keep:
        for t in TABLES:
            client.command(f"TRUNCATE TABLE IF EXISTS weirvern.{t}")

    window_end = datetime.now().replace(minute=0, second=0, microsecond=0)
    window_start = window_end - timedelta(hours=args.window_hours)
    history_start = window_start - timedelta(days=args.days)

    print(f"history {history_start:%Y-%m-%d %H:%M} -> {window_start:%Y-%m-%d %H:%M} "
          f"({args.days}d), window -> {window_end:%H:%M} ({args.window_hours}h)")
    t0 = time.time()
    flows = seed_history(client, args.days, args.devices, args.seed, window_start)
    print(f"history: {flows} flows in {time.time() - t0:.0f}s")

    built = host_hour.build_features(client, history_start, window_start)
    ref = host_hour.rebuild_references(client, days=args.days, now=window_start)
    print(f"history features: {built} host-hour(s); reference: {ref}")

    # The attack window, seeded exactly as the gate seeds it.
    n = EVAL.seed(client, args.window_hours * 60, args.devices, args.seed, [],
                  attack_start_minute=200, start=int(window_start.timestamp()))
    print(f"attack window: {n} flows")

    summary = host_hour.run(client, alerts_per_day=args.budget, now=window_end,
                            lookback_hours=args.window_hours)
    print(f"\ntick: {summary}")

    attack_hosts = set(EVAL.ATTACK_HOSTS)
    rows = client.query(
        "SELECT src_addr, hour, p_value FROM weirvern.host_hour_scores FINAL "
        "WHERE channel = 'fused' AND hour >= %(since)s ORDER BY src_addr, hour",
        parameters={"since": window_start}).result_rows
    by_host: dict[str, list[float]] = {}
    for host, _hour, p in rows:
        by_host.setdefault(str(host), []).append(float(p))

    alpha = summary["alpha"]
    false_episodes = 0
    covered = []
    for host, ps in by_host.items():
        anomalous = [p <= alpha for p in ps]
        runs = 0
        streak = 0
        for a in anomalous:
            streak = streak + 1 if a else 0
            if streak == 2:
                runs += 1
        if host in attack_hosts:
            if runs:
                covered.append(host)
        else:
            false_episodes += runs

    hours = args.window_hours
    print(f"\n{'host':<16}{'kind':<10}{'hours':>6}{'min p':>9}{'episodes':>10}")
    for host in sorted(by_host):
        ps = by_host[host]
        kind = "attack" if host in attack_hosts else "benign"
        eps = 0
        streak = 0
        for p in ps:
            streak = streak + 1 if p <= alpha else 0
            if streak == 2:
                eps += 1
        print(f"{host:<16}{kind:<10}{len(ps):>6}{min(ps):>9.4f}{eps:>10}")

    print(f"\nattack hosts seen: {len(covered)}/{len(attack_hosts)} "
          f"({', '.join(sorted(covered)) if covered else 'none'})")
    print(f"episodes: {summary['episodes']} total, {false_episodes} on benign hosts")
    print(f"episodes/day at this rate: {summary['episodes'] * 24 / hours:.1f}")
    print(f"budget: {args.budget}/day, alpha {alpha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
