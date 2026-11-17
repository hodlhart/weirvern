#!/usr/bin/env python3
"""The replay scorecard: four numbers, two runs, one page.

WHY THIS EXISTS (ml backlog item 6, 2026-11-13): the eval gate answers a yes/no question --
did the seeded attacks reach a verdict -- and answers nothing about how much noise came with
them. "176 episodes a day, zero dispositions, no precision measured anywhere" was the state
of the engine, and every channel proposal after that point was unfalsifiable because there
was no instrument to falsify it with.

WHAT IT REPORTS

  episodes/day      distinct host-window verdicts, normalised to 24h
  precision@20      of the twenty highest-ranked verdicts, the share that land on a seeded
                    attacker. Ranked by severity, then the ensemble's own score, then time --
                    the operator's reading order, not a metric-only ordering invented here.
  canary recall     seeded scenarios that reached a final verdict inside their deadline
  time to detect    median minutes from scenario start to first qualifying verdict

and the run-to-run drift of all four. Two runs over the same pinned window must agree within
2%; anything larger means a clock, an ordering or a hash seed is leaking into detection, and
none of the other three numbers can be trusted until it is fixed.

WHAT THIS IS NOT: precision@20 here is measured against the SEED's own labels -- which hosts
were scripted to attack. It is not operator precision. Dispositions are deliberately not
training labels in this system, and there are zero of them today, so a true precision number
does not exist yet. This measures whether the top of the ranking is the attack and not the
heavy-tailed backup, which is the question a seed can answer honestly.

HOW IT RELATES TO THE PROMOTION GATE: `scripts/eval_budget.py` measures a candidate against
the baseline at a fixed alerts/day budget over the LIVE stored population, ranking by fused
score; its labels come from an operator corpus that does not exist yet. This scorecard ranks
in the operator's reading order (severity first) over a REPLAY, so it can run in CI with no
live data and no dispositions. They answer different questions, and the day a real label
corpus exists the two precision numbers must be reconciled rather than averaged.

USAGE

  python scripts/scorecard.py --minutes 300 --devices 12
  python scripts/scorecard.py --runs 1            # skip the determinism comparison
  python scripts/scorecard.py --json out.json     # machine-readable copy

Same guard as the eval: refuses to seed into anything but a local ClickHouse unless
WEIRVERN_EVAL_CONFIRM=yes, because it writes rows into weirvern.flows.
"""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import json
import os
import statistics
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

# The operator's reading order. Named here rather than inlined so the ranking is auditable.
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}

# The drift a metric may show between two identical runs before the scorecard calls it
# non-deterministic. 2% is the number the backlog item names.
DRIFT_LIMIT = 0.02

# The aggregates are five-minute buckets, so "detected immediately" means "in the bucket that
# contains the attack", not "at zero minutes". Reporting the raw bucket-start delta gives 0.0
# for every immediate detection, which reads as a broken clock. Latency is therefore measured
# to the END of the first qualifying bucket, and the resolution is stated with the number.
BUCKET_MIN = 5.0

TABLES = ("flows", "flows_aggregated", "flows_window", "flows_aggregated_diversity",
          "flows_aggregated_temporal")


def _load_eval():
    """Import the eval harness as a module.

    It is a script, not a package, so it is loaded by path. Reusing its `seed`,
    `run_detection`, `scenario_results` and `SCENARIO_SPECS` is the point: the scorecard must
    measure the SAME replay the gate measures, or the two instruments drift apart and nobody
    can say which one is wrong.
    """
    path = Path(__file__).with_name("eval_detection.py")
    spec = importlib.util.spec_from_file_location("wv_eval_detection", path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _as_dt(value) -> datetime | None:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def rank_verdicts(verdicts: list[dict]) -> list[dict]:
    """The operator's reading order: worst severity first, then the ensemble's own score."""
    return sorted(
        verdicts,
        key=lambda v: (
            -SEVERITY_RANK.get(str(v.get("severity") or ""), 0),
            -float(v.get("anomaly_score") or 0.0),
            str(v.get("window_start") or ""),
            str(v.get("src_addr") or ""),
        ),
    )


def _latency_to_bucket_end(row: dict) -> float:
    """Minutes from the scenario's start to the end of the first bucket that caught it.

    The bucket START can precede the attack, so the naive delta is negative and gets clamped to
    zero; the bucket END is the first moment the verdict could actually have been produced.
    """
    start, first = row.get("start"), row.get("first_detection")
    if start is None or first is None:
        return 0.0
    return round(max(0.0, (first - start).total_seconds() / 60.0) + BUCKET_MIN, 1)


def measure(verdicts: list[dict], *, attack_hosts: set[str], scenario_rows: list[dict],
            minutes: int, top: int = 20) -> dict:
    """Turn a verdict list into the four numbers. Pure, so the unit tests can call it."""
    episodes = [v for v in verdicts if str(v.get("src_addr") or "")]
    ranked = rank_verdicts(episodes)[:top]
    hits = sum(1 for v in ranked if str(v["src_addr"]) in attack_hosts)
    latencies = [_latency_to_bucket_end(r) for r in scenario_rows
                 if r.get("first_detection") is not None]
    passed = sum(1 for r in scenario_rows if r.get("passed"))
    return {
        "episodes": len(episodes),
        "episodes_per_day": round(len(episodes) * 1440.0 / max(1, minutes), 1),
        "precision_at_20": round(hits / len(ranked), 3) if ranked else None,
        "top20_size": len(ranked),
        "top20_hits": hits,
        "canary_recall": round(passed / len(scenario_rows), 3) if scenario_rows else None,
        "canaries": len(scenario_rows),
        "canaries_passed": passed,
        "time_to_detect_min": round(statistics.median(latencies), 1) if latencies else None,
        "time_to_detect_resolution_min": BUCKET_MIN,
    }


def drift(a, b) -> float:
    """Relative difference between two runs of one metric; 0 when both are absent."""
    if a is None or b is None:
        return 0.0 if a == b else float("inf")
    if a == 0 and b == 0:
        return 0.0
    return abs(a - b) / max(abs(a), abs(b))


def run_once(mod, *, client, settings, cfg, minutes: int, devices: int, seed: int,
             pinned_start: int) -> dict:
    """Seed, train, drain -- the same replay the gate runs, with the metrics kept."""
    for table in TABLES:
        with contextlib.suppress(Exception):
            client.command(f"TRUNCATE TABLE IF EXISTS weirvern.{table}")
    mod._reset_sweep_state(client, settings.model_dir)

    attack_start_minute = (minutes * 2) // 3
    mod.seed(client, minutes, devices, seed, [], attack_start_minute=attack_start_minute,
             start=pinned_start)
    verdicts, err = mod.run_detection(client, (settings, cfg), minutes, attack_start_minute)
    if err:
        raise SystemExit(f"replay failed: {err}")

    # `lo` comes from the DATA, exactly as the gate computes it. ClickHouse hands back naive
    # datetimes and `scenario_results` compares verdict windows (also naive) against this value;
    # building it from the pinned epoch instead gives an aware datetime and the comparison raises
    # "can't compare offset-naive and offset-aware". Measured the hard way.
    from weirvern import db as _db

    lo, _hi = _db.fetch_rows(
        client, "SELECT min(window_start), max(window_start) FROM weirvern.flows_aggregated")[0]
    attack_dt = lo + timedelta(minutes=attack_start_minute)
    by_host: dict[str, list[dict]] = {}
    for verdict in verdicts or []:
        by_host.setdefault(str(verdict.get("src_addr") or ""), []).append(verdict)
    scenario_rows = mod.scenario_results(by_host, attack_dt)
    result = measure(verdicts or [], attack_hosts=mod.ATTACK_HOSTS,
                     scenario_rows=scenario_rows, minutes=minutes)
    result["scenarios"] = [
        {"key": r["key"], "severity": r["severity"], "latency_min": r["latency_min"],
         "passed": r["passed"]}
        for r in scenario_rows
    ]
    return result


def _fmt(value, unit: str = "") -> str:
    if value is None:
        return "n/a"
    return f"{value}{unit}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=os.environ.get("CLICKHOUSE_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("CLICKHOUSE_PORT", "8123")))
    ap.add_argument("--minutes", type=int, default=300)
    ap.add_argument("--devices", type=int, default=12)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--runs", type=int, default=2,
                    help="replays to run; 2 measures the drift, 1 skips it")
    ap.add_argument("--json", default="", help="also write the result as JSON here")
    args = ap.parse_args()

    if args.host not in ("127.0.0.1", "localhost") and \
            os.environ.get("WEIRVERN_EVAL_CONFIRM") != "yes":
        print("Refusing to seed into a non-local ClickHouse without WEIRVERN_EVAL_CONFIRM=yes.")
        print("This scorecard writes rows into weirvern.flows of whatever it points at.")
        return 2

    os.environ["CLICKHOUSE_HOST"] = args.host
    os.environ["CLICKHOUSE_PORT"] = str(args.port)
    os.environ.setdefault("CLICKHOUSE_PASSWORD", "")

    from weirvern import db
    from weirvern.config import ModelConfig, Settings

    settings = Settings()
    cfg = ModelConfig()

    try:
        client = db.connect(settings, retries=3, delay_s=1)
        client.command("SELECT 1")
        from weirvern.db import apply_schema
        apply_schema(client, settings)
    except Exception as exc:  # noqa: BLE001
        print(f"  ✗ cannot reach ClickHouse at {args.host}:{args.port}: {exc}")
        return 2

    # Same anchor as the gate: the span ENDS at the most recent UTC midnight. See
    # eval_detection.py for why the start-anchored version failed CI between midnight and 05:00.
    pinned_start = (int(time.time()) // 86_400) * 86_400 - args.minutes * 60

    print(f"weirvern replay scorecard -- {args.minutes} seeded minutes, {args.devices} devices, "
          f"seed {args.seed}")
    print(f"window {datetime.fromtimestamp(pinned_start, tz=UTC).isoformat()}"
          f" .. {datetime.fromtimestamp(pinned_start + args.minutes * 60, tz=UTC).isoformat()}"
          f"  ({args.runs} run(s))")

    runs: list[dict] = []
    for i in range(max(1, args.runs)):
        t0 = time.time()
        result = run_once(_load_eval(), client=client, settings=settings, cfg=cfg,
                          minutes=args.minutes, devices=args.devices, seed=args.seed,
                          pinned_start=pinned_start)
        result["seconds"] = round(time.time() - t0, 1)
        runs.append(result)
        print(f"  run {i + 1}: {result['episodes']} episode(s), "
              f"precision@20 {_fmt(result['precision_at_20'])}, "
              f"canary recall {_fmt(result['canary_recall'])}, "
              f"ttd {_fmt(result['time_to_detect_min'], ' min')} "
              f"({result['seconds']}s)", flush=True)

    first = runs[0]
    print()
    print(f"  {'metric':<24}{'run 1':>10}{'run 2':>10}{'drift':>9}")
    for key, label, unit in (
        ("episodes_per_day", "episodes/day", ""),
        ("precision_at_20", "precision@20", ""),
        ("canary_recall", "canary recall", ""),
        ("time_to_detect_min", "time to detect", " min"),
    ):
        values = [r[key] for r in runs]
        a = values[0]
        b = values[1] if len(values) > 1 else a
        print(f"  {label:<24}{_fmt(a, unit):>10}{_fmt(b, unit):>10}"
              f"{_fmt(round(drift(a, b) * 100.0, 1), '%'):>9}")

    failures = 0
    if len(runs) > 1:
        worst = {key: drift(runs[0][key], runs[1][key]) for key in
                 ("episodes_per_day", "precision_at_20", "canary_recall",
                  "time_to_detect_min")}
        over = {k: round(v * 100.0, 1) for k, v in worst.items() if v > DRIFT_LIMIT}
        if over:
            print(f"  ✗ drift above {DRIFT_LIMIT * 100:.0f}% between identical runs: {over}")
            failures += 1
        else:
            print(f"  ✓ two runs agree within {DRIFT_LIMIT * 100:.0f}%")
    if first["canary_recall"] is not None and first["canary_recall"] < 1.0:
        missed = [s["key"] for s in first["scenarios"] if not s["passed"]]
        print(f"  ✗ canary recall {first['canary_recall']}: missed {missed}")
        failures += 1

    print()
    print("  precision@20 is against the seed's own attack labels, not operator dispositions.")
    print("  There are zero dispositions in this system; operator precision does not exist yet.")

    if args.json:
        Path(args.json).write_text(json.dumps(
            {"inputs": {"minutes": args.minutes, "devices": args.devices, "seed": args.seed,
                        "pinned_start": pinned_start, "runs": args.runs},
             "runs": runs}, indent=2) + "\n")
        print(f"  wrote {args.json}")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
