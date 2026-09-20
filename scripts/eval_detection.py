#!/usr/bin/env python3
"""SEEDED-ATTACK EVAL HARNESS: does the pipeline actually DETECT the attacks it exists for?

WHY THIS EXISTS (ML-1, the audit's flagship ML finding). Detection quality was never
measured. The suite passed 1000+ tests while an arity bug stopped ALL detection, because
every test asserted components in isolation -- the insert path, the scoring maths, the
fixture shapes -- and nothing asserted the end-to-end question an operator actually has:
"if a port scan happens on my network, does an alert come out the other end?"

The distinction between testing COMPONENTS and testing OUTCOMES:
    * a unit test proves the scorer adds up
    * this harness proves a seeded port scan ends as a high-severity verdict
The arity bug sat in the gap between the two, and this file is the gap closed.

HOW IT WORKS. It runs the REAL pipeline against a disposable ClickHouse:
    1. seed demo_flows output into weirvern.flows     (the real generator)
    2. let the REAL materialized views aggregate it   (no re-derived aggregation SQL here,
       deliberately -- if the MVs are broken, this harness must fail)
    3. train the REAL detectors on the benign part    (worker.build_detectors -> .train())
    4. run the REAL detection sweep                   (worker-style enrichment + ensemble)
    5. assert the seeded attacks appear in the final verdicts, and benign hosts do not
       dominate the alerts (a precision smoke check)

The seeded attacks and their expected verdicts:
    scanner  (198.51.100.10)  -> high/critical severity, T1046-class discovery
    beacon   (198.51.100.11)  -> detected at all (severity medium+)
    exfil    (198.51.100.12)  -> high severity (the volume spike)
    benign hosts              -> not high/critical  (precision smoke check)

USAGE
    # against a throwaway ClickHouse on localhost (see the CI job for the exact image):
    CLICKHOUSE_HOST=127.0.0.1 CLICKHOUSE_PORT=8123 python scripts/eval_detection.py

    # against the live deployment's ClickHouse (READ-WRITE; seeds into the real tables):
    WEIRVERN_EVAL_CONFIRM=yes python scripts/eval_detection.py --host <node-ip>

EXIT CODES: 0 all assertions passed; 1 one or more failed; 2 could not run (no database).

THIS IS NOT A BENCHMARK. It does not measure precision/recall curves; it answers the
binary question that went unasked for too long, with room to grow into the former (see
the TODOs at the bottom).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Attack hosts, by seed convention in demo_flows: devices[0..2] are the attackers.
SCANNER = "198.51.100.10"
BEACON = "198.51.100.11"
EXFIL = "198.51.100.12"
ATTACK_HOSTS = {SCANNER, BEACON, EXFIL}
BENIGN = {f"198.51.100.{13 + i}" for i in range(8)}


def _fail(msg: str) -> None:
    print(f"  ✗ {msg}")


def _ok(msg: str) -> None:
    print(f"  ✓ {msg}")


def seed(client, minutes: int, devices: int, seed: int, batch: list[str]) -> int:
    """Generate demo flows and insert them through the REAL flow table + MVs."""
    from weirvern.ingester import map_flow
    from weirvern.tools.demo_flows import generate

    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "demo.jsonl")
        generate(type("A", (), {
            "minutes": minutes, "devices": devices, "output": out, "seed": seed,
            "scanner": True, "scan_ports": 400, "beacon": True, "exfil": True,
        })())

        rows = []
        with open(out) as fh:
            for line in fh:
                if not line.strip():
                    continue
                rows.append(map_flow(json.loads(line)))

    # BATCH the insert; 60k+ rows in one call is fine for ClickHouse but slow to build,
    # so insert in chunks of 20k.
    total = 0
    for i in range(0, len(rows), 20_000):
        chunk = rows[i:i + 20_000]
        client.insert(
            "weirvern.flows",
            [list(r.values()) for r in chunk],
            column_names=list(chunk[0].keys()),
        )
        total += len(chunk)
    return total


def run_detection(client, cfg_settings, window_minutes: int):
    """The worker's REAL detection sweep, with the window widened to cover the seed.

    WHY NOT CALL detection_sweep AS-IS: it reads the last `detect_interval_s` of
    aggregates (300s by default), and the seeded data spans `window_minutes`. Widening
    the interval on a COPY of the settings object is the whole trick -- everything else
    is the worker's own code path: the same enrichment (side-table merging, Zeek joins),
    the same ensemble, the same netflow_anomalies insert. An earlier version of this
    harness re-implemented the enrichment locally, which would have made it a test of
    a COPY of the pipeline rather than of the pipeline.

    THE WINDOW COMES FROM THE DATA, NOT FROM WALL-CLOCK. demo_flows generates forward
    from "now" (t0 = start + minute*60), so several minutes of the seed are in the
    FUTURE relative to a naive `[now-48h, now]` window -- measured: that window found 12
    training rows out of 216 aggregates and IGNORED THE REST, which made the harness
    fail with "not enough data" on a database that had plenty. Reading
    min/max(window_start) and training across exactly that span removes the clock from
    the equation entirely, which is also what makes the harness deterministic.
    """
    import dataclasses

    from weirvern import db
    from weirvern.config import ModelConfig
    from weirvern.worker import build_detectors, detection_sweep

    settings, cfg = cfg_settings

    lo, hi = db.fetch_rows(
        client, "SELECT min(window_start), max(window_start) FROM weirvern.flows_aggregated")[0]
    margin = timedelta(minutes=6)
    start_dt, end_dt = lo - margin, hi + margin

    # The sweep's `since = now - interval_s` must be <= lo so every seeded window is in
    # scope, whether the seed sits in the past or the future relative to now.
    interval_s = max(0, int((datetime.now() - lo).total_seconds())) + 1200
    widened = dataclasses.replace(settings, detect_interval_s=interval_s)

    detectors = build_detectors(settings, cfg)
    if_model, gb_model, db_model, bl_model = detectors
    if not if_model.train(start_dt, end_dt, client):
        return None, ("Isolation Forest could not train on the seeded window "
                      f"[{start_dt} .. {end_dt}]")
    if if_model.X_train_unscaled is not None:
        gb_model.train(if_model, if_model.X_train_unscaled, start_dt, end_dt, client)
    db_model.train(start_dt, end_dt, client)
    bl_model.train(start_dt, end_dt, client)

    verdicts = detection_sweep(client, detectors, widened, cfg)
    return verdicts, None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=os.environ.get("CLICKHOUSE_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("CLICKHOUSE_PORT", "8123")))
    ap.add_argument("--minutes", type=int, default=90,
                    help="simulated minutes to seed (more = more training data)")
    ap.add_argument("--devices", type=int, default=12)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    if args.host not in ("127.0.0.1", "localhost") and \
            os.environ.get("WEIRVERN_EVAL_CONFIRM") != "yes":
        print("Refusing to seed into a non-local ClickHouse without WEIRVERN_EVAL_CONFIRM=yes.")
        print("This harness writes rows into weirvern.flows of whatever it points at.")
        return 2

    os.environ["CLICKHOUSE_HOST"] = args.host
    os.environ["CLICKHOUSE_PORT"] = str(args.port)
    os.environ.setdefault("CLICKHOUSE_PASSWORD", "")

    from weirvern import db
    from weirvern.config import ModelConfig, Settings

    settings = Settings()
    cfg = ModelConfig()

    print(f"Seeded-attack eval against {args.host}:{args.port}")
    try:
        client = db.connect(settings, retries=3, delay_s=1)
        client.command("SELECT 1")
    except Exception as exc:  # noqa: BLE001
        print(f"  ✗ cannot reach ClickHouse: {exc}")
        return 2

    # Ensure schema (idempotent; a fresh container needs it).
    try:
        from weirvern.db import apply_schema
        apply_schema(client, settings)
    except Exception as exc:  # noqa: BLE001
        print(f"  ! schema bootstrap said: {exc} -- continuing if tables already exist")

    # Start clean so a re-run is deterministic. The harness owns this database.
    for t in ("flows", "flows_aggregated", "flows_aggregated_diversity",
              "flows_aggregated_temporal", "netflow_anomalies"):
        try:
            client.command(f"TRUNCATE TABLE IF EXISTS weirvern.{t}")
        except Exception:  # noqa: BLE001
            pass

    t0 = time.time()
    n = seed(client, args.minutes, args.devices, args.seed, [])
    print(f"  seeded {n} flows ({time.time() - t0:.1f}s)")

    # The MVs populate asynchronously via their insert triggers; poll briefly.
    for _ in range(20):
        rows = db.fetch_rows(client, "SELECT count() FROM weirvern.flows_aggregated")
        if rows and rows[0][0] > 0:
            break
        time.sleep(0.5)
    agg = db.fetch_rows(client, "SELECT count() FROM weirvern.flows_aggregated")[0][0]
    print(f"  flows_aggregated: {agg} rows")
    if agg == 0:
        _fail("the materialized view produced no aggregates -- detection cannot run")
        return 1

    verdicts, err = run_detection(client, (settings, cfg), args.minutes)
    if err:
        _fail(err)
        return 1
    print(f"  verdicts: {len(verdicts or [])}")

    # ── ASSERTIONS ─────────────────────────────────────────────────────────────
    failures = 0

    by_host: dict[str, list[dict]] = {}
    for v in verdicts or []:
        by_host.setdefault(v["src_addr"], []).append(v)

    def worst_severity(host: str) -> str:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}
        best = ""
        for v in by_host.get(host, []):
            if order.get(str(v.get("severity")), 0) > order.get(best, 0):
                best = str(v.get("severity"))
        return best

    # 1. THE SCANNER. A /400-port sweep is the most legible attack there is.
    sev = worst_severity(SCANNER)
    if sev in ("high", "critical"):
        _ok(f"port scanner detected as {sev}")
    else:
        _fail(f"port scanner NOT detected (worst severity: {sev or 'none'}) -- a 400-port "
              f"sweep must not pass silently")
        failures += 1

    # 2. THE BEACON. Detected at all is the bar for a single small flow pair.
    sev = worst_severity(BEACON)
    if sev in ("medium", "high", "critical"):
        _ok(f"beacon detected ({sev})")
    else:
        _fail(f"beacon NOT detected (worst severity: {sev or 'none'})")
        failures += 1

    # 3. THE EXFIL SPIKE. 450 MB outbound in one flow.
    sev = worst_severity(EXFIL)
    if sev in ("high", "critical"):
        _ok(f"exfiltration spike detected as {sev}")
    else:
        _fail(f"exfiltration spike NOT detected (worst severity: {sev or 'none'})")
        failures += 1

    # 4. PRECISION SMOKE CHECK. If most benign hosts alert high, the threshold is
    #    miscalibrated and the scanner result above is not trustworthy either.
    benign_high = [h for h in BENIGN if worst_severity(h) in ("high", "critical")]
    if len(benign_high) <= 1:
        _ok(f"benign hosts mostly quiet ({len(benign_high)} of {len(BENIGN)} at high+)")
    else:
        _fail(f"{len(benign_high)} of {len(BENIGN)} benign hosts alerted at high+ -- "
              f"the detection above is noise, not signal")
        failures += 1

    print()
    if failures:
        print(f"FAILED: {failures} assertion(s) did not hold")
        return 1
    print("PASSED: every seeded attack reached a final verdict, benign traffic stayed quiet")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# TODO (ML-1b): persist these outcomes per run and chart detection quality over time.
# TODO (ML-1c): once SOC-1 lands, feed false-positive dispositions back as labels.
# TODO (ML-5): sweep fusion weights / damping / thresholds against this same seeded data.
