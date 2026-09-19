#!/usr/bin/env python3
"""Run every new assets.py query against the live database and report what it returns.

WHY: a helper that returns `{"available": true}` with an empty host list looks identical to a
quiet network, and three of this project's worst defects were queries that raised at runtime
because a column name was assumed rather than checked. So each helper is exercised here against
the real schema BEFORE it is wired into a route, and the probe prints the failure text rather
than swallowing it.

Run from the repository root with WEIRVERN_SENSOR_HOST set (no default -- an address in the
tree would be a sanitation problem).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, ".")

from weirvern.admin import assets  # noqa: E402


class _RemoteClient:
    """A DB-API-ish shim so assets.py queries run from a workstation, not in-cluster.

    `assets.py` calls `client.query(sql, parameters=...)` and reads `.result_rows`, which is
    the clickhouse_connect interface. Rather than import that driver here (it is only in the
    cluster image), the SQL is handed to scripts/chq.py over ssh, and this class presents the
    same `.result_rows` shape. That keeps ONE definition of each query -- the one that ships.
    """

    def __init__(self, runner):
        self._run = runner

    def query(self, sql: str, parameters: dict | None = None):
        # clickhouse_connect accepts %(name)s placeholders; chq.py runs raw SQL, so the
        # parameters are interpolated here. Values are simple (ints, str, tuple-of-str) and
        # are quoted for ClickHouse, not for a shell -- chq.py handles the shell quoting.
        return _Result(self._run(_interpolate(sql, parameters or {})))


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


def _interpolate(sql: str, params: dict) -> str:
    """Substitute %(name)s placeholders with ClickHouse literals."""
    out = sql
    for key, value in params.items():
        lit = (
            "(" + ", ".join(_lit(v) for v in value) + ")"
            if isinstance(value, tuple)
            else _lit(value)
        )
        out = out.replace(f"%({key})s", lit)
    return out


def _lit(value) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    # Escape single quotes the way ClickHouse expects; these are our own values, not user input.
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _make_runner():
    host = os.environ.get("WEIRVERN_SENSOR_HOST")
    if not host:
        sys.exit("WEIRVERN_SENSOR_HOST is not set (e.g. root@sensor)")
    import subprocess

    def run(sql: str):
        proc = subprocess.run(
            [sys.executable, "scripts/chq.py", "--tsv", sql],
            capture_output=True, text=True, timeout=300,
            env={**os.environ, "WEIRVERN_SENSOR_HOST": host},
        )
        text = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode != 0:
            raise RuntimeError(text.strip()[:400])
        # --tsv means plain text, so each line is a row and each tab a cell. Types are
        # recovered loosely: integers stay integers, everything else is a string.
        rows = []
        for line in text.splitlines():
            if not line.strip():
                continue
            cells = line.split("\t")
            rows.append(tuple(_coerce(c) for c in cells))
        return rows

    return run


def _coerce(cell: str):
    if cell.isdigit():
        return int(cell)
    try:
        return float(cell)
    except ValueError:
        return cell


def _summarise(payload: dict) -> str:
    if not payload.get("available"):
        return f"UNAVAILABLE: {payload.get('reason')}"
    keys = {k: v for k, v in payload.items() if k not in ("hosts", "nodes", "edges", "logs")}
    bits = [f"{k}={v!r}" for k, v in keys.items() if k not in ("reason", "available")]
    for name in ("hosts", "nodes", "edges", "logs"):
        if name in payload:
            bits.append(f"{name}={len(payload[name])}")
    return "  ".join(bits)


def main() -> int:
    client = _RemoteClient(_make_runner())
    failures = 0

    print("  ── asset_inventory ──")
    inv = assets.asset_inventory(client, hours=48)
    print(f"     {_summarise(inv)}")
    if inv.get("available") and inv.get("hosts"):
        h = inv["hosts"][0]
        print(f"     busiest host: {h['addr']} bytes={h['bytes']} flows={h['flows']} "
              f"services={h.get('services')} anomalies={h['anomalies']}")
    if not inv.get("available"):
        failures += 1

    print("\n  ── connection_graph ──")
    graph = assets.connection_graph(client, hours=48)
    print(f"     {_summarise(graph)}")
    if graph.get("available") and graph.get("edges"):
        e = graph["edges"][0]
        print(f"     heaviest edge: {e['source']} -> {e['target']} bytes={e['bytes']}")
        n = graph["nodes"][0]
        print(f"     highest degree: {n['id']} degree={n['degree']} name={n['name']!r}")
    if not graph.get("available"):
        failures += 1

    print("\n  ── host_zeek_activity (for the busiest host) ──")
    addr = inv["hosts"][0]["addr"] if inv.get("available") and inv.get("hosts") else ""
    activity = assets.host_zeek_activity(client, addr, hours=48)
    print(f"     {_summarise(activity)}")
    if activity.get("available"):
        for lg in activity["logs"][:5]:
            print(f"       {lg['log']:14s} {lg['events']}")
    if not activity.get("available"):
        failures += 1

    print("\n  ── top_edges_for (two hosts) ──")
    addrs = [h["addr"] for h in inv.get("hosts", [])[:2]]
    tracked = assets.top_edges_for(client, addrs, hours=48)
    print(f"     tracked={addrs} {_summarise(tracked)}")
    if not tracked.get("available"):
        failures += 1

    print("\n  ── the empty-selection contract ──")
    empty = assets.top_edges_for(client, [], hours=48)
    ok = not empty["available"] and "empty selection" in empty["reason"]
    print(f"     {'OK  ' if ok else 'FAIL'} empty selection returns unavailable-with-reason: "
          f"{empty['reason'][:70]}")
    if not ok:
        failures += 1

    print(f"\n  {'ALL HELPERS ANSWERED' if failures == 0 else f'{failures} HELPER(S) FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
