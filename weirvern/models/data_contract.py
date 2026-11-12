"""The data coverage contract: what "covered" means, measured (DATA-0).

WHY THIS EXISTS. Coverage was reported source by source, with no host denominator and no
statement of what a missing row means. A panel could therefore say "DNS: 350k rows, fresh" while
most monitored hosts had never been seen in DNS at all, and no detector could tell whether its
own family was usable. This module reads the machine-readable contract in
`docs/design/data-coverage-contract.json`, measures it against the live tables, and returns one
shape that separates:

  * required from optional (a required source missing blocks promotion);
  * not measured from zero (an unreadable or empty source is never 0% coverage);
  * a host that is quiet from a host that was never observed;
  * a family that is usable from a family whose source is absent.

The host population is the same monitored decision the detectors train on
(`networks.training_filter_sql`), so the denominator cannot drift from the models' own scope.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from weirvern import networks

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "docs" / "design" / "data-coverage-contract.json"

MAX_HOSTS = 500          # the per-host list is capped; the counts are not
TOP_GAPS = 10            # names per source in the gap report


def load_contract(path: Path | None = None) -> dict[str, Any]:
    """Read and shape-check the contract. A malformed contract is a loud failure.

    A contract that silently loads as an empty dict would make every coverage claim vacuous,
    which is the exact failure this module exists to prevent.
    """
    source = path or CONTRACT_PATH
    data = json.loads(source.read_text())
    if not isinstance(data, dict):
        raise ValueError("the data coverage contract must be a JSON object")
    for key in ("version", "window_hours", "host_population", "sources"):
        if key not in data:
            raise ValueError(f"the data coverage contract is missing {key!r}")
    if not isinstance(data["sources"], list) or not data["sources"]:
        raise ValueError("the data coverage contract declares no sources")
    for entry in data["sources"]:
        for key in ("name", "table", "time_column", "host_column", "required",
                    "freshness_s", "accepted_missing_pct", "accepted_missingness", "feeds"):
            if key not in entry:
                raise ValueError(f"source {entry.get('name', '?')} is missing {key!r}")
    return data


def validate_contract(contract: dict[str, Any], schema_tables: set[str]) -> list[str]:
    """Names every table the contract claims that the schema does not declare."""
    problems: list[str] = []
    for entry in contract["sources"]:
        table = str(entry["table"]).split(".")[-1]
        if table not in schema_tables:
            problems.append(f"{entry['name']}: table {entry['table']} is not in the schema")
        if not 0 <= int(entry["accepted_missing_pct"]) <= 100:
            problems.append(f"{entry['name']}: accepted_missing_pct must be 0..100")
        if int(entry["freshness_s"]) <= 0:
            problems.append(f"{entry['name']}: freshness_s must be positive")
    return problems


def _state(rows: int | None, last: Any, freshness_s: int) -> tuple[str, str]:
    """The same vocabulary the rest of the console uses, never a zero for an unknown."""
    if rows is None:
        return "unknown", "the source could not be read"
    if rows <= 0:
        return "not measured", "no records in the source"
    if last is None:
        return "unknown", "the source has rows but no readable newest row"
    moment = last
    if isinstance(moment, str):
        try:
            moment = datetime.fromisoformat(moment.replace("Z", "+00:00"))
        except ValueError:
            return "unknown", "the newest row has no readable timestamp"
    if not isinstance(moment, datetime):
        return "unknown", "the newest row has no readable timestamp"
    moment = moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment
    age = (datetime.now(UTC) - moment.astimezone(UTC)).total_seconds()
    if age < -300:
        return "failed", "the newest row is in the future (clock fault)"
    if age > freshness_s:
        return "stale", f"newest row is {int(age // 60)} min old"
    return "fresh", f"newest row is {int(age)} s old"


def _predicate(client) -> tuple[str, dict[str, Any]]:
    """The monitored-scope predicate and the facts behind it, from one source of truth."""
    scopes = networks.load_scopes(client)
    pred = networks.training_filter_sql(scopes, alias="s")
    monitored = [s for s in scopes if networks.is_monitored(s)]
    return pred, {
        "definition": "source addresses inside a network scope declared monitored",
        "declared_scopes": len(scopes),
        "monitored_scopes": [s.cidr for s in monitored],
        "legacy": not scopes,
        "no_monitored_scope": bool(scopes) and not monitored,
    }


def _hosts(client, table: str, time_column: str, host_column: str, hours: int,
           pred: str) -> set[str] | None:
    """Distinct in-scope hosts in the window; None means the read failed, never an empty set."""
    try:
        rows = client.query(
            f"SELECT DISTINCT s.{host_column} FROM {table} AS s "
            f"WHERE s.{time_column} >= now() - INTERVAL {int(hours)} HOUR {pred}"
        ).result_rows
    except Exception:  # noqa: BLE001 - a failed read is a state, not a crash
        return None
    return {str(row[0]) for row in rows if row and row[0]}


def _counts(client, table: str, time_column: str) -> tuple[int | None, Any]:
    try:
        rows = client.query(
            f"SELECT count(), max({time_column}) FROM {table}"
        ).result_rows
        n, last = rows[0] if rows else (None, None)
        return (int(n) if n is not None else None), last
    except Exception:  # noqa: BLE001
        return None, None


def inventory(client, *, contract: dict[str, Any] | None = None) -> dict[str, Any]:
    """Measure the contract against the live deployment and name every gap."""
    try:
        data = contract or load_contract()
    except (OSError, ValueError) as exc:
        return {"available": False, "reason": f"the data coverage contract is unreadable: {exc}",
                "sources": [], "families": [], "gaps": [], "hosts": [], "population": {}}

    hours = int(data["window_hours"])
    pred, population = _predicate(client)

    population_hosts: set[str] = set()
    host_sets: dict[str, set[str] | None] = {}
    sources: list[dict[str, Any]] = []
    for entry in data["sources"]:
        name = str(entry["name"])
        table = str(entry["table"])
        rows, last = _counts(client, table, str(entry["time_column"]))
        state, reason = _state(rows, last, int(entry["freshness_s"]))
        hosts = _hosts(client, table, str(entry["time_column"]), str(entry["host_column"]),
                       hours, pred)
        host_sets[name] = hosts
        if hosts:
            population_hosts |= hosts
        covered = len(hosts) if hosts is not None else None
        sources.append({
            "name": name, "table": table, "required": bool(entry["required"]),
            "state": state, "reason": reason, "rows": rows,
            "freshness_s": int(entry["freshness_s"]),
            "accepted_missing_pct": int(entry["accepted_missing_pct"]),
            "accepted_missingness": str(entry["accepted_missingness"]),
            "hosts_covered": covered,
            "feeds": list(entry["feeds"]),
        })

    total = len(population_hosts)
    for source in sources:
        covered = source["hosts_covered"]
        source["coverage_pct"] = (round(100.0 * covered / total, 1)
                                  if covered is not None and total else None)
        source["hosts_missing"] = (total - covered) if covered is not None and total else None
        source["usable"] = bool(
            source["state"] == "fresh"
            and total > 0
            and covered is not None
            and 100.0 * covered / total >= 100 - source["accepted_missing_pct"]
        )

    families: list[dict[str, Any]] = []
    for family in sorted({f for source in sources for f in source["feeds"]}):
        needed = [s for s in sources if family in s["feeds"]]
        failing = [s for s in needed if not s["usable"]]
        families.append({
            "name": family,
            "sources": [s["name"] for s in needed],
            "usable": not failing,
            "reason": "" if not failing else "; ".join(
                f"{s['name']} is {s['state']}"
                + (f" ({s['coverage_pct']}% of hosts)" if s["coverage_pct"] is not None else "")
                for s in failing),
        })

    gaps: list[dict[str, Any]] = []
    for source in sources:
        covered_hosts = host_sets.get(source["name"])
        if covered_hosts is None or not population_hosts:
            continue
        missing = sorted(population_hosts - covered_hosts)
        gaps.append({"source": source["name"], "missing": len(missing),
                     "accepted_missing_pct": source["accepted_missing_pct"],
                     "over_accepted": 100.0 * len(missing) / total > source["accepted_missing_pct"]
                     if total else None,
                     "hosts": missing[:TOP_GAPS]})
    gaps.sort(key=lambda g: (-g["missing"], g["source"]))

    host_rows: list[dict[str, Any]] = []
    for host in sorted(population_hosts)[:MAX_HOSTS]:
        absent = [s["name"] for s in sources if host_sets.get(s["name"]) is not None
                  and host not in (host_sets[s["name"]] or set())]
        present = [s["name"] for s in sources if host in (host_sets.get(s["name"]) or set())]
        required_absent = [s["name"] for s in sources if s["required"] and s["name"] in absent]
        host_rows.append({
            "src_addr": host,
            "observed": bool(present),
            "covered_by": present,
            "missing": absent,
            "status": "covered" if not required_absent else "not observed",
        })

    return {
        "available": True,
        "reason": "",
        "contract_version": str(data["version"]),
        "window_hours": hours,
        "population": {**population, "hosts": total},
        "sources": sources,
        "families": families,
        "gaps": gaps,
        "hosts": host_rows,
        "hosts_truncated": total > MAX_HOSTS,
        "promotion_ok": all(s["usable"] for s in sources if s["required"]),
    }


__all__ = ["CONTRACT_PATH", "MAX_HOSTS", "TOP_GAPS", "inventory", "load_contract",
           "validate_contract"]
