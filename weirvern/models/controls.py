"""Two controls the detection cycle runs on itself, so a broken ranking cannot pass as a quiet night.

WHY CONTROLS AND NOT MORE TESTS. A unit test proves the ranking was right on the day it was
written. These two run EVERY cycle against the code actually deployed, and a failure marks the run
degraded instead of leaving an operator to infer it from a chart that looks calm.

MEASURED, 2026-11-17, on the live host scope: the chatty host (the umbrel: 5.4 MB against its own
p90 of 2.5 MB, 155 peers, the host that used to be 19-45% of the whole alert volume) sat SIXTH of
seven at 2.18x, while two ordinary hosts departed by 45x and 100x. That is the shape the host scope
exists to produce, and it is a control: if a host with the widest peer set ever leads the ranking,
the profile has collapsed back into a fleet-wide baseline and every alert after it is noise.

THE EXFIL CONTROL IS THE OPPOSITE DIRECTION. A host sending 100x its own p90 must outrank a host
sending more absolute bytes at 2x. If it does not, the ranking has started measuring volume instead
of departure -- the exact regression the p90 was chosen to prevent -- and an exfiltration would be
missed behind a large ordinary transfer. The control calls `scopes.rank_from`, the same rule the
product uses, deliberately: a control that re-implements what it checks passes when both are wrong.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from weirvern.models import scopes

# A host with the widest peer set may sit at the top of a small list; what it may not do is read as
# anomalous. 5x its own p90 is comfortably above the measured 2.18x and far below the 45x/100x the
# ordinary hosts reached on the same data.
CHATTY_RATIO_CEILING = 5.0
CHATTY_TOP_N = 3


@dataclass(frozen=True)
class Control:
    name: str
    ok: bool | None          # None = could not be evaluated (no history yet), never a silent pass
    detail: str


def exfil_fires() -> Control:
    """A host at 100x its own p90 MUST rank first, even against a bigger ordinary transfer.

    Pure: fixed fixtures, no database. It exercises the ranking rule, not the SQL that feeds it --
    a broken query shows up as `new_hour` on every host in the umbrel control instead.
    """
    hour = 3
    profiles = {
        "192.0.2.10": {hour: {"median_bytes": 1_000.0, "p90_bytes": 1_000.0, "median_peers": 2.0}},
        "192.0.2.20": {hour: {"median_bytes": 900_000.0, "p90_bytes": 1_000_000.0,
                              "median_peers": 40.0}},
    }
    recent = {"192.0.2.10": {"bytes": 100_000, "peers": 2},
              "192.0.2.20": {"bytes": 2_000_000, "peers": 40}}
    rows = scopes.rank_from(profiles, recent, hour, limit=5)
    if not rows:
        return Control("exfil_fires", False, "the ranking returned nothing for a known fixture")
    top = rows[0]
    ratio = top.get("ratio") or 0
    ok = top.get("host") == "192.0.2.10" and ratio >= 90
    return Control(
        "exfil_fires", ok,
        f"{top.get('host')} ({ratio}x its own p90) ranked first"
        if ok else
        f"a 100x departure ranked behind {top.get('host')} ({ratio}x): the rule is ranking volume, "
        "not departure",
    )


def umbrel_quiet(rows: list[dict[str, Any]]) -> Control:
    """The host with the widest peer set must not read as an anomaly.

    `rows` is the output of `scopes.rank_from`, already sorted by ratio. The chatty host is chosen
    by MEDIAN PEERS from its own profile, not by name or address: a control that hardcodes an
    address stops controlling anything the day DHCP moves it.
    """
    scored = [r for r in rows
              if r.get("ratio") is not None and r.get("median_peers") is not None]
    if not scored:
        return Control("umbrel_quiet", None,
                       "no host has both a ratio and a peer history yet; nothing to hold quiet")
    chatty = max(scored, key=lambda r: float(r["median_peers"]))
    rank = scored.index(chatty) + 1
    ok = float(chatty["ratio"]) < CHATTY_RATIO_CEILING or rank > CHATTY_TOP_N
    return Control(
        "umbrel_quiet", ok,
        f"the widest-peer host ({int(chatty['median_peers'])} median peers) ranked {rank} of "
        f"{len(scored)} at {chatty['ratio']}x",
    )


def run_controls(client: Any, *, rows: list[dict[str, Any]] | None = None) -> list[Control]:
    """Both controls, one sweep. Never raises: a control that cannot run says so."""
    checks = [exfil_fires()]
    try:
        ranked = rows if rows is not None else scopes.rank_departures(client, limit=25)
        checks.append(umbrel_quiet(ranked))
    except Exception as exc:  # noqa: BLE001 -- a failed control is a verdict, not a crash
        checks.append(Control("umbrel_quiet", None, f"could not be evaluated: {exc}"))
    return checks


def degraded(checks: Iterable[Control]) -> list[Control]:
    return [c for c in checks if c.ok is False]


def describe(checks: Iterable[Control]) -> str:
    state = {True: "PASS", False: "FAIL", None: "N/A"}
    return "; ".join(f"{c.name}={state[c.ok]}: {c.detail}" for c in checks)
