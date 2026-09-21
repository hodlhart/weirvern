"""SIPHON-1: a siphon-CONFIGURED sensor with no live intercept must say so LOUDLY.

THE DEFECT THIS FILE EXISTS FOR. SENSOR_MODE=siphon is a fact about a ConfigMap. An intercept
is a RUNNING process. In-cluster, nothing starts the intercept -- it is operator-triggered --
so a deployment can set SENSOR_MODE=siphon, pass every check that reads configuration, print
"mode siphon -- IN-PATH intercept" from the Zeek container, and redirect ZERO hosts forever.

Every surface that answered from the config said "healthy in-path sensor". That is the exact
defect class the project's changelog names: a failure that renders identically to a
successful measurement of zero. `siphon_liveness` converts it into a loud one.

WHY THE OBVIOUS CHECKS ARE WRONG, pinned as tests below:
  * `mode == 'siphon'` is not evidence: in a siphon deployment the WORKER also publishes
    mode='siphon' (observe() publishes the configured value) with mappings=0.
  * `running == 1` is not evidence: the worker's running means "Zeek logs are fresh",
    true on a healthy passive sensor.
  * A STALE siphon row is a PAST intercept -- reported as `stopped`, with the honest
    uncertainty about whether the node was restored.
The only positive evidence is a FRESH `siphon` row with mappings > 0, because only an
intercept writes mappings and it writes them only after actually forging a mapping.
"""
from __future__ import annotations

import datetime
from pathlib import Path

from weirvern.admin import status as status_mod

NOW = datetime.datetime(2026, 9, 20, 12, 0, 0, tzinfo=datetime.UTC)


class _Client:
    def __init__(self, rows: list[dict] | None = None, fail: bool = False) -> None:
        self._rows = rows or []
        self._fail = fail

    def query(self, _sql: str):
        if self._fail:
            raise RuntimeError("simulated query failure")
        rows = self._rows

        class _Result:
            def named_results(self):
                return iter(rows)

        return _Result()


def _row(mode: str, seconds_ago: float, **over) -> dict:
    row = {
        "sensor_id": "Weirvern", "mode": mode, "iface": "eth1", "segment": "",
        "hosts": 0, "mappings": 0, "running": 1, "uptime_s": 100.0,
        "restores": 0, "refreshes": 0, "failures": [],
        "ts": NOW - datetime.timedelta(seconds=seconds_ago),
        "capture_loss_pct": None, "packets_recv": None, "packets_dropped": None,
    }
    row.update(over)
    return row


# ── not applicable ─────────────────────────────────────────────────────────────

def test_loch_config_needs_no_intercept():
    """Most deployments are passive; the check must cost nothing and say nothing there."""
    out = status_mod.siphon_liveness("loch", _Client(), now=NOW)
    assert out["applicable"] is False
    assert out["error"] is None, "a passive deployment was nagged about an intercept"
    assert out["live"] is False


# ── the loud case ──────────────────────────────────────────────────────────────

def test_siphon_config_with_only_worker_rows_is_an_error():
    """THE HEADLINE. A worker publishing mode=siphon (its configured value) with zero
    mappings must NOT be mistaken for a live intercept -- this is the in-cluster state
    where the config says in-path and reality says nothing is redirected."""
    rows = [
        _row("siphon", 5, hosts=0, mappings=0, running=1),   # the worker's config echo
        _row("loch", 5),
    ]
    out = status_mod.siphon_liveness("siphon", _Client(rows), now=NOW)
    assert out["applicable"] and out["verified"]
    assert out["live"] is False, (
        "a config-echo row with zero mappings was accepted as a live intercept"
    )
    assert out["error"] and "NO intercept is running" in out["error"]
    assert "operator-triggered" in out["error"], (
        "the message does not explain WHY this is the expected in-cluster state, so an "
        "operator reads it as a bug report rather than a fact about the design"
    )


def test_siphon_config_with_no_rows_at_all_is_an_error():
    out = status_mod.siphon_liveness("siphon", _Client([]), now=NOW)
    assert out["live"] is False
    assert out["error"] and "no sensor has ever reported" in out["error"]


def test_an_unreadable_table_is_cannot_tell_not_no_intercept():
    """The three-valued honesty rule: cannot-tell must not read as either verdict."""
    out = status_mod.siphon_liveness("siphon", _Client(fail=True), now=NOW)
    assert out["live"] is False
    assert out["verified"] is False, "an unreadable table was reported as verified"
    assert out["error"] and "cannot be determined" in out["error"], (
        "an unreadable table produced a definite-sounding claim"
    )


def test_a_stale_intercept_row_is_stopped_not_absent():
    """The kill -9 case: an intercept RAN, its row aged out, and whether the forged ARP
    entries were restored cannot be known from here. The message must carry that
    uncertainty rather than either comfortable answer."""
    rows = [
        _row("siphon", 600, hosts=10, mappings=20),          # ran, now stale
        _row("loch", 5),
    ]
    out = status_mod.siphon_liveness("siphon", _Client(rows), now=NOW)
    assert out["live"] is False
    assert out["stopped"] is True
    assert out["error"] and "RAN on this sensor" in out["error"]
    assert "restored cannot" in out["error"] or "cannot be" in out["error"], (
        "the stopped message claims a definite restore state it cannot know"
    )


# ── the healthy case ───────────────────────────────────────────────────────────

def test_a_fresh_intercept_row_is_live():
    rows = [
        _row("siphon", 5, hosts=10, mappings=20, segment="198.51.100.0/24", running=1),
        _row("loch", 5),
    ]
    out = status_mod.siphon_liveness("siphon", _Client(rows), now=NOW)
    assert out["live"] is True
    assert out["hosts"] == 10 and out["mappings"] == 20
    assert out["error"] is None
    assert out["age_s"] is not None and out["age_s"] <= 5.1


def test_a_fresh_intercept_row_wins_even_when_a_worker_row_is_fresher():
    """Liveness must not depend on which row wrote last -- the wall-clock bug."""
    rows = [
        _row("siphon", 20, hosts=3, mappings=6),   # older, but real evidence
        _row("siphon", 1, hosts=0, mappings=0),    # the worker, fresher, no evidence
    ]
    out = status_mod.siphon_liveness("siphon", _Client(rows), now=NOW)
    assert out["live"] is True, (
        "the check picked the freshest row rather than the one with intercept evidence"
    )
    assert out["hosts"] == 3


# ── wiring ─────────────────────────────────────────────────────────────────────

def test_the_status_command_runs_the_check():
    """The check is worthless unless `weirvern status` calls it AND fails on it."""
    root = Path(__file__).resolve().parents[1]
    src = (root / "weirvern" / "admin" / "cli.py").read_text()
    assert "siphon_liveness(" in src, (
        "cmd_status no longer calls siphon_liveness, so an in-path sensor that redirects "
        "nothing reports as healthy again"
    )
    start = src.index("def cmd_status")
    body = src[start:start + 8000]
    assert "EXIT_FAIL" in body[body.index("siphon_liveness"):], (
        "the status command reads the liveness verdict but does not fail on it"
    )
