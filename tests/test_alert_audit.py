"""SOC-8: the alert audit -- every decision, not just the deliveries.

THE GAP. The worker writes every alert decision to `alert_events`: sent, suppressed by
cooldown, dropped at the rate cap, and the log-only path when Pushover is unconfigured.
That is a complete account of "what did the alerting layer decide, and why did it not
reach me" -- and the GUI surfaced it as a single row COUNT on the Health probe table.

The consequence, measured on the live box before this panel existed: with Pushover
unconfigured, five decisions sat in the table and the only visible fact was a number.
"0 alerts sent" reads as "nothing happened"; the audit says "five anomalies fired and
the layer acted on each". Those are different operational facts.

WHAT THIS FILE PINS:
  * the reason breakdown and the recent-events list are both read, with the vocabulary
    the worker writes (sent / cooldown / cap / log-only / pushover-error);
  * SUPPRESSED counts cooldown+cap only. The log-only path is also sent=0, and counting
    it as suppressed would claim alerts were withheld when nothing was configured to
    withhold them -- a configuration state rendered as an operational decision;
  * an unavailable query says so, rather than rendering an empty audit that reads as
    "nothing was suppressed".
"""
from __future__ import annotations

import datetime
from pathlib import Path

from weirvern.admin import soc

ROOT = Path(__file__).resolve().parents[1]


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    """Returns rows per query, dispatching on the SQL text -- the two queries differ."""

    def __init__(self, by_reason_rows, recent_rows):
        self.by_reason_rows = by_reason_rows
        self.recent_rows = recent_rows
        self.queries: list[str] = []

    def query(self, sql, parameters=None):  # noqa: ANN001
        self.queries.append(sql)
        if "GROUP BY reason" in sql:
            return _Result(self.by_reason_rows)
        return _Result(self.recent_rows)


def test_the_breakdown_and_the_events_are_both_read():
    stamp = datetime.datetime(2026, 9, 20, 18, 5, 0)
    c = _Client(
        by_reason_rows=[["log-only", 0, 5, stamp], ["cooldown", 0, 3, stamp]],
        recent_rows=[[stamp, "198.51.100.9", "high", 0.81, 0, "cooldown", ""]],
    )
    out = soc.alert_audit(c, hours=24)
    assert out["available"] is True
    assert [(r["reason"], r["count"]) for r in out["by_reason"]] == \
        [("log-only", 5), ("cooldown", 3)]
    assert out["recent"][0]["src_addr"] == "198.51.100.9"
    assert out["recent"][0]["severity"] == "high"
    # Both statements asked, and both bounded by the window.
    assert len(c.queries) == 2
    for q in c.queries:
        assert "INTERVAL %(h)s HOUR" in q
    assert "weirvern.alert_events" in c.queries[0]


def test_suppressed_counts_cooldown_and_cap_but_not_log_only():
    """THE DISTINCTION THE PANEL EXISTS FOR. log-only is sent=0 because nothing was
    configured to send; cooldown/cap are sent=0 because the system chose to withhold.
    Only the second is 'suppressed'."""
    c = _Client(
        by_reason_rows=[["log-only", 0, 7, None], ["cooldown", 0, 2, None],
                        ["cap", 0, 1, None], ["sent", 1, 4, None]],
        recent_rows=[],
    )
    out = soc.alert_audit(c, hours=24)
    assert out["suppressed"] == 3, (
        "suppressed must count cooldown+cap (3) and NOT the log-only rows (7); "
        f"got {out['suppressed']}"
    )


def test_a_sent_row_is_never_counted_as_suppressed():
    c = _Client(by_reason_rows=[["cooldown", 1, 2, None]], recent_rows=[])
    out = soc.alert_audit(c, hours=24)
    assert out["suppressed"] == 0, "a sent row with a cooldown reason was counted as withheld"


def test_an_unavailable_query_says_so_instead_of_rendering_empty():
    class _Boom:
        def query(self, sql, parameters=None):  # noqa: ANN001
            raise RuntimeError("no such table")

    out = soc.alert_audit(_Boom(), hours=24)
    assert out["available"] is False
    assert "no such table" not in out["reason"], "raw exception text leaked"
    assert "RuntimeError" in out["reason"], "the reason must name the failure class"
    assert out["by_reason"] == [] and out["recent"] == []


def test_the_reason_vocabulary_matches_what_the_worker_writes():
    """One vocabulary across alerts.py (writer), soc.py (counter) and soc.js (labeller)."""
    alerts = (ROOT / "weirvern" / "alerts.py").read_text()
    for reason in ("log-only", "sent", "pushover-error"):
        assert f'reason = "{reason}"' in alerts, f"alerts.py no longer writes {reason!r}"
    soc_src = (ROOT / "weirvern" / "admin" / "soc.py").read_text()
    assert '("cooldown", "cap")' in soc_src, "the suppressed-reason list moved"
    js = (ROOT / "weirvern" / "admin" / "web" / "soc.js").read_text()
    assert "log-only" in js and "suppressed" in js, (
        "the GUI cannot distinguish the log-only state from suppression"
    )


def test_the_health_payload_carries_the_audit_in_every_shape():
    """Threaded through /api/health: present on success, present-and-unavailable on
    failure. A key that exists only on success makes `d.alerts` undefined on the error
    path, and the panel silently renders nothing."""
    src = (ROOT / "weirvern" / "admin" / "web.py").read_text()
    i = src.index("SOC-8: the alert audit")
    region = src[i:i + 900]
    assert "alert_audit" in region and "audit" in region
    # The error return path must carry it too.
    j = src.index('"alerts": audit,')
    assert j > 0, "the failure path drops the alerts key"
    api = (ROOT / "weirvern" / "admin" / "web_api.py").read_text()
    assert '"alerts": audit if audit is not None else {' in api, (
        "health_deep_payload no longer degrades to an explicit unavailable block"
    )
