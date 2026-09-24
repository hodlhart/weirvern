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
    """Returns rows per query, dispatching on the SQL text -- the three queries differ.

    THREE, not two: the panel pages its event list, so the product also asks for a real COUNT
    over the window. That count is what lets the GUI say "showing the newest N of M" instead of
    letting a full page of rows read as "this is everything" -- so the fake has to answer it, and
    a fake that quietly returned the recent rows for it would have made the truncation logic
    untestable (it would have compared the list against itself).
    """

    def __init__(self, by_reason_rows, recent_rows, total=None):
        self.by_reason_rows = by_reason_rows
        self.recent_rows = recent_rows
        # Default: the window holds exactly the rows we handed back, i.e. not truncated. Tests
        # that care about truncation pass a larger number explicitly.
        self.total = len(recent_rows) if total is None else total
        self.queries: list[str] = []

    def query(self, sql, parameters=None):  # noqa: ANN001
        self.queries.append(sql)
        if "GROUP BY reason" in sql:
            return _Result(self.by_reason_rows)
        if "count() FROM" in sql:
            return _Result([[self.total]])
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
    # All three statements asked, and all bounded by the window.
    assert len(c.queries) == 3, f"expected breakdown+count+events, got {len(c.queries)}"
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


# ── THE PAGING REWORK: the fetch is capped, and says so ──────────────────────────────────────
#
# The GUI pages these tables 15 rows at a time out of a fetch capped at `limit`. A cap nobody
# states is indistinguishable from completeness: a full page of rows with no note reads as "this
# is everything that happened", while the window may hold thousands. That is the same misreading
# the audit panel exists to prevent, one level up -- so the payload carries the real total and
# whether the list was truncated, and the panel says which.


def test_the_payload_reports_the_real_total_and_whether_it_was_truncated():
    """A FULL page under a real total of 4000: the fetch hit its cap, so there is more."""
    full = [[None, f"198.51.100.{i}", "low", 0.5, 0, "cooldown", ""] for i in range(1, 16)]
    c = _Client(by_reason_rows=[["cooldown", 0, 4000, None]], recent_rows=full, total=4000)
    out = soc.alert_audit(c, hours=24, limit=15)
    assert out["total"] == 4000, f"the window's real size was not reported: {out['total']}"
    assert len(out["recent"]) == 15
    assert out["truncated"] is True, (
        "a fetch that filled its 15-row cap out of a 4000-row window was presented as complete"
    )


def test_a_window_that_fits_is_not_reported_as_truncated():
    """The other direction, so the note cannot become permanent furniture that a reader learns to
    skip -- which would defeat the point of adding it."""
    rows = [[None, f"198.51.100.{i}", "low", 0.5, 0, "cooldown", ""] for i in range(1, 4)]
    c = _Client(by_reason_rows=[["cooldown", 0, 3, None]], recent_rows=rows, total=3)
    out = soc.alert_audit(c, hours=24)
    assert out["truncated"] is False, f"3 rows were reported as truncated: {out}"
    assert out["total"] == 3


def test_a_count_that_disagrees_with_the_list_does_not_decide_truncation():
    """TRUNCATION IS WHETHER THE FETCH HIT ITS CAP, not a comparison against the count.

    `total` is a separate query, so a row inserted between the two makes the count exceed a list
    that is nonetheless COMPLETE. Deciding truncation from that comparison reports a complete
    window as truncated. (The `max()` this replaced was algebraically identical to the plain
    comparison it claimed to guard against -- a mutation swapping the two survived, which is how
    the equivalence surfaced.)
    """
    rows = [[None, "198.51.100.9", "low", 0.5, 0, "cooldown", ""]]
    c = _Client(by_reason_rows=[], recent_rows=rows, total=99)  # count ran after/independently
    out = soc.alert_audit(c, hours=24, limit=15)
    assert out["total"] == 99, "the count is still reported for the display"
    assert out["truncated"] is False, (
        f"a 1-row list under a 15-row cap was called truncated because the count disagreed "
        f"({out['truncated']}). The count is a display figure, not a truncation test."
    )


def test_a_fetch_that_comes_back_EXACTLY_full_is_reported_as_truncated():
    """A full page is the only evidence the table had more to give. This is the direction that
    matters: reporting a truncated window as complete hides rows with no indication."""
    rows = [[None, f"198.51.100.{i}", "low", 0.5, 0, "cooldown", ""] for i in range(1, 16)]
    c = _Client(by_reason_rows=[], recent_rows=rows, total=15)
    out = soc.alert_audit(c, hours=24, limit=15)
    assert len(out["recent"]) == 15
    assert out["truncated"] is True, (
        "a fetch that returned exactly the cap is indistinguishable from one that filled the "
        "cap and stopped -- it must be reported as possibly truncated"
    )


def test_hostnames_are_attached_for_the_addresses_in_the_window(monkeypatch):
    """A standing directive: names appear ALONGSIDE the address, everywhere hosts are listed.
    The renderer read `ev.hostname`, which the payload never set -- so the name column was
    always blank and nothing noticed."""
    import weirvern.admin.revdns as revdns

    monkeypatch.setattr(revdns, "lookup",
                        lambda a, use_cache=True: {"198.51.100.9": "gateway.example"}.get(a))
    rows = [[None, "198.51.100.9", "high", 0.8, 1, "sent", "msg"],
            [None, "203.0.113.5", "low", 0.4, 0, "cooldown", ""]]
    c = _Client(by_reason_rows=[], recent_rows=rows)
    out = soc.alert_audit(c, hours=24)
    assert out["names"]["198.51.100.9"] == "gateway.example"
    assert out["names"].get("203.0.113.5", "") == "", (
        "an address with no PTR must map to empty, not to a name"
    )


def test_a_failing_resolver_never_fails_the_audit(monkeypatch):
    """A name is never worth failing the page for."""
    import weirvern.admin.revdns as revdns

    def _boom(*_a, **_k):
        raise RuntimeError("resolver exploded")

    monkeypatch.setattr(revdns, "lookup", _boom)
    c = _Client(by_reason_rows=[], recent_rows=[[None, "198.51.100.9", "low", 0.1, 0, "cap", ""]])
    out = soc.alert_audit(c, hours=24)
    assert out["available"] is True, "a resolver failure took the whole audit down"
    assert out["names"] == {}, f"expected no names, got {out['names']}"


def test_the_unavailable_payload_carries_every_key_the_panel_reads():
    """The panel reads total/truncated/names unconditionally. A key present only on the success
    path makes the pager throw on the error path, replacing the explanation the operator needed
    with a TypeError."""
    class _Boom:
        def query(self, sql, parameters=None):  # noqa: ANN001
            raise RuntimeError("nope")

    out = soc.alert_audit(_Boom(), hours=24)
    for key in ("available", "reason", "by_reason", "recent", "suppressed",
                "total", "truncated", "names"):
        assert key in out, f"the unavailable payload is missing {key!r}"


def test_the_cap_boundary_is_exact():
    """cap-1 rows is NOT full: the table gave one fewer than it was allowed, so it had nothing
    more at that moment and the window is complete at the cap.

    Pinning both sides of the boundary, because an off-by-one here is a real defect in a
    specific direction: treating cap-1 as full adds a note to complete windows until readers
    learn to skip it, and treating cap+1 as short hides rows silently. The first version of this
    check only pinned "exactly cap", so a mutation moving the boundary by one survived.
    """
    def audit_with(n_rows, cap=15):
        rows = [[None, f"198.51.100.{i % 250}", "low", 0.1, 0, "cooldown", ""]
                for i in range(n_rows)]
        c = _Client(by_reason_rows=[], recent_rows=rows, total=n_rows)
        return soc.alert_audit(c, hours=24, limit=cap)

    assert audit_with(14)["truncated"] is False, (
        "14 rows under a 15-row cap was reported as truncated -- the cap was not reached, so "
        "the table had nothing more to give"
    )
    assert audit_with(15)["truncated"] is True, (
        "15 rows under a 15-row cap was reported as complete -- a full fetch is the only "
        "evidence there is more, and calling it complete hides rows"
    )
