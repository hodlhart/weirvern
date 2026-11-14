"""AB-1 pins: the adaptive baseline has a surface, and the surface cannot lie.

The failure this pins against is a specific one, measured live: the detector trained and
persisted every five minutes while nothing in the console showed it, so "I have not seen
it work" was true of a working feature. The seams here are (a) the route reads through
the shared client context, (b) the builder returns the LATEST snapshot per host -- the
`LIMIT 1 BY` is what keeps a refresh history from rendering as duplicate hosts -- and
(c) a store that cannot be read is UNAVAILABLE-WITH-REASON, never an empty list.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


class _CH:
    """A stub answering the three queries baselines_overview makes, by their own text."""

    def __init__(self, fail_hosts: bool = False):
        self.queries: list[str] = []
        self.fail_hosts = fail_hosts

    def query(self, q, parameters=None):  # noqa: ANN001
        self.queries.append(q)

        class _R:
            result_rows: list = []

        r = _R()
        if "baseline_history" in q:
            if self.fail_hosts:
                raise RuntimeError("baseline_history went away")
            r.result_rows = [
                ("203.0.113.7", 60.0, 1.0, 2.0, 1.0, 50.0, 60.0, 70.0, 24, "2026-10-17 15:24:53"),
                ("198.51.100.5", 9394.0, 9258.0, 40.0, 2.5, 5000.0, 12000.0, 20000.0, 24,
                 "2026-10-17 15:24:53"),
            ]
        elif "ml_models" in q:
            r.result_rows = [
                ('{"baseline_count": 10, "zeek_baselined_hosts": 9, "hosts_with_fp_history": 1}',
                 "2026-10-17 15:24:53"),
            ]
        elif "netflow_anomalies" in q:
            r.result_rows = [(4, "2026-10-17 15:28:33")]
        return r


def test_the_builder_returns_latest_snapshot_per_host_sorted_by_volume():
    from weirvern.admin import status

    out = status.baselines_overview(_CH())
    assert out["available"] is True
    assert out["host_count"] == 2
    assert [h["src_addr"] for h in out["hosts"]] == ["198.51.100.5", "203.0.113.7"], \
        "hosts are not sorted by learned volume (descending)"
    # The latest-snapshot contract lives in the SQL; dropping it duplicates hosts silently.
    ch = _CH()
    status.baselines_overview(ch)
    hosts_q = next(q for q in ch.queries if "baseline_history" in q)
    assert "LIMIT 1 BY src_addr" in hosts_q, "a refresh history would render as duplicate hosts"
    assert "ORDER BY computed_at DESC" in hosts_q


def test_the_builder_reports_behavioural_counts_and_fired_rows():
    from weirvern.admin import status

    out = status.baselines_overview(_CH())
    assert out["behavioural_hosts"] == 9
    assert out["fingerprint_hosts"] == 1
    assert out["fired_24h"] == 4
    assert out["last_fired"], "the last-fired time vanished"


def test_a_failed_store_is_unavailable_with_reason_not_empty():
    from weirvern.admin import status

    out = status.baselines_overview(_CH(fail_hosts=True))
    assert out["available"] is False
    assert "baseline history query failed" in out["reason"], out


def test_the_payload_passes_counts_and_availability_through():
    from weirvern.admin import web_api

    ok = web_api.baselines_payload({
        "available": True, "host_count": 2, "fired_24h": 4, "last_fired": "x",
        "behavioural_hosts": 9, "fingerprint_hosts": 1, "hosts": [{"src_addr": "a"}],
        "refreshed_age_s": 245, "refreshed_at": "t", "last_trained": "t", "errors": None,
    })
    assert ok["fired_24h"] == 4 and ok["behavioural_hosts"] == 9 and ok["hosts"]
    assert ok["refreshed_age_s"] == 245
    bad = web_api.baselines_payload({"available": False, "reason": "boom"})
    assert bad == {"available": False, "reason": "boom"}


def test_the_payload_resolves_only_the_rows_the_card_renders(monkeypatch):
    """The baseline card shows twelve rows; resolving a PTR for every host is a tab stall.

    A 2,935-host baseline made `/api/baselines` exceed 25 seconds while its SQL completed in
    roughly a quarter second. Pin the serializer to the visible page, not the whole table.
    """
    from weirvern.admin import web_api

    seen: list[str] = []
    monkeypatch.setattr(web_api, "_hostname", lambda addr: seen.append(str(addr)) or "host")

    hosts = [{"src_addr": f"198.51.100.{i}"} for i in range(20)]
    out = web_api.baselines_payload({"available": True, "host_count": 20, "hosts": hosts})
    assert len(seen) == 12, f"resolved {len(seen)} hostnames, expected the 12 rendered rows"
    assert out["hosts"][0]["hostname"] == "host"
    assert out["hosts"][-1]["hostname"] is None


def test_the_route_reads_through_the_context_manager():
    src = (ROOT / "weirvern" / "admin" / "web.py").read_text()
    assert 'if path == "/api/baselines":' in src
    seg = src.split("def _baselines(self)", 1)[1].split("\n        def ", 1)[0]
    assert "with self._with_client() as client:" in seg, \
        "the handler must read through the shared client context, like its neighbours"
    # THE FETCHER MOVED, THE PROPERTY DID NOT. It used to be called inline here; it now lives in
    # `payloads.baselines`, shared with the Flask surface, so the handler delegates. Asserting the
    # old name would demand the duplication back. What this test still must catch is a handler that
    # bypasses the shared fetcher, so either shape is accepted.
    assert "baselines_overview" in seg or "payloads.baselines(" in seg


def test_the_card_exists_and_its_header_matches_its_rows():
    """The seam that made US-1's thead defect possible: a table whose header count and row
    cell count drift apart. Both are pinned here by number."""
    html = (WEB / "index.html").read_text()
    for el_id in ("mb-window", "mb-note", "mb-summary", "mb-hosts", "mb-fired", "mb-info"):
        assert f'id="{el_id}"' in html, f"the baseline card lost #{el_id}"
    head = html[html.index('<table id="mb-hosts">'):]
    head = head[:head.index("</thead>")]
    import re

    n_cols = len(re.findall(r"<th[ >]", head))

    app = (WEB / "app.js").read_text()
    seg = app.split("function renderBaselines(", 1)[1].split("function ", 1)[0]
    loop = seg.split("for (const h of show)", 1)[1]
    loop = loop[:loop.index("if (hosts.length > show.length)")]
    n_cells = loop.count('el("td"')
    assert n_cells == n_cols, (
        f"the baseline table's {n_cols} columns and its {n_cells} row cells disagree")
    for el_id in ("mb-note", "mb-summary", "mb-fired"):
        assert f'getElementById("{el_id}")' in app, f"#{el_id} is written by nothing"
