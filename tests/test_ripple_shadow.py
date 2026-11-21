"""RIP-5: the ripple fusion must be wired, must abstain honestly, and must never page."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from weirvern.admin.status import ripple_overview
from weirvern.models import ripple_shadow
from weirvern.models.ripple import ChannelEvidence, fuse

NOW = datetime(2026, 11, 11, 18, 0, 0, tzinfo=UTC)


def _ts(seconds_ago: int = 30) -> datetime:
    """ClickHouse hands back naive UTC; the module must treat it as UTC, not local."""
    return (NOW - timedelta(seconds=seconds_ago)).replace(tzinfo=None)


REFERENCE = [i / 100.0 for i in range(50)]  # 0.00 .. 0.49


class FakeClient:
    """Answers the reads by shape, and records the write."""

    def __init__(self, *, references=None, recent=None, fail=None, history=None):
        self.references = references if references is not None else {
            "ml_candidate_scores": [("FlowSpecialist", v) for v in REFERENCE]
                                   + [("DNSSpecialist", v) for v in REFERENCE],
            "ml_temporal_scores": [("temporal:bytes", v) for v in REFERENCE],
            "ml_changepoints": [("changepoint:bytes:up", v) for v in REFERENCE],
        }
        self.recent = recent if recent is not None else {}
        # The deployment's own fused history: what the operating point is derived from.
        self.history = history if history is not None else []
        self.fail = fail or set()
        self.inserted = []

    def query(self, sql, parameters=None):
        for table in self.fail:
            if table in sql:
                raise RuntimeError(f"{table} unavailable")
        if "FROM weirvern.ml_ripple" in sql:
            return SimpleNamespace(result_rows=list(self.history))
        is_reference = "BY model" in sql
        source = self.references if is_reference else self.recent
        for table, rows in source.items():
            if table in sql:
                return SimpleNamespace(result_rows=list(rows))
        return SimpleNamespace(result_rows=[])

    def insert(self, table, rows, column_names=None):
        self.inserted.append((table, list(rows), list(column_names or [])))


def _recent(host="198.51.100.5", *, flow=0.99, dns=0.99, cp=None, temporal=None):
    rows = {
        "ml_candidate_scores": [(host, "FlowSpecialist", flow, "v4", _ts()),
                                (host, "DNSSpecialist", dns, "v4", _ts())],
        "ml_temporal_scores": [],
        "ml_changepoints": [],
    }
    if temporal is not None:
        rows["ml_temporal_scores"] = [(host, "temporal:bytes", temporal, "mp-1", _ts())]
    if cp is not None:
        probability, run_length = cp
        rows["ml_changepoints"] = [
            (host, "changepoint:bytes:up", probability, "v4", _ts(), run_length,
             _ts(120))]
    return rows


def test_retired_ripple_channels_are_never_evidence():
    """RIP-5 read every shadow channel, including the ones the inventory retired.

    FlowSpecialist / DNSSpecialist / Temporal / change-point are all `merge` or `retire` in
    `models.dispositions`; the live pass still turned them into families and every one of the
    21 ripples in the 24-hour population was built on at least one of them.
    """
    client = FakeClient(recent=_recent(cp=(0.99, 288), temporal=3.9))
    out = ripple_shadow.evaluate(client, now=NOW)

    assert len(out) == 1
    assert out[0]["status"] == "unknown", out[0]["reason"]
    assert out[0]["contributors"] == []
    # A retired channel is not even a missing channel: it is not expected to report.
    assert out[0]["unknown_channels"] == []


def test_a_stale_change_point_is_not_fresh_because_its_row_was_rewritten():
    """`computed_at` is when the pass ran; `changepoint_at` is when the regime changed."""
    nov_21 = datetime(2026, 11, 21, 12, 0, 0, tzinfo=UTC)
    nov_15 = datetime(2026, 11, 15, 3, 0, 0, tzinfo=UTC)
    assert ripple_shadow.changepoint_stale(nov_15, nov_21) is True
    assert ripple_shadow.changepoint_stale(
        nov_21 - timedelta(seconds=30), nov_21) is False
    assert ripple_shadow.changepoint_stale(None, nov_21) is True


def test_a_missing_channel_is_named_missing_and_never_scored_as_zero():
    # A non-retired channel with no row is an honest unknown, with its own reason.
    lone = ChannelEvidence(channel="dns", family="dns", scale="5m", model_id="dns",
                           model_version="v1", score=0.0, pvalue=float("nan"),
                           freshness_s=float("inf"), present=False)
    out = fuse([lone])
    assert out.status == "unknown"
    assert out.unknown == [{"channel": "dns", "family": "dns", "reason": "missing"}]


def test_a_model_without_a_reference_is_skipped_not_given_a_fabricated_p_value():
    recent = _recent()
    recent["ml_candidate_scores"].append(
        ("198.51.100.5", "NewDetector", 0.99, "v1", _ts()))
    out = ripple_shadow.evaluate(FakeClient(recent=recent), now=NOW)

    channels = {c["channel"] for c in out[0]["contributors"]}
    assert "NewDetector" not in channels
    assert all(u["channel"] != "NewDetector" for u in out[0]["unknown_channels"])


def test_stale_rows_are_unknown_not_evidence():
    # The lookback is enforced in SQL, but the fusion enforces freshness too: a row whose age
    # slipped past 900 s must not enter the combined p-value.
    client = FakeClient(recent=_recent(cp=(0.99, 288)))
    out = ripple_shadow.evaluate(client, now=NOW + timedelta(hours=1))

    assert out[0]["status"] in {"observation", "unknown"}
    assert out[0]["status"] != "ripple"


def test_run_persists_one_row_per_host_and_never_pages_or_alerts():
    # A warm deployment: enough of its own history that the operating point can be derived.
    history = [(0.9, "198.51.100.5") for _ in range(200)]
    client = FakeClient(recent=_recent(cp=(0.99, 288)), history=history)
    summary = ripple_shadow.run(client, now=NOW)

    assert summary["hosts"] == 1 and summary["rows"] == 1
    # No ripple can be made from retired evidence, which is the honest result of this pass.
    assert summary["ripple"] == 0
    assert summary["unknown"] == 1
    assert summary["operating_point"]["cold_start"] is False
    table, rows, columns = client.inserted[0]
    assert table == "weirvern.ml_ripple"
    assert len(rows) == 1
    # pageable is the 12th column and is 0 by construction: a shadow pass cannot page.
    assert columns[11] == "pageable" and rows[0][11] == 0
    assert set(columns) == {
        "evaluated_at", "src_addr", "status", "reason", "confidence", "combined_p",
        "families", "scales", "contributors", "unknown_channels", "channel_count",
        "pageable", "model_version",
    }


def test_the_changepoint_scale_comes_from_the_regime_that_ended():
    assert ripple_shadow.changepoint_scale(1) == "5m"
    assert ripple_shadow.changepoint_scale(11) == "5m"
    assert ripple_shadow.changepoint_scale(12) == "1h"
    assert ripple_shadow.changepoint_scale(287) == "1h"
    assert ripple_shadow.changepoint_scale(288) == "24h"


def test_an_unknown_model_keeps_its_own_family():
    # Two unknown detectors must not be folded into one family, or they could vote twice for
    # the same kind of evidence.
    assert ripple_shadow.family_scale_for("New Detector")[0] == "new_detector"
    assert ripple_shadow.family_scale_for("FlowSpecialist") == ("flow", "5m")


def _status_client(*, head, rows):
    class Stub:
        def query(self, sql, parameters=None):
            if "count() AS n, max(evaluated_at)" in sql:
                return SimpleNamespace(result_rows=[head])
            return SimpleNamespace(result_rows=list(rows))

    return Stub()


def test_the_api_payload_names_the_unavailable_states_instead_of_returning_empty_success():
    class Broken:
        def query(self, sql, parameters=None):
            raise RuntimeError("table missing")

    broken = ripple_overview(Broken())
    assert broken["available"] is False and "table missing" in broken["reason"]
    assert broken["pageable"] is False

    empty = ripple_overview(_status_client(head=(0, None), rows=[]))
    assert empty["available"] is False
    assert "no ripple evaluation" in empty["reason"]


def test_the_headline_prefers_a_ripple_and_carries_the_explanation():
    stamp = datetime(2026, 11, 11, 17, 40, 0)
    rows = [
        (stamp, "198.51.100.9", "observation", "one scale is a burst, not a ripple", 0.99, 0.01,
         ["flow", "dns"], ["5m"], "[]", "[]", 2, "ripple-1"),
        (stamp, "198.51.100.5", "ripple", "independent calibrated evidence across families and scales",
         0.999, 0.0004, ["flow", "dns"], ["5m", "24h"],
         '[{"channel":"dns_volume","family":"dns","scale":"5m","pvalue":0.001}]',
         '[{"channel":"tls_unvalidated","family":"tls","reason":"missing"}]', 3, "ripple-1"),
    ]
    out = ripple_overview(_status_client(head=(2, stamp), rows=rows))

    assert out["available"] is True and out["pageable"] is False
    assert out["status"] == "ripple" and out["src_addr"] == "198.51.100.5"
    assert out["counts"] == {"hosts": 2, "ripple": 1, "observation": 1, "unknown": 0}
    assert out["contributors"][0]["channel"] == "dns_volume"
    assert out["unknown"][0]["reason"] == "missing"
    assert out["scales"] == ["5m", "24h"]


def test_one_evidence_per_channel_and_scale_keeps_the_most_significant():
    # Measured live 2026-11-12: HDBSCAN wrote hundreds of correlated candidates per host and
    # every one of them entered Fisher's combination, which is not a valid independence
    # assumption and produced a 187 KB payload for 22 hosts.
    def row(scale: str, pvalue: float, score: float) -> ChannelEvidence:
        return ChannelEvidence(channel="HDBSCAN", family="candidate", scale=scale,
                               model_id="HDBSCAN", model_version="v", score=score,
                               pvalue=pvalue, freshness_s=1.0)

    rows = [row("5m", 0.9 - i * 0.01, 0.1) for i in range(50)]
    rows.append(row("5m", 0.0005, 0.99))
    rows.append(row("1h", 0.30, 0.50))
    out = ripple_shadow.strongest_per_channel(rows)
    assert len(out) == 2, "one evidence per channel AND scale"
    five_minute = next(item for item in out if item.scale == "5m")
    assert five_minute.pvalue == 0.0005 and five_minute.score == 0.99


def test_a_deployment_with_no_history_abstains_instead_of_firing():
    client = FakeClient(recent=_recent(cp=(0.99, 288)), history=[])
    summary = ripple_shadow.run(client, now=NOW)

    assert summary["ripple"] == 0
    assert summary["unknown"] == 1
    assert summary["operating_point"]["cold_start"] is True
    rows = client.inserted[0][1]
    assert rows[0][2] == "unknown"
    assert "learning" in rows[0][3]
