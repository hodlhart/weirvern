"""LRN-1 active learning: bounded, attributable review adjustments, not training data."""
from __future__ import annotations

import datetime
from pathlib import Path

from weirvern.models import active_learning as al

NOW = datetime.datetime(2026, 10, 31, 12, 0, 0)


def _adjustment():
    return al.build_adjustment(
        scope="host", subject="198.51.100.10", metric="page_budget",
        before_value=2, after_value=1, reason="operator marked the episode a false positive",
        reviewer="operator", review_window_start=NOW, review_src_addr="198.51.100.10",
        expiry_days=14, now=NOW,
    )


def test_adjustment_has_before_after_reason_reviewer_and_expiry():
    adj = _adjustment()
    assert adj["before_value"] == 2.0
    assert adj["after_value"] == 1.0
    assert adj["reason"].startswith("operator marked")
    assert adj["reviewer"] == "operator"
    assert adj["expiry"] > NOW
    assert adj["active"] == 1


def test_replay_applies_only_while_effective():
    adj = _adjustment()
    assert al.effective_value(2.0, adj, now=NOW) == 1.0
    reverted = al.revert(adj, reason="operator changed their mind", now=NOW)
    assert al.effective_value(2.0, reverted, now=NOW) == 2.0
    expired = dict(adj, expiry=NOW - datetime.timedelta(seconds=1))
    assert al.effective_value(2.0, expired, now=NOW) == 2.0


def test_adjustment_is_bounded_and_requires_a_change():
    adj = al.build_adjustment(scope="host", subject="h", metric="page_budget",
                              before_value=99, after_value=-3, reason="bounded",
                              now=NOW)
    assert adj["before_value"] == 10.0
    assert adj["after_value"] == 0.0
    try:
        al.build_adjustment(scope="host", subject="h", metric="page_budget",
                            before_value=2, after_value=2, reason="no-op", now=NOW)
    except ValueError:
        pass
    else:
        raise AssertionError("a no-op adjustment must be refused")


def test_uncertain_queue_is_bounded_and_closest_to_midpoint():
    rows = [{"src_addr": f"h{i}", "score": s} for i, s in enumerate(
        [0.1, 0.2, 0.45, 0.49, 0.50, 0.51, 0.8])]
    queue = al.select_uncertain(rows, low=0.40, high=0.60, budget=2)
    assert len(queue) == 2
    assert [row["src_addr"] for row in queue] == ["h4", "h3"]


class _Res:
    def __init__(self, rows):
        self.result_rows = rows


class FakeClient:
    def __init__(self):
        self.inserts = []

    def insert(self, table, data, column_names=None):
        self.inserts.append((table, data, column_names))


def test_write_goes_to_the_adjustment_store_only():
    client = FakeClient()
    assert al.write_adjustment(client, _adjustment()) is True
    assert client.inserts and client.inserts[0][0] == "weirvern.ml_review_adjustments"
    assert "ml_models" not in str(client.inserts)
    assert "netflow_anomalies" not in str(client.inserts)


def test_source_never_writes_training_or_alert_tables():
    source = Path(al.__file__).read_text()
    for forbidden in ("ml_models", "netflow_anomalies", "push_alert"):
        assert forbidden not in source
