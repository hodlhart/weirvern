"""The alert path obeys the episode page budget flag."""
from __future__ import annotations

from weirvern.alerts import AlertState, push_alert
from weirvern.config import Settings


class FakeClient:
    def __init__(self):
        self.rows = []

    def insert(self, table, rows, column_names=None):
        self.rows.append((table, rows, column_names))


def test_non_pageable_verdict_is_audited_budget_and_not_sent():
    client = FakeClient()
    verdict = {
        "src_addr": "192.0.2.10",
        "window_start": "2026-10-30 00:00:00",
        "severity": "high",
        "anomaly_score": 0.91,
        "_pageable": False,
    }
    sent, reason = push_alert(verdict, Settings(pushover_enabled=False), AlertState(), client)
    assert sent is False
    assert reason == "budget"
    assert client.rows
    table, rows, columns = client.rows[-1]
    assert table == "weirvern.alert_events"
    assert rows[0][columns.index("reason")] == "budget"


def test_legacy_caller_without_flag_still_reaches_the_transport_gate():
    client = FakeClient()
    verdict = {
        "src_addr": "192.0.2.10",
        "window_start": "2026-10-30 00:00:00",
        "severity": "high",
        "anomaly_score": 0.91,
        "detected_by_models": "Isolation Forest",
        "isolation_forest_score": 0.91,
        "gradient_boosting_score": 0.1,
        "dbscan_score": 0.1,
        "baseline_score": 0.1,
        "model_agreement": 0.25,
    }
    sent, reason = push_alert(verdict, Settings(pushover_enabled=False), AlertState(), client)
    assert sent is False
    assert reason == "log-only"
