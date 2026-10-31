"""TMP-3 drift monitoring: a shift is a notice, never a page or an auto-retrain."""
from __future__ import annotations

from pathlib import Path

from weirvern.models import drift as dr


def test_psi_is_zero_for_identical_and_high_for_a_shift():
    baseline = [float(i) for i in range(100)]
    assert dr.psi(baseline, baseline) == 0.0
    shifted = [float(i + 100) for i in range(100)]
    assert dr.psi(baseline, shifted) > dr.DRIFT_THRESHOLD
    assert dr.psi([1.0], [2.0]) == 0.0


def test_classify_has_three_operable_words():
    assert dr.classify(0.0) == "stable"
    assert dr.classify(0.15) == "watch"
    assert dr.classify(0.30) == "drift"


def test_retrain_policy_is_manual():
    policy = dr.retrain_policy([{"model_name": "IF", "drift_score": 0.4}])
    assert policy["trigger"] is True
    assert policy["automatic"] is False
    assert dr.retrain_policy([])["trigger"] is False


class _Res:
    def __init__(self, rows):
        self.result_rows = rows


class FakeClient:
    def __init__(self):
        self.calls = 0
        self.inserts = []

    def query(self, sql, parameters=None):
        self.calls += 1
        if self.calls == 1:
            return _Res([("IsolationForest", "198.51.100.10",
                          [float(i + 100) for i in range(100)])])
        if self.calls == 2:
            return _Res([("IsolationForest", "198.51.100.10",
                          [float(i) for i in range(100)])])
        return _Res([("198.51.100.10", "workstation")])

    def insert(self, table, data, column_names=None):
        self.inserts.append((table, data, column_names))


def test_run_writes_drift_notice_and_never_the_alert_table():
    client = FakeClient()
    report = dr.run(client, hours=24)
    assert report["available"] is True
    assert report["rows"] == 1
    assert report["notices"] and report["notices"][0]["status"] == "drift"
    assert report["retrain"]["trigger"] is True
    assert report["retrain"]["automatic"] is False
    assert client.inserts and client.inserts[0][0] == "weirvern.ml_drift"
    assert "netflow_anomalies" not in str(client.inserts)


class EmptyClient:
    def query(self, sql, parameters=None):
        return _Res([])

    def insert(self, table, data, column_names=None):
        raise AssertionError("empty split must not write")


def test_run_is_explicit_when_the_splits_have_no_rows():
    report = dr.run(EmptyClient(), hours=24)
    assert report["available"] is True
    assert report["rows"] == 0
    assert report["notices"] == []


def test_module_does_not_write_the_alert_path():
    source = Path(dr.__file__).read_text()
    assert "netflow_anomalies" not in source
    assert "push_alert" not in source
    assert "retrain(" not in source
