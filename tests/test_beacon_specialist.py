"""TMP-1 beacon/periodicity specialist: regular callbacks, not regular volume."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from weirvern.models import beacon_specialist as bs


def _periodic_times(n: int = 12, step: int = 300) -> list[float]:
    return [float(i * step) for i in range(n)]


def test_seeded_beacon_beats_a_periodic_backup():
    beacon = bs.features_from_times(_periodic_times(), [500.0] * 12)
    backup = bs.features_from_times(
        [0.0, 3300.0, 7200.0, 11100.0, 15000.0, 18900.0],
        [50_000_000.0] * 6,
    )
    beacon_score, beacon_evidence = bs.score(beacon)
    backup_score, _ = bs.score(backup)
    assert beacon_score > 0.85, beacon_evidence
    assert backup_score < 0.75, f"periodic backup scored {backup_score}"


def test_irregular_burst_is_not_a_beacon():
    burst = bs.features_from_times([0.0, 2.0, 3.0, 50.0, 120.0, 121.0, 400.0], [2_000.0] * 7)
    score, evidence = bs.score(burst)
    assert score < 0.45, evidence


def test_fewer_than_four_events_is_absent():
    features = bs.features_from_times([0.0, 300.0, 600.0])
    score, evidence = bs.score(features)
    assert features["present"] is False
    assert score == 0.0
    assert "absent" in evidence


def test_source_ablation_count_only_loses_the_periodicity():
    features = bs.features_from_times(_periodic_times(), [500.0] * 12)
    shaped, _ = bs.score(features)
    count_only, _ = bs.score(features, use_periodicity=False)
    assert shaped - count_only > 0.40


def test_query_reads_flow_times_and_bytes_and_not_the_alert_path():
    sql = bs.query_sql(60, scope_filter="AND 1")
    for column in ("time_flow_start", "bytes", "src_addr", "dst_addr"):
        assert column in sql, f"beacon query lost {column}"
    assert "weirvern.flows" in sql
    assert "netflow_anomalies" not in sql


class _Res:
    def __init__(self, rows):
        self.result_rows = rows


class FakeClient:
    def __init__(self, rows):
        self.rows = rows
        self.inserts = []

    def query(self, sql, parameters=None):
        return _Res(self.rows)

    def insert(self, table, data, column_names=None):
        self.inserts.append((table, data, column_names))


def test_run_writes_only_the_candidate_store():
    start = datetime(2026, 10, 31, tzinfo=UTC)
    times = [start + timedelta(seconds=300 * i) for i in range(12)]
    client = FakeClient([("198.51.100.10", "203.0.113.66", start, 12, times, [500] * 12)])
    report = bs.run(client, minutes=60, scope_filter="")
    assert report["available"] is True
    assert report["rows"] == 1
    assert client.inserts and client.inserts[0][0] == "weirvern.ml_candidate_scores"
    assert client.inserts[0][1][0][2] == "BeaconSpecialist"
    assert "netflow_anomalies" not in str(client.inserts)


def test_run_names_an_empty_window():
    report = bs.run(FakeClient([]), minutes=60, scope_filter="")
    assert report["available"] is False
    assert "no flow-time pairs" in report["reason"]


def test_module_does_not_write_the_alert_path():
    source = Path(bs.__file__).read_text()
    assert "netflow_anomalies" not in source
    assert "push_alert" not in source
