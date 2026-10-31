"""SRC-3 raw-flow specialist: shape catches what volume hides."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from weirvern.models import flow_specialist as fs


def test_zero_byte_syn_sweep_beats_a_busy_volume_host():
    scan = fs.features_from_counts(
        flows=400, zero_bytes=400, syn=400, rst=0, unique_dsts=1, unique_ports=400,
        short_lived=200, total_bytes=0, total_packets=400,
    )
    busy = fs.features_from_counts(
        flows=1000, zero_bytes=0, syn=10, rst=5, unique_dsts=200, unique_ports=50,
        short_lived=100, total_bytes=1_000_000_000, total_packets=1_000_000,
    )
    scan_score, scan_evidence = fs.score(scan)
    busy_score, _ = fs.score(busy)
    assert scan_score > 0.85, scan_evidence
    assert busy_score < 0.30, f"busy server scored {busy_score}"
    assert "zero_byte=1.00" in scan_evidence


def test_source_ablation_volume_only_loses_the_zero_byte_scan():
    scan = fs.features_from_counts(
        flows=400, zero_bytes=400, syn=400, rst=0, unique_dsts=1, unique_ports=400,
        short_lived=200, total_bytes=0, total_packets=400,
    )
    shaped, _ = fs.score(scan, use_raw_shape=True)
    volume_only, _ = fs.score(scan, use_raw_shape=False)
    assert shaped - volume_only > 0.40, (
        f"raw-flow shape contributed too little: shaped={shaped}, volume={volume_only}")


def test_query_reads_raw_flow_columns_and_never_the_alert_path():
    sql = fs.query_sql(15, scope_filter="AND 1")
    for column in ("time_flow_start", "bytes", "tcp_flags", "dst_addr", "dst_port"):
        assert column in sql, f"raw-flow query lost {column}"
    assert "weirvern.flows" in sql
    assert "netflow_anomalies" not in sql
    assert "INTERVAL 15 MINUTE" in sql


def test_score_rows_ranks_within_each_window_and_keeps_presence():
    rows = [
        (datetime(2026, 10, 31, tzinfo=UTC), "198.51.100.10", 400, 400, 400, 0, 1, 400, 200, 0, 400),
        (datetime(2026, 10, 31, tzinfo=UTC), "198.51.100.11", 10, 0, 1, 0, 2, 2, 1, 900, 5),
    ]
    scored = fs.score_rows(rows)
    assert [r["rank"] for r in scored] == [1, 2]
    assert scored[0]["src_addr"] == "198.51.100.10"
    assert scored[0]["score"] > scored[1]["score"]


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
    client = FakeClient([
        (datetime(2026, 10, 31, tzinfo=UTC), "198.51.100.10",
         400, 400, 400, 0, 1, 400, 200, 0, 400),
    ])
    report = fs.run(client, minutes=15, scope_filter="")
    assert report["available"] is True
    assert report["rows"] == 1
    assert client.inserts and client.inserts[0][0] == "weirvern.ml_candidate_scores"
    assert client.inserts[0][1][0][2] == "FlowSpecialist"
    assert "netflow_anomalies" not in str(client.inserts)


def test_run_names_an_empty_window_instead_of_padding_zero_hosts():
    report = fs.run(FakeClient([]), minutes=15, scope_filter="")
    assert report["available"] is False
    assert "no raw flows" in report["reason"]


def test_module_does_not_write_the_alert_path():
    source = Path(fs.__file__).read_text()
    assert "netflow_anomalies" not in source
    assert "push_alert" not in source
