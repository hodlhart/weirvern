"""SRC-2 TLS/JA4 specialist: novelty and rarity, not session volume."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from weirvern.models import tls_specialist as ts


def _session(ja4: str, *, version: str = "TLSv1.3", sni: str = "example.com") -> dict:
    return {"ja4": ja4, "version": version, "server_name": sni}


def test_new_rare_ja4_scores_above_a_common_browser_fingerprint():
    new_host = ts.features_from_sessions(
        [_session("t13d1516h2_new")], seen_ja4=set(),
        fleet_host_counts={"t13d1516h2_new": 1, "t13d1516h2_common": 100},
    )
    benign = ts.features_from_sessions(
        [_session("t13d1516h2_common")], seen_ja4={"t13d1516h2_common"},
        fleet_host_counts={"t13d1516h2_new": 1, "t13d1516h2_common": 100},
    )
    new_score, evidence = ts.score(new_host)
    benign_score, _ = ts.score(benign)
    assert new_score > 0.55, evidence
    assert benign_score < 0.30, f"benign browser update scored {benign_score}"
    assert "new_ja4=1.00" in evidence
    assert "fleet_rarity=" in evidence


def test_old_tls_and_sni_mismatch_add_evidence():
    features = ts.features_from_sessions(
        [_session("t13_old", version="TLSv1.0", sni="wrong.example")],
        seen_ja4=set(), fleet_host_counts={"t13_old": 1},
        expected_sni={"t13_old": "right.example"},
    )
    score, evidence = ts.score(features)
    assert score > 0.5
    assert "old_tls=1.00" in evidence
    assert "sni_mismatch=1.00" in evidence


def test_absent_tls_is_stated_not_zero_normal():
    features = ts.features_from_sessions([])
    score, evidence = ts.score(features)
    assert features["present"] is False
    assert score == 0.0
    assert "absent" in evidence


def test_source_ablation_count_only_loses_the_new_ja4():
    features = ts.features_from_sessions(
        [_session("t13_new")], seen_ja4=set(), fleet_host_counts={"t13_new": 1})
    shaped, _ = ts.score(features)
    count_only, _ = ts.score(features, use_ja4_shape=False)
    assert shaped - count_only > 0.30


def test_query_reads_tls_columns_and_not_the_alert_path():
    sql = ts.query_sql(15, scope_filter="AND 1")
    for column in ("ts", "ja4", "version", "server_name", "src_addr"):
        assert column in sql, f"TLS query lost {column}"
    assert "weirvern.zeek_ssl" in sql
    assert "netflow_anomalies" not in sql


def test_score_rows_ranks_within_window():
    start = datetime(2026, 10, 31, tzinfo=UTC)
    rows = [
        (start, "198.51.100.10", 1, 1, 1, 0, 1, ["t13_new"]),
        (start, "198.51.100.11", 20, 2, 20, 0, 2, ["t13_a", "t13_b"]),
    ]
    scored = ts.score_rows(rows)
    assert [row["rank"] for row in scored] == [1, 2]
    assert scored[0]["src_addr"] == "198.51.100.10"


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
    client = FakeClient([(start, "198.51.100.10", 1, 1, 1, 0, 1, ["t13_new"])])
    report = ts.run(client, minutes=15, scope_filter="")
    assert report["available"] is True
    assert report["rows"] == 1
    assert client.inserts and client.inserts[0][0] == "weirvern.ml_candidate_scores"
    assert client.inserts[0][1][0][2] == "TLSSpecialist"
    assert "netflow_anomalies" not in str(client.inserts)


def test_run_names_an_empty_window():
    report = ts.run(FakeClient([]), minutes=15, scope_filter="")
    assert report["available"] is False
    assert "no TLS sessions" in report["reason"]


def test_module_does_not_write_the_alert_path():
    source = Path(ts.__file__).read_text()
    assert "netflow_anomalies" not in source
    assert "push_alert" not in source
