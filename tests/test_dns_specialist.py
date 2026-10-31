"""SRC-1 DNS specialist: query shape distinguishes a tunnel from a busy resolver."""
from __future__ import annotations

import random
from datetime import UTC, datetime
from pathlib import Path

from weirvern.models import dns_specialist as ds


def _tunnel_queries(n: int = 120) -> list[dict]:
    rng = random.Random(7)
    out = []
    for _ in range(n):
        label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(48))
        query = f"{label}.tunnel.example.com"
        out.append({"query": query, "qtype": 16, "rcode": 0, "query_len": len(query),
                    "query_entropy": ds.shannon_entropy(query), "answers": ""})
    return out


def _benign_queries(n: int = 120) -> list[dict]:
    out = []
    for i in range(n):
        query = f"www.example{i % 3}.com"
        out.append({"query": query, "qtype": 1, "rcode": 0, "query_len": len(query),
                    "query_entropy": ds.shannon_entropy(query), "answers": "203.0.113.10"})
    return out


def test_entropy_and_registrable_domain_are_deterministic():
    assert ds.shannon_entropy("") == 0.0
    assert ds.shannon_entropy("aaaa") == 0.0
    assert ds.shannon_entropy("abcd") == 2.0
    assert ds.registrable_domain("a.b.Example.COM.") == "example.com"


def test_seeded_dns_tunnel_beats_a_busy_benign_resolver():
    tunnel = ds.features_from_queries(_tunnel_queries(), seen_domains=set())
    benign = ds.features_from_queries(_benign_queries(), seen_domains=set())
    t_score, t_evidence = ds.score(tunnel)
    b_score, _ = ds.score(benign)
    assert t_score > 0.75, t_evidence
    assert b_score < 0.40, f"benign resolver scored {b_score}"
    assert "mean_entropy=" in t_evidence and "txt=" in t_evidence


def test_absent_dns_is_stated_not_zero_normal():
    features = ds.features_from_queries([])
    score, evidence = ds.score(features)
    assert features["present"] is False
    assert score == 0.0
    assert "absent" in evidence


def test_source_ablation_count_only_loses_the_tunnel():
    tunnel = ds.features_from_queries(_tunnel_queries(), seen_domains=set())
    shaped, _ = ds.score(tunnel, use_dns_shape=True)
    count_only, _ = ds.score(tunnel, use_dns_shape=False)
    assert shaped - count_only > 0.40, (shaped, count_only)


def test_query_reads_dns_columns_and_not_the_alert_path():
    sql = ds.query_sql(15, scope_filter="AND 1")
    for column in ("ts", "query", "qtype", "rcode", "query_len", "query_entropy"):
        assert column in sql, f"DNS query lost {column}"
    assert "weirvern.zeek_dns" in sql
    assert "netflow_anomalies" not in sql


def test_score_rows_ranks_within_window():
    start = datetime(2026, 10, 31, tzinfo=UTC)
    rows = [
        (start, "198.51.100.10", 120, 120, 4.6, 4.9, 60.0, 2.0, 120, 0, 0, 0, 0, 0, 0),
        (start, "198.51.100.11", 120, 3, 2.1, 2.4, 25.0, 1.0, 0, 0, 0, 0, 0, 0, 120),
    ]
    scored = ds.score_rows(rows)
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
    client = FakeClient([(start, "198.51.100.10", 120, 120, 4.6, 4.9, 60.0, 2.0, 120, 0, 0, 0, 0, 0, 0)])
    report = ds.run(client, minutes=15, scope_filter="")
    assert report["available"] is True
    assert report["rows"] == 1
    assert client.inserts and client.inserts[0][0] == "weirvern.ml_candidate_scores"
    assert client.inserts[0][1][0][2] == "DNSSpecialist"
    assert "netflow_anomalies" not in str(client.inserts)


def test_run_names_an_empty_window():
    report = ds.run(FakeClient([]), minutes=15, scope_filter="")
    assert report["available"] is False
    assert "no DNS queries" in report["reason"]


def test_module_does_not_write_the_alert_path():
    source = Path(ds.__file__).read_text()
    assert "netflow_anomalies" not in source
    assert "push_alert" not in source
