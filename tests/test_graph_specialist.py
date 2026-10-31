"""TMP-2 graph/peer specialist: fan-out and new edges, not degree alone."""
from __future__ import annotations

from pathlib import Path

from weirvern.models import graph_specialist as gs


def _star():
    return [("198.51.100.10", f"198.51.100.{100 + i}") for i in range(40)]


def _mesh():
    hosts = [f"198.51.100.{20 + i}" for i in range(10)]
    return [(a, b) for a in hosts for b in hosts if a != b]


def test_seeded_lateral_star_beats_a_reciprocal_mesh():
    star = gs.features_from_edges(_star(), "198.51.100.10", seen_edges=set())
    mesh = gs.features_from_edges(_mesh(), "198.51.100.20", seen_edges=set(_mesh()))
    star_score, star_evidence = gs.score(star)
    mesh_score, _ = gs.score(mesh)
    assert star_score > 0.80, star_evidence
    assert mesh_score < 0.40, f"reciprocal mesh scored {mesh_score}"


def test_reciprocity_reduces_the_fanout_signal():
    star = gs.features_from_edges(_star(), "198.51.100.10", seen_edges=set())
    reverse = [(dst, src) for src, dst in _star()]
    reciprocal = gs.features_from_edges(_star() + reverse, "198.51.100.10",
                                        seen_edges=set())
    assert gs.score(reciprocal)[0] < gs.score(star)[0]


def test_absent_graph_is_stated_not_zero_normal():
    features = gs.features_from_edges([], "198.51.100.10")
    score, evidence = gs.score(features)
    assert features["present"] is False
    assert score == 0.0
    assert "absent" in evidence


def test_source_ablation_degree_only_loses_the_lateral_shape():
    star = gs.features_from_edges(_star(), "198.51.100.10", seen_edges=set())
    shaped, _ = gs.score(star)
    degree_only, _ = gs.score(star, use_graph_shape=False)
    assert shaped - degree_only > 0.35


def test_query_reads_conn_edges_and_not_the_alert_path():
    sql = gs.query_sql(15, scope_filter="AND 1")
    for column in ("src_addr", "dst_addr", "ts"):
        assert column in sql
    assert "weirvern.zeek_conn" in sql
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
    client = FakeClient([("198.51.100.10", f"198.51.100.{100 + i}", 1) for i in range(10)])
    report = gs.run(client, minutes=15, scope_filter="")
    assert report["available"] is True
    assert report["rows"] == 1
    assert client.inserts and client.inserts[0][0] == "weirvern.ml_candidate_scores"
    assert client.inserts[0][1][0][2] == "GraphSpecialist"
    assert "netflow_anomalies" not in str(client.inserts)


def test_run_names_an_empty_graph():
    report = gs.run(FakeClient([]), minutes=15, scope_filter="")
    assert report["available"] is False
    assert "no Zeek connection edges" in report["reason"]


def test_module_does_not_write_the_alert_path():
    source = Path(gs.__file__).read_text()
    assert "netflow_anomalies" not in source
    assert "push_alert" not in source


def test_score_rows_aggregates_edges_per_source():
    rows = [("198.51.100.10", f"198.51.100.{100 + i}", 1) for i in range(40)]
    scored = gs.score_rows(rows)
    assert len(scored) == 1
    assert scored[0]["features"]["out_degree"] == 40
    assert 0.0 <= scored[0]["score"] <= 1.0
