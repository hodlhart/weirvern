"""SRC-4 identity/lateral specialist: coverage first, then protocol-shape evidence."""
from __future__ import annotations

from pathlib import Path

from weirvern.models import identity_specialist as ids


def _lateral_events():
    events = []
    for i in range(6):
        events.append({"kind": "kerberos", "service": f"HTTP/host{i}.example.com",
                       "success": 1, "client": "alice"})
        events.append({"kind": "ntlm", "success": 0, "hostname": f"host{i}",
                       "username": "alice", "domainname": "EXAMPLE"})
        events.append({"kind": "smb_mapping", "path": rf"\\host{i}\ADMIN$",
                       "service": "SMB"})
        events.append({"kind": "dce_rpc", "operation": f"Op{i}", "endpoint": "svcctl"})
        events.append({"kind": "ldap_search", "ldap_filter": f"(uid=user{i})",
                       "base_object": "dc=example,dc=com"})
    return events


def _benign_events(seen_services, seen_operations, seen_filters):
    events = []
    for _ in range(4):
        events.append({"kind": "kerberos", "service": "HTTP/files.example.com",
                       "success": 1, "client": "alice"})
        events.append({"kind": "ntlm", "success": 1, "hostname": "files",
                       "username": "alice", "domainname": "EXAMPLE"})
        events.append({"kind": "smb_mapping", "path": r"\\files\Users", "service": "SMB"})
        events.append({"kind": "dce_rpc", "operation": "NetShareEnum", "endpoint": "srvsvc"})
        events.append({"kind": "ldap_search", "ldap_filter": "(objectClass=user)",
                       "base_object": "dc=example,dc=com"})
    return events


def test_seeded_lateral_shape_beats_a_benign_identity_pattern():
    lateral = ids.features_from_events(_lateral_events(), seen_services=set(),
                                       seen_operations=set(), seen_filters=set())
    benign = ids.features_from_events(
        _benign_events(set(), set(), set()), seen_services={"HTTP/files.example.com"},
        seen_operations={"NetShareEnum"}, seen_filters={"(objectClass=user)"})
    l_score, l_evidence = ids.score(lateral)
    b_score, _ = ids.score(benign)
    assert l_score > 0.80, l_evidence
    assert b_score < 0.50, f"benign identity pattern scored {b_score}"


def test_evidence_contains_no_usernames_filters_or_paths():
    events = _lateral_events()
    _, evidence = ids.score(ids.features_from_events(events, seen_services=set(),
                                                     seen_operations=set(),
                                                     seen_filters=set()))
    for secret in ("alice", "uid=user", "ADMIN$", "host0"):
        assert secret not in evidence, f"identity evidence leaked {secret!r}: {evidence}"


def test_absent_identity_is_stated_not_zero_normal():
    features = ids.features_from_events([])
    score, evidence = ids.score(features)
    assert features["present"] is False
    assert score == 0.0
    assert "absent" in evidence


def test_source_ablation_count_only_loses_the_lateral_shape():
    lateral = ids.features_from_events(_lateral_events(), seen_services=set(),
                                       seen_operations=set(), seen_filters=set())
    shaped, _ = ids.score(lateral)
    count_only, _ = ids.score(lateral, use_identity_shape=False)
    assert shaped - count_only > 0.40


class _Res:
    def __init__(self, rows):
        self.result_rows = rows


class FakeClient:
    def __init__(self, counts):
        self.counts = counts
        self.queries = []

    def query(self, sql, parameters=None):
        self.queries.append(sql)
        for key, table in ids.COVERAGE_TABLES.items():
            if table in sql:
                return _Res([(self.counts.get(key, 0),)])
        return _Res([(0,)])


def test_coverage_names_every_zero_table_and_refuses_to_train():
    client = FakeClient({"kerberos": 0, "ntlm": 0, "smb_mapping": 0,
                         "smb_files": 0, "dce_rpc": 0, "ldap_search": 0})
    report = ids.run(client, hours=24)
    assert report["available"] is False
    assert "identity coverage gap" in report["reason"]
    assert set(report["coverage"]["zero_tables"]) == set(ids.COVERAGE_TABLES)
    assert "no train" not in report["reason"]  # the reason is the gap, not a claim


def test_coverage_accepts_a_complete_source_set():
    client = FakeClient({key: 10 for key in ids.COVERAGE_TABLES})
    report = ids.run(client, hours=24)
    assert report["available"] is True
    assert report["coverage"]["zero_tables"] == []


def test_identity_path_does_not_write_the_alert_store():
    source = Path(ids.__file__).read_text()
    assert "netflow_anomalies" not in source
    assert "push_alert" not in source
    assert "ml_candidate_scores" not in source  # coverage-only until a fixture exists


def test_score_events_is_pure_and_bounded():
    out = ids.score_events(_lateral_events()[:2], seen_services=set())
    assert len(out) == 2
    for row in out:
        assert 0.0 <= row["score"] <= 1.0
