"""The defects a full audit found, pinned so they cannot come back silently.

EVERY TEST HERE CORRESPONDS TO A DEFECT THAT SHIPPED AND WAS INVISIBLE. That is the point of the
file, and it is why the assertions are shaped the way they are: each one fails in a way that names
the consequence rather than merely the difference.

Why the existing suite did not catch them: the anomaly-insert arity error was hidden because every
FakeCH in the suite accepted `column_names` and ignored it, so a row two values short inserted
"successfully" forever. The scoring defects were hidden because the tests asserted on the SOURCE
TEXT of the queries (checking that the words `zeek_seen` or `avg_s0` appear) rather than on the
values those expressions produce. Both are the same mistake in two shapes -- testing that the code
says something rather than that it does something.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from weirvern import attack
from weirvern.alerts import format_message
from weirvern.models.detectors import AdaptiveBaselineDetector
from weirvern.zeek_features import ZEEK_FEATURES

ROOT = Path(__file__).resolve().parents[1]


def _anomaly_row_and_columns() -> tuple[int, list[str]]:
    """(values in the anomaly row, names in _ANOMALY_COLUMNS), read from the shipping source.

    One definition so the several assertions below cannot disagree about what they are measuring.
    """
    src = (ROOT / "weirvern" / "worker.py").read_text()
    n_values = 0
    for node in ast.walk(ast.parse(src)):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "append" and node.args
                and isinstance(node.args[0], ast.List)):
            n_values = len(node.args[0].elts)
    assert n_values, "the anomaly row literal was not found"
    start = src.index("_ANOMALY_COLUMNS")
    names = re.findall(r'"([a-z_]+)"', src[start:src.index(")", start)])
    return n_values, names


# ── the insert that would have killed detection ────────────────────────────────

def test_the_anomaly_row_supplies_one_value_per_column_name():
    """A positional INSERT is correct only while the row and the column list agree in LENGTH and
    ORDER. They disagreed by two (the ATT&CK pair was added to the names, not to the row), so
    clickhouse-connect raised ProgrammingError at driver/insert.py:94 on EVERY insert.

    The consequence was not a crash anyone saw: the exception was caught by the worker loop's
    generic handler, so the worker logged nothing unusual, the status page showed ingest and
    training healthy, and netflow_anomalies simply stayed empty. A total detection outage that
    presented as a quiet network. Counted with the AST because the row contains nested calls
    (json.dumps, datetime.now) where a comma-split cannot tell an argument from an element.
    """
    n_values, names = _anomaly_row_and_columns()
    assert n_values == len(names), (
        f"the anomaly insert writes {n_values} values against {len(names)} column names; "
        "every insert will raise and detection will stop without saying so"
    )


def test_the_insert_site_guards_its_own_arity():
    """The length check must exist at the insert, not only in this test.

    A test protects the repository; it does not protect a running deployment whose worker was
    built from a branch. The check has to be in the code path that would otherwise raise deep
    inside the driver, where the generic handler hides it.
    """
    src = (ROOT / "weirvern" / "worker.py").read_text()
    assert "len(_row) != len(_ANOMALY_COLUMNS)" in src, (
        "the insert site does not verify its own row length, so a future drift raises inside the "
        "driver and is swallowed as a quiet network"
    )


def test_the_attack_columns_are_last_in_the_column_list():
    """Order matters as much as length: the ATT&CK pair must stay last, matching the row.

    If either drifts, values land in the wrong columns. That does not raise -- ClickHouse will
    happily store a label in a score column -- so nothing but this assertion would notice.
    """
    _n, names = _anomaly_row_and_columns()
    assert names[-2:] == ["attack_techniques", "attack_label"], names[-3:]


def test_a_row_with_the_wrong_length_is_refused_by_a_realistic_client():
    """Drive the real insert path against a client that validates like clickhouse-connect.

    The fake clients in this suite accepted anything, which is precisely why the defect shipped.
    This one raises on a mismatch, the way the driver does.
    """
    from clickhouse_connect.driver.exceptions import ProgrammingError

    class ValidatingClient:
        def __init__(self):
            self.received = []

        def insert(self, table, rows, column_names=None):
            for row in rows:
                if column_names is not None and len(row) != len(column_names):
                    raise ProgrammingError("Insert data column count does not match column names")
            self.received.append((table, rows, column_names))

    n_values, names = _anomaly_row_and_columns()

    # The shipping row length against the shipping column count must be accepted.
    client = ValidatingClient()
    client.insert("weirvern.netflow_anomalies", [[None] * n_values], column_names=names)
    assert len(client.received) == 1

    # And a row one short must be REFUSED, so this test would fail if the guard were removed.
    with pytest.raises(ProgrammingError):
        client.insert("weirvern.netflow_anomalies", [[None] * (n_values - 1)], column_names=names)


# ── the alert that could never be sent ─────────────────────────────────────────

def test_an_alert_carrying_a_technique_can_actually_be_formatted():
    """Every detection that mapped to a technique produced NO alert at all.

    worker.py stored dicts (m.as_dict()) where attack.summarise() expects Match objects, so
    format_message raised AttributeError on `.confidence`. push_alert calls format_message with no
    try/except, so the exception escaped to the worker loop's handler and the alert was lost --
    along with its alert_events audit row, because _audit runs after the format call. The one
    case where the alert carries its most valuable content was the one case that never arrived.
    """
    import json

    techs = attack.map_techniques({
        "unique_dst_ports": 300, "port_entropy": 7.9, "total_bytes": 0, "resp_bytes": 0,
        "unique_dst_ips": 60,
    })
    assert techs, "the fixture no longer maps to any technique"

    verdict = {
        "src_addr": "192.0.2.10", "window_start": "2026-09-19 21:00:00", "anomaly_score": 0.91,
        "severity": "medium", "detected_by_models": "DBSCAN", "model_agreement": 1.0,
        "isolation_forest_score": 0.2, "gradient_boosting_score": 0.3, "dbscan_score": 0.99,
        "baseline_score": 0.1, "primary_deviation_feature": "unique_dst_ports",
        "primary_deviation_zscore": 3.4, "baseline_comparison": "{}", "duration_minutes": 5,
        "attack_techniques": [m.as_dict() for m in techs],
        "_attack_matches": techs,
        "attack_label": attack.label(techs),
    }
    message = format_message(verdict)
    assert "ATT&CK:" in message, "the technique line vanished from the alert"

    # The DB form must round-trip too: the stored row is dicts only, and an alert rendered from a
    # stored row must still work.
    stored = {k: v for k, v in verdict.items() if k != "_attack_matches"}
    stored["attack_techniques"] = json.loads(json.dumps(verdict["attack_techniques"]))
    assert "ATT&CK:" in format_message(stored)


def test_the_worker_keeps_the_match_objects_for_the_alert_path():
    """The alert path needs Match objects; the DB needs dicts. Both must be carried.

    Keeping only the dicts is what broke the alert, and keeping only the objects would break the
    JSON column, so the intent has to be explicit in the code.
    """
    src = (ROOT / "weirvern" / "worker.py").read_text()
    assert '_attack_matches' in src, (
        "the worker no longer keeps the Match objects, so alerts carrying a technique would raise "
        "inside the formatter and be lost"
    )


def test_match_round_trips_through_its_json_form():
    """as_dict/from_dict must be inverses, so the two shapes cannot drift apart silently."""
    techs = attack.map_techniques({
        "unique_dst_ports": 300, "port_entropy": 7.9, "total_bytes": 0, "resp_bytes": 0,
        "unique_dst_ips": 60,
    })
    for m in techs:
        back = attack.Match.from_dict(m.as_dict())
        assert back.technique.id == m.technique.id
        assert back.confidence == m.confidence
        assert list(back.evidence) == list(m.evidence)


# ── the baseline that read the wrong columns ───────────────────────────────────

def test_the_baseline_reads_its_zeek_fields_by_name():
    """The Adaptive Baseline read r[9]..r[15] positionally, but the query emits 50 Zeek columns.

    So r[9] was `max(zeek_present)` -- a 0/1 flag -- not a connection count, and every value read
    landed on a different measurement. Because `zeek_seen` gates the whole behavioural term in
    predict(), a host with no DNS silently scored volume-only, and the detector carried the
    highest fusion weight of the four. Nothing raised; the numbers were simply about other things.

    This drives the real helper against a row laid out the way the SQL lays it out.
    """
    base = 9
    row = ["192.0.2.10"] + [0.0] * 6 + [(1, 2, 3), (1, 2, 3)] + [0.0] * len(ZEEK_FEATURES) + [1]
    row[base + ZEEK_FEATURES.index("zeek_conn_count")] = 91.0
    row[base + ZEEK_FEATURES.index("zeek_s0_ratio")] = 0.02
    row[base + ZEEK_FEATURES.index("zeek_service_count")] = 6.0
    row[base + ZEEK_FEATURES.index("zeek_notice_count")] = 3.0

    out = AdaptiveBaselineDetector._zeek_baseline_fields(tuple(row))
    assert out["zeek_seen"] is True, "the presence flag was read from the wrong column"
    assert out["avg_conn"] == 91.0, "avg_conn did not read zeek_conn_count"
    assert out["avg_s0"] == 0.02, "avg_s0 did not read zeek_s0_ratio"
    assert out["avg_services"] == 6.0
    assert out["avg_notices"] == 3.0

    # And the offset must be DERIVED, so a new Zeek feature cannot shift these reads again.
    src = (ROOT / "weirvern" / "models" / "detectors.py").read_text()
    assert "ZEEK_FEATURES.index(" in src or "enumerate(ZEEK_FEATURES)" in src, (
        "the baseline offsets are hardcoded again; a reordered ZEEK_FEATURES would silently "
        "re-introduce the wrong-column defect"
    )


def test_zeek_seen_is_not_the_dns_count():
    """The specific confusion that made the detector volume-only, stated as its own case.

    A host Zeek saw with 40 connections and no DNS must still report zeek_seen. Under the old
    positional read it read r[14], which was the DNS count, so 0 DNS meant "not seen by Zeek".
    """
    base = 9
    row = ["192.0.2.10"] + [0.0] * 6 + [(1, 2, 3), (1, 2, 3)] + [0.0] * len(ZEEK_FEATURES) + [1]
    row[base + ZEEK_FEATURES.index("zeek_conn_count")] = 40.0
    row[base + ZEEK_FEATURES.index("zeek_dns_count")] = 0.0
    out = AdaptiveBaselineDetector._zeek_baseline_fields(tuple(row))
    assert out["zeek_seen"] is True, (
        "a host with 40 Zeek-observed connections but no DNS must still count as seen; reading "
        "the DNS count as the presence flag is what disabled the behavioural term"
    )
