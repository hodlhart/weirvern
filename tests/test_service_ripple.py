"""Service-set changes are a ripple channel: one COMPLETE scan against the host's own history.

WHAT THESE TESTS PIN. The scanner now measures a truthfully current service set; this channel is
how that measurement reaches detection. The comparison unit is a scan, not an hour, because a
scan is episodic -- so the fake answers the two reads the channel makes (the scan ledger and the
per-scan history) and the tests assert the statistic, the p-value's method, and the sentence the
operator reads.

Every fixture uses RFC 5737 addresses: the gate refuses deployment identifiers in tracked files.
"""
from __future__ import annotations

import ipaddress
import math
from datetime import UTC, datetime, timedelta

from weirvern.models import ripple_evidence
from weirvern.models.ripple import (
    CHANNEL_FAMILIES,
    ChannelEvidence,
    group_evidence,
    severity_bands,
)

HOST = "198.51.100.10"
NET = "198.51.100.0/24"
NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
STEP = timedelta(hours=1)
SSH96 = (22, "tcp", "ssh", "OpenSSH", "9.6")
SSH100 = (22, "tcp", "ssh", "OpenSSH", "10.0")
HTTP = (8080, "tcp", "http", "Golang net/http", "")

REQUIRED = ("scan_id", "ip", "port", "protocol", "service", "product", "version", "observed_at")


class _Rows:
    def __init__(self, rows):
        self.result_rows = rows


class ScanClient:
    """Answers the scanner reads, honouring the completeness predicate the module builds."""

    def __init__(self, scans, history):
        # scans: [(scan_id, ip, finished_at, scan_complete)]
        self.scans = scans
        self.history = history
        self.inserted: list[tuple[str, list, list]] = []
        self.queries: list[str] = []

    def query(self, sql: str, parameters=None):
        self.queries.append(sql)
        if "weirvern.network_scopes" in sql:
            return _Rows([(NET,)])
        if "system.columns" in sql:
            return _Rows([("asset_service_history", name) for name in REQUIRED])
        if "weirvern.asset_scans" in sql:
            rows = self.scans
            if "scan_complete = 1" in sql:
                rows = [row for row in rows if row[3]]
            return _Rows([(row[0], row[1], row[2]) for row in rows])
        if "weirvern.asset_service_history" in sql:
            return _Rows(self.history)
        return _Rows([])

    def insert(self, table, rows, column_names=None):
        self.inserted.append((table, [list(row) for row in rows], list(column_names or [])))


class StoreClient(ScanClient):
    """Adds the evidence table's insert/read round-trip."""

    def __init__(self, scans, history):
        super().__init__(scans, history)
        self.evidence: list[dict] = []

    def insert(self, table, rows, column_names=None):
        columns = list(column_names or [])
        super().insert(table, rows, columns)
        if table != "weirvern.ml_ripple_evidence":
            return
        for row in rows:
            self.evidence.append(dict(zip(columns, row, strict=False)))

    def query(self, sql: str, parameters=None):
        if "FROM weirvern.ml_ripple_evidence" in sql:
            return _Rows([
                tuple(row.get(name) for name in ripple_evidence.READ_COLUMNS)
                for row in self.evidence
            ])
        return super().query(sql, parameters)


def _build(snapshots, *, complete=True) -> tuple[list, list]:
    """Turn a list of service sets into the ledger rows and history rows a scan would write."""
    scans, history = [], []
    total = len(snapshots)
    for index, services in enumerate(snapshots):
        scan_id = f"s{index:04d}"
        finished = NOW - STEP * (total - 1 - index)
        scans.append((scan_id, HOST, finished, complete))
        for port, protocol, service, product, version in services:
            history.append((scan_id, HOST, port, protocol, service, product, version))
    return scans, history


def _compute(snapshots, *, complete=True):
    scans, history = _build(snapshots, complete=complete)
    client = ScanClient(scans, history)
    return ripple_evidence.compute(client, now=NOW, retention_days=30,
                                   specs=ripple_evidence.SERVICE_SPECS)


def _one(snapshots) -> ChannelEvidence:
    items = _compute(snapshots)
    assert len(items) == 1, f"expected one service row, got {items}"
    return items[0]


# ── the four behaviours the channel must have ───────────────────────────────────────────────

def test_a_NEW_PORT_fires_with_the_port_and_product_in_words():
    item = _one([{SSH96}] * 120 + [{SSH96, HTTP}])

    assert item.channel == "service_set_change"
    assert item.family == "service"
    assert item.value == 1.0
    assert item.p_method == "empirical"
    assert item.pvalue <= 0.01
    assert item.detail == (f"{HOST} opened 8080/tcp (Golang net/http) since the previous scan")


def test_a_CLOSED_PORT_fires():
    item = _one([{SSH96, HTTP}] * 120 + [{SSH96}])

    assert item.value == 1.0
    assert item.pvalue <= 0.01
    assert item.detail == (f"{HOST} closed 8080/tcp (Golang net/http) since the previous scan")


def test_a_VERSION_CHANGE_fires_and_names_BOTH_versions():
    item = _one([{SSH96}] * 120 + [{SSH100}])

    assert item.value == 1.0
    assert item.pvalue <= 0.01
    assert item.detail == (f"{HOST} changed 22/tcp from OpenSSH 9.6 to OpenSSH 10.0 "
                           "since the previous scan")


def test_an_UNCHANGED_set_is_measured_and_quiet():
    item = _one([{SSH96}] * 121)

    assert item.value == 0.0
    assert item.pvalue == 1.0
    assert item.detail == f"{HOST} has no service change since the previous scan"
    # Measured and quiet is a result, not a missing measurement.
    assert item.p_method == "empirical" and item.sample_count == 119


# ── no previous scan is INSUFFICIENT, never "no change" ─────────────────────────────────────

def test_a_hosts_FIRST_scan_is_insufficient_not_a_change():
    item = _one([{SSH96}])

    assert item.p_method == "insufficient"
    assert math.isnan(item.pvalue)
    assert item.sample_count == 0 and item.baseline_short is True
    assert "one complete scan" in item.detail
    assert "no service change" not in item.detail


def test_ONE_earlier_scan_is_a_comparison_but_not_a_baseline():
    item = _one([{SSH96}, {SSH96, HTTP}])

    assert item.p_method == "insufficient"
    assert math.isnan(item.pvalue)
    assert "one earlier scan" in item.detail
    assert "opened 8080/tcp" in item.detail


def test_a_PARTIAL_scan_is_not_in_the_series():
    """A timed-out scan's empty port list must not look like a closure."""
    scans, history = _build([{SSH96}] * 120 + [{SSH96}])
    partial = ("s-partial", HOST, NOW + timedelta(minutes=5), False)
    scans.append(partial)
    client = ScanClient(scans, history)

    items = ripple_evidence.compute(client, now=NOW, retention_days=30,
                                    specs=ripple_evidence.SERVICE_SPECS)

    assert len(items) == 1
    assert items[0].value == 0.0
    assert items[0].pvalue == 1.0


# ── the row ships like every other channel's ────────────────────────────────────────────────

def test_the_sentence_is_stored_and_read_back_from_the_evidence_row():
    item = _one([{SSH96}] * 120 + [{SSH96, HTTP}])
    scans, history = _build([{SSH96}] * 120 + [{SSH96, HTTP}])
    client = StoreClient(scans, history)

    assert ripple_evidence.store(client, [item]) == 1
    stored = client.evidence[0]
    assert "opened 8080/tcp" in stored["p_detail"]
    assert stored["channel"] == "service_set_change"
    assert stored["family"] == "service"
    assert stored["value"] == 1.0

    back = ripple_evidence.read(client, hours=24, now=NOW)
    assert len(back) == 1
    assert "opened 8080/tcp (Golang net/http) since the previous scan" in back[0].detail


def test_the_channel_corroborates_and_gets_a_SEVERITY_from_the_one_band_table():
    item = _one([{SSH96}] * 120 + [{SSH96, HTTP}])
    conn = ChannelEvidence(
        channel="conn_volume", family="conn", scale="1h", model_id="source:conn_volume",
        model_version="test", score=1.0, pvalue=0.008, freshness_s=0.0, host=HOST,
        observed_at=NOW, value=1.0, baseline_median=0.0, sample_count=200,
        coverage=1.0, direction="rose", p_floor=1.0 / 201.0,
    )

    ripples = group_evidence([item, conn], monitored=[ipaddress.ip_network(NET)])

    assert len(ripples) == 1
    payload = ripples[0].as_dict()
    assert payload["severity"] == "medium"
    assert payload["families"] == ["conn", "service"]
    assert "opened 8080/tcp (Golang net/http) since the previous scan" in payload["explanation"]
    # The bands are the server's, not a second table invented for this channel.
    assert payload["severity"] in severity_bands()


def test_the_family_and_statistic_are_DECLARED_not_implied():
    assert CHANNEL_FAMILIES["service_set_change"] == "service"
    spec = ripple_evidence.SERVICE_SPECS[0]
    assert spec.channel == "service_set_change"
    assert spec.table == "weirvern.asset_service_history"
    assert set(spec.required_columns) <= {"scan_id", "ip", "port", "protocol", "service",
                                          "product", "version", "observed_at"}
    assert "previous complete scan" in ripple_evidence.statistic(spec)


def test_the_scan_read_does_not_alias_an_aggregate_to_the_column_it_filters():
    """Measured live: `max(finished_at) AS finished_at` is an aggregate in WHERE (code 184).

    ClickHouse substitutes a SELECT alias into the WHERE clause. The alias must differ, or the
    channel reads nothing and `compute()` swallows the failure as 'no evidence' -- a silence
    with no error, which is the defect class this module keeps naming.
    """
    scans, history = _build([{SSH96}] * 3)
    client = ScanClient(scans, history)

    ripple_evidence.compute(client, now=NOW, retention_days=30,
                            specs=ripple_evidence.SERVICE_SPECS)

    scan_sql = next(sql for sql in client.queries if "weirvern.asset_scans" in sql)
    assert "AS finished_at" not in scan_sql
    assert "AS last_finished" in scan_sql
