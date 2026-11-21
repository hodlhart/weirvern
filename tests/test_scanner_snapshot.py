"""`asset_services` is a SNAPSHOT of the newest complete scan, not a life-long union.

THE DEFECT THESE TESTS PIN. `ReplacingMergeTree` replaces a row only when the whole sorting key
matches, so a port that stopped answering was never overwritten: the measured deployment listed
twelve services for a host whose latest scan found one, and six for a host whose latest scan found
four. The history was correct; the "current" table accumulated.

The fake below implements the two writes this module's rule depends on -- ReplacingMergeTree
semantics for a repeated (asset_key, port, protocol), and the lightweight DELETE predicate
`last_seen_scan_id != <this scan>` -- so the tests fail if the writer stops carrying the scan id
or stops deleting stale rows. A list-of-rows fixture would not catch either.
"""
from __future__ import annotations

from datetime import UTC, datetime

from weirvern import scanner

HOST = "198.51.100.10"
ASSET = {
    "asset_key": "ip:198.51.100.10", "ip": HOST, "mac": "", "hostname": "",
    "first_seen": datetime(2026, 1, 1, tzinfo=UTC),
    "last_scan_at": datetime(2026, 1, 1, tzinfo=UTC), "source": "scanner",
}


class _Rows:
    def __init__(self, rows):
        self.result_rows = rows


class SnapshotClient:
    """In-memory asset_services + asset_service_history with the real replacement rules."""

    def __init__(self, services=None):
        self.services = list(services or [])
        self.history: list[dict] = []
        self.inserted: list[tuple[str, list, list]] = []
        self.deleted: list[int] = []

    # ── reads ──────────────────────────────────────────────────────────────────────────────
    def query(self, sql: str, parameters=None):
        parameters = parameters or {}
        if "count() FROM weirvern.asset_services" in sql:
            key = parameters["asset_key"]
            scan_id = parameters["scan_id"]
            return _Rows([(sum(1 for row in self.services
                               if row["asset_key"] == key
                               and row["last_seen_scan_id"] != scan_id),)])
        if "FROM weirvern.asset_services FINAL" in sql:
            key = parameters.get("asset_key")
            rows = [row for row in self.services if key is None or row["asset_key"] == key]
            return _Rows([
                (row["port"], row["protocol"], row["service"], row["product"], row["version"],
                 row["cpe"]) for row in sorted(rows, key=lambda item: item["port"])
            ])
        if "FROM weirvern.asset_service_history" in sql:
            return _Rows([(row["port"], row["protocol"]) for row in self.history])
        if "weirvern.asset_changes" in sql:
            return _Rows([])
        raise AssertionError(f"unexpected query: {sql}")

    # ── writes ─────────────────────────────────────────────────────────────────────────────
    def insert(self, table: str, rows, column_names=None):
        columns = list(column_names or [])
        self.inserted.append((table, [list(row) for row in rows], columns))
        for row in rows:
            record = dict(zip(columns, row, strict=False))
            if table == "weirvern.asset_services":
                self.services = [
                    held for held in self.services
                    if (held["asset_key"], held["port"], held["protocol"])
                    != (record["asset_key"], record["port"], record["protocol"])
                ]
                self.services.append(record)
            elif table == "weirvern.asset_service_history":
                self.history.append(record)

    def command(self, sql: str, parameters=None):
        if not sql.startswith("DELETE FROM weirvern.asset_services"):
            return None
        parameters = parameters or {}
        key = parameters["asset_key"]
        scan_id = parameters["scan_id"]
        before = len(self.services)
        self.services = [
            row for row in self.services
            if not (row["asset_key"] == key and row["last_seen_scan_id"] != scan_id)
        ]
        self.deleted.append(before - len(self.services))
        return None


def _service(port: int, product: str = "", version: str = "") -> dict:
    return {"port": port, "protocol": "tcp", "service": "http", "product": product,
            "version": version, "cpe": ""}


def _result(services, *, complete: bool | None = True, ok=True, observations=None) -> dict:
    payload = {"ok": ok, "command": "nmap -sV ...", "error": "" if ok else "nmap failed",
               "services": services, "observations": observations or []}
    if complete is not None:
        payload["complete"] = complete
    return payload


def _ports(client: SnapshotClient) -> set[int]:
    return {row["port"] for row in client.services}


def test_a_complete_scan_REPLACES_the_hosts_service_set():
    """Measured defect: {22,80} scanned, then {22}; the table must hold {22}, not the union."""
    client = SnapshotClient()
    assert scanner.record_scan_result(
        client, ASSET, _result([_service(22), _service(80)]), scan_id="scan-1")
    assert _ports(client) == {22, 80}

    assert scanner.record_scan_result(
        client, ASSET, _result([_service(22)]), scan_id="scan-2")

    assert _ports(client) == {22}, "the closed port survived in the current-service snapshot"
    assert {row["last_seen_scan_id"] for row in client.services} == {"scan-2"}
    # BOTH scans remain in the append-only history: the snapshot change loses nothing.
    assert [(row["scan_id"], row["port"]) for row in client.history] == [
        ("scan-1", 22), ("scan-1", 80), ("scan-2", 22),
    ]
    assert client.deleted[-1] == 1


def test_a_COMPLETE_scan_with_no_open_ports_is_an_EMPTY_snapshot_not_a_stale_one():
    client = SnapshotClient()
    scanner.record_scan_result(client, ASSET, _result([_service(22)]), scan_id="scan-1")
    scanner.record_scan_result(client, ASSET, _result([]), scan_id="scan-2")

    assert client.services == []
    assert {row["scan_id"] for row in client.history} == {"scan-1"}


def test_a_FAILED_scan_does_not_touch_the_previous_snapshot():
    client = SnapshotClient()
    scanner.record_scan_result(client, ASSET, _result([_service(22)]), scan_id="scan-1")
    deletions_before = list(client.deleted)

    assert scanner.record_scan_result(
        client, ASSET, _result([], complete=False, ok=False), scan_id="scan-2") is False

    assert _ports(client) == {22}
    assert {row["last_seen_scan_id"] for row in client.services} == {"scan-1"}
    assert client.deleted == deletions_before, "a failed scan must not delete snapshot rows"
    assert [row["scan_id"] for row in client.history] == ["scan-1"]


def test_a_PARTIAL_scan_does_not_wipe_or_extend_the_snapshot():
    """A timed-out Nmap's port list is not the host's set: neither added nor deleted."""
    client = SnapshotClient()
    scanner.record_scan_result(client, ASSET, _result([_service(22), _service(80)]),
                               scan_id="scan-1")

    scanner.record_scan_result(client, ASSET, _result([_service(22)], complete=False),
                               scan_id="scan-2")

    assert _ports(client) == {22, 80}
    assert {row["last_seen_scan_id"] for row in client.services} == {"scan-1"}
    # The measurement is still in the audit ledger, marked as belonging to its scan.
    assert ("scan-2", 22) in {(row["scan_id"], row["port"]) for row in client.history}


def test_an_OBSERVATION_ONLY_run_does_not_delete_rows():
    """No completeness marker (an NSE-only result, or an older weirling) is not evidence."""
    client = SnapshotClient()
    scanner.record_scan_result(client, ASSET, _result([_service(22)]), scan_id="scan-1")
    observation = {"port": 22, "script": "ssh-hostkey", "key": "fingerprint",
                   "value": "SHA256:abc"}

    scanner.record_scan_result(
        client, ASSET,
        _result([], complete=None, observations=[observation]), scan_id="scan-2")

    assert _ports(client) == {22}
    assert {row["last_seen_scan_id"] for row in client.services} == {"scan-1"}
    assert any(table == "weirvern.asset_observations"
               for table, _rows, _columns in client.inserted)


# ── Nmap's own completeness verdict ─────────────────────────────────────────────────────────

def _xml(*, exit_status="success", timedout=None, hosts=1) -> str:
    host = '<host><status state="up"/><ports/></host>' if hosts else ""
    extra = f' timedout="{timedout}"' if timedout is not None else ""
    return (
        '<?xml version="1.0"?><nmaprun>'
        f"{host}<runstats><finished time=\"0\" exit=\"{exit_status}\"/></runstats>"
        "</nmaprun>"
    ).replace("<host>", f"<host{extra}>")


def test_a_completed_run_is_complete():
    assert scanner.scan_complete(_xml()) is True


def test_a_host_timeout_is_not_complete():
    assert scanner.scan_complete(_xml(timedout="true")) is False


def test_a_failed_runstats_verdict_is_not_complete():
    assert scanner.scan_complete(_xml(exit_status="timeout")) is False


def test_a_document_without_runstats_is_not_complete():
    assert scanner.scan_complete('<?xml version="1.0"?><nmaprun><host/></nmaprun>') is False


def test_a_reply_with_no_host_is_not_complete():
    assert scanner.scan_complete(_xml(hosts=0)) is False
