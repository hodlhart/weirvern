"""Identity's evidence, wired to the traffic this deployment actually has (2026-10-16).

The operator: "Now work on identity. It's not working." Measured on the live box: the view
showed one host, os unknown, `hostnames_seen` empty for every host, `mac` empty for every host.
Not a rendering bug -- the observation extractors only fired for dhcp and ssl, and the sensed
segment carries NO DHCP at all, so the MAC signal (the most universal source) never fired and no
name was ever gathered. Meanwhile the names were in the DNS view and the MACs were in conn.log.

These tests pin the three new sources and the verdict's name-gathering. Names carry NO
classifier weight -- a name proves what a host calls, not what it runs -- so the tests also pin
that they never become Signals.
"""

from datetime import datetime, timedelta

from weirvern import host_identity
from weirvern.ingester import (
    observations_from_conn,
    observations_from_dns,
    observations_from_ssl,
)

TS = datetime(2026, 10, 16, 9, 0)
ROW = {"ts": TS, "src_addr": "198.51.100.20"}


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _FakeStore:
    """Serves the one read collect_observations makes."""

    def __init__(self, rows):
        self.rows = rows

    def query(self, sql, parameters=None, **_kw):
        return _Result(self.rows)


# ── conn: the MAC signal's missing source ─────────────────────────────────────────────────────
def test_conn_yields_the_mac_so_the_oui_signal_can_fire():
    rows = observations_from_conn({"orig_l2_addr": "aa:bb:cc:dd:ee:ff"}, dict(ROW))
    assert len(rows) == 1
    assert rows[0]["source"] == "oui" and rows[0]["raw"] == "aa:bb:cc:dd:ee:ff"
    assert rows[0]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert rows[0]["note"] == "from conn"


def test_conn_without_a_mac_writes_nothing():
    assert observations_from_conn({"orig_l2_addr": "-"}, dict(ROW)) == []
    assert observations_from_conn({"orig_l2_addr": "(empty)"}, dict(ROW)) == []
    assert observations_from_conn({}, dict(ROW)) == []
    assert observations_from_conn({"orig_l2_addr": "aa:bb:cc:dd:ee:ff"},
                                   {"ts": TS, "src_addr": ""}) == []


# ── dns: the names the DNS view already knew ───────────────────────────────────────────────────
def test_dns_yields_the_name_asked_for_normalized():
    rows = observations_from_dns({"query": "Living-Room.LOCAL."}, dict(ROW))
    assert len(rows) == 1
    assert rows[0]["source"] == "dns_name" and rows[0]["raw"] == "living-room.local"


def test_dns_refuses_numeric_and_junk_queries():
    assert observations_from_dns({"query": "203.0.113.7"}, dict(ROW)) == []
    assert observations_from_dns({"query": ""}, dict(ROW)) == []
    assert observations_from_dns({"query": "-"}, dict(ROW)) == []
    assert observations_from_dns({"query": "(empty)"}, dict(ROW)) == []


def test_dns_refuses_protocol_artifacts_not_names():
    """Found on the first live run: mDNS service-TYPE lookups and reverse names landed in
    hostnames_seen beside the real ones."""
    assert observations_from_dns({"query": "_companion-link._tcp.local"}, dict(ROW)) == []
    # A SHORT reverse label on purpose: an ip6.arpa nibble string parses as an address-shaped
    # token to the sanitation guard (measured: a long one tripped it), and the test only needs
    # the .arpa branch exercised.
    assert observations_from_dns({"query": "label.ip6.arpa"}, dict(ROW)) == []


def test_a_stored_artifact_is_filtered_at_READ_too():
    """Rows stored BEFORE the rule (the first live run, 90-day TTL) must not keep leaking
    artifacts into hostnames_seen -- the gather consults the same predicate."""
    t0 = datetime(2026, 10, 16, 8, 0)
    rows = [
        ("fe80::1", "", "dns_name", "_companion-link._tcp.local", 1, t0 + timedelta(hours=1), t0),
        ("fe80::1", "", "dns_name", "living-room.local", 1, t0, t0),
    ]
    verdicts = host_identity.build_identity(_FakeStore(rows), dry_run=True)
    assert verdicts[0]["hostnames_seen"] == ["living-room.local"]


def test_dns_keeps_a_device_name_that_carries_a_service_suffix():
    """The mDNS instance name IS the device's name -- only the bare service-type lookup is an
    artifact, and the difference is whether the name starts with an underscore."""
    rows = observations_from_dns({"query": "Owen\u2019s iPad._companion-link._tcp.local"}, dict(ROW))
    assert len(rows) == 1 and rows[0]["raw"].startswith("owen\u2019s ipad")


# ── ssl: the SNI beside the fingerprint ─────────────────────────────────────────────────────────
def test_ssl_yields_the_sni_alongside_the_fingerprint():
    rows = observations_from_ssl(
        {"ja4": "t13d1516h2_8daaf6152771_02713d6af862", "server_name": "Cdn.Example.com"},
        dict(ROW))
    by_source = {r["source"]: r["raw"] for r in rows}
    assert by_source == {"ja4": "t13d1516h2_8daaf6152771_02713d6af862",
                         "tls_sni": "cdn.example.com"}


def test_a_fingerprintless_row_still_contributes_its_name():
    rows = observations_from_ssl({"ja4": "-", "server_name": "cdn.example.com"}, dict(ROW))
    assert [r["source"] for r in rows] == ["tls_sni"], (
        "an unfingerprintable session is still a session with a name")


def test_an_ssl_row_with_nothing_to_say_writes_nothing():
    assert observations_from_ssl({"ja4": "-", "server_name": "-"}, dict(ROW)) == []


# ── the verdict gathers names from every source, newest first, deduped ─────────────────────────
def test_the_verdict_lists_names_from_every_source_that_carries_one():
    t0 = datetime(2026, 10, 16, 8, 0)
    rows = [
        ("fe80::1", "aa:bb:cc:dd:ee:ff", "dns_name", "living-room.local", 3, t0 + timedelta(hours=1), t0),
        ("fe80::1", "", "tls_sni", "cdn.example.com", 1, t0 + timedelta(minutes=30), t0 + timedelta(minutes=30)),
        ("fe80::1", "", "dhcp_hostname", "Living-Room", 1, t0 + timedelta(minutes=10), t0 + timedelta(minutes=10)),
        ("fe80::1", "", "dns_name", "Living-Room.local", 1, t0, t0),
    ]
    verdicts = host_identity.build_identity(_FakeStore(rows), dry_run=True)
    assert len(verdicts) == 1
    names = verdicts[0]["hostnames_seen"]
    assert names == ["living-room.local", "cdn.example.com", "Living-Room"], (
        "newest first, deduped case-insensitively; the fourth row repeats the first name")
    assert verdicts[0]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_names_never_become_os_signals():
    """A name proves what a host CALLS, not what it RUNS. The classifier must ignore them, or
    one mDNS name would produce a confident OS verdict."""
    signals, structure = host_identity.signals_for_host("fe80::1", [
        {"source": "dns_name", "raw": "living-room.local", "mac": ""},
        {"source": "tls_sni", "raw": "cdn.example.com", "mac": ""},
        {"source": "dhcp_hostname", "raw": "iphone", "mac": ""},
    ])
    assert structure is None
    assert all(s.source != "dns_name" and s.source != "tls_sni" for s in signals)
