"""WL-1 pins: the list's trend and taps come from EVIDENCE.

The trend is flows per bucket from the flows table's own `sampler_address` -- the exporter's
address, which is the sensor's reported address -- and an empty series is "not observed", never
a flat zero line. The taps are word+colour, lit only on evidence, with the reason in the title.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from weirvern import fleet_store

WEB = Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web"
PY = Path(__file__).resolve().parents[1] / "weirvern"


class Stub:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def query(self, sql, parameters=None):
        self.calls.append({"sql": sql, "params": parameters or {}})
        return SimpleNamespace(result_rows=self.rows)


def test_flow_evidence_maps_by_exporter_and_skips_empty_fleets():
    c = Stub([("198.51.100.7", 42, "2026-09-23 12:00:00", 600)])
    out, err = fleet_store.flow_evidence(c, ["198.51.100.7", ""])
    assert err == "" and out["198.51.100.7"]["flows"] == 42
    assert out["198.51.100.7"]["age_s"] == 600
    assert "sampler_address IN" in c.calls[0]["sql"]
    assert c.calls[0]["params"]["addrs"] == ["198.51.100.7"]
    empty_stub = Stub([])
    empty, err2 = fleet_store.flow_evidence(empty_stub, [])
    assert empty == {} and err2 == ""
    assert empty_stub.calls == [], "an empty fleet must not query at all"


def test_flow_series_buckets_and_zero_fills_but_never_invents_a_series():
    now = datetime(2026, 9, 23, 12, 0, tzinfo=UTC)
    since = now.replace(tzinfo=None) - timedelta(minutes=60)
    rows = [
        ("198.51.100.7", since + timedelta(minutes=1), 5),    # bucket 0
        ("198.51.100.7", since + timedelta(minutes=6), 3),    # bucket 1
        ("198.51.100.7", since + timedelta(minutes=57), 9),   # bucket 11
    ]
    out, err = fleet_store.flow_series(Stub(rows), ["198.51.100.7"], minutes=60, buckets=12,
                                       now=now)
    assert err == ""
    series = out["198.51.100.7"]
    assert len(series) == 12 and series[0] == 5 and series[1] == 3 and series[11] == 9
    assert series[2] == 0, "gaps are real zeroes only because the exporter had flows"
    none, _ = fleet_store.flow_series(Stub([]), ["198.51.100.7"], now=now)
    assert none == {}, "no flows at all must be NO series, not twelve zeroes"


def test_zeek_evidence_says_why_when_dark():
    ok = Stub([(10, "2026-09-23 12:00:00")])
    out, _ = fleet_store.zeek_evidence(ok)
    assert out["observed"] is True and out["rows"] == 10
    dark = Stub([(0, None)])
    out2, _ = fleet_store.zeek_evidence(dark)
    assert out2["observed"] is False and "nothing in the last 24h" in out2["why"]


def test_the_payload_attaches_evidence_and_remote_zeek_is_unknown():
    # THE FLEET FETCH MOVED into payloads.weirlings with the port; the helpers stayed in web.py.
    src = (PY / "admin" / "payloads.py").read_text()
    seg = src.split("def weirlings(", 1)[1].split("\ndef ", 1)[0]
    assert "flow_evidence(" in seg and "flow_series(" in seg and "zeek_evidence(" in seg
    # The exporter mapping is owned by _flow_exporters: a LOCAL sensor's goflow2 writes
    # loopback even when its heartbeat carries a management address.
    assert "_flow_exporters(" in seg
    web = (PY / "admin" / "web.py").read_text()
    helper = web.split("def _flow_exporters(", 1)[1].split("def _attach_anomaly_locations", 1)[0]
    assert "127.0.0.1" in helper and "::1" in helper
    assert 'row["flow_series"] = merged_series' in seg
    assert "only the hub runs Zeek" in seg, \
        "a remote weirling's Zeek must be unknown, never falsely dark"


def test_the_row_is_a_scan_line_not_a_fact_dump():
    src = (WEB / "weirlings.js").read_text()
    seg = src.split("function wlNicFacts(", 1)[1].split("function wlNicRows(", 1)[0]
    seg += src.split("function wlNicRows(", 1)[1].split("function renderWeirlings(", 1)[0]
    assert 'wlTap("netflow", n.netflow)' in seg and 'wlTap("zeek"' in seg
    assert "wlSparkline(r)" in seg
    assert "(r.plan && r.plan.segment)" in seg and "r.reported_segment" in seg
    assert "el(\"li\", { text: f }" not in seg, "findings prose came back into the list"


def test_netflow_chip_names_the_feed_and_the_active_nic_owns_it():
    # THE FETCH MOVED into payloads.weirlings with the port; the chip vocabulary is unchanged.
    src = (PY / "admin" / "payloads.py").read_text()
    seg = src.split("def weirlings(", 1)[1].split("\ndef ", 1)[0]
    assert '"scope": "sensor"' in seg
    assert '"scope_label": "netflow"' in seg
    assert "attribute it to this NIC" in seg

    js = (WEB / "weirlings.js").read_text()
    tap = js.split("function wlTap(", 1)[1].split("function wlCfg(", 1)[0]
    assert '· sensor feed' not in tap, "the visible chip must say netflow, not sensor feed"
    assert "sensorScoped" not in tap
    assert '"netflow"' in tap
    assert "not attributed to this NIC" in tap

    facts = js.split("function wlNicFacts(", 1)[1].split("function wlNicRows(", 1)[0]
    assert "activeOwner" in facts and 'wlCfgValue("netflow_iface")' in facts
    assert 'wlCfgValue("netflow_mode")' in facts
    assert "active NetFlow samples" in facts
