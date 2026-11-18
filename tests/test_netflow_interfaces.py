"""A flow must be able to say which NIC it came through, and the console must say it too.

0.23.70 gave every row `in_iface`: one collector per NIC, one port (2055), the collector's file
stamped onto each record by the ingester. This file tests the READ side -- the mix the Netflow
view prints and the sentence it prints it in -- because an attributed column nobody displays is
attribution that never reaches the operator.

Fixtures are doc-range addresses only (RFC 5737), the invariant the gate enforces.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from weirvern.admin import soc

ROOT = Path(__file__).resolve().parent.parent


class FakeClient:
    """Stands in for clickhouse_connect: records the SQL, returns fixed rows."""

    def __init__(self, rows=None, raises: Exception | None = None):
        self.rows = rows or []
        self.raises = raises
        self.sql = ""

    def query(self, sql, parameters=None):
        self.sql = sql
        if self.raises is not None:
            raise self.raises
        return type("Result", (), {"result_rows": self.rows})()


def test_the_mix_says_which_nic_each_flow_came_through():
    client = FakeClient([("eth1", 120, 9000), ("eth2", 80, 4000), ("", 5, 100)])

    out = soc.interface_mix(client, hours=6, filters={})

    assert out["available"] is True
    assert out["total_flows"] == 205
    assert [(p["iface"], p["flows"], p["bytes"]) for p in out["points"]] == [
        ("eth1", 120, 9000),
        ("eth2", 80, 4000),
        ("", 5, 100),
    ]


def test_an_unattributed_flow_is_reported_as_empty_never_as_a_nic():
    client = FakeClient([("", 7, 700)])

    out = soc.interface_mix(client, hours=1, filters={})

    assert out["points"][0]["iface"] == "", (
        "an empty in_iface means the export did not arrive on a NIC's loopback socket; "
        "filling in a default NIC here would invent a fact"
    )


def test_the_mix_reads_the_raw_table_because_only_it_has_in_iface():
    client = FakeClient([("eth1", 1, 1)])

    soc.interface_mix(client, hours=1, filters={})

    assert "weirvern.flows " in client.sql
    assert "flows_aggregated" not in client.sql
    assert "in_iface" in client.sql


def test_a_failed_read_is_unavailable_with_a_reason_not_an_empty_mix():
    client = FakeClient(raises=RuntimeError("clickhouse said no"))

    out = soc.interface_mix(client, hours=1, filters={})

    assert out["available"] is False
    assert "RuntimeError" in out["reason"]


def test_the_netflow_payload_carries_the_split():
    from weirvern.admin import web_api

    mix = {"available": True, "reason": "", "points": [{"iface": "eth1", "flows": 3, "bytes": 9}],
           "total_flows": 3}

    payload = web_api.netflow_payload({}, {}, {}, {}, {}, interfaces=mix)

    assert payload["interfaces"] == mix


def test_a_missing_split_stays_its_own_card_shaped_gap():
    from weirvern.admin import web_api

    payload = web_api.netflow_payload({}, {}, {}, {}, {})

    assert payload["interfaces"]["available"] is False
    assert payload["interfaces"]["points"] == []


def _iface_split_text(cases: list[dict]) -> list[str]:
    node = shutil.which("node") or ""
    if not node:
        pytest.skip("node is not installed; the gate requires it for the shipping-JS tests")
    out = subprocess.run([node, str(ROOT / "scripts" / "iface_split_text.js"), json.dumps(cases)],
                         capture_output=True, text=True, timeout=30, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_the_sentence_names_each_nic_and_admits_the_unattributed():
    out = _iface_split_text([
        {"available": True, "points": [{"iface": "eth1", "flows": 2100},
                                      {"iface": "eth2", "flows": 1140}]},
        {"available": True, "points": [{"iface": "", "flows": 12}]},
        {"available": True, "points": []},
        {"available": False, "points": []},
    ])

    assert "by NIC" in out[0] and "eth1" in out[0] and "eth2" in out[0]
    assert "unattributed 12" in out[1], "an empty interface is named, not hidden"
    assert out[2] == "", "a window with no flows adds no clause"
    assert "unavailable" in out[3], "a failed read says so instead of reading as a quiet network"
