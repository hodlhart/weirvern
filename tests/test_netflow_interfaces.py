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


# ── the launcher: one process per NIC, one port ─────────────────────────────────────────────
def _launcher_script(tmp_path: Path) -> Path:
    """THE SHIPPING SCRIPT, extracted from the ConfigMap that mounts it.

    A test that kept its own copy of the launcher would pass while the cluster ran something
    else -- the same trap the 0.23.69 review-text tests were written to avoid.
    """
    import yaml

    doc = yaml.safe_load((ROOT / "k8s" / "35-goflow2-launcher.yaml").read_text())
    script = doc["data"]["goflow2-multi.sh"]
    path = tmp_path / "goflow2-multi.sh"
    path.write_text(script)
    return path


def _launch_commands(tmp_path: Path, ifaces: str) -> list[list[str]]:
    import os

    script = _launcher_script(tmp_path)
    env = dict(os.environ, DRY_RUN="1", NETFLOW_IFACE=ifaces,
               NODE_IP="192.0.2.10", FLOW_DATA_DIR="/data")
    out = subprocess.run(["sh", str(script)], capture_output=True, text=True, timeout=30,
                         env=env, check=False)
    assert out.returncode == 0, out.stderr
    return [line.split() for line in out.stdout.strip().splitlines() if line.strip()]


def test_the_launcher_opens_one_socket_per_nic_on_the_same_port(tmp_path):
    cmds = _launch_commands(tmp_path, "eth1,eth2,eth3")

    listens = [c[c.index("-listen") + 1] for c in cmds[:3]]
    assert listens == ["netflow://127.0.0.1:2055,sflow://:6343",
                       "netflow://127.0.0.2:2055",
                       "netflow://127.0.0.3:2055"], (
        "the operator asked to keep 2055 for every NIC: only the loopback ADDRESS may differ"
    )
    assert all(":2055" in listen for listen in listens)


def test_the_launcher_names_the_files_the_ingester_expects(tmp_path):
    cmds = _launch_commands(tmp_path, "eth1,eth2,eth3")

    files = [c[c.index("-transport.file") + 1] for c in cmds[:3]]
    assert files == ["/data/flows.jsonl", "/data/flows-eth2.jsonl", "/data/flows-eth3.jsonl"]
    # And the same rule on the reading side, from the same input.
    assert _targets("eth1,eth2,eth3") == [
        ("/data/flows.jsonl", "eth1"),
        ("/data/flows-eth2.jsonl", "eth2"),
        ("/data/flows-eth3.jsonl", "eth3"),
        ("/data/flows-external.jsonl", ""),
    ]


def test_the_launcher_keeps_the_node_address_for_a_lan_router(tmp_path):
    cmds = _launch_commands(tmp_path, "eth1")

    assert cmds[-1][cmds[-1].index("-listen") + 1] == "netflow://192.0.2.10:2055"
    assert cmds[-1][cmds[-1].index("-transport.file") + 1] == "/data/flows-external.jsonl"


def test_more_nics_than_loopback_addresses_is_refused_before_it_starts(tmp_path):
    import os

    script = _launcher_script(tmp_path)
    too_many = ",".join(f"eth{i}" for i in range(1, 257))
    out = subprocess.run(["sh", str(script)], capture_output=True, text=True, timeout=30,
                         env=dict(os.environ, DRY_RUN="1", NETFLOW_IFACE=too_many,
                                  NODE_IP="192.0.2.10", FLOW_DATA_DIR="/data"), check=False)

    assert out.returncode != 0
    assert "254" in out.stderr


def _targets(ifaces: str) -> list[tuple[str, str]]:
    from weirvern.ingester import tail_targets

    return tail_targets("/data/flows.jsonl", "", ifaces)


def test_the_interface_chip_filters_the_view_on_the_raw_table():
    clause, params = soc.flow_filter({"iface": "eth2"})

    assert "in_iface = %(fiface)s" in clause
    assert params["fiface"] == "eth2"
    assert soc.flow_filter_is_raw({"iface": "eth2"}) is True, (
        "flows_aggregated has no in_iface; the chip must force the raw table or it would be "
        "silently ignored"
    )


def test_an_interface_filter_that_is_not_a_name_is_refused():
    from weirvern.admin import web

    with pytest.raises(ValueError):
        web.netflow_filters({"iface": "eth2; drop table"})
    assert web.netflow_filters({"iface": "eth2"})["iface"] == "eth2"
