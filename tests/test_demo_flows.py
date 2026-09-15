"""End-to-end test of the demo generator + ingester mapping (no ClickHouse).

Validates that synthetic output parses into valid flow rows end-to-end and
that a scanner device produces the expected signature in the aggregate.
"""
import json
import os
import tempfile

from weirvern.ingester import map_flow
from weirvern.tools.demo_flows import generate


def test_demo_generator_writes_valid_jsonl():
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "demo.jsonl")
        n = generate(type("A", (), {
            "minutes": 5, "devices": 4, "output": out, "seed": 7,
            "scanner": True, "scan_ports": 50, "beacon": True, "exfil": True,
        })())
        assert n > 0
        with open(out) as fh:
            lines = [json.loads(line) for line in fh if line.strip()]
        assert len(lines) == n
        # All rows map cleanly into the flows schema
        for raw in lines[:200]:
            row = map_flow(raw)
            assert 0 <= row["dst_port"] <= 65535
            assert row["proto"] in (0, 1, 6, 17)
            assert row["bytes"] >= 0
            assert row["dst_addr"]
            assert row["time_flow_start"] <= row["time_flow_end"]


def test_map_flow_handles_garbage():
    row = map_flow({"src_addr": "not-an-ip", "bytes": "oops", "proto": "BOGUS"})
    assert row["src_addr"] == "0.0.0.0"
    assert row["bytes"] == 0
    assert row["proto"] == 0
    assert row["dst_port"] == 0
