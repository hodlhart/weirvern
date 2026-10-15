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


def test_attacks_can_start_late_for_a_training_holdout():
    """`--attack-start-minute` moves ALL seeded attacks to start at that minute (review
    round 2026-10-15): the eval harness uses it so training can hold the attack period
    out -- a detector scored on attacks it trained on measures memorisation."""
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "demo.jsonl")
        generate(type("A", (), {
            "minutes": 30, "devices": 4, "output": out, "seed": 7,
            "scanner": True, "scan_ports": 50, "beacon": True, "exfil": True,
            "attack_start_minute": 20,
        })())
        with open(out) as fh:
            rows = [json.loads(line) for line in fh if line.strip()]

    # The attack SIGNATURE rows, not "rows from the attack hosts": the attackers also
    # send ordinary traffic from minute 0 (part of the realism), so source alone cannot
    # identify the seeded attacks. Each attack has a destination only it uses.
    def is_attack(r: dict) -> bool:
        return r["dst_addr"] in ("198.51.100.99",   # scanner target
                                 "203.0.113.66",    # beacon C2
                                 "198.51.100.7")    # exfil sink

    # Attacks sit on exact minute boundaries; benign rows carry a 0-59s jitter (see the
    # generator), so the reference is the earliest row and attack minutes read as 19 or 20
    # depending on that jitter. The substantive claim is "not from the start, from ~20".
    seed_start = min(r["time_flow_start_ns"] for r in rows)

    def minute_of(r: dict) -> int:
        return (r["time_flow_start_ns"] - seed_start) // (60 * 1_000_000_000)

    attack_minutes = [minute_of(r) for r in rows if is_attack(r)]
    assert attack_minutes, "no attack flows were produced at all"
    assert 19 <= min(attack_minutes) <= 20, (
        f"the earliest attack is at minute {min(attack_minutes)}; with the holdout flag it "
        f"must begin at the flagged minute (~20), not at the start"
    )
    # And ordinary traffic still fills the beginning of the seed, so the training window
    # has something to train on.
    benign_minutes = [minute_of(r) for r in rows if not is_attack(r)]
    assert min(benign_minutes) == 0
