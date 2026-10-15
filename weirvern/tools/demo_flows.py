"""Synthetic flow generator — exercises the whole Weirvern pipeline locally.

Produces JSONL in goflow2's output shape (so the ingester needs zero changes
to consume it) with:
  * N "normal" devices doing routine traffic (Web/DNS/SMB/games)
  * 1-2 seeded attack devices per run: port scanner and/or beacon (C2-style)
  * `--attack-start-minute N` delays ALL seeded attacks to start at minute N -- used by
    scripts/eval_detection.py so the training window can HOLD OUT the attack period.

Usage:
  python -m weirvern.tools.demo_flows --minutes 60 --devices 8 --output /tmp/demo.jsonl
"""
from __future__ import annotations

import argparse
import json
import random
import time

# goflow2 record field -> synthetic value
_DEFAULT_PROTO = 6  # TCP


def _flow(time_ns: int, src: str, dst: str, sport: int, dport: int, proto: int,
          bytes_: int, packets: int, flags: int = 16) -> dict:
    return {
        "time_flow_start_ns": time_ns,
        "time_flow_end_ns": time_ns + random.randint(50_000_000, 5_000_000_000),
        "src_addr": src,
        "dst_addr": dst,
        "src_port": sport,
        "dst_port": dport,
        "proto": proto,
        "etype": "IPv4",
        "bytes": bytes_,
        "packets": packets,
        "tcp_flags": flags,
        "sampling_rate": 1,
        "sampler_address": "198.51.100.1",
        "in_if": 0,
        "out_if": 0,
    }


def generate(args) -> int:
    """Generate synthetic traffic.

    Realism note (learned during v20 validation): byte sizes are drawn from a
    heavy-tailed distribution typical of real LAN traffic — most flows small,
    a few large (backups, streaming) — rather than a flat uniform range. A flat
    uniform range makes EVERY host look statistically novel and produced benign
    hosts scoring as high as a port scanner, which disguised model-tuning bugs.
    """
    rng = random.Random(args.seed)
    devices = [f"198.51.100.{10 + i}" for i in range(args.devices)]
    # Documentation addresses (RFC 5737), not real resolvers: this fixture is invented, and a
    # real address here reads as observed traffic from the network this was developed on.
    servers = ["198.51.100.53", "203.0.113.53", "192.0.2.53", "198.51.100.54", "203.0.113.54"]
    start = int(time.time())
    total = 0
    # The minute the seeded attacks begin. Default 0 (attacks from the start -- the shape
    # every pre-review caller relied on). The eval harness passes the last-third mark so
    # training can HOLD OUT the attack period: scoring a detector on attacks it trained on
    # measures memorisation, not detection.
    attack_from = max(0, min(int(getattr(args, "attack_start_minute", 0) or 0),
                             args.minutes - 1))

    def realistic_bytes(rng: random.Random) -> int:
        """Heavy-tailed: ~80% small web/DNS flows, occasional large transfers."""
        roll = rng.random()
        if roll < 0.80:
            return rng.randint(200, 60_000)          # small: web, DNS, keepalive
        if roll < 0.97:
            return rng.randint(60_000, 2_000_000)    # medium: updates, images
        return rng.randint(2_000_000, 40_000_000)    # large: backups, streaming

    with open(args.output, "w") as fh:
        for minute in range(args.minutes):
            t0 = start + minute * 60
            for dev in devices:
                # Normal traffic: 2-8 flows/min per device
                for _ in range(rng.randint(2, 8)):
                    dport = rng.choice([80, 443, 53, 445, 3389, 22, 3074])
                    b = realistic_bytes(rng)
                    f = _flow(
                        (t0 + rng.randint(0, 59)) * 1_000_000_000,
                        dev, rng.choice(servers),
                        rng.randint(1024, 65535), dport, 6,
                        b, max(1, b // rng.randint(400, 1400)),
                    )
                    fh.write(json.dumps(f) + "\n")
                    total += 1
            # Attack device 1: port scanner (many dst ports on one host)
            if args.scanner and minute == attack_from:
                scanner = devices[0]
                for dport in range(1, min(1024, args.scan_ports + 1)):
                    f = _flow(t0 * 1_000_000_000, scanner, "198.51.100.99", 40000 + dport, dport, 6, 0, 1, flags=2)
                    fh.write(json.dumps(f) + "\n")
                    total += 1
            # Attack device 2: beacon (regular callbacks every 15 min, from the attack start)
            if args.beacon and minute >= attack_from and minute % 15 == 0:
                f = _flow(
                    (t0 + 7) * 1_000_000_000, devices[1], "203.0.113.66",
                    4444, 443, 6, rng.randint(200, 900), rng.randint(1, 3),
                )
                fh.write(json.dumps(f) + "\n")
                total += 1
            # Attack device 3: exfil spike (huge outbound volume once, mid-attack-period)
            if args.exfil and minute == attack_from + (args.minutes - attack_from) // 2:
                f = _flow(
                    t0 * 1_000_000_000, devices[2], "198.51.100.7",
                    50000, 8443, 6, 450_000_000, 400_000,
                )
                fh.write(json.dumps(f) + "\n")
                total += 1

    print(f"Wrote {total} flows to {args.output} ({args.minutes} simulated minutes)")
    return total


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--minutes", type=int, default=60)
    p.add_argument("--devices", type=int, default=8)
    p.add_argument("--output", default="/data/demo.jsonl")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--scanner", action="store_true", default=True)
    p.add_argument("--scan-ports", type=int, default=100)
    p.add_argument("--beacon", action="store_true", default=True)
    p.add_argument("--exfil", action="store_true", default=True)
    p.add_argument("--attack-start-minute", type=int, default=0,
                   help="minute the seeded attacks begin (default 0 = from the start); "
                        "used by scripts/eval_detection.py to hold the attack period out "
                        "of the training window")
    generate(p.parse_args())


if __name__ == "__main__":
    main()
