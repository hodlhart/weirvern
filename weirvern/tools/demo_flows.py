"""Synthetic flow generator — exercises the whole Weirvern pipeline locally.

Produces JSONL in goflow2's output shape (so the ingester needs zero changes
to consume it) with:
  * N "normal" devices doing routine traffic (Web/DNS/SMB/games)
  * 1-2 seeded attack devices per run: port scanner and/or beacon (C2-style)

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
        "sampler_address": "192.168.3.1",
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
    devices = [f"192.168.3.{10 + i}" for i in range(args.devices)]
    servers = ["8.8.8.8", "1.1.1.1", "13.107.42.14", "20.190.160.10", "172.217.3.110"]
    start = int(time.time())
    total = 0

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
            if args.scanner and minute == 0:
                scanner = devices[0]
                for dport in range(1, min(1024, args.scan_ports + 1)):
                    f = _flow(t0 * 1_000_000_000, scanner, "192.168.3.99", 40000 + dport, dport, 6, 0, 1, flags=2)
                    fh.write(json.dumps(f) + "\n")
                    total += 1
            # Attack device 2: beacon (regular callbacks every 15 min)
            if args.beacon and minute % 15 == 0:
                f = _flow(
                    (t0 + 7) * 1_000_000_000, devices[1], "203.0.113.66",
                    4444, 443, 6, rng.randint(200, 900), rng.randint(1, 3),
                )
                fh.write(json.dumps(f) + "\n")
                total += 1
            # Attack device 3: exfil spike (huge outbound volume once)
            if args.exfil and minute == args.minutes // 2:
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
    generate(p.parse_args())


if __name__ == "__main__":
    main()
