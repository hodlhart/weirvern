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


# Scenario hosts are deliberately OUTSIDE the normal `devices` range, so the benign host
# set and the three original attacker conventions stay stable. The values are documentation
# addresses (RFC 5737); the fixture is invented.
SCENARIO_HOSTS = {
    "ssh_brute": "198.51.100.210",
    "smb_lateral": "198.51.100.211",
    "dce_rpc": "198.51.100.212",
    "dns_tunnel": "198.51.100.213",
    "quic_c2": "198.51.100.214",
    "http_c2": "198.51.100.215",
}


def _flow(time_ns: int, src: str, dst: str, sport: int, dport: int, proto: int,
          bytes_: int, packets: int, flags: int = 16, *, rng: random.Random) -> dict:
    # The duration draw comes from the SEEDED rng, never the module-global `random` (issue
    # #49): with the global, two runs of the same seed produced different end timestamps --
    # so the fixture was not a function of its seed, and no run could be reproduced from the
    # inputs it printed.
    return {
        "time_flow_start_ns": time_ns,
        "time_flow_end_ns": time_ns + rng.randint(50_000_000, 5_000_000_000),
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


def _anchored_start(now: float, grid_s: int = 300) -> int:
    """The seed's start second, ANCHORED to the aggregation grid (issue #49).

    The dataset is generated forward from this second and ClickHouse's five-minute buckets
    (`toStartOfFiveMinute`) split it, so an unanchored start made that split a function of
    WHEN the run happened. Measured on the eval harness: two runs two minutes apart settled
    728 vs 732 aggregate rows, 158 vs 118 verdicts, benign hosts flipped in and out of the
    high+ set, and DBSCAN's cluster centres appeared in one run and vanished in the other --
    one fixture, two different datasets. Anchored, the phase relative to the grid is a
    constant, so the same seed lands the same flows in the same buckets on every run.

    `grid_s` is the bucket width (AGG_BUCKET_S, 300s); the docstring repeats the number
    rather than importing it because this module deliberately has no package imports.
    """
    return (int(now) // grid_s) * grid_s


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
    # Grid-anchored (issue #49) unless the caller passes an exact epoch as `args.start`
    # (tests use that to freeze the clock). See _anchored_start for the measured why.
    provided = getattr(args, "start", None)
    start = int(provided) if provided else _anchored_start(time.time())
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
                        rng=rng,
                    )
                    fh.write(json.dumps(f) + "\n")
                    total += 1
            # Scenario hosts get a benign pre-attack baseline too. Without it the adaptive
            # baseline and the host-history features never see these hosts before their
            # attack, which made the HTTP-staging fixture score LOW despite its volume.
            if getattr(args, "new_scenarios", False) and minute < attack_from:
                for host in SCENARIO_HOSTS.values():
                    for _ in range(rng.randint(2, 8)):
                        dport = rng.choice([80, 443, 53, 445, 22])
                        b = realistic_bytes(rng)
                        f = _flow((t0 + rng.randint(0, 59)) * 1_000_000_000,
                                  host, rng.choice(servers), rng.randint(1024, 65535),
                                  dport, 6, b, max(1, b // rng.randint(400, 1400)),
                                  rng=rng)
                        fh.write(json.dumps(f) + "\n")
                        total += 1
            # Attack device 1: port scanner (many dst ports on one host)
            if args.scanner and minute == attack_from:
                scanner = devices[0]
                for dport in range(1, min(1024, args.scan_ports + 1)):
                    f = _flow(t0 * 1_000_000_000, scanner, "198.51.100.99", 40000 + dport, dport, 6, 0, 1,
                              flags=2, rng=rng)
                    fh.write(json.dumps(f) + "\n")
                    total += 1
            # Attack device 2: beacon (regular callbacks every 15 min, from the attack start)
            if args.beacon and minute >= attack_from and minute % 15 == 0:
                f = _flow(
                    (t0 + 7) * 1_000_000_000, devices[1], "203.0.113.66",
                    4444, 443, 6, rng.randint(200, 900), rng.randint(1, 3),
                    rng=rng,
                )
                fh.write(json.dumps(f) + "\n")
                total += 1
            # Attack device 3: exfil spike (huge outbound volume once, mid-attack-period)
            if args.exfil and minute == attack_from + (args.minutes - attack_from) // 2:
                f = _flow(
                    t0 * 1_000_000_000, devices[2], "198.51.100.7",
                    50000, 8443, 6, 450_000_000, 400_000,
                    rng=rng,
                )
                fh.write(json.dumps(f) + "\n")
                total += 1
            # ── FND-3 scenario corpus ─────────────────────────────────────────────────
            # Six additional deterministic behaviours, each on its own host so a failure
            # names the scenario. All are flow-visible; Zeek-only classes (new JA4, DHCP)
            # stay specialist work and are not pretended to be covered here.
            if getattr(args, "new_scenarios", False) and minute >= attack_from:
                elapsed = minute - attack_from
                # SSH brute: repeated short connections to one SSH service.
                if elapsed < 5:
                    for i in range(25):
                        f = _flow((t0 + i % 60) * 1_000_000_000,
                                  SCENARIO_HOSTS["ssh_brute"], "198.51.100.99",
                                  41000 + i, 22, 6, 0, 1, flags=2, rng=rng)
                        fh.write(json.dumps(f) + "\n")
                        total += 1
                # SMB admin-share lateral: one short attempt per internal host.
                if elapsed == 2:
                    for i in range(40):
                        f = _flow(t0 * 1_000_000_000,
                                  SCENARIO_HOSTS["smb_lateral"],
                                  f"198.51.100.{120 + i}", 42000 + i, 445, 6,
                                  0, 1, flags=2, rng=rng)
                        fh.write(json.dumps(f) + "\n")
                        total += 1
                # DCE/RPC service execution probe: many endpoint mapper touches.
                if elapsed == 3:
                    for i in range(40):
                        f = _flow(t0 * 1_000_000_000,
                                  SCENARIO_HOSTS["dce_rpc"],
                                  f"198.51.100.{120 + i}", 43000 + i, 135, 6,
                                  0, 1, flags=2, rng=rng)
                        fh.write(json.dumps(f) + "\n")
                        total += 1
                # DNS tunnel proxy: many short queries to the resolver, high flow count.
                if elapsed < 10:
                    for i in range(30):
                        f = _flow((t0 + i % 60) * 1_000_000_000,
                                  SCENARIO_HOSTS["dns_tunnel"], "198.51.100.53",
                                  44000 + i, 53, 17, rng.randint(80, 300),
                                  1, rng=rng)
                        fh.write(json.dumps(f) + "\n")
                        total += 1
                # QUIC C2: periodic small UDP/443 callbacks, repeated within each burst so
                # the flow-count signal is visible without pretending a single packet is.
                if elapsed % 5 == 0:
                    for i in range(20):
                        f = _flow((t0 + 11 + i % 5) * 1_000_000_000,
                                  SCENARIO_HOSTS["quic_c2"], "203.0.113.77",
                                  45000 + i, 443, 17, rng.randint(2_000, 8_000), 3, rng=rng)
                        fh.write(json.dumps(f) + "\n")
                        total += 1
                # HTTP C2 / staging: repeated upload-sized POSTs to multiple external HTTP
                # endpoints. A single destination/port sat inside the benign web mix; the
                # fan-out is what makes this a separable staging fixture.
                if 1 <= elapsed <= 3:
                    for i in range(30):
                        f = _flow((t0 + 17 + i % 5) * 1_000_000_000,
                                  SCENARIO_HOSTS["http_c2"], f"203.0.113.{100 + i}",
                                  46000 + i, 8080, 6, 8_000_000, 6_000, rng=rng)
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
    p.add_argument("--new-scenarios", action="store_true", default=False,
                   help="add the FND-3 scenario corpus (SSH brute, SMB/DCE lateral, DNS tunnel, "
                        "QUIC C2, HTTP C2); off by default so the original three-attack seed is "
                        "unchanged for callers that do not opt in")
    p.add_argument("--attack-start-minute", type=int, default=0,
                   help="minute the seeded attacks begin (default 0 = from the start); "
                        "used by scripts/eval_detection.py to hold the attack period out "
                        "of the training window")
    generate(p.parse_args())


if __name__ == "__main__":
    main()
