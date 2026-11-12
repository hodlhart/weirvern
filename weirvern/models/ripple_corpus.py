"""A versioned, machine-generated ripple corpus (RIP-1).

WHY THIS EXISTS. Every acceptance criterion on RIP-1 through RIP-4 ends the same way: "measured,
not asserted". There was nothing to measure against. The live capture is unlabelled, the
operator's reviews are explicitly NOT labels, and a clean 24-hour background window has never
been isolated. So the detectors could only be argued for, never scored.

WHAT THIS PRODUCES. Host-days at 5-minute resolution, each carrying the row shapes the shadow
specialists already consume (flows, DNS queries, TLS sessions, connection edges) plus a
machine-generated label. Five scenario families:

  clean              nothing injected -- the false-alarm denominator
  low_and_slow       a persistent, sub-threshold, multi-channel change over hours
  multi_stage        quiet recon, then lateral movement, then an exfil-shaped channel
  burst              one loud window (a negative control: not a ripple by definition)
  benign_new_service a genuinely new peer that behaves normally (a lookalike, also negative)

The label is written by the generator, carries its version and seed, and is the ONLY ground
truth. There is no human queue and no operator judgement anywhere in the artifact.

DETERMINISM. Every draw comes from a per-(seed, host, day) RNG, and the manifest hashes the
canonical JSON. The same seed reproduces the same corpus, byte for byte, which is what makes a
result from last week comparable to a result from today.

HONEST LIMITS. This is synthetic. It can show that a detector finds the shapes the generator
knows how to make, and that it stays quiet on the shapes it knows are benign. It cannot show
that real attackers behave like this; that is what the live corpus and the canaries are for.
"""
from __future__ import annotations

import hashlib
import json
import math
import random
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

GENERATOR_VERSION = "ripple-corpus/1"
BUCKET_MINUTES = 5
BUCKETS_PER_DAY = 24 * 60 // BUCKET_MINUTES

# Documentation ranges only: this file is committed, and the sanitation gate is right to reject
# a real private address in the tree.
CLIENT_PREFIX = "203.0.113."
PEER_PREFIX = "198.51.100."
INTERNAL_PREFIX = "192.0.2."

SCENARIOS = ("clean", "low_and_slow", "multi_stage", "lateral", "dns_tunnel", "burst",
             "benign_new_service")
NEGATIVE_SCENARIOS = frozenset({"clean", "burst", "benign_new_service"})

# Amplitude is a fraction of the host's own baseline, so "0.2" means "20% above what this host
# normally does". Duration is in minutes; both are the axes the card asks to vary.
AMPLITUDES = (0.10, 0.25, 0.50)
DURATIONS = (60, 180, 360)


@dataclass(frozen=True)
class Label:
    """One injected scenario instance. Machine-generated; never edited by hand."""

    scenario: str
    host: str
    start_minute: int
    end_minute: int
    amplitude: float
    channels: tuple[str, ...]
    expected: str          # "ripple" or "negative"

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "host": self.host,
            "start_minute": self.start_minute,
            "end_minute": self.end_minute,
            "amplitude": self.amplitude,
            "channels": list(self.channels),
            "expected": self.expected,
        }


@dataclass
class HostDay:
    """One host for one day: a baseline series plus the rows a specialist can score."""

    host: str
    day: str
    scenario: str
    seed: int
    # 288 buckets of 5 minutes.
    bytes_out: list[float]
    packets_out: list[float]
    conn_count: list[float]
    dns_count: list[float]
    tls_count: list[float]
    # Per-bucket rows, aligned with the series above.
    edges: list[list[tuple[str, str]]] = field(default_factory=list)
    queries: list[list[dict[str, Any]]] = field(default_factory=list)
    sessions: list[list[dict[str, Any]]] = field(default_factory=list)
    flow_times: list[list[float]] = field(default_factory=list)
    label: Label | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "day": self.day,
            "scenario": self.scenario,
            "seed": self.seed,
            "bytes_out": [round(v, 3) for v in self.bytes_out],
            "packets_out": [round(v, 3) for v in self.packets_out],
            "conn_count": [round(v, 3) for v in self.conn_count],
            "dns_count": [round(v, 3) for v in self.dns_count],
            "tls_count": [round(v, 3) for v in self.tls_count],
            "edges": [[list(edge) for edge in bucket] for bucket in self.edges],
            "queries": self.queries,
            "sessions": self.sessions,
            "flow_times": [[round(t, 3) for t in bucket] for bucket in self.flow_times],
            "label": self.label.to_dict() if self.label else None,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> HostDay:
        label = raw.get("label")
        return cls(
            host=raw["host"], day=raw["day"], scenario=raw["scenario"], seed=raw["seed"],
            bytes_out=list(raw["bytes_out"]), packets_out=list(raw["packets_out"]),
            conn_count=list(raw["conn_count"]), dns_count=list(raw["dns_count"]),
            tls_count=list(raw["tls_count"]),
            edges=[[(str(a), str(b)) for a, b in bucket] for bucket in raw.get("edges", [])],
            queries=[list(b) for b in raw.get("queries", [])],
            sessions=[list(b) for b in raw.get("sessions", [])],
            flow_times=[[float(t) for t in bucket] for bucket in raw.get("flow_times", [])],
            label=Label(**{**label, "channels": tuple(label["channels"])}) if label else None,
        )


def _diurnal(bucket: int, peak: float = 1.0) -> float:
    """A smooth workday curve: quiet at 03:00, busy at 14:00."""
    hour = (bucket * BUCKET_MINUTES) / 60.0
    return 0.35 + 0.65 * max(0.0, math.sin(math.pi * (hour - 6) / 16.0)) * peak


def _rng(seed: int, host: str, day: str) -> random.Random:
    material = f"{GENERATOR_VERSION}|{seed}|{host}|{day}".encode()
    return random.Random(int.from_bytes(hashlib.sha256(material).digest()[:8], "big"))


def _base_host(rng: random.Random, host: str, day: str, seed: int) -> HostDay:
    """A host's ordinary day: a diurnal mean, lognormal jitter, stable peers."""
    peers = [f"{PEER_PREFIX}{rng.randint(10, 60)}" for _ in range(rng.randint(3, 6))]
    bytes_out, packets, conns, dns, tls = [], [], [], [], []
    edges: list[list[tuple[str, str]]] = []
    queries: list[list[dict[str, Any]]] = []
    sessions: list[list[dict[str, Any]]] = []
    times: list[list[float]] = []
    hosts_ja4 = [f"t13d1516h2_{rng.randint(100, 999)}", f"t13d1517h2_{rng.randint(100, 999)}"]

    for bucket in range(BUCKETS_PER_DAY):
        curve = _diurnal(bucket)
        level = max(1.0, 2.0e6 * curve * rng.lognormvariate(0.0, 0.18))
        bytes_out.append(level)
        packets.append(level / rng.uniform(500, 900))
        conns.append(max(1.0, 30.0 * curve * rng.lognormvariate(0.0, 0.12)))
        dns.append(max(0.0, 12.0 * curve * rng.lognormvariate(0.0, 0.25)))
        tls.append(max(0.0, 8.0 * curve * rng.lognormvariate(0.0, 0.25)))

        bucket_edges = [(host, peer) for peer in peers if rng.random() < 0.35 * curve + 0.05]
        edge_partners = [p for _, p in bucket_edges]
        edges.append(bucket_edges)
        queries.append([
            {"query": f"host{rng.randint(1, 40)}.example.net", "qtype": 1, "rcode": 0}
            for _ in range(int(dns[-1]))
        ])
        sessions.append([
            {"ja4": rng.choice(hosts_ja4), "server_name": f"host{rng.randint(1, 40)}.example.net",
             "version": "TLSv1.3"}
            for _ in range(int(tls[-1]))
        ])
        times.append(sorted(
            bucket * 300.0 + rng.uniform(0, 300) for _ in range(int(conns[-1]))
        ))
        # Keep the partner list meaningful for the graph features of this bucket.
        if not edge_partners:
            edges[-1] = []

    return HostDay(host=host, day=day, scenario="clean", seed=seed, bytes_out=bytes_out,
                   packets_out=packets, conn_count=conns, dns_count=dns, tls_count=tls,
                   edges=edges, queries=queries, sessions=sessions, flow_times=times)


def _apply_scenario(day: HostDay, scenario: str, rng: random.Random, *,
                    amplitude: float, duration_min: int, start_minute: int) -> HostDay:
    """Inject one scenario into a clean day and label it."""
    start = max(0, start_minute // BUCKET_MINUTES)
    # A burst is ONE window by definition; every other scenario spans its duration.
    span = 1 if scenario == "burst" else max(1, duration_min // BUCKET_MINUTES)
    end = min(BUCKETS_PER_DAY, start + span)
    channels: tuple[str, ...] = ()
    expected = "negative"

    if scenario == "low_and_slow":
        # Persistent, small, and spread across volume, graph and name channels: individually
        # under any single detector's threshold, collectively a change.
        channels = ("flow", "graph", "dns")
        expected = "ripple"
        for bucket in range(start, end):
            day.bytes_out[bucket] *= 1.0 + amplitude
            day.packets_out[bucket] *= 1.0 + amplitude
            new_peer = f"{PEER_PREFIX}{200 + bucket % 5}"
            day.edges[bucket].append((day.host, new_peer))
            for _ in range(max(1, int(3 * amplitude * 10))):
                label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                                for _ in range(40))
                day.queries[bucket].append(
                    {"query": f"{label}.tunnel.example.org", "qtype": 16, "rcode": 0})

    elif scenario == "multi_stage":
        # Three phases with different footprints, all sub-threshold on their own.
        channels = ("graph", "flow", "dns", "tls")
        expected = "ripple"
        third = max(1, (end - start) // 3)
        for i, bucket in enumerate(range(start, end)):
            phase = 0 if i < third else (1 if i < 2 * third else 2)
            if phase == 0:      # quiet recon: one new peer per 15 minutes
                if i % 3 == 0:
                    day.edges[bucket].append((day.host, f"{INTERNAL_PREFIX}{10 + i % 4}"))
            elif phase == 1:    # lateral: fixed internal peers, tiny volume
                day.edges[bucket].extend(
                    (day.host, f"{INTERNAL_PREFIX}{20 + k}") for k in range(3))
                day.bytes_out[bucket] *= 1.0 + amplitude * 0.5
            else:               # exfil shape: DNS tunnel plus a modest upload
                day.bytes_out[bucket] *= 1.0 + amplitude
                for _ in range(6):
                    label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                                    for _ in range(48))
                    day.queries[bucket].append(
                        {"query": f"{label}.exfil.example.org", "qtype": 16, "rcode": 0})
                day.sessions[bucket].append(
                    {"ja4": "t13d9999h2_newja4", "server_name": "exfil.example.org",
                     "version": "TLSv1.2"})

    elif scenario == "lateral":
        # RIP-3's claim, made testable: a host whose VOLUME does not move but whose peer set
        # does. Reverse lookups are included because they are what lateral movement actually
        # produces, and because two families are required before anything can be a ripple.
        channels = ("graph", "dns")
        expected = "ripple"
        newcomers = [f"{INTERNAL_PREFIX}{70 + k}" for k in range(3)]
        for bucket in range(start, end):
            day.edges[bucket].extend((day.host, peer) for peer in newcomers)
            for peer in newcomers:
                day.queries[bucket].append(
                    {"query": f"{peer.split('.')[-1]}.in-addr.arpa", "qtype": 12, "rcode": 0})

    elif scenario == "dns_tunnel":
        # RIP-4's claim: a protocol-only change. Bytes stay exactly where they were; the names
        # are long, high-entropy and unique, and the tunnel endpoint is one new edge.
        channels = ("dns", "graph")
        expected = "ripple"
        endpoint = f"{PEER_PREFIX}250"
        for bucket in range(start, end):
            for _ in range(8):
                label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567")
                                for _ in range(52))
                day.queries[bucket].append(
                    {"query": f"{label}.cdn-metrics.example.net", "qtype": 16, "rcode": 0})
            day.edges[bucket].append((day.host, endpoint))

    elif scenario == "burst":
        # ONE loud window. By definition this is not a ripple, and a fusion that fires here is
        # measuring loudness rather than persistence.
        channels = ("flow",)
        expected = "negative"
        day.bytes_out[start] *= 8.0
        day.packets_out[start] *= 8.0

    elif scenario == "benign_new_service":
        # A real, lasting change that is not malicious: a new internal service appears and is
        # used normally. A detector that fires on "new" alone will fail this.
        channels = ("graph",)
        expected = "negative"
        service = f"{INTERNAL_PREFIX}50"
        for bucket in range(start, BUCKETS_PER_DAY):
            day.edges[bucket].append((day.host, service))
        for bucket in range(start, min(BUCKETS_PER_DAY, start + span)):
            day.bytes_out[bucket] *= 1.05

    if scenario == "clean":
        return day

    day.scenario = scenario
    day.label = Label(scenario=scenario, host=day.host, start_minute=start * BUCKET_MINUTES,
                      end_minute=end * BUCKET_MINUTES, amplitude=amplitude,
                      channels=channels, expected=expected)
    return day


def generate(*, seed: int = 20261112, days: int = 3,
             hosts_per_scenario: int = 2, reference_days: int = 0) -> dict[str, Any]:
    """Build the corpus: every scenario family, every amplitude, every duration.

    The layout is deliberately balanced: each (scenario, amplitude, duration) cell gets the same
    number of hosts, so a detection rate can be read per cell without reweighting.
    """
    start_day = date(2026, 1, 5)
    host_days: list[HostDay] = []

    for scenario in SCENARIOS:
        variants = ([(a, d) for a in AMPLITUDES for d in DURATIONS]
                    if scenario in {"low_and_slow", "multi_stage"}
                    else [(0.0, 60)])
        for index, (amplitude, duration) in enumerate(variants):
            for replica in range(hosts_per_scenario):
                host = f"{CLIENT_PREFIX}{10 + (index * hosts_per_scenario + replica) % 200}"
                day = (start_day + timedelta(days=(index + replica) % max(1, days))).isoformat()
                rng = _rng(seed, host, day)
                base = _base_host(rng, host, day, seed)
                # Start times spread over the working day so the diurnal curve cannot stand in
                # for the scenario: a 09:00 ripple and a 15:00 ripple are both represented.
                start_minute = 8 * 60 + (index * 97 + replica * 53) % (8 * 60)
                host_days.append(_apply_scenario(
                    base, scenario, rng, amplitude=amplitude, duration_min=duration,
                    start_minute=start_minute))

    # A SEASONAL REFERENCE POOL. Every channel rises and falls with the working day, so a
    # calibration that pools all hours makes 09:00 look anomalous against 03:00 and lets the
    # diurnal curve stand in for agreement between channels. These host-days exist only to say
    # what "normal at this time of day" looks like; they are excluded from the measurement.
    for index in range(reference_days):
        host = f"{CLIENT_PREFIX}{60 + index % 140}"
        day = (start_day + timedelta(days=index % max(1, days))).isoformat()
        rng = _rng(seed, host, day)
        base = _base_host(rng, host, day, seed)
        base.scenario = "clean_reference"
        host_days.append(base)

    payload = {
        "generator_version": GENERATOR_VERSION,
        "seed": seed,
        "bucket_minutes": BUCKET_MINUTES,
        "created_for": "RIP-1..RIP-4 evaluation; machine labels only",
        "host_days": [h.to_dict() for h in host_days],
    }
    payload["manifest"] = manifest(payload)
    return payload


def _canonical(payload: dict[str, Any]) -> str:
    body = {k: v for k, v in payload.items() if k != "manifest"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def manifest(payload: dict[str, Any]) -> dict[str, Any]:
    """Counts and a content hash, so a result can name the exact corpus it was measured on."""
    host_days = payload.get("host_days", [])
    by_scenario: dict[str, int] = {}
    positives = 0
    for item in host_days:
        by_scenario[item["scenario"]] = by_scenario.get(item["scenario"], 0) + 1
        if item.get("label") and item["label"]["expected"] == "ripple":
            positives += 1
    return {
        "generator_version": payload.get("generator_version", GENERATOR_VERSION),
        "seed": payload.get("seed"),
        "host_days": len(host_days),
        "by_scenario": dict(sorted(by_scenario.items())),
        "ripple_host_days": positives,
        "sha256": hashlib.sha256(_canonical(payload).encode()).hexdigest(),
    }


def dump(payload: dict[str, Any], path) -> None:
    from pathlib import Path

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, sort_keys=True, indent=1) + "\n")


def load(path) -> dict[str, Any]:
    from pathlib import Path

    payload = json.loads(Path(path).read_text())
    if payload.get("generator_version") != GENERATOR_VERSION:
        raise ValueError(
            f"corpus was generated by {payload.get('generator_version')!r}, "
            f"this code expects {GENERATOR_VERSION!r}")
    expected = payload.get("manifest", {}).get("sha256")
    if expected != manifest(payload)["sha256"]:
        raise ValueError("corpus manifest does not match its contents; regenerate it")
    return payload


def host_days(payload: dict[str, Any]) -> list[HostDay]:
    return [HostDay.from_dict(raw) for raw in payload["host_days"]]


def summarise(payload: dict[str, Any]) -> str:
    m = payload["manifest"]
    return (f"{m['host_days']} host-days, {m['ripple_host_days']} labelled ripples, "
            f"seed {m['seed']}, {m['generator_version']} ({m['sha256'][:12]})")


__all__ = ["AMPLITUDES", "BUCKETS_PER_DAY", "BUCKET_MINUTES", "DURATIONS", "GENERATOR_VERSION",
           "HostDay", "Label", "NEGATIVE_SCENARIOS", "SCENARIOS", "dump", "generate",
           "host_days", "load", "manifest", "summarise"]
