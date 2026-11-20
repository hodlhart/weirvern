"""Seed a demo dataset into ClickHouse, through the real ingest mappers.

WHY THIS IS NOT A ROW DUMPER. Writing finished rows straight into `flows` and `zeek_conn` would make
the dashboard light up and would prove nothing, because the layer where this project's ingestion bugs
have actually lived is the mapper: `ZEEK_COLUMNS` silently drops every field not on its keep-list, one
log type uses `client_addr` where the others use `src_addr`, and a nested author object turned every
row into an unknown. A seeder that skips the mapper leaves that layer untested.

So every record here is generated in Zeek's own field shape (`id.orig_h`, `id.resp_p`, ...) and pushed
through `ingester.map_zeek_*`, the same functions the tailer calls. If a mapper changes its mind about
a field, this breaks too, which is the point.

WHAT IT DOES NOT DO. It does not replay packets and it does not pretend to. There is no capture behind
this data; the README says so. `--hours 6` produces six hours of plausible traffic ending at the
current minute, which is what makes every `now() - INTERVAL` view in the console render, and it is
reproducible from a seed.

The demo is meant to be honest about being a demo. The alternative, tcpreplay, is documented in the
README, and it needs a capture, capture privileges, and a timestamp rewrite before any windowed query
sees it.
"""

from __future__ import annotations

import argparse
import random
import sys
from datetime import timedelta
from typing import Any

from weirvern import ingester
from weirvern.clock import utcnow

# Column order per table, taken from the schema. The mappers return dicts, so the insert list is built
# from these and a mapper that grows a column without a matching entry here fails loudly at insert
# rather than silently dropping it.
COLUMNS: dict[str, list[str]] = {
    "zeek_conn": ["ts", "uid", "src_addr", "src_port", "dst_addr", "dst_port", "proto", "service",
                  "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "conn_state",
                  "history"],
    "zeek_dns": ["ts", "uid", "src_addr", "dst_addr", "proto", "trans_id", "query", "qtype",
                 "rcode", "answers", "query_len", "query_entropy"],
    "zeek_ssl": ["ts", "uid", "src_addr", "dst_addr", "dst_port", "version", "cipher",
                 "server_name", "ja4", "ja4_orig", "validation_status", "established"],
    "zeek_weird": ["ts", "uid", "src_addr", "src_port", "dst_addr", "dst_port", "name", "noticed",
                   "peer"],
    "zeek_http": ["ts", "uid", "src_addr", "src_port", "dst_addr", "dst_port", "method", "host",
                  "uri", "referrer", "user_agent", "status_code", "resp_mime", "resp_bytes",
                  "uri_len", "uri_entropy"],
    "flows": ["timestamp", "sampler_address", "time_flow_start", "time_flow_end", "src_addr",
              "dst_addr", "src_port", "dst_port", "proto", "etype", "bytes", "packets", "tcp_flags",
              "sampling_rate", "src_as", "dst_as", "src_vlan", "dst_vlan", "in_if", "out_if",
              "next_hop", "ip_tos", "ip_ttl", "frag_offset"],
}

# Documentation ranges only. Nothing here is a real address, and nothing is derived from a capture.
INTERNAL_PREFIX = "192.0.2."
# The ripple evidence cannot measure a scale without MIN_BASELINE_SAMPLES windows of the
# host's own history, which is about 30 hours at the 1h scale. A default below that ships a
# demo whose Ripples card is empty for a reason nobody can see, so the default clears it.
DEFAULT_HOURS = 144

#: The ripple plant. A ripple needs two FAMILIES to clear p <= 0.01 on the same host in the same
#: window, and the evidence measures only the current hour, so the burst has to sit in the final hour
#: and beat every hour the host has ever had. The p-value is empirical: 0.006 means "more extreme
#: than all 167 baseline windows", which a gentle nudge never reaches. A normal host here makes
#: about 36 flows an hour, so this is tens of times that.
RIPPLE_WINDOWS = 12            # one hour of the five-minute windows
RIPPLE_CONNS_PER_WINDOW = 60
RIPPLE_LOOKUPS_PER_WINDOW = 40
RIPPLE_WEIRD_PER_WINDOW = 25
#: A CHANNEL NEEDS A PAST BEFORE A BURST MEANS ANYTHING. The evidence builds a baseline only from
#: windows that HAVE rows, so a channel that never spoke is skipped as unmeasurable rather than
#: reported as a spike from zero. The live site's weird log runs continuously (median 109 an hour),
#: so the seed carries a small background and only the final hour is extreme.
WEIRD_BACKGROUND_PER_WINDOW = (2, 4)

#: The name the beacon resolves. It exists so the DNS block has a rule AND a query that refers to
#: real seeded traffic; a blocked name nothing ever looked up is a rule with no story.
BEACON_DOMAIN = "updates.example.net"

#: Every rule this seeder creates carries this origin, which is how a second run tells that the
#: enforcement picture is already there instead of stacking a duplicate block on top of it.
DEMO_ORIGIN = "demo-seed"
RIPPLE_HTTP_HOSTS_PER_WINDOW = 40
EXTERNAL = ["198.51.100.10", "198.51.100.23", "203.0.113.66", "203.0.113.90"]
BEACON_TARGET = "203.0.113.66"
SERVICES = [(443, "ssl"), (80, "http"), (53, "dns"), (22, "ssh"), (8080, "http")]
WEIRD_NAMES = ["bad_TCP_checksum", "truncated_IP", "data_before_established",
              "window_recision", "possible_split_routing"]
DOMAINS = ["example.com", "updates.example.net", "mail.example.org", "cdn.example.com"]
SNI = ["example.com", "cdn.example.com", "updates.example.net"]
WINDOW = timedelta(minutes=5)


def _uid(rng: random.Random) -> str:
    """A Zeek-shaped connection id. Not a hash of anything; it only needs to be unique per row."""
    return "C" + "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16))


def _hosts(rng: random.Random, count: int) -> list[str]:
    return [f"{INTERNAL_PREFIX}{n}" for n in range(10, 10 + count)]


def _conn(ts: float, src: str, dst: str, dport: int, service: str, rng: random.Random,
          *, orig_bytes: int = 0, resp_bytes: int = 0) -> dict[str, str]:
    """One record in Zeek's own field shape, so the real mapper is the thing that interprets it."""
    return {
        "ts": f"{ts:.6f}",
        "uid": _uid(rng),
        "id.orig_h": src,
        "id.orig_p": str(rng.randint(49152, 65000)),
        "id.resp_h": dst,
        "id.resp_p": str(dport),
        "proto": "tcp" if dport != 53 else "udp",
        "service": service,
        "duration": f"{rng.uniform(0.01, 4.0):.4f}",
        "orig_bytes": str(orig_bytes),
        "resp_bytes": str(resp_bytes),
        "orig_pkts": str(max(1, orig_bytes // 200)),
        "resp_pkts": str(max(1, resp_bytes // 200)),
        "conn_state": rng.choice(["SF", "SF", "SF", "S1", "RSTO"]),
        "history": "ShADadFf",
    }


def _dns(ts: float, src: str, query: str, rng: random.Random) -> dict[str, str]:
    return {
        "ts": f"{ts:.6f}",
        "uid": _uid(rng),
        "id.orig_h": src,
        "id.resp_h": "198.51.100.23",
        "id.resp_p": "53",
        "proto": "udp",
        "trans_id": str(rng.randint(1, 65535)),
        "query": query,
        "qtype": "A",
        "rcode": "NOERROR" if rng.random() > 0.06 else "NXDOMAIN",
        "answers": ",".join(f"192.0.2.{rng.randint(1, 250)}" for _ in range(rng.randint(0, 3))),
    }


def _ssl(ts: float, src: str, dst: str, sni: str, rng: random.Random) -> dict[str, str]:
    return {
        "ts": f"{ts:.6f}",
        "uid": _uid(rng),
        "id.orig_h": src,
        "id.orig_p": str(rng.randint(49152, 65000)),
        "id.resp_h": dst,
        "id.resp_p": "443",
        "version": "TLSv13",
        "cipher": rng.choice(["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]),
        "server_name": sni,
        "ja4": "t13d1516h2_8daaf6152771_02713d6af862",
        "validation_status": "ok",
    }


def _http(ts: float, src: str, dst: str, host: str, rng: random.Random) -> dict[str, str]:
    return {
        "ts": f"{ts:.6f}",
        "uid": _uid(rng),
        "id.orig_h": src,
        "id.orig_p": str(rng.randint(49152, 65000)),
        "id.resp_h": dst,
        "id.resp_p": "80",
        "method": rng.choice(["GET", "GET", "POST"]),
        "host": host,
        "uri": rng.choice(["/", "/index.html", "/api/v1/status", "/assets/app.js"]),
        "referrer": "",
        "user_agent": "Mozilla/5.0 (demo seed)",
        "status_code": "200",
        "resp_mime": "text/html",
        "resp_bytes": str(rng.randint(200, 20000)),
    }


def _flows_row(ts: float, src: str, dst: str, dport: int, orig_bytes: int, resp_bytes: int) -> dict:
    """The NetFlow view of the SAME conversation, so the two channels agree instead of contradicting.

    A demo where the flow view and the Zeek view disagree is worse than one channel being empty: it
    reads as a defect in the product rather than in the seed.
    """
    # EVERY COLUMN IS NAMED. An earlier version set 18 of the 24 and relied on `build` substituting 0
    # for the rest, which means a column added to COLUMNS later would insert a silent zero instead of
    # failing. The timestamp fields are filled by the caller.
    return {
        "timestamp": None,
        "sampler_address": "192.0.2.1",
        "time_flow_start": None,
        "time_flow_end": None,
        "src_addr": src,
        "dst_addr": dst,
        "src_port": 0,
        "dst_port": dport,
        "proto": 6 if dport != 53 else 17,
        "etype": 2048,
        "bytes": orig_bytes + resp_bytes,
        "packets": max(2, (orig_bytes + resp_bytes) // 200),
        "tcp_flags": 16,
        "sampling_rate": 1,
        "src_as": 0,
        "dst_as": 0,
        "src_vlan": 0,
        "dst_vlan": 0,
        "in_if": 0,
        "out_if": 0,
        "next_hop": "192.0.2.1",
        "ip_tos": 0,
        "ip_ttl": 64,
        "frag_offset": 0,
    }


def _flow_values(flow: dict) -> list:
    """Assemble a flow row BY KEY, so a column with no value raises instead of becoming 0.

    Three call sites build flow rows (the segment loop, the beacon and the scan) and an earlier
    version had `.get(c, 0)` at each of them. That is the silent-default shape this project keeps
    finding: a schema column added later would insert a zero into a field nobody meant to leave at
    zero, and the row would look valid. One helper means one place to be right.
    """
    return [flow[c] for c in COLUMNS["flows"]]


def build(hours: int = 6, hosts: int = 22, seed: int = 1337,
          connections_per_host_window: int = 5) -> dict[str, list[list[Any]]]:
    """Generate the demo, ending at the current minute.

    Timestamps END AT NOW, which is the whole reason this exists: every windowed query in the console
    is relative to now, so a dataset ending yesterday renders an empty dashboard no matter how good
    the data is.
    """
    rng = random.Random(seed)
    end = utcnow().replace(second=0, microsecond=0)
    windows = max(1, int(hours * 60 / (WINDOW.total_seconds() / 60)))
    segment = _hosts(rng, hosts)
    # Modulo, not indexing: a seed with one or two hosts is a legitimate smoke run, and it used to
    # raise IndexError. With fewer than three hosts the roles land on the same machine, which is
    # odd-looking but honest, and it beats refusing to build a small demo at all.
    beacon = segment[0]
    scanner = segment[1 % len(segment)]
    rippled = segment[2 % len(segment)]  # the volume-shaped incident
    broad = segment[3 % len(segment)]    # the diversity-shaped incident

    out: dict[str, list[list[Any]]] = {name: [] for name in COLUMNS}

    for w in range(windows):
        w_start = end - timedelta(hours=hours) + w * WINDOW
        w_epoch = w_start.timestamp()

        for host in segment:
            for _ in range(rng.randint(1, connections_per_host_window)):
                dport, service = rng.choice(SERVICES)
                dst = rng.choice(EXTERNAL)
                orig = rng.randint(120, 4000)
                resp = rng.randint(200, 60000)
                ts = w_epoch + rng.uniform(0, 290)

                conn = _conn(ts, host, dst, dport, service, rng, orig_bytes=orig, resp_bytes=resp)
                row = ingester.map_zeek_conn(conn)
                if row:
                    out["zeek_conn"].append([row[c] for c in COLUMNS["zeek_conn"]])

                flow = _flows_row(ts, host, dst, dport, orig, resp)
                flow["time_flow_start"] = w_start
                flow["time_flow_end"] = w_start + timedelta(seconds=rng.uniform(1, 240))
                flow["timestamp"] = w_start
                out["flows"].append([flow[c] for c in COLUMNS["flows"]])

                if dport == 53:
                    dns = ingester.map_zeek_dns(_dns(ts, host, rng.choice(DOMAINS), rng))
                    if dns:
                        out["zeek_dns"].append([dns[c] for c in COLUMNS["zeek_dns"]])
                elif dport == 443:
                    ssl = ingester.map_zeek_ssl(_ssl(ts, host, dst, rng.choice(SNI), rng))
                    if ssl:
                        out["zeek_ssl"].append([ssl[c] for c in COLUMNS["zeek_ssl"]])
                elif dport == 80:
                    http = ingester.map_zeek_http(_http(ts, host, dst, rng.choice(DOMAINS), rng))
                    if http:
                        out["zeek_http"].append([http[c] for c in COLUMNS["zeek_http"]])

        # The weird background runs for one host only, and it is not an anomaly: it is what makes
        # the notice family measurable at all for that host, so the final-hour burst has a baseline
        # to be extreme against.
        for _ in range(rng.randint(*WEIRD_BACKGROUND_PER_WINDOW)):
            ts = w_epoch + rng.uniform(0, 290)
            weird = ingester.map_zeek_weird({
                "ts": str(ts), "uid": _uid(rng), "id.orig_h": rippled,
                "id.orig_p": str(rng.randint(1024, 65535)),
                "id.resp_h": rng.choice(EXTERNAL), "id.resp_p": "443",
                "name": rng.choice(WEIRD_NAMES), "notice": "F", "peer": "zeek",
            })
            if weird:
                out["zeek_weird"].append([weird[c] for c in COLUMNS["zeek_weird"]])

        # ANOMALY 1: a host beaconing to one external address every window, small and steady. This is
        # the shape a per-host volume baseline will not flag on size, which is what makes it useful.
        bts = w_epoch + rng.uniform(0, 290)
        bconn = _conn(bts, beacon, BEACON_TARGET, 443, "ssl", rng,
                      orig_bytes=rng.randint(180, 240), resp_bytes=rng.randint(90, 140))
        brow = ingester.map_zeek_conn(bconn)
        if brow:
            out["zeek_conn"].append([brow[c] for c in COLUMNS["zeek_conn"]])
        bflow = _flows_row(bts, beacon, BEACON_TARGET, 443, 200, 110)
        bflow["time_flow_start"] = w_start
        bflow["time_flow_end"] = w_start + timedelta(seconds=30)
        bflow["timestamp"] = w_start
        out["flows"].append(_flow_values(bflow))

        # ANOMALY 2: one window where a host sweeps ports on a single peer. A scan is high flow count
        # with near-zero bytes per flow, which the diversity channel and the volume models read very
        # differently, so the demo exercises the disagreement rather than a tidy single signal.
        if w == windows // 2:
            for port in range(20, 60):
                sts = w_epoch + rng.uniform(0, 120)
                sconn = _conn(sts, scanner, "198.51.100.10", port, "-", rng,
                              orig_bytes=40, resp_bytes=0)
                sconn["conn_state"] = "S0"
                srow = ingester.map_zeek_conn(sconn)
                if srow:
                    out["zeek_conn"].append([srow[c] for c in COLUMNS["zeek_conn"]])
                sflow = _flows_row(sts, scanner, "198.51.100.10", port, 40, 0)
                sflow["time_flow_start"] = w_start
                sflow["time_flow_end"] = w_start + timedelta(seconds=2)
                sflow["timestamp"] = w_start
                out["flows"].append(_flow_values(sflow))

        # ANOMALY 3: the ripple, and the only anomaly here the Ripples card can see. The other two
        # are shapes a per-host baseline is meant to survive; this one is deliberately past the bar.
        # It has to be: a ripple is two families under p <= 0.01 on one host in one window, and the
        # evidence measures the current hour only, so the burst sits in the final hour and clears
        # everything that host has ever done.
        if w >= windows - RIPPLE_WINDOWS:
            for _ in range(RIPPLE_CONNS_PER_WINDOW):
                dport, service = rng.choice(SERVICES)
                dst = rng.choice(EXTERNAL)
                ts = w_epoch + rng.uniform(0, 290)
                orig, resp = rng.randint(120, 4000), rng.randint(200, 60000)
                conn = _conn(ts, rippled, dst, dport, service, rng,
                             orig_bytes=orig, resp_bytes=resp)
                brow = ingester.map_zeek_conn(conn)
                if brow:
                    out["zeek_conn"].append([brow[c] for c in COLUMNS["zeek_conn"]])
                flow = _flows_row(ts, rippled, dst, dport, orig, resp)
                flow["time_flow_start"] = w_start
                flow["time_flow_end"] = w_start + timedelta(seconds=rng.uniform(1, 240))
                flow["timestamp"] = w_start
                out["flows"].append(_flow_values(flow))
            # The DNS family too, so two families corroborate instead of one carrying it alone.
            for _ in range(RIPPLE_LOOKUPS_PER_WINDOW):
                ts = w_epoch + rng.uniform(0, 290)
                lookup = ingester.map_zeek_dns(_dns(ts, rippled, rng.choice(DOMAINS), rng))
                if lookup:
                    out["zeek_dns"].append([lookup[c] for c in COLUMNS["zeek_dns"]])
            # ZEEK'S OWN FINDINGS, because the notice family is the one the live deployment leans on
            # for its highest-severity ripples. Without weird rows this family is simply absent from
            # the demo, and a family that never speaks looks the same as one that had nothing to say.
            for _ in range(RIPPLE_WEIRD_PER_WINDOW):
                ts = w_epoch + rng.uniform(0, 290)
                weird = ingester.map_zeek_weird({
                    "ts": str(ts), "uid": _uid(rng), "id.orig_h": rippled,
                    "id.orig_p": str(rng.randint(1024, 65535)),
                    "id.resp_h": rng.choice(EXTERNAL), "id.resp_p": "443",
                    "name": rng.choice(WEIRD_NAMES), "notice": "T" if rng.random() < 0.2 else "F",
                    "peer": "zeek",
                })
                if weird:
                    out["zeek_weird"].append([weird[c] for c in COLUMNS["zeek_weird"]])

            # A SECOND INCIDENT WITH A DIFFERENT SHAPE. The first host is a volume burst; this one is
            # diversity, reaching many distinct destinations and Host headers that it has never used
            # before. Two ripples of different shapes are what shows the grouping is reading the
            # evidence rather than matching one template.
            for _ in range(RIPPLE_HTTP_HOSTS_PER_WINDOW):
                ts = w_epoch + rng.uniform(0, 290)
                dst = rng.choice(EXTERNAL)
                port = rng.choice((80, 8080, 8000))
                orig, resp = rng.randint(120, 900), rng.randint(200, 5000)
                brow_conn = ingester.map_zeek_conn(
                    _conn(ts, broad, dst, port, "http", rng, orig_bytes=orig, resp_bytes=resp))
                if brow_conn:
                    out["zeek_conn"].append([brow_conn[c] for c in COLUMNS["zeek_conn"]])
                flow = _flows_row(ts, broad, dst, port, orig, resp)
                flow["time_flow_start"] = w_start
                flow["time_flow_end"] = w_start + timedelta(seconds=rng.uniform(1, 240))
                flow["timestamp"] = w_start
                out["flows"].append(_flow_values(flow))
                req = ingester.map_zeek_http(_http(
                    ts, broad, dst, f"node-{rng.randint(1, 9999)}.example.com", rng))
                if req:
                    out["zeek_http"].append([req[c] for c in COLUMNS["zeek_http"]])

    return out


def _live_data(client, *, hours: int = 24) -> int:
    """How many flow rows arrived recently. Used to refuse a seed on a working install."""
    res = client.query(
        "SELECT count() FROM weirvern.flows WHERE time_flow_start >= now() - INTERVAL %(h)s HOUR",
        parameters={"h": hours},
    )
    rows = getattr(res, "result_rows", []) or []
    return int(rows[0][0]) if rows else 0


def insert_all(client, data: dict[str, list[list[Any]]]) -> dict[str, int]:
    """Insert every table. Returns the row count per table so the caller can report what landed.

    AN EMPTY TABLE IS REPORTED AS EMPTY rather than skipped in silence: a seed that quietly writes
    nothing for `zeek_ssl` looks identical to a seed that worked until someone opens the TLS view.
    """
    written: dict[str, int] = {}
    for table, rows in data.items():
        if not rows:
            written[table] = 0
            continue
        client.insert(f"weirvern.{table}", rows, column_names=COLUMNS[table])
        written[table] = len(rows)
    return written


def _report_scope(client, *, declare: bool) -> None:
    """Say whether the seeded addresses are inside a monitored network, and only widen on request.

    `network_scopes.monitored = 1` decides what the console treats as OURS, and in the end what the
    scanner is allowed to touch. A demo seeder must not widen that quietly, so this reports the gap
    and only writes a scope when the caller asked for it by name.

    IT MATTERS BECAUSE OTHERWISE THE DEMO LOOKS BROKEN AND IS NOT. Every seeded host is in
    192.0.2.0/24, so with no covering scope the ripple evidence classifies all of them as peers,
    measures nothing, and the Ripples card reports a scope reason. That is a correct absence, and
    it is indistinguishable to an audience from a feature that does not work.
    """
    import ipaddress  # noqa: PLC0415

    from weirvern import monitored as monitored_mod  # noqa: PLC0415
    from weirvern import networks  # noqa: PLC0415

    # IPv4Network directly, not ip_network(): that returns a union, and the stub then binds
    # subnet_of to the IPv6 arm and reports a mismatch that cannot happen at runtime.
    seeded = ipaddress.IPv4Network(f"{INTERNAL_PREFIX}0/24")
    nets = monitored_mod.networks(client)
    # Rebuilt as IPv4 networks rather than filtered or cast: mypy resolves the stub's generic
    # subnet_of to IPv6 for a union, and a cast would silence that instead of proving the version.
    v4 = [ipaddress.IPv4Network(str(n)) for n in nets if n.version == 4]
    covered = any(seeded.subnet_of(n) for n in v4)

    if covered:
        print(f"  scope:    {seeded} is monitored, so seeded hosts will be attributed")
        return

    if declare:
        try:
            # The label is a closed vocabulary (internal, vpn, dmz, external), so "demo" is not a
            # choice here: these addresses stand in for an internal network, and the description is
            # where the fact that they are synthetic belongs.
            networks.save_scope(client, {
                "cidr": str(seeded),
                "label": "internal",
                "monitored": True,
                "description": "declared by `weirvern demo-seed --scope` for seeded demo traffic",
            })
        except Exception as exc:  # noqa: BLE001 - a scope write failure must not lose the seed
            print(f"  scope:    could not declare {seeded}: {exc}")
            return
        print(f"  scope:    declared {seeded} as a monitored network "
              "(labelled internal, described as demo data)")
        return

    print(
        f"  scope:    WARNING. No monitored network covers {seeded}, so these hosts are peers and "
        "the Ripples card will report a scope reason instead of evidence.\n"
        "            Fix: re-run with --scope, or add the network under Settings > Networks."
    )


def _run_evidence(client, *, hours: int) -> None:
    """Measure the ripple evidence over the seeded span, so the demo does not wait for a tick.

    The worker runs this on its shadow cycle, which is the right place in production and the wrong
    place for a demo: the time between seeding and a ripple existing is however long the next tick
    takes, and a demo that depends on that is not reproducible.

    A measurement that produced no scales says WHY rather than reporting a silent zero. The 1h scale
    needs MIN_BASELINE_SAMPLES windows of the host's own history, which is about 30 hours, so a
    short seed is the usual reason for an empty result here.
    """
    from weirvern.models import ripple_evidence  # noqa: PLC0415

    try:
        measured = ripple_evidence.run(client)
    except Exception as exc:  # noqa: BLE001 - the seed is already written; say so and stop here
        print(f"  evidence: pass failed: {exc}")
        return

    scales = ", ".join(measured.get("scales") or []) or "none"
    print(f"  evidence: {measured.get('rows', 0)} row(s), {measured.get('hosts', 0)} host(s), "
          f"scales {scales}")
    if not measured.get("scales"):
        print(
            f"  evidence: no scale is measurable from {hours}h. The 1h scale needs about 30 hours "
            "of a host's own history, and the lookback is 7 days, so seed at least 30 hours "
            "(144 is the default) before expecting a ripple."
        )


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Declare the seeder's flags on a parser.

    ONE DECLARATION, TWO FRONT DOORS. `weirvern demo-seed` and `python -m weirvern.demo_seed` both
    end up in `main`, and the CLI used to carry its own copy of these flags with its own defaults.
    A default fixed in one place and not the other is how a demo ships six hours of data while the
    module says six days.
    """
    parser.add_argument(
        "--hours", type=int, default=DEFAULT_HOURS,
        help=f"how many hours of data to generate (default {DEFAULT_HOURS}: the ripple evidence "
             "needs at least 30 hours of a host's own history before any scale can be measured, "
             "so a 6-hour seed renders an empty Ripples card)",
    )
    parser.add_argument("--hosts", type=int, default=22, help="how many internal hosts to simulate")
    parser.add_argument("--seed", type=int, default=1337, help="RNG seed, so the demo is reproducible")
    parser.add_argument("--force", action="store_true",
                        help="seed even though recent flow data exists")
    parser.add_argument("--scope", action="store_true",
                        help=f"declare {INTERNAL_PREFIX}0/24 as a monitored network, so seeded "
                             "hosts are attributed; without it the seeder only reports the gap")
    parser.add_argument("--no-enforcement", action="store_true",
                        help="skip the traffic block, the name block, their hits and the pending "
                             "proposal, leaving the Sluice and Approvals surfaces empty")
    parser.add_argument("--no-evidence", action="store_true",
                        help="skip the ripple evidence pass, leaving the Ripples card empty until "
                             "the worker's next shadow tick")
    parser.add_argument("--dry-run", action="store_true", help="print the plan, write nothing")


#: Device archetypes, so a seeded inventory looks like a household rather than 22 copies of one
#: machine. The User-Agent is what the classifier actually reads; the MAC vendor and the hostname are
#: what an operator recognises on the page.
ARCHETYPES: list[dict[str, str]] = [
    {"os": "windows", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/141.0 Safari/537.36",
     "oui": "3c:52:82", "name": "desk-laptop"},
    {"os": "macos", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
                          "(KHTML, like Gecko) Version/18.1 Safari/605.1.15",
     "oui": "00:1b:63", "name": "studio-mac"},
    {"os": "ios", "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 "
                        "(KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
     "oui": "a4:83:e7", "name": "phone"},
    {"os": "android", "ua": "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 "
                            "(KHTML, like Gecko) Chrome/141.0 Mobile Safari/537.36",
     "oui": "f4:f5:d8", "name": "tablet"},
    {"os": "linux", "ua": "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
     "oui": "00:1a:2b", "name": "nas"},
    {"os": "linux", "ua": "curl/8.11.0", "oui": "3c:d9:2b", "name": "print-server"},
]


def _seed_identity(client, *, hosts: int = 22, seed: int = 1337) -> int:
    """Give the inventory something to inventory.

    THE NETWORK AND ASSETS SURFACES READ A CLASSIFICATION, NOT THE TRAFFIC TABLES. Without observations
    every seeded host renders as an address the console knows nothing about, which is the emptiest
    possible version of a product whose front page is a host list. The observations go through
    `host_identity.record_observation`, the same writer the ingest path calls, and the classification
    through `build_identity`, so the seeded inventory is produced the way a real one is.
    """
    from weirvern import host_identity  # noqa: PLC0415

    rng = random.Random(seed + 1)
    moment = utcnow()
    segment = _hosts(random.Random(seed), hosts)
    for index, host in enumerate(segment):
        shape = ARCHETYPES[index % len(ARCHETYPES)]
        mac = f"{shape['oui']}:{rng.randrange(256):02x}:{rng.randrange(256):02x}:{index:02x}"
        host_identity.record_observation(client, moment, host, mac, "oui", shape["oui"])
        host_identity.record_observation(
            client, moment, host, mac, "dhcp_hostname",
            f"{shape['name']}-{index:02d}")
        # Two user agents per host where the archetype allows it, because one banner is one signal and
        # the classifier is explicit about what it can say from a single observation.
        host_identity.record_observation(client, moment, host, mac, "software", shape["ua"])

    verdicts = host_identity.build_identity(client, days=7)
    host_identity.persist(client, verdicts)
    return len(verdicts)


def _enforcement_exists(client) -> int:
    """How many demo rules are already stored, so a second run does not stack duplicates.

    A demo that leaves two identical blocks behind after someone runs the command twice is worse than
    one that reports it already did this: the second rule has no hits, so it reads as a rule that
    matched nothing rather than as a rerun.
    """
    from weirvern import sluice_store  # noqa: PLC0415

    try:
        rules = sluice_store.load_all_rules(client)
    except Exception:  # noqa: BLE001 - an unreadable rule table must not stop the seed itself
        return 0
    return sum(1 for rule in rules if getattr(rule, "origin", "") == DEMO_ORIGIN)


def _seed_enforcement(client, *, hosts: int = 22, seed: int = 1337) -> dict[str, Any]:
    """Create the two blocks the product exists to perform, and the evidence that they fired.

    A TEST DRIVE IS NOT A TOUR OF THE DETECTORS. Someone who runs this command and clicks through
    the console should find the Sluice gate holding rules, the blocklist holding a name, those rules
    carrying the hits they caught, and a proposal waiting for a decision. Empty enforcement panels in
    a product whose point is enforcement reads as unfinished rather than quiet, and the same is true
    in a class demo where nobody can tell an empty table from a broken one.

    EVERY WRITE GOES THROUGH THE PRODUCT'S OWN STORE, not a hand-built row: `sluice_store.create_rule`
    validates the address, `blocklists.add_custom_domain` runs the same validator as a manual entry,
    and `proposals.create_proposal` refuses an unexplained target. A seeder that wrote finished rows
    would let a validation bug live through the demo and appear on the day someone tries it for real.

    THE GATE IS ARMED IN THE RECORD ONLY. Nothing here touches the kernel or nftables: this writes
    what the console reads, which is what a demo needs, and it cannot block real traffic.
    """
    from datetime import timedelta as _timedelta

    from weirvern import blocklists, proposals, sluice, sluice_store  # noqa: PLC0415

    segment = _hosts(random.Random(seed), hosts)
    beacon = segment[0]
    scanner = segment[1 % len(segment)]

    traffic_rule = sluice_store.create_rule(
        client,
        src_cidr=f"{beacon}/32",
        mode="block",
        ttl_minutes=60,
        created_by="demo-seed",
        reason=(
            f"beacons to {BEACON_TARGET} every five minutes at a constant size; a per-host volume "
            "baseline will never flag it on size"
        ),
        origin=DEMO_ORIGIN,
        severity="high",
    )
    dns_rule = sluice_store.create_rule(
        client,
        domain=BEACON_DOMAIN,
        mode="block",
        ttl_minutes=240,
        created_by="demo-seed",
        reason=(
            f"{BEACON_DOMAIN} is what {beacon} resolves before it beacons; blocking the name "
            "removes the rendezvous rather than one address"
        ),
        origin=DEMO_ORIGIN,
        severity="medium",
    )
    blocklists.add_custom_domain(client, BEACON_DOMAIN)
    # The source list is part of the pane, not decoration: a test drive that shows an empty Blocklists
    # tab teaches a new user the feature does not exist. These rows carry no domains until a sync
    # fetches one, so the pane honestly shows "configured, not yet synced" rather than fake counts.
    blocklists.ensure_default_sources(client)

    # THE HITS. A rule with no events is indistinguishable from a rule that never matched, which is
    # the difference an operator is usually asking about.
    now = utcnow()
    events: list[dict[str, Any]] = []
    packets = 0
    octets = 0
    for step in range(12):
        ts = now - _timedelta(minutes=55 - step * 5)
        pkt, byt = 4 + step % 3, 2400 + step * 96
        packets += pkt
        octets += byt
        events.append({
            "ts": ts, "rule_id": traffic_rule.rule_id, "kind": "flow",
            "src_addr": beacon, "dst_addr": BEACON_TARGET, "dst_port": 443,
            "protocol": "tcp", "packets": pkt, "bytes": byt, "direction": "forward",
        })
    dns_packets = 0
    for step in range(10):
        dns_packets += 1
        events.append({
            "ts": now - _timedelta(minutes=50 - step * 5), "rule_id": dns_rule.rule_id,
            "kind": "dns", "domain": BEACON_DOMAIN, "query": BEACON_DOMAIN, "src_addr": beacon,
            "dst_addr": "203.0.113.90", "dst_port": 53, "protocol": "udp",
            "packets": 1, "bytes": 88, "direction": "forward",
        })
    written = sluice_store.write_events(client, events)

    # The gate says ARMED because the rules are live, and it reports the same counts the events
    # carry. It is the state a reader gets from the console, not a claim about the kernel.
    from weirvern.config import get_settings  # noqa: PLC0415
    from weirvern.worker import _sensor_name  # noqa: PLC0415

    state = sluice.GateState(
        state=sluice.GATE_STATE_ARMED,
        iface="demo0",
        mgmt_iface="",
        rules_active=2,
        rules_total=2,
        packets_blocked=packets + dns_packets,
        bytes_blocked=octets + 88 * dns_packets,
        detail="demo seed: one traffic block and one name block armed; no kernel changes",
        backend="nft",
        backend_expected="nft",
        enforcement="nft",
    )
    sluice_store.write_gate_state(client, _sensor_name(get_settings()), state)

    # A PROPOSAL LEFT UNDECIDED, because the approval path is part of the product and an empty
    # Approvals surface teaches a new user that the feature is missing.
    proposal = proposals.create_proposal(client, {
        "host": scanner,
        "proposed_by": "demo-seed",
        "reason": (
            f"{scanner} opened 40 ports on 198.51.100.10 in one window with almost no bytes back: "
            "a sweep, and worth a decision rather than an automatic block"
        ),
        "evidence": f"40 connections, 0 bytes returned, all refused, window ending {now:%H:%M} UTC",
        "ttl_minutes": 60,
    })

    return {
        "traffic_rule": traffic_rule.rule_id,
        "dns_rule": dns_rule.rule_id,
        "flows": written,
        "packets": packets + dns_packets,
        "domain": BEACON_DOMAIN,
        "proposal": proposal.get("proposal_id", ""),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="weirvern demo-seed",
        description="Fill ClickHouse with plausible demo traffic ending now, for a reproducible demo.",
    )
    add_arguments(parser)
    args = parser.parse_args(argv)

    data = build(hours=args.hours, hosts=args.hosts, seed=args.seed)
    total = sum(len(rows) for rows in data.values())

    print(f"demo seed: {args.hours}h, {args.hosts} hosts, seed {args.seed}")
    for table, rows in data.items():
        print(f"  {table:12s} {len(rows):7,d} rows")
    print(f"  {'total':12s} {total:7,d}")

    if args.dry_run:
        print("dry run: nothing written")
        return 0

    from weirvern import db  # noqa: PLC0415
    from weirvern.config import get_settings  # noqa: PLC0415

    settings = get_settings()
    with db.connect(settings) as client:
        live = _live_data(client)
        if live and not args.force:
            print(
                f"refusing: {live:,} flow rows arrived in the last 24 hours, so this looks like a "
                "working install and seeding it would mix demo data with real traffic. "
                "Use --force if that is what you want.",
                file=sys.stderr,
            )
            return 2
        written = insert_all(client, data)
        for table, count in written.items():
            print(f"  wrote {table:12s} {count:7,d}")
        empty = [t for t, n in written.items() if n == 0]
        if empty:
            print(f"  NOTE: no rows generated for {', '.join(empty)}; that view will be empty")
        # After the writes, and in this order: whether the hosts will be attributed at all, then
        # whether anything measurable came of them. Both print below the row counts, so the output
        # reads as a sequence instead of interleaving with what the seed just wrote.
        _report_scope(client, declare=args.scope)
        if not args.no_enforcement:
            existing = _enforcement_exists(client)
            if existing:
                print(f"  blocks:   {existing} demo rule(s) already present, left alone")
            else:
                made = _seed_enforcement(client, hosts=args.hosts, seed=args.seed)
                print(
                    f"  blocks:   traffic rule {made['traffic_rule']}, name rule "
                    f"{made['dns_rule']} for {made['domain']}, "
                    f"{made['flows']} hit(s) recorded, gate armed"
                )
                print(f"  proposal: {made['proposal']} waiting for a decision")
        if not args.no_enforcement:
            classified = _seed_identity(client, hosts=args.hosts, seed=args.seed)
            print(f"  inventory: {classified} host(s) classified for the Network and Assets views")
        if not args.no_evidence:
            _run_evidence(client, hours=args.hours)
    return 0


if __name__ == "__main__":
    sys.exit(main())
