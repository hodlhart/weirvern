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
import os
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

# THE REST OF ZEEK. `zeek_conn`, `zeek_dns`, `zeek_ssl`, `zeek_http` and `zeek_weird` are written by
# the traffic generator above because the anomaly story needs them. The other tier 1-3 logs have
# their own views and their own detectors, and a demo that leaves thirteen of them empty teaches a
# reader that those features do not exist. Their column orders are taken from the ingester's own
# ZEEK_COLUMNS, so an INSERT here cannot drift from the tailer's positional order.
EXTRA_LOGS = ("notice", "files", "ssh", "kerberos", "dce_rpc", "smb_mapping", "smb_files",
              "ntlm", "dhcp", "x509", "tunnel", "quic", "ldap_search")
for _extra in EXTRA_LOGS:
    COLUMNS[f"zeek_{_extra}"] = list(ingester.ZEEK_COLUMNS[_extra])

# Private ranges for the client sites, documentation ranges for everything outside. The three
# sites deliberately use DIFFERENT private blocks: an operator reading the map can tell a 10.x
# host from a 192.168 host at a glance, which three /25s of 192.0.2 could not do.
INTERNAL_PREFIX = "10.10.0."
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
RIPPLE_HTTP_HOSTS_PER_WINDOW = 40

#: The name the beacon resolves. It exists so the DNS block has a rule AND a query that refers to
#: real seeded traffic; a blocked name nothing ever looked up is a rule with no story.
BEACON_DOMAIN = "updates.example.net"

#: Every rule this seeder creates carries this origin, which is how a second run tells that the
#: enforcement picture is already there instead of stacking a duplicate block on top of it.
DEMO_ORIGIN = "demo-seed"
#: THREE CLIENT SITES, ONE DMZ, ONE INTERNET. The sites use three different private blocks so a
#: reader can tell them apart by address alone: HQ on 10.10.0.0/24, the branch on 192.168.20.0/24,
#: the warehouse on 172.16.30.0/24. The DMZ and the public web stay on RFC 5737 documentation
#: ranges. Separate scopes matter beyond the addresses: the Network graph colours nodes by scope
#: and the hop rings come from the TTL each host's own packets carry, so the seed draws three
#: client clusters, a server cluster and a public cloud instead of one hairball.
SITE_A_NET = "10.10.0.0/24"
SITE_B_NET = "192.168.20.0/24"
SITE_C_NET = "172.16.30.0/24"
DMZ_NET = "198.51.100.0/24"
SITE_A = [f"10.10.0.{n}" for n in range(10, 22)]
SITE_B = [f"192.168.20.{n}" for n in range(10, 22)]
SITE_C = [f"172.16.30.{n}" for n in range(10, 22)]
DMZ = ["198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13"]
INTERNET = ["203.0.113.10", "203.0.113.23", "203.0.113.66", "203.0.113.90"]
EXTERNAL = DMZ + INTERNET
BEACON_TARGET = "203.0.113.66"
SERVICES = [(443, "ssl"), (80, "http"), (53, "dns"), (22, "ssh"), (8080, "http")]
#: Ports that belong to a zone. A client talks HTTPS to the web and SMB to its own site; the DMZ
#: serves web, application and database ports and never appears as a DNS peer.
DMZ_SERVICES = [(443, "ssl"), (80, "http"), (5432, "pgsql"), (25, "smtp")]
LOCAL_SERVICES = [(445, "smb"), (22, "ssh"), (80, "http")]
WEIRD_NAMES = ["bad_TCP_checksum", "truncated_IP", "data_before_established",
              "window_recision", "possible_split_routing"]
DOMAINS = ["example.com", "updates.example.net", "mail.example.org", "cdn.example.com"]
SNI = ["example.com", "cdn.example.com", "updates.example.net"]
WINDOW = timedelta(minutes=5)


def _uid(rng: random.Random) -> str:
    """A Zeek-shaped connection id. Not a hash of anything; it only needs to be unique per row."""
    return "C" + "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16))


def _hosts(rng: random.Random, count: int) -> list[str]:
    """The client hosts, split across THREE SITES with three different private blocks.

    HQ is 10.10.0.0/24, the branch 192.168.20.0/24, the warehouse 172.16.30.0/24. The split is
    what lets the graph, the scopes and the sensors describe three locations; one flat range
    gives the force layout an undifferentiated blob, which is what the old demo looked like.
    """
    a_count = max(1, (count + 2) // 3)
    b_count = max(1, (count - a_count + 1) // 2)
    c_count = max(1, count - a_count - b_count)
    return SITE_A[:a_count] + SITE_B[:b_count] + SITE_C[:c_count]


def _site(host: str) -> str:
    """Which client site a host belongs to, from its own address."""
    if host.startswith("10.10.0."):
        return "Site A"
    if host.startswith("192.168.20."):
        return "Site B"
    return "Site C"


def _client_ttl(host: str) -> int:
    """The TTL a client's packets arrive with, so the graph gets real hop rings.

    Site A is one hop from the hub's sensor and Site B is three, which is the structure the view
    draws. These are demo values and deliberately different: equal TTLs would collapse both sites
    into one ring and hide the feature the seed exists to show.
    """
    return {"Site A": 127, "Site B": 125, "Site C": 122}.get(_site(host), 127)


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
        "id.resp_h": "203.0.113.10",
        "id.resp_p": "53",
        "proto": "udp",
        "trans_id": str(rng.randint(1, 65535)),
        "query": query,
        "qtype": "A",
        "rcode": "NOERROR" if rng.random() > 0.06 else "NXDOMAIN",
        "answers": ",".join(f"10.10.0.{rng.randint(1, 250)}" for _ in range(rng.randint(0, 3))),
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


def _flows_row(ts: float, src: str, dst: str, dport: int, orig_bytes: int, resp_bytes: int,
               ttl: int = 64, client_port: int = 0) -> dict:
    """The NetFlow view of the SAME conversation, so the two channels agree instead of contradicting.

    A demo where the flow view and the Zeek view disagree is worse than one channel being empty: it
    reads as a defect in the product rather than in the seed.

    ONE DIRECTION PER RECORD. A NetFlow exporter reports each direction separately, so this row
    carries the request bytes and `_flows_pair` writes the response as its own record with the
    addresses and ports swapped. Folding both directions into one row, as an earlier version did,
    left every server looking like a leaf that never sent anything back.
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
        "src_port": client_port,
        "dst_port": dport,
        "proto": 6 if dport != 53 else 17,
        "etype": 2048,
        "bytes": orig_bytes,
        "packets": max(1, orig_bytes // 200),
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
        "ip_ttl": ttl,
        "frag_offset": 0,
    }


def _server_ttl(addr: str) -> int:
    """The TTL a server's packets arrive with, so the reverse direction has its own hop path."""
    if addr.startswith("203.0.113."):
        return 61
    if addr.startswith("198.51.100."):
        return 62
    return 64


def _flows_pair(ts: float, src: str, dst: str, dport: int, orig_bytes: int, resp_bytes: int,
                *, ttl: int = 64, client_port: int = 0) -> list[dict]:
    """Both directions of one conversation, which is what an exporter actually emits.

    The forward record carries the request, the reverse carries the response with the addresses
    and ports swapped. The byte totals across the two records equal what the old combined row
    carried, so the detectors see the same volume; what changes is that the server now appears as
    a source, which is what makes top-talkers, the graph and any reverse-direction analysis honest.
    """
    forward = _flows_row(ts, src, dst, dport, orig_bytes, resp_bytes, ttl=ttl,
                         client_port=client_port)
    reverse = dict(forward)
    reverse["src_addr"], reverse["dst_addr"] = forward["dst_addr"], forward["src_addr"]
    reverse["src_port"], reverse["dst_port"] = forward["dst_port"], forward["src_port"]
    reverse["bytes"] = max(0, resp_bytes)
    # A response with zero payload (a refused scan) is still a packet on the wire.
    reverse["packets"] = max(1, resp_bytes // 200) if resp_bytes else 1
    reverse["ip_ttl"] = _server_ttl(dst)
    return [forward, reverse]


def _flow_values(flow: dict) -> list:
    """Assemble a flow row BY KEY, so a column with no value raises instead of becoming 0.

    Three call sites build flow rows (the segment loop, the beacon and the scan) and an earlier
    version had `.get(c, 0)` at each of them. That is the silent-default shape this project keeps
    finding: a schema column added later would insert a zero into a field nobody meant to leave at
    zero, and the row would look valid. One helper means one place to be right.
    """
    return [flow[c] for c in COLUMNS["flows"]]


def _extra_record(log: str, ts: float, host: str, dst: str,
                  rng: random.Random) -> dict[str, str]:
    """One record for a Zeek log the traffic generator does not otherwise write.

    THE FIELD NAMES ARE ZEEK'S OWN, not the table's: the point is to push a record through the
    same mapper the tailer uses, so a rename in the ingester breaks this seeder too. Values are
    deliberately ordinary (a successful SSH login, a share mapping, a DHCP lease) except where a
    log only exists to carry an anomaly, and then the anomaly is one a detector can name.
    """
    base = {
        "ts": f"{ts:.6f}",
        "uid": _uid(rng),
        "id.orig_h": host,
        "id.orig_p": str(rng.randint(49152, 65000)),
        "id.resp_h": dst,
        "id.resp_p": "445",
    }
    hexish = lambda n: "".join(rng.choice("0123456789abcdef") for _ in range(n))  # noqa: E731

    if log == "notice":
        note, msg = rng.choice([
            ("Scan::Port_Scan", f"{host} scanned a port on {dst}"),
            ("SMB::Bad_share_access", "SMB share access was refused"),
            ("SSL::Invalid_Server_Cert", "certificate validation failed"),
        ])
        return {**base, "note": note, "msg": msg, "sub": dst, "peer_descr": "worker-1",
                "actions": "Notice::ACTION_LOG", "suppress_for": "3600.000000"}
    if log == "files":
        size = rng.randint(4096, 900000)
        return {**base, "id.resp_p": "80", "fuid": _uid(rng), "source": "HTTP",
                "filename": rng.choice(["update.bin", "report.pdf", "installer.exe"]),
                "mime_type": "application/octet-stream", "sha256": hexish(64),
                "md5": hexish(32), "seen_bytes": str(size), "total_bytes": str(size),
                "missing_bytes": "0", "overflow_bytes": "0"}
    if log == "ssh":
        return {**base, "id.resp_p": "22", "version": "SSH-2.0-OpenSSH_9.6",
                "auth_success": rng.choice(["T", "T", "F"]), "auth_attempts": "1",
                "direction": "INBOUND", "client": "SSH-2.0-OpenSSH_9.6",
                "server": "SSH-2.0-OpenSSH_9.6p1"}
    if log == "kerberos":
        return {**base, "id.resp_p": "88", "request_type": "TGS",
                "client": "svc-demo$@DEMO.LOCAL", "service": "krbtgt/DEMO.LOCAL",
                "success": "T", "error_msg": "-", "from": str(ts - 3600),
                "till": str(ts + 3600), "cipher": "aes256-cts-hmac-sha1-96",
                "forwardable": "T", "renewable": "T"}
    if log == "dce_rpc":
        return {**base, "rtt": "0.0015", "named_pipe": "\\PIPE\\svcctl",
                "endpoint": "svcctl", "operation": "NetrStartServiceW"}
    if log == "smb_mapping":
        return {**base, "path": "\\\\fileserver\\shared", "service": "SMB2",
                "native_file_system": "NTFS", "share_type": "DISK"}
    if log == "smb_files":
        return {**base, "fuid": _uid(rng), "action": "SMB_FILE_WRITE",
                "path": "\\\\fileserver\\shared", "name": "quarterly.docx",
                "size": str(rng.randint(12000, 400000)), "prev_name": "-"}
    if log == "ntlm":
        return {**base, "username": rng.choice(["asmith", "jdoe", "svc-backup"]),
                "hostname": "WS-01", "domainname": "DEMO", "success": "T"}
    if log == "dhcp":
        return {**base, "id.orig_h": "0.0.0.0", "id.resp_h": "192.0.2.1", "uids": "",
                "client_addr": "0.0.0.0", "server_addr": "192.0.2.1",
                "mac": "3c:52:82:" + ":".join(hexish(2) for _ in range(3)),
                "host_name": "desk-laptop", "client_fqdn": "desk-laptop.demo",
                "domain": "demo.local", "requested_addr": host, "assigned_addr": host,
                "lease_time": "86400.000000", "msg_types": "REQUEST,ACK", "duration": "0.1"}
    if log == "x509":
        return {**base, "id.resp_p": "443", "fingerprint": hexish(64),
                "subject": "CN=updates.example.net", "issuer": "CN=Demo CA",
                "common_name": "updates.example.net",
                "not_valid_before": str(ts - 86400 * 30), "not_valid_after": str(ts + 86400 * 300),
                "key_alg": "rsaEncryption", "key_length": "2048",
                "sig_alg": "sha256WithRSAEncryption", "is_ca": "F",
                "san_dns": "updates.example.net", "host_cert": "T", "client_cert": "F"}
    if log == "tunnel":
        return {**base, "id.resp_p": "443", "tunnel_type": "Tunnel::DNS",
                "action": "Tunnel::DISCOVER"}
    if log == "quic":
        return {**base, "id.resp_p": "443", "server_name": "cdn.example.com",
                "client_protocol": "h3", "version": "1"}
    if log == "ldap_search":
        return {**base, "id.resp_p": "389", "ldap_filter": "(objectClass=user)",
                "base_object": "DC=demo,DC=local", "scope": "wholeSubtree",
                "deref_aliases": "never", "result_count": str(rng.randint(1, 40)),
                "result": "success"}
    return {}


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
    half = len(segment) // 2 or 1
    beacon = segment[0]
    scanner = segment[1 % len(segment)]
    # Kept at the third and fourth hosts so the incident arithmetic the tests pin does not move;
    # the two sites are carried by the address split, the scopes and the sensors.
    rippled = segment[2 % len(segment)]
    broad = segment[3 % len(segment)]

    out: dict[str, list[list[Any]]] = {name: [] for name in COLUMNS}

    for w in range(windows):
        w_start = end - timedelta(hours=hours) + w * WINDOW
        w_epoch = w_start.timestamp()

        for host in segment:
            for _ in range(rng.randint(1, connections_per_host_window)):
                # A CLIENT'S DAY, MIXED BY DESTINATION: mostly the public web, often the DMZ's
                # servers, sometimes a colleague on its own site. The mix is what gives the graph
                # three kinds of edge instead of every client talking to the same four addresses.
                roll = rng.random()
                if roll < 0.18:
                    peers = [h for h in segment if h != host and _site(h) == _site(host)]
                    dst = rng.choice(peers) if peers else rng.choice(INTERNET)
                    dport, service = rng.choice(LOCAL_SERVICES)
                elif roll < 0.55:
                    dst = rng.choice(DMZ)
                    dport, service = rng.choice(DMZ_SERVICES)
                else:
                    dst = rng.choice(INTERNET)
                    dport, service = rng.choice(SERVICES)
                orig = rng.randint(120, 4000)
                resp = rng.randint(200, 60000)
                ts = w_epoch + rng.uniform(0, 290)

                conn = _conn(ts, host, dst, dport, service, rng, orig_bytes=orig, resp_bytes=resp)
                row = ingester.map_zeek_conn(conn)
                if row:
                    out["zeek_conn"].append([row[c] for c in COLUMNS["zeek_conn"]])

                for flow in _flows_pair(ts, host, dst, dport, orig, resp,
                                        ttl=_client_ttl(host),
                                        client_port=int(conn["id.orig_p"])):
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

        # THE SERVERS ALSO TALK TO THE WEB, so the graph has a server-to-cloud edge and the DMZ
        # is not a terminal node. Two conversations per window is enough to draw it.
        for _ in range(2):
            dts = w_epoch + rng.uniform(0, 290)
            dmz_host = rng.choice(DMZ)
            dst = rng.choice(INTERNET)
            dport, service = rng.choice([(443, "ssl"), (80, "http")])
            orig, resp = rng.randint(400, 9000), rng.randint(800, 90000)
            dconn = _conn(dts, dmz_host, dst, dport, service, rng, orig_bytes=orig, resp_bytes=resp)
            drow = ingester.map_zeek_conn(dconn)
            if drow:
                out["zeek_conn"].append([drow[c] for c in COLUMNS["zeek_conn"]])
            for flow in _flows_pair(dts, dmz_host, dst, dport, orig, resp, ttl=61,
                                    client_port=int(dconn["id.orig_p"])):
                flow["time_flow_start"] = w_start
                flow["time_flow_end"] = w_start + timedelta(seconds=rng.uniform(1, 120))
                flow["timestamp"] = w_start
                out["flows"].append([flow[c] for c in COLUMNS["flows"]])

        # THE REST OF ZEEK, one log at a time, through its own mapper. One host per window keeps
        # the volume honest (about 1,700 rows per log over six days) while every Zeek view has
        # rows to read. The host rotates so no single machine carries every log.
        extra_host = segment[w % len(segment)]
        extra_dst = EXTERNAL[w % len(EXTERNAL)]
        for log in EXTRA_LOGS:
            rec = _extra_record(log, w_epoch + rng.uniform(0, 290), extra_host, extra_dst, rng)
            mapped = getattr(ingester, f"map_zeek_{log}")(rec)
            if mapped:
                out[f"zeek_{log}"].append([mapped[c] for c in COLUMNS[f"zeek_{log}"]])

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
                      orig_bytes=200, resp_bytes=110)
        brow = ingester.map_zeek_conn(bconn)
        if brow:
            out["zeek_conn"].append([brow[c] for c in COLUMNS["zeek_conn"]])
        for flow in _flows_pair(bts, beacon, BEACON_TARGET, 443, 200, 110,
                                ttl=_client_ttl(beacon),
                                client_port=int(bconn["id.orig_p"])):
            flow["time_flow_start"] = w_start
            flow["time_flow_end"] = w_start + timedelta(seconds=30)
            flow["timestamp"] = w_start
            out["flows"].append(_flow_values(flow))

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
                for flow in _flows_pair(sts, scanner, "198.51.100.10", port, 40, 0,
                                        ttl=_client_ttl(scanner),
                                        client_port=int(sconn["id.orig_p"])):
                    flow["time_flow_start"] = w_start
                    flow["time_flow_end"] = w_start + timedelta(seconds=2)
                    flow["timestamp"] = w_start
                    out["flows"].append(_flow_values(flow))

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
                for flow in _flows_pair(ts, rippled, dst, dport, orig, resp,
                                        client_port=int(conn["id.orig_p"])):
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
                bconn = _conn(ts, broad, dst, port, "http", rng, orig_bytes=orig, resp_bytes=resp)
                brow_conn = ingester.map_zeek_conn(bconn)
                if brow_conn:
                    out["zeek_conn"].append([brow_conn[c] for c in COLUMNS["zeek_conn"]])
                for flow in _flows_pair(ts, broad, dst, port, orig, resp,
                                        client_port=int(bconn["id.orig_p"])):
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
    scopes = [
        (SITE_A_NET, "internal", "HQ clients (demo, 10.10.0.0/24)"),
        (SITE_B_NET, "vpn", "Branch clients, over VPN (demo, 192.168.20.0/24)"),
        (SITE_C_NET, "internal", "Warehouse clients (demo, 172.16.30.0/24)"),
        (DMZ_NET, "dmz", "Company DMZ (demo)"),
    ]
    for cidr, label, description in scopes:
        seeded = ipaddress.IPv4Network(cidr)
        nets = monitored_mod.networks(client)
        v4 = [ipaddress.IPv4Network(str(n)) for n in nets if n.version == 4]
        if any(seeded.subnet_of(n) for n in v4):
            print(f"  scope:    {seeded} is monitored ({label})")
            continue
        if not declare:
            print(
                f"  scope:    WARNING. No monitored network covers {seeded}, so these hosts are "
                "peers and the views that attribute them will report a scope reason.\n"
                "            Fix: re-run with --scope, or add the network under Settings > Networks."
            )
            continue
        try:
            # The label is a closed vocabulary (internal, vpn, dmz, external), so "demo" is not a
            # choice here: the description is where the fact that these are synthetic belongs.
            networks.save_scope(client, {
                "cidr": cidr,
                "label": label,
                "monitored": True,
                "description": description,
            })
            print(f"  scope:    declared {seeded} as {label} ({description})")
        except Exception as exc:  # noqa: BLE001 - a scope write failure must not lose the seed
            print(f"  scope:    could not declare {seeded}: {exc}")

    # EVERY SEEDED CLIENT MUST BE INSIDE A MONITORED SCOPE. The ripple evidence attributes a host
    # by resolving it against these declarations; a client outside all of them is measured as a
    # peer and the incident disappears with no error.
    nets = monitored_mod.networks(client)
    v4 = [ipaddress.IPv4Network(str(n)) for n in nets if n.version == 4]
    uncovered = [h for h in SITE_A + SITE_B + SITE_C
                 if not any(ipaddress.IPv4Network(h) in n for n in v4)]
    if uncovered:
        print(f"  scope:    WARNING. {len(uncovered)} seeded client(s) are outside every monitored "
              f"scope, starting with {uncovered[0]}")
    else:
        print("  scope:    every seeded client is inside a monitored scope")


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
    parser.add_argument("--hosts", type=int, default=36, help="how many internal hosts to simulate")
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
    parser.add_argument("--traffic-only", action="store_true",
                        help="write only the traffic tables: no fleet, no assets, no detector run, "
                             "no demo flag. This is the old behaviour and is not a test drive.")
    parser.add_argument("--no-ml", action="store_true",
                        help="seed the data without training the detectors or scoring the windows; "
                             "the Alerts and Evidence views stay empty")
    parser.add_argument("--ml-hours", type=int, default=8,
                        help="how far back the detector sweep scores during the demo run "
                             "(default 8; the training window is RETRAIN_WINDOW_H)")
    parser.add_argument("--clear-demo", action="store_true",
                        help="retire demo mode without touching the data: the banner goes away and "
                             "the live feed checks come back")
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


def _seed_normalization(client, *, hosts: int = 22, seed: int = 1337) -> dict[str, Any]:
    """Teach the console that one observed pattern is expected, which is a feature in its own right.

    NORMALIZING IS THE OTHER HALF OF DETECTION. Every deployment accumulates values that are strange
    once and ordinary forever: a backup job, a vendor's update service, a printer that only speaks one
    ancient protocol. Left alone they fire on every pass and train the operator to ignore the page.
    The console lets a value be marked expected, with a reason and a review date, and stops counting
    it -- so a test drive without one never shows the mechanism at all.

    THE VALUE IS READ FROM THE SEEDED TRAFFIC, not invented: `candidates` asks the source table the
    same question the measurement asks, so the row names something this host actually sent. A made-up
    value would be a signature that filters nothing while looking like it works.
    """
    from datetime import timedelta as _timedelta

    from weirvern import ripple_signatures  # noqa: PLC0415
    from weirvern.models import ripple_evidence as rev  # noqa: PLC0415

    segment = _hosts(random.Random(seed), hosts)
    host = segment[4 % len(segment)]
    channels = ripple_signatures.channels_for(rev.SPECS)
    now = utcnow()
    start = now - _timedelta(hours=24)

    for channel in sorted(channels):
        spec = ripple_signatures.find_spec(rev.SPECS, channel)
        if spec is None:
            continue
        try:
            seen = ripple_signatures.candidates(client, spec, host=host, start=start, end=now)
        except Exception:  # noqa: BLE001 - one unreadable source must not stop the seed
            continue
        if not seen:
            continue
        top = max(seen, key=lambda row: row["count"])
        entry = ripple_signatures.new_signature(
            host=host,
            channel=channel,
            value=top["value"],
            reason=(
                f"demo seed: {top['value']} is this host's routine pattern ({top['count']} times "
                "in 24h), so it is expected here rather than novel"
            ),
            channels=channels,
            actor="demo-seed",
        )
        if ripple_signatures.write(client, [entry]):
            return {"host": host, "channel": channel, "value": top["value"],
                    "review_after": str(entry["review_after"])}
    return {}


def _seed_normal_traffic(client, *, hosts: int = 22, seed: int = 1337) -> int:
    """Mark the BENIGN baseline expected, and leave the malicious hosts un-normalized.

    WHY THIS IS THE OTHER HALF OF THE DEMO. A detector that fires on everything teaches nothing,
    and a demo where every host is either silent or malicious never shows the mechanism an operator
    actually uses: say "this backup job is ordinary" once, and from then on the only alerts that
    survive are the ones nobody has explained. The incident hosts (beacon, scanner, volume burst,
    diversity burst) are deliberately NOT normalized, so the ML and the ripple evidence still have
    something to find and fathom can still investigate it.

    THE ROWS ARE READ FROM THE SEEDED TRAFFIC, not invented: the top conversation for each benign
    host is measured with the same aggregate a real review would read. A made-up entry would be an
    expectation about traffic that never existed, which is the shape of a rule that filters nothing.
    """
    from uuid import uuid4  # noqa: PLC0415

    segment = _hosts(random.Random(seed), hosts)
    incidents = set(segment[:4])  # beacon, scanner, volume burst, diversity burst
    benign = [h for h in segment if h not in incidents]
    now = utcnow()
    rows: list[list[Any]] = []
    seen: set[tuple[str, str, int]] = set()
    # LOTS OF EXPECTED TRAFFIC, WHICH IS THE POINT. One normalized conversation per host made the
    # Normalize view look like a curated list of exceptions; a real deployment marks the ordinary
    # shapes so the few that remain unexplained are the ones an operator sees. Four conversations
    # per benign host is enough to cover web, mail, DNS and the DMZ without turning the page into a
    # dump, and every incident host is still excluded.
    for host in benign:
        try:
            res = client.query(
                "SELECT dst_addr, dst_port, proto, count() AS flows, sum(bytes) AS b, "
                "sum(packets) AS p, min(timestamp) AS first, max(timestamp) AS last "
                "FROM weirvern.flows WHERE src_addr = %(a)s "
                "AND timestamp >= now() - INTERVAL 24 HOUR "
                "GROUP BY dst_addr, dst_port, proto ORDER BY flows DESC LIMIT 4",
                parameters={"a": host},
            ).result_rows
        except Exception:  # noqa: BLE001 - one unreadable host must not stop the seed
            continue
        for dst, port, proto, flows, nbytes, packets, first, last in res:
            # THE MALICIOUS DESTINATIONS ARE NEVER MARKED EXPECTED. A benign host can happen to
            # talk to the same address the beacon uses; normalizing that pair would tell the
            # console the C2 endpoint is ordinary, which is the opposite of the demo.
            if str(dst) in {BEACON_TARGET, "198.51.100.10"}:
                continue
            key = (str(host), str(dst), int(port or 0))
            if key in seen:
                continue
            seen.add(key)
            n = max(1, int(flows))
            avg_bytes = float(nbytes) / n
            # THE KEY MUST BE THE FEED'S KEY, or the row never turns green. The Normalize feed
            # groups destinations at /24 and carries the service NAME in dns_name (the first
            # observed row was 203.0.113.0/24 port 80 service http). An entry written as /32 with
            # an empty name matches nothing, which is why the seeded patterns showed as pending.
            import ipaddress  # noqa: PLC0415

            prefix = ipaddress.ip_network(f"{dst}/24", strict=False)
            service = {80: "http", 443: "ssl", 53: "dns", 22: "ssh", 8080: "http",
                       5432: "pgsql", 25: "smtp", 445: "smb"}.get(int(port or 0), "")
            rows.append([
                uuid4().hex, now, "demo-seed", "flow", "active", None, "",
                host, str(prefix), int(port or 0), int(proto or 0), service, 0,
                int(flows), int(nbytes), int(packets), n, avg_bytes, 0.0,
                float(packets) / n, 0.0, first, last,
                f"demo seed: routine {dst}:{port} from {host}; expected in this deployment",
            ])
    # SHARED NAMES, because a normalized flow table with two DNS entries leaves the name half of
    # the Normalize view nearly empty. The beacon's name is deliberately absent: that is the
    # malicious resolution the hunt is meant to find.
    for name in ("example.com", "cdn.example.com", "mail.example.org", "docs.example.net",
                 "api.example.org", "static.example.com"):
        rows.append([
            uuid4().hex, now, "demo-seed", "dns", "active", None, "",
            "", "203.0.113.0/24", 53, 17, name, 1,
            500, 250_000, 500, 500, 500.0, 0.0, 1.0, 0.0,
            now - timedelta(hours=24), now,
            f"demo seed: {name} is looked up by ordinary clients every day",
        ])
    if not rows:
        return 0
    try:
        client.insert("weirvern.normal_traffic", rows, column_names=[
            "entry_id", "created_at", "created_by", "source", "status", "removed_at",
            "removed_by", "src_addr", "dst_prefix", "dst_port", "proto", "dns_name",
            "dns_qtype", "flows", "bytes", "packets", "samples", "avg_bytes", "var_bytes",
            "avg_packets", "var_packets", "first_seen", "last_seen", "note"])
    except Exception as exc:  # noqa: BLE001 - the seed already landed; say so
        print(f"  normalized traffic: could not write: {exc}")
        return 0
    return len(rows)


def _seed_demo_login() -> str:
    """Create the published demo admin, or say why it could not be created.

    THE CREDENTIAL IS PART OF THE DEMO, so it is seeded like the data is. It goes to the file
    store when WEIRVERN_USERS_FILE names one (a laptop console) and to the cluster ConfigMap
    otherwise (the deployed console). A failure does NOT fail the seed: the data is already
    written, and a demo without a login still opens its reads.
    """
    from weirvern.admin import users as users_mod  # noqa: PLC0415

    try:
        path = os.environ.get("WEIRVERN_USERS_FILE", "").strip()
        if path:
            store = users_mod.UserStore(users_mod.FileUserClient(path))
        else:
            from weirvern.admin.cluster_config import ClusterConfig  # noqa: PLC0415

            store = users_mod.UserStore(ClusterConfig(configmap=users_mod.USERS_CONFIGMAP))
        store.load()
        return users_mod.ensure_demo_admin(store)
    except Exception as exc:  # noqa: BLE001 - the seed already landed; a login is the bonus
        return f"not created ({exc}); set WEIRVERN_USERS_FILE on the console and re-run"


def _seed_models(client, *, now: Any = None) -> dict:
    """Seed the Models tab: training history and calibration, without training anything.

    THE TAB READS ml_models AND ml_calibration. With the ML off in demo mode those two tables are
    empty, and a Models view that says "never trained" on a deployment showing findings contradicts
    itself. The rows say demo-seed in reference_source so nobody mistakes them for a real fit.
    """
    from uuid import uuid4  # noqa: PLC0415

    now = now or utcnow()
    names = ["Isolation Forest", "Gradient Boosting", "KNN distance", "LOF", "Adaptive Baseline"]
    model_rows = [[
        uuid4().hex, name, now - timedelta(hours=6), 180,
        ["conn_volume", "flow_bytes", "unique_dst_ips"], "{}", '{"samples": 1440}',
        now - timedelta(days=7), now, 1440, 0.2,
    ] for name in names]
    client.insert("weirvern.ml_models", model_rows, column_names=[
        "model_id", "model_type", "trained_at", "training_duration_seconds",
        "feature_columns", "model_params", "metrics", "training_window_start",
        "training_window_end", "training_sample_count", "current_weight",
    ])
    cal_rows = [[
        name, "segment", "10.10.0.0/24", "score", 0.01, 0.85,
        0.40, 0.70, 0.90, 1440, 288, 0.01, "demo-seed", "demo-6", now,
        1.0, 0, 1440, 1440, "seeded demo calibration", "", 0.008, 0.012,
    ] for name in names]
    client.insert("weirvern.ml_calibration", cal_rows, column_names=[
        "model_name", "scope", "subject", "statistic", "target_far", "threshold",
        "p50", "p95", "p99", "sample_count", "validation_count", "observed_far",
        "reference_source", "model_version", "computed_at", "coverage",
        "excluded_windows", "coverage_observed", "coverage_expected", "coverage_detail",
        "missing_mode", "far_lower", "far_upper",
    ])
    return {"models": len(model_rows), "calibration": len(cal_rows)}


def _seed_ml_results(client, *, hosts: int = 22, seed: int = 1337, hours: int = 6) -> dict:
    """Write the ML and ripple RESULTS instead of running either.

    DEMO MODE TURNS THE ML OFF (Samuel, 2026-11-23). Training and sweeping over the seeded window
    produced hundreds of findings and a slow seed, when the demo needs a deployment that already
    decided what happened. So this writes the findings the console should show: a handful on the
    two incident hosts, and the evidence behind two ripples. The live worker skips detection in
    demo mode for the same reason; see worker.py.
    """
    segment = _hosts(random.Random(seed), hosts)
    rippled, broad = segment[2], segment[3]
    now = utcnow()
    anomalies: list[list[Any]] = []
    for host in (rippled, broad):
        for i in range(6):
            end = now - timedelta(hours=i)
            start = end - timedelta(minutes=5)
            score = 0.92 - i * 0.01
            anomalies.append([
                now, start, end, host, score, min(0.99, score + 0.02),
                score, min(0.99, score + 0.05), 0.0, 0.60, 0.80,
                "conn_volume" if host == broad else "flow_bytes",
                4.2, 4.2, "{}", "{}", "Isolation Forest,Gradient Boosting",
                "high", "[]", "", 2, "fused score", "internal",
            ])
    client.insert("weirvern.netflow_anomalies", anomalies, column_names=[
        "detected_at", "window_start", "window_end", "src_addr", "anomaly_score",
        "confidence", "isolation_forest_score", "gradient_boosting_score", "dbscan_score",
        "baseline_score", "model_agreement", "primary_deviation_feature",
        "primary_deviation_zscore", "deviation_magnitude", "feature_contributions",
        "baseline_comparison", "detected_by_models", "severity", "attack_techniques",
        "attack_label", "strong_families", "severity_basis", "network_scope",
    ])
    # TWO RIPPLES, EACH CORROBORATED BY THREE FAMILIES. The evidence table is what the Ripples card
    # groups; the values are deliberately past the bar (p=0.0004 against 144 baseline windows) so
    # the grouping reads as two incidents rather than a wall of findings.
    channels = {
        rippled: [("flow_bytes", "flow", 2_400_000.0, 1_140_000.0),
                  ("conn_volume", "conn", 476.0, 36.0),
                  ("dns_volume", "dns", 16.0, 7.0)],
        broad: [("http_host_diversity", "http", 423.0, 3.0),
                ("flow_bytes", "flow", 1_900_000.0, 900_000.0),
                ("conn_volume", "conn", 310.0, 25.0)],
    }
    evidence: list[list[Any]] = []
    for host, rows in channels.items():
        for channel, family, value, base in rows:
            evidence.append([
                now - timedelta(hours=1), now, host, channel, family, "1h", value, base,
                0.0004, "empirical", "ranks n=144", 144, 0.9, "above",
                "ripple-evidence-6", now, now,
            ])
    client.insert("weirvern.ml_ripple_evidence", evidence, column_names=[
        "window_start", "window_end", "src_addr", "channel", "family", "scale", "value",
        "baseline_median", "p_value", "p_method", "p_detail", "sample_count", "coverage",
        "direction", "model_version", "observed_at", "computed_at",
    ])
    return {"anomalies": len(anomalies), "ripples": len(channels), "evidence": len(evidence),
            "models": _seed_models(client, now=now)}


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

    if args.clear_demo:
        from weirvern import db, demo_state  # noqa: PLC0415
        from weirvern.config import get_settings  # noqa: PLC0415

        with db.connect(get_settings()) as client:
            demo_state.disable(client)
        print("demo mode retired: the banner is gone and the live feed checks are back. "
              "The seeded rows are still there, so delete them before treating this as live.")
        return 0

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
        _report_scope(client, declare=args.scope or not args.traffic_only)
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
        if not args.traffic_only:
            # THE TWO TABS TRAFFIC CANNOT REACH. The Weirlings view needs a registered sensor and
            # a heartbeat; the Assets view needs a registry, services and a scan. Both are seeded
            # with demo markers rather than left empty, which would read as "the product has no
            # fleet and no inventory".
            from weirvern import demo_extras  # noqa: PLC0415

            fleet = demo_extras.seed_fleet(client, hosts=args.hosts)
            print(f"  fleet:    {fleet}")
            assets = demo_extras.seed_assets(client, hosts=args.hosts)
            print(f"  assets:   {assets}")
        if not args.no_enforcement:
            normalized = _seed_normalization(client, hosts=args.hosts, seed=args.seed)
            if normalized:
                print(f"  normalized: {normalized['channel']} on {normalized['host']}, "
                      f"expected until {normalized['review_after']}")
            normal_rows = _seed_normal_traffic(client, hosts=args.hosts, seed=args.seed)
            print(f"  normalized traffic: {normal_rows} expected flow pattern(s); the four "
                  "incident hosts are deliberately left un-normalized")
        login_state = _seed_demo_login()
        print(f"  login:    weirvern / demo ({login_state}); demo only, not a real credential")
        if not args.no_evidence:
            _run_evidence(client, hours=args.hours)
        if not args.traffic_only:
            # DEMO MODE IS A FACT ABOUT THE DATA, so it is written by the thing that wrote the
            # data, before anything reads it. The GUI banner and the health checks both take it
            # from this row rather than from an environment variable a restart could lose.
            from weirvern import demo_state  # noqa: PLC0415

            demo_state.enable(
                client, seed=args.seed, hosts=args.hosts,
                note=f"seeded by `weirvern demo-seed --hours {args.hours}`",
            )
            print(f"  demo:     marked this deployment as seeded data ({args.hosts} hosts, "
                  f"seed {args.seed})")
        if not args.traffic_only and not args.no_ml:
            seeded = _seed_ml_results(client, hosts=args.hosts, seed=args.seed,
                                      hours=args.ml_hours)
            print(f"  ml:       seeded results, no training: {seeded['anomalies']} anomalies, "
                  f"{seeded['ripples']} ripples ({seeded['evidence']} evidence rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
