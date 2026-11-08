"""Asset inventory and connection-graph queries behind the Hosts and Network views.

WHY A THIRD MODULE. `status.py` answers "what is the current state" (heartbeat, health, the
dashboard panels). `soc.py` answers "what SHAPE is the traffic" (volume, protocol mix, per-log
counts). These answer "WHICH HOSTS exist and HOW ARE THEY CONNECTED", which is a different
question again and needs different tables: the per-host view is built from the aggregate plus
every Zeek protocol log, and the graph view needs per-EDGE facts (src -> dst), which only the
raw `flows` table holds.

THE TWO VIEWS SHARE ONE HONESTY RULE, and it is the rule this codebase keeps having to relearn:
an endpoint that could not be read is NOT an endpoint with nothing on it. Every helper returns
`{"available": bool, "reason": str, ...}` and NAMES the sources it could not read, so the panel
can say "three Zeek logs were unreadable" instead of drawing a host with no activity. A host
list that silently omits the logs it failed to query is worse than no list, because an analyst
reads absence as evidence.

HOSTNAMES ARE RESOLVED AT THE READ LAYER and always carried ALONGSIDE the address, never
instead of it. The user's standing instruction is explicit: keep the source IP too. A name is a
convenience and it can be wrong, change, or be shared by several addresses; the address is the
fact. `resolve_names` therefore returns a mapping and every payload includes both.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from weirvern import addressing, networks
from weirvern.admin import revdns, timewindow

logger = logging.getLogger(__name__)

# The Zeek tables that carry an observed HOST identity, and which column holds the address.
# Listed here rather than derived so the set is auditable; every entry is a table the ingester
# actually writes (checked by scripts/audit_schema.py).
_ZEEK_HOST_TABLES: list[tuple[str, str]] = [
    ("zeek_conn", "src_addr"),
    ("zeek_dns", "src_addr"),
    ("zeek_ssl", "src_addr"),
    ("zeek_http", "src_addr"),
    ("zeek_ssh", "src_addr"),
    ("zeek_notice", "src_addr"),
    ("zeek_weird", "src_addr"),
    ("zeek_kerberos", "src_addr"),
    ("zeek_ntlm", "src_addr"),
    ("zeek_dce_rpc", "src_addr"),
    ("zeek_smb_files", "src_addr"),
    ("zeek_smb_mapping", "src_addr"),
    ("zeek_dhcp", "client_addr"),   # keys its peers as client_addr/server_addr, NOT src_addr
    ("zeek_ldap_search", "src_addr"),
    ("zeek_quic", "src_addr"),
    ("zeek_tunnel", "src_addr"),
]


def _unavailable(reason: str, **extra) -> dict:
    """The shape every helper returns when it cannot answer.

    Not an empty list: a caller must be able to tell "no data" from "the query failed".
    """
    return {"available": False, "reason": reason, **extra}


def _rows(client, sql: str, params: dict, what: str) -> list | None:
    """Run a query, returning None (and logging which one) if it fails.

    A failed source must be reportable, so callers collect None and name it rather than
    treating it as an empty result.
    """
    try:
        return client.query(sql, parameters=params).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("%s failed: %s", what, exc)
        return None


def _has_curated_service_port(ports: list[int]) -> bool:
    """A port named in the shared curated service table (not merely a low-numbered port)."""
    from weirvern.admin import soc  # noqa: PLC0415

    return any(int(p) in soc._SERVICE_PORTS for p in ports if p)


def _port_shape(ports: list[int], src_ports: list[int]) -> tuple[str, str]:
    """The role a port pair suggests, and the evidence name for it.

    FIRST the shared service table. When neither side is a known service, fall back to the
    client-port convention: the side whose destination ports are all above 32768 is the side
    receiving an ephemeral reply, and the side whose source ports are all above it is the
    client. 32768 is the usual Linux client start, not the IANA dynamic boundary (49152); the
    fallback is named `ephemeral-shape` and is never presented as proven. This is what keeps a
    registered service such as NNTP on 5563 or Bitcoin on 8333 from becoming 'unknown' merely
    because it is not in the curated list.
    """
    # A CURATED SERVICE OUTRANKS THE BROAD LOW-PORT RANGE. A client's ephemeral 978 beside
    # an NFS 2049 must not read as "two services"; 2049 is the fact, 978 is the client.
    dst_curated = _has_curated_service_port(ports)
    src_curated = _has_curated_service_port(src_ports)
    if dst_curated and not src_curated:
        return "request", "service-port"
    if src_curated and not dst_curated:
        return "reply", "service-port"
    dst_service = _has_service_port(ports)
    src_service = _has_service_port(src_ports)
    if dst_service and not src_service:
        return "request", "service-port"
    if src_service and not dst_service:
        return "reply", "service-port"
    if ports and src_ports:
        if all(p >= 32768 for p in ports) and all(p < 32768 for p in src_ports):
            return "reply", "ephemeral-shape"
        if all(p < 32768 for p in ports) and all(p >= 32768 for p in src_ports):
            return "request", "ephemeral-shape"
    return "", ""


def _has_service_port(ports: list[int]) -> bool:
    """Whether any port in this side names a service, using the SOC's one shared table.

    The Network graph used to treat every port below 32768 as a service, which is not what
    IANA says and not what the Flows tab uses: 32768-49151 are USER ports, and a peer-to-peer
    source port in that range was therefore misread as a service. The Flows/Discover ladder
    already owns the narrow definition (`soc._is_service_port`: system ports plus a curated
    list), so the graph now calls that definition instead of keeping a second one.
    """
    from weirvern.admin import soc  # noqa: PLC0415 -- avoids an import cycle at module load

    return any(soc._is_service_port(int(p)) for p in ports if p)


def _merge_direction_pairs(raw_edges: list[dict]) -> list[dict]:
    """One connection from its two halves, with the initiator first.

    A flow record is unidirectional. The graph used to group only by host pair and then call
    EVERY port below 32768 a service, so a reply half could become the source of an edge and
    several services between the same two hosts collapsed into one misleading port list.
    This pass keeps the raw 5-tuple (the query aggregates it) and applies the same evidence
    ladder the Flows tab uses where the aggregate can support it:

      * a service port on the destination side and none on the source side -> request
      * a service port on the source side and none on the destination side -> reply
      * neither shape -> no claimed direction; the observed source stays the source

    A one-sided reply is re-ORIENTED client -> server. That is the fact the ports prove and
    the reason an external server no longer appears to have dialled the local host.
    """
    by_key: dict[tuple, dict] = {}
    order: list[tuple] = []
    for e in raw_edges:
        key = (str(e.get("source")), int(e.get("src_port") or 0),
               str(e.get("target")), int(e.get("dst_port") or 0),
               int(e.get("proto") or 0))
        by_key[key] = e
        order.append(key)

    def _single(e: dict, role: str, evidence: str) -> dict:
        out = dict(e)
        ports = list(e.get("ports") or [])
        src_ports = list(e.get("src_ports") or [])
        b, f = int(e["bytes"]), int(e["flows"])
        if role == "request":
            out.update({
                "ports": ports, "source_ports": src_ports,
                "bytes_source": b, "bytes_target": 0,
                "flows_source": f, "flows_target": 0,
                "source_ttl_min": e.get("ttl_min", 0),
                "source_ttl_max": e.get("ttl_max", 0),
                "target_ttl_min": 0, "target_ttl_max": 0,
                "reply_seen": False,
                "direction": "seen in one direction only; this side dialled a service port, "
                             "so the reply was not captured",
                "direction_evidence": evidence,
                "direction_confidence": "inferred" if evidence == "service-port" else "unknown",
            })
        elif role == "reply":
            # The observed source ANSWERED. The client is the observed destination, so the
            # edge's source is the destination and the service port is the observed source's
            # port. Bytes were sent by the server (target), not the client (source).
            out.update({
                "source": e["target"], "target": e["source"],
                "ports": src_ports, "source_ports": ports,
                "bytes_source": 0, "bytes_target": b,
                "flows_source": 0, "flows_target": f,
                "source_ttl_min": 0, "source_ttl_max": 0,
                "target_ttl_min": e.get("ttl_min", 0),
                "target_ttl_max": e.get("ttl_max", 0),
                "reply_seen": False,
                "direction": "seen in one direction only; the request was not captured — this "
                             "is the reply half, oriented client → server",
                "direction_evidence": evidence,
                "direction_confidence": "inferred" if evidence == "service-port" else "unknown",
            })
        else:
            out.update({
                "ports": ports, "source_ports": src_ports,
                "bytes_source": b, "bytes_target": 0,
                "flows_source": f, "flows_target": 0,
                "source_ttl_min": e.get("ttl_min", 0),
                "source_ttl_max": e.get("ttl_max", 0),
                "target_ttl_min": 0, "target_ttl_max": 0,
                "reply_seen": False,
                "direction": "seen in one direction only; direction not claimed",
                "direction_evidence": "",
                "direction_confidence": "unknown",
            })
        return out

    merged: list[dict] = []
    consumed: set[tuple] = set()
    for key in order:
        if key in consumed:
            continue
        e = by_key[key]
        rev_key = (key[2], key[3], key[0], key[1], key[4])
        rev = by_key.get(rev_key)
        e_ports = list(e.get("ports") or [])
        e_src_ports = list(e.get("src_ports") or [])
        e_role, e_evidence = _port_shape(e_ports, e_src_ports)
        req: dict | None = None
        rep: dict | None = None
        if rev is not None and rev_key not in consumed:
            r_ports = list(rev.get("ports") or [])
            r_src_ports = list(rev.get("src_ports") or [])
            r_role, r_evidence = _port_shape(r_ports, r_src_ports)
            if e_role == "request" and r_role == "reply":
                req, rep = e, rev
                consumed.add(rev_key)
            elif e_role == "reply" and r_role == "request":
                req, rep = rev, e
                consumed.add(rev_key)
            if req is not None and rep is not None:
                consumed.add(key)
                merged.append({
                    "source": req["source"], "target": req["target"],
                    "proto": int(req.get("proto") or 0),
                    "ports": list(req.get("ports") or []),
                    "source_ports": list(rep.get("ports") or []),
                    "_source_port_total": max(1, len(rep.get("ports") or [])),
                    "bytes": int(req["bytes"]) + int(rep["bytes"]),
                    "flows": int(req["flows"]) + int(rep["flows"]),
                    "bytes_source": int(req["bytes"]), "bytes_target": int(rep["bytes"]),
                    "flows_source": int(req["flows"]), "flows_target": int(rep["flows"]),
                    "first_seen": min(req["first_seen"], rep["first_seen"]),
                    "last_seen": max(req["last_seen"], rep["last_seen"]),
                    "source_ttl_min": req.get("ttl_min", 0),
                    "source_ttl_max": req.get("ttl_max", 0),
                    "target_ttl_min": rep.get("ttl_min", 0),
                    "target_ttl_max": rep.get("ttl_max", 0),
                    "ttl_min": req.get("ttl_min", 0), "ttl_max": req.get("ttl_max", 0),
                    "direction": "request/reply",
                    "direction_evidence": f"{e_evidence or r_evidence} request + reply",
                    "direction_confidence": "inferred",
                    "reply_seen": True,
                })
                continue
        consumed.add(key)
        merged.append(_single(e, e_role, e_evidence if e_role else ""))
    return merged

def _coalesce_service_edges(edges: list[dict]) -> list[dict]:
    """Fold the individual client connections of one service into one graph edge.

    The 5-tuple is what makes direction provable, but drawing one line per source port turns a
    normal browser or Usenet client into hundreds of identical edges. Direction is decided on
    the 5-tuple first (above); only edges that already point the same way are folded here.
    Unknown edges are not folded across a reverse direction: their source is an observation,
    not a role.
    """
    groups: dict[tuple, dict] = {}
    order: list[tuple] = []
    for e in edges:
        known = bool(e.get("direction_evidence"))
        key = (e["source"], e["target"], tuple(e.get("ports") or []),
               int(e.get("proto") or 0), "known" if known else "unknown")
        if key not in groups:
            groups[key] = dict(e)
            order.append(key)
            continue
        g = groups[key]
        g["bytes"] = int(g.get("bytes") or 0) + int(e.get("bytes") or 0)
        g["flows"] = int(g.get("flows") or 0) + int(e.get("flows") or 0)
        g["bytes_source"] = int(g.get("bytes_source") or 0) + int(e.get("bytes_source") or 0)
        g["bytes_target"] = int(g.get("bytes_target") or 0) + int(e.get("bytes_target") or 0)
        g["flows_source"] = int(g.get("flows_source") or 0) + int(e.get("flows_source") or 0)
        g["flows_target"] = int(g.get("flows_target") or 0) + int(e.get("flows_target") or 0)
        g["reply_seen"] = bool(g.get("reply_seen")) or bool(e.get("reply_seen"))
        if e.get("first_seen") and (not g.get("first_seen") or e["first_seen"] < g["first_seen"]):
            g["first_seen"] = e["first_seen"]
        if e.get("last_seen") and (not g.get("last_seen") or e["last_seen"] > g["last_seen"]):
            g["last_seen"] = e["last_seen"]
        ports = set(g.get("source_ports") or []) | set(e.get("source_ports") or [])
        g["source_ports"] = sorted(ports)[:20]
        g["_source_port_total"] = int(g.get("_source_port_total") or 0) + max(
            1, len(e.get("source_ports") or []))
        # The direction wording is the strongest common claim: a reply in the group makes it
        # request/reply; otherwise keep the one-sided label it already carried.
        if g["reply_seen"]:
            g["direction"] = "request/reply"
            g["direction_evidence"] = "port shape; multiple client connections folded"
        g["source_ttl_max"] = max(int(g.get("source_ttl_max") or 0),
                                  int(e.get("source_ttl_max") or 0))
        g["target_ttl_max"] = max(int(g.get("target_ttl_max") or 0),
                                  int(e.get("target_ttl_max") or 0))
        g["source_ttl_min"] = min(x for x in (int(g.get("source_ttl_min") or 0),
                                              int(e.get("source_ttl_min") or 0)) if x > 0) \
            if any(x > 0 for x in (int(g.get("source_ttl_min") or 0),
                                   int(e.get("source_ttl_min") or 0))) else 0
        g["target_ttl_min"] = min(x for x in (int(g.get("target_ttl_min") or 0),
                                              int(e.get("target_ttl_min") or 0)) if x > 0) \
            if any(x > 0 for x in (int(g.get("target_ttl_min") or 0),
                                   int(e.get("target_ttl_min") or 0))) else 0
    return [groups[k] for k in order]


def _as_ports(value) -> list[int]:
    """A ClickHouse array of ports as a list of ints, tolerant of how the driver returns it.

    `topK(5)(dst_port)` comes back as a real `Array(UInt16)` through clickhouse-connect, but a
    text-protocol client hands back the string form `[443,80]`. Both reach this function in
    practice -- the shipped client and the probes used to verify it -- and `int("[443,80]")`
    raises ValueError, which took the whole connection graph down.

    Anything unparseable is dropped rather than raised on: a port list is decoration on an edge,
    and a malformed one must not cost the analyst the graph.
    """
    if value is None:
        return []
    if isinstance(value, str):
        value = value.strip().strip("[]")
        parts = [p.strip() for p in value.split(",") if p.strip()]
    elif isinstance(value, (list, tuple, set)):
        parts = list(value)
    else:
        parts = [value]
    out: list[int] = []
    for item in parts:
        try:
            out.append(int(item))
        except (TypeError, ValueError):
            continue
    return out


def _hops_from_ttl(ttl: int) -> int:
    """The hop distance one observed IP TTL implies.

    A sender stamps an initial TTL (64, 128 and 255 cover virtually everything), and every
    router on the path decrements it once -- so the largest common initial value at-or-above
    the observation, minus the observation, is the hop count: 64 -> 0 (same segment as the
    collector), 63 -> 1, 61 -> 3, 128 -> 0. Clamped at 8: a smaller reading than that is far
    more likely a mid-path or spoofed value than a real path, and it must not fling a node
    off the map. TTL 0 is NOT MEASURED (many exporter templates do not carry the field) and
    callers must skip it -- treating it as \"distance zero\" would drop every unmeasured host
    onto the sensor's own ring.
    """
    for initial in (64, 128, 255):
        if ttl <= initial:
            return min(initial - ttl, 8)
    return 8




# ── SCANNED EXPOSURE ────────────────────────────────────────────────────────────────────────
# The inventory's Scan column says whether Nmap ran; this layer says what it FOUND. They are
# deliberately separate states: "not scanned" is not "clear", and a scan that failed is not a
# host with no findings. The scanner is optional, so a missing table degrades the annotation
# without taking the passive inventory down with it.

_SCAN_BANDS = ("critical", "high", "medium", "low")
_SCAN_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}


def _scan_band(state: str, counts: dict | None) -> str:
    """The one word the inventory can honestly print for a host's scan state.

    NOT SCANNED and CLEAR are different answers. A done scan with no recorded finding is
    `clear`; a host with no registry row, a pending row, or an in-flight scan is not. A failed
    scan is `failed`, never `clear`. `unknown` means the findings source could not be read.
    """
    state = str(state or "").lower()
    if state == "error":
        return "failed"
    if state == "unknown":
        return "unknown"
    if state in ("pending", "queued", "scanning"):
        return "not scanned"
    if state != "done":
        return "not scanned"
    if counts is None:
        return "unknown"
    for band in _SCAN_BANDS:
        if int(counts.get(band, 0) or 0) > 0:
            return band
    if int(counts.get("info", 0) or 0) > 0:
        return "low"
    return "clear"


def _scan_ts(value: Any) -> str:
    """An unset ClickHouse DateTime is epoch zero; do not render it as a real scan time."""
    text = _iso(value)
    return "" if not text or text.startswith("1970-01-01") else text


def _scan_summaries(client: Any) -> tuple[dict[str, dict], list[str], dict[str, bool]]:
    """One bulk read of the scanner's three small tables, keyed by host address.

    Three grouped queries, not one per asset: the inventory renders up to 200 hosts, and a
    per-host Nmap read would put a second slow query behind every row. The caller keeps the
    three readable flags so a missing/optional table is named instead of becoming a zero.
    """
    registry = _rows(
        client,
        "SELECT ip, asset_key, hostname, scan_state, last_scan_at, scan_error "
        "FROM weirvern.asset_registry FINAL",
        {},
        "asset inventory (scan registry)",
    )
    services = _rows(
        client,
        "SELECT ip, count() AS services FROM weirvern.asset_services FINAL GROUP BY ip",
        {},
        "asset inventory (scan services)",
    )
    findings = _rows(
        client,
        "SELECT ip, countIf(lower(severity) = 'critical') AS critical, "
        "       countIf(lower(severity) = 'high') AS high, "
        "       countIf(lower(severity) = 'medium') AS medium, "
        "       countIf(lower(severity) = 'low') AS low, "
        "       countIf(lower(severity) = 'info') AS info, count() AS total "
        "FROM weirvern.asset_findings FINAL GROUP BY ip",
        {},
        "asset inventory (scan findings)",
    )
    readable = {"registry": registry is not None, "services": services is not None,
                "findings": findings is not None}
    failed = [name for name, ok in readable.items() if not ok]
    out: dict[str, dict] = {}
    for r in registry or []:
        ip = str(r[0] or "")
        if not ip:
            continue
        out[ip] = {
            "state": str(r[3] or "pending"),
            "last_scan": _scan_ts(r[4]),
            "error": str(r[5] or ""),
            "services": None,
            "findings": None,
        }
    for r in services or []:
        ip = str(r[0] or "")
        if ip in out:
            out[ip]["services"] = int(r[1] or 0)
    for r in findings or []:
        ip = str(r[0] or "")
        if ip not in out:
            continue
        counts = {"critical": int(r[1] or 0), "high": int(r[2] or 0),
                  "medium": int(r[3] or 0), "low": int(r[4] or 0),
                  "info": int(r[5] or 0), "total": int(r[6] or 0)}
        out[ip]["findings"] = counts
    # A readable findings table with no row for a scanned host means ZERO findings, not an
    # unknown read. Only a failed table leaves `None`, which stays `unknown` in the band.
    if findings is not None:
        for entry in out.values():
            if entry["findings"] is None:
                entry["findings"] = {"critical": 0, "high": 0, "medium": 0,
                                     "low": 0, "info": 0, "total": 0}
    for entry in out.values():
        entry["exposure"] = _scan_band(entry["state"], entry["findings"])
    return out, failed, readable


def _attach_scan_summaries(hosts: dict[str, dict], summaries: dict[str, dict],
                           readable: dict[str, bool]) -> None:
    """Attach a compact, honest scan object to each inventory row."""
    for addr, host in hosts.items():
        entry = summaries.get(addr)
        if entry is None:
            # No registry row means the scanner has not adopted this host. If the registry
            # itself failed, the state is unknown rather than a claim of "not scanned".
            state = "not_scanned" if readable["registry"] else "unknown"
            host["scan"] = {
                "state": state, "exposure": _scan_band(state, None),
                "last_scan": "", "error": "",
                "services": None, "findings": None, "available": readable["registry"],
            }
            continue
        host["scan"] = {
            **entry,
            "available": readable["registry"] or readable["services"] or readable["findings"],
        }


def asset_exposure(client: Any, addr: str) -> dict:
    """The host page's scanner card: state, services and recorded findings for ONE address.

    `available=False` is a broken source, not a clean host. An address with no registry row is
    `registered=False` + state `not_scanned`; that is a real answer and must remain distinct
    from a failed read. Findings are evidence, not proof of exploitability.
    """
    registry = _rows(
        client,
        "SELECT ip, asset_key, hostname, scan_state, last_scan_at, scan_error "
        "FROM weirvern.asset_registry FINAL WHERE ip = %(ip)s LIMIT 1",
        {"ip": addr},
        "host exposure (registry)",
    )
    services = _rows(
        client,
        "SELECT port, protocol, service, product, version, cpe, observed_at "
        "FROM weirvern.asset_services FINAL WHERE ip = %(ip)s ORDER BY port",
        {"ip": addr},
        "host exposure (services)",
    )
    findings = _rows(
        client,
        "SELECT severity, name, template_id, cve, last_seen, remediation "
        "FROM weirvern.asset_findings FINAL WHERE ip = %(ip)s ORDER BY last_seen DESC",
        {"ip": addr},
        "host exposure (findings)",
    )
    errors = []
    if registry is None:
        errors.append("registry")
    if services is None:
        errors.append("services")
    if findings is None:
        errors.append("findings")
    if registry is None:
        return _unavailable("the scanner registry could not be read",
                            registered=False, state="unknown", exposure="unknown",
                            errors=errors, services=[], findings=[], counts={})
    if not registry:
        return {
            "available": services is not None and findings is not None,
            "reason": "", "registered": False, "state": "not_scanned",
            "exposure": "not scanned", "last_scan": "", "error": "",
            "errors": errors,
            "services": [{"port": int(r[0] or 0), "protocol": str(r[1] or ""),
                          "service": str(r[2] or ""), "product": str(r[3] or ""),
                          "version": str(r[4] or ""), "cpe": str(r[5] or ""),
                          "observed_at": _scan_ts(r[6])}
                         for r in services or []],
            "findings": [], "counts": {},
        }
    r = registry[0]
    counts = None
    if findings is not None:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        for f in findings:
            sev = str(f[0] or "unknown").lower()
            if sev in counts:
                counts[sev] += 1
            counts["total"] += 1
    state = str(r[3] or "pending")
    return {
        "available": services is not None and findings is not None,
        "reason": "" if not errors else f"could not read the scanner {', '.join(errors)} table(s)",
        "registered": True, "state": state,
        "exposure": _scan_band(state, counts),
        "last_scan": _scan_ts(r[4]), "error": str(r[5] or ""),
        "errors": errors,
        "services": [{"port": int(x[0] or 0), "protocol": str(x[1] or ""),
                      "service": str(x[2] or ""), "product": str(x[3] or ""),
                      "version": str(x[4] or ""), "cpe": str(x[5] or ""),
                      "observed_at": _scan_ts(x[6])}
                     for x in services or []],
        "findings": [{"severity": str(x[0] or "unknown"), "name": str(x[1] or ""),
                      "template_id": str(x[2] or ""), "cve": str(x[3] or ""),
                      "last_seen": _scan_ts(x[4]), "remediation": str(x[5] or "")}
                     for x in findings or []],
        "counts": counts or {},
    }

def asset_inventory(client, hours: int = 24, limit: int = 200) -> dict:
    """Every host we have seen, with a per-host summary, for the asset inventory view.

    BUILT FROM THREE SOURCES AND HONEST ABOUT EACH:

      * `flows_aggregated` -- bytes, flows, distinct destinations, and first/last seen.
      * the raw `flows` table -- outbound vs inbound byte split, which the aggregate cannot
        give because it stores per-window volume per SOURCE only.
      * every Zeek host table -- which protocols each host actually spoke, so the inventory
        lists "http, ssl, dns" and not just a byte count.

    A host seen only in Zeek (a DHCP lease, a notice) still appears: the inventory is meant to
    be the list of things that exist on the wire, not the list of things that moved bytes.

    `hours` bounds the TRAFFIC columns only. A host whose last packet was three days ago is
    still an asset, so it appears with zeroed counters rather than being dropped -- and the
    payload says how many such hosts there are, so the panel can explain the zeros.
    """
    hosts: dict[str, dict] = {}

    def _h(addr: str) -> dict:
        return hosts.setdefault(addr, {
            "addr": addr, "name": "", "bytes": 0, "flows": 0, "dst_count": 0,
            "first_seen": "", "last_seen": "", "services": [], "anomalies": 0,
            "role": "unknown", "scope": "external" if not revdns.is_private(addr) else "monitored",
        })

    # ---- 1. Volume and windowed activity from the aggregate.
    agg = _rows(
        client,
        "SELECT src_addr, sum(total_bytes) AS bytes, sum(flow_count) AS flows, "
        "       max(unique_dst_ips) AS dsts, min(window_start) AS first, max(window_end) AS last "
        "FROM weirvern.flows_aggregated "
        "WHERE window_start >= %(since)s AND window_start <= %(until)s "
        "GROUP BY src_addr ORDER BY bytes DESC LIMIT %(n)s",
        {**timewindow.w(hours), "n": limit},
        "asset inventory (aggregate)",
    )
    read_ok = {"aggregate": agg is not None}

    for r in agg or []:
        h = _h(str(r[0]))
        h["bytes"] = int(r[1] or 0)
        h["flows"] = int(r[2] or 0)
        h["dst_count"] = int(r[3] or 0)
        h["first_seen"] = r[4].isoformat() if hasattr(r[4], "isoformat") else str(r[4] or "")
        h["last_seen"] = r[5].isoformat() if hasattr(r[5], "isoformat") else str(r[5] or "")

    # ---- 2. Direction split from the RAW flows table. The aggregate has no dst_addr, so an
    #         inbound/outbound split is impossible without this. Recorded honestly if it fails.
    direction = _rows(
        client,
        "SELECT addr, sum(outbound) AS out_b, sum(inbound) AS in_b FROM ("
        "  SELECT src_addr AS addr, bytes AS outbound, 0 AS inbound FROM weirvern.flows "
        "  WHERE timestamp >= %(since)s AND timestamp <= %(until)s "
        "  UNION ALL "
        "  SELECT dst_addr AS addr, 0 AS outbound, bytes AS inbound FROM weirvern.flows "
        "  WHERE timestamp >= %(since)s AND timestamp <= %(until)s "
        ") GROUP BY addr ORDER BY out_b DESC LIMIT %(n)s",
        {**timewindow.w(hours), "n": limit},
        "asset inventory (direction split)",
    )
    read_ok["direction"] = direction is not None
    for r in direction or []:
        h = _h(str(r[0]))
        h["bytes_out"] = int(r[1] or 0)
        h["bytes_in"] = int(r[2] or 0)

    # ---- 3. Which protocols each host spoke, from every Zeek host table.
    zeek_unreadable: list[str] = []
    for table, addrcol in _ZEEK_HOST_TABLES:
        rows = _rows(
            client,
            # `toString(...)` because zeek_dhcp's address column is IPv4 while the others are
            # String; comparing the raw column against a string literal raises a type error on
            # the IPv4 ones. The '-' sentinel is Zeek's "unset" and is excluded rather than
            # counted as a host, which would create a host literally named "-".
            f"SELECT {addrcol} AS addr, count() AS n FROM weirvern.{table} "  # noqa: S608
            "WHERE ts >= %(since)s AND ts <= %(until)s "
            f"AND toString({addrcol}) != '' AND toString({addrcol}) != '-' "
            "GROUP BY addr ORDER BY n DESC LIMIT %(n)s",
            {**timewindow.w(hours), "n": limit},
            f"asset inventory ({table})",
        )
        if rows is None:
            zeek_unreadable.append(table)
            continue
        # The log name is the service label an analyst recognises (zeek_ssl -> ssl).
        service = table.removeprefix("zeek_")
        for r in rows:
            h = _h(str(r[0]))
            if service not in h["services"]:
                h["services"].append(service)
            h[f"{service}_events"] = int(r[1] or 0)

    # ---- 4. Anomaly counts, so the inventory can be sorted by suspicion as well as volume.
    anom = _rows(
        client,
        "SELECT src_addr, count() AS n FROM weirvern.netflow_anomalies "
        "WHERE detected_at >= %(since)s AND detected_at <= %(until)s "
        "GROUP BY src_addr ORDER BY n DESC LIMIT %(n)s",
        {**timewindow.w(hours), "n": limit},
        "asset inventory (anomalies)",
    )
    read_ok["anomalies"] = anom is not None
    for r in anom or []:
        _h(str(r[0]))["anomalies"] = int(r[1] or 0)

    if not hosts:
        missing = [k for k, ok in read_ok.items() if not ok]
        reason = "no host has been seen in this window"
        if missing:
            reason = f"no host could be read; failed sources: {', '.join(missing)}"
        return _unavailable(reason, hosts=[], unreadable=zeek_unreadable)

    # NAMES FOR EVERY ROW. The dict above declares `"name": ""` per host, and nothing ever
    # filled it -- the Assets table has a Name column that rendered blank for every row while
    # the graph view, which does call resolve_names, showed names fine. One resolver, one
    # policy (revdns), applied to the field that exists for it. A failure to resolve is ""
    # (the column then shows the address alone), never an error: a name is a display
    # convenience and must not cost the panel.
    try:
        names = resolve_names(client, [h["addr"] for h in hosts.values()])
    except Exception:  # noqa: BLE001
        names = {}
    for addr, entry in hosts.items():
        entry["name"] = names.get(addr, "")

    # ---- 5. Role/scope proposals (031). The table is a proposal store; an absent row is
    #         `unknown`, never a default workstation. A failed read is named in sources_failed.
    roles = _rows(
        client,
        "SELECT host, role, scope, source, confidence FROM weirvern.host_roles FINAL",
        {},
        "asset inventory (roles)",
    )
    read_ok["roles"] = roles is not None
    for r in roles or []:
        host = str(r[0])
        if host not in hosts:
            continue
        hosts[host]["role"] = str(r[1] or "unknown")
        hosts[host]["scope"] = str(r[2] or "unknown")
        hosts[host]["role_source"] = str(r[3] or "auto")
        hosts[host]["role_confidence"] = float(r[4] or 0)

    # ---- 6. Scanned exposure. A separate grouped read; a missing scanner table degrades
    #         this annotation but never the passive inventory.
    summaries, scan_failed, scan_readable = _scan_summaries(client)
    _attach_scan_summaries(hosts, summaries, scan_readable)

    ordered = sorted(
        hosts.values(),
        key=lambda h: (h["anomalies"], h["bytes"]),
        reverse=True,
    )
    return {
        "available": True,
        "reason": "",
        "hours": hours,
        "count": len(ordered),
        "hosts": ordered,
        "unreadable": zeek_unreadable,
        "scan_available": not scan_failed,
        "scan_sources_failed": scan_failed,
        "sources_read": [k for k, ok in read_ok.items() if ok],
        "sources_failed": [k for k, ok in read_ok.items() if not ok],
    }


def connection_graph(client, hours: int = 24, limit: int = 400) -> dict:
    """Nodes and edges for the Network view's connection graph.

    READS RAW `flows` because the graph needs per-EDGE facts. `flows_aggregated` has no
    dst_addr, so it can say how many destinations a host reached but not WHICH ones -- and a
    graph of "how many" is not a graph.

    SELF-EDGES ARE EXCLUDED (src_addr = dst_addr): broadcast and multicast traffic produces
    them constantly on a LAN and they render as a node loop, which reads as a rendering fault.

    NODES CARRY THEIR DEGREE, because a force layout that does not know how connected a node
    is produces a hairball. The degree is computed here and shipped, so the layout in the
    browser is drawing a measured quantity rather than guessing.

    `truncated` IS REPORTED. The limit is a hard cap on edges; without saying so, a busy
    segment would silently lose hosts and the graph would look complete while being partial.

    EDGES CARRY THEIR TTL RANGE, and nodes carry the `hops` distance derived from it -- when
    the exporter's records carry the field at all. 0 means NOT MEASURED and `hops` is ABSENT
    rather than zero, because "no reading" and "right here" are different facts.
    """
    # THE UNIT IS A CONVERSATION, NOT A HOST PAIR. Grouping only by src/dst mixed every
    # service between two hosts into one port list -- SMB 445 beside a reply on 59837 -- and
    # then asked a port heuristic to decide direction across unrelated conversations. The
    # 5-tuple is the flow's own identity; keep it through the aggregate and merge only the
    # exact reverse tuple.
    scan = max(int(limit) * 4, 1200)
    edges = _rows(
        client,
        "SELECT src_addr, dst_addr, src_port, dst_port, proto, "
        "       sum(bytes) AS bytes, count() AS flows, "
        "       min(timestamp) AS first_seen, max(timestamp) AS last_seen, "
        "       minIf(ip_ttl, ip_ttl > 0) AS ttl_min, maxIf(ip_ttl, ip_ttl > 0) AS ttl_max "
        "FROM weirvern.flows "
        "WHERE timestamp >= %(since)s AND timestamp <= %(until)s "
        "  AND src_addr != '' AND dst_addr != '' "
        "  AND src_addr != dst_addr "
        "  AND " + addressing.sql_host("src_addr") + " "
        "  AND " + addressing.sql_host("dst_addr") + " "
        "GROUP BY src_addr, dst_addr, src_port, dst_port, proto "
        "ORDER BY bytes DESC LIMIT %(n)s",
        {**timewindow.w(hours), "n": scan},
        "connection graph",
    )
    if edges is None:
        return _unavailable("the connection query failed (see the worker log for the reason)")

    # A conversation is the unordered port pair; the raw rows are its two directions.
    total_rows = _rows(
        client,
        "SELECT uniqExact(tuple(least(src_addr, dst_addr), greatest(src_addr, dst_addr), "
        "                  least(src_port, dst_port), greatest(src_port, dst_port), proto)) "
        "FROM weirvern.flows "
        "WHERE timestamp >= %(since)s AND timestamp <= %(until)s "
        "  AND src_addr != '' AND dst_addr != '' AND src_addr != dst_addr "
        "  AND " + addressing.sql_host("src_addr") + " "
        "  AND " + addressing.sql_host("dst_addr") + " ",
        {**timewindow.w(hours)},
        "connection graph (total)",
    )
    total = int(total_rows[0][0] or 0) if total_rows else len(edges)

    out_edges: list[dict] = []
    for r in edges:
        src, dst = str(r[0]), str(r[1])
        sport, dport, proto = int(r[2] or 0), int(r[3] or 0), int(r[4] or 0)
        b, f = int(r[5] or 0), int(r[6] or 0)
        out_edges.append({
            "source": src, "target": dst, "bytes": b, "flows": f,
            "src_port": sport, "dst_port": dport, "proto": proto,
            "ports": [dport] if dport else [],
            "src_ports": [sport] if sport else [],
            "first_seen": r[7].isoformat() if hasattr(r[7], "isoformat") else str(r[7] or ""),
            "last_seen": r[8].isoformat() if hasattr(r[8], "isoformat") else str(r[8] or ""),
            # 0/0 means these records do not carry the field.
            "ttl_min": int(r[9] or 0),
            "ttl_max": int(r[10] or 0),
        })

    # Merge exact reverse tuples, then keep the heaviest `limit` conversations. The scan is
    # deliberately wider than the returned graph, because a pair of halves is two rows before
    # the merge; sorting after the merge keeps the cap meaningful.
    out_edges = _merge_direction_pairs(out_edges)
    out_edges = _coalesce_service_edges(out_edges)
    out_edges.sort(key=lambda e: int(e.get("bytes") or 0), reverse=True)
    out_edges = out_edges[:int(limit)]

    nodes: dict[str, dict] = {}

    def _n(addr: str) -> dict:
        return nodes.setdefault(addr, {"id": addr, "degree": 0, "bytes": 0})

    for e in out_edges:
        _n(e["source"])["degree"] += 1
        _n(e["target"])["degree"] += 1
        _n(e["source"])["bytes"] += int(e.get("bytes") or 0)
        _n(e["target"])["bytes"] += int(e.get("bytes") or 0)

    if not nodes:
        return _unavailable("no host-to-host traffic in this window",
                            nodes=[], edges=[], total_edges=total)

    # Names are attached if a resolver is available, but never instead of the address.
    names = resolve_names(client, list(nodes))
    for addr, node in nodes.items():
        node["name"] = names.get(addr, "")
    # The edge carries its endpoints' names too, so the details panel does not have to join two
    # node rows to render one line -- and so a name is never shown without its address.
    for e in out_edges:
        e["source_name"] = names.get(e["source"], "")
        e["target_name"] = names.get(e["target"], "")

    # ── OPERATOR-DECLARED SCOPE ON THE GRAPH ───────────────────────────────────────────────
    # The graph is a reading surface, not a second declaration source. If no scopes are
    # declared, legacy graph (no scope colouring) is preserved. Once declarations exist, each
    # node carries the winning label and whether it is monitored; the browser only renders it.
    scopes = networks.load_scopes(client)
    if scopes:
        for node in nodes.values():
            scope = networks.resolve(node["id"], scopes)
            node["network_scope"] = scope.label if scope else "unclassified"
            node["scope_monitored"] = bool(networks.is_monitored(scope))

    # ── WHERE each host SITS, from the TTLs its OWN packets carried ──────────────────────────
    # A host's outbound packets arrive at the collector with their TTL decremented once per
    # router hop, so the observed value (rounded up to the nearest common initial TTL) gives
    # the host's distance from the sensor. This is the signal the Network view's force layout
    # pulls hosts into hop rings with -- structure a pure link layout cannot see. Only
    # SOURCE-side records count (a target's TTL describes whoever sent TO it), only records
    # with ttl > 0 count (0 is NOT MEASURED), and when a host's flows disagree the smallest
    # hop reading wins: decrements can only be ADDED by multi-path noise, never removed.
    # BOTH ENDS, EACH FROM ITS OWN PACKETS. Before the halves were merged this loop could only
    # read the source side of each raw row; a merged edge now carries a TTL pair per END (the
    # initiator's from its packets, the responder's from the reply), so each host is placed by
    # evidence that is actually its own.
    for e in out_edges:
        for side, key in (("source", "source_ttl_max"), ("target", "target_ttl_max")):
            ttl = int(e.get(key) or 0)
            if ttl <= 0:
                continue
            end_node = nodes.get(e[side])
            if end_node is None:
                continue
            hops = _hops_from_ttl(ttl)
            if end_node.get("hops") is None or hops < end_node["hops"]:
                end_node["hops"] = hops
                end_node["ttl"] = ttl

    max_degree = max(n["degree"] for n in nodes.values())
    max_bytes = max((n["bytes"] for n in nodes.values()), default=1) or 1
    for node in nodes.values():
        # Normalised 0..1 sizes, computed once here so the browser does no scaling maths and
        # two clients cannot disagree about the layout.
        node["degree_norm"] = node["degree"] / max_degree if max_degree else 0.0
        node["bytes_norm"] = node["bytes"] / max_bytes

    status_available, status_reason = attach_host_status(client, nodes, out_edges, hours=hours)
    return {
        "available": True,
        "reason": "",
        "hours": hours,
        "nodes": sorted(nodes.values(), key=lambda n: n["degree"], reverse=True),
        "edges": out_edges,
        "total_edges": total,
        "truncated": total > len(out_edges),
        "status_available": status_available,
        "status_reason": status_reason,
    }



# ── WHAT A HOST IS DOING, FOR THE NETWORK MAP ───────────────────────────────────────────────
# The connection graph answers "who talks to whom"; it used to leave "is either end blocked or
# alerted?" for the operator to infer from another tab. These annotations put that answer on
# the same host object the map already draws, and in the same object the click detail reads.
#
# TWO SEPARATE FACTS, NEVER ONE COLOUR:
#   * BLOCKED means a LIVE SLUICE BLOCK RULE names this host, either as a source/destination
#     CIDR or through a domain rule's currently-resolved addresses. It is a policy fact.
#   * ALERTED means the host has at least one anomaly window in the graph's range. It is an
#     observation fact. An alert-mode Sluice rule is not a detection and does not make a host
#     "alerted" -- that rule only records matching names.
# A host can be both; the status is "blocked" (the stronger action) but `alerted` and both
# reasons remain on the payload, so the detail can say so without hiding one.
def _addr_in_cidr(addr: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(addr) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def attach_host_status(client, nodes: dict[str, dict], edges: list[dict], *, hours: int) -> tuple[bool, str]:
    """Annotate graph nodes and edges with `blocked` / `alerted` and their evidence.

    Returns (status_available, status_reason). If either source cannot be read, the map still
    draws, but `status_available` is False and the reason is carried to the UI: an unknown
    status must not look like a normal host.
    """
    reasons: list[str] = []
    blocked_by: dict[str, list[str]] = {}
    available = True

    # Live block rules. Domain rules must be resolved through the same reverse map the gate
    # uses; this is read-only and deliberately uses the one resolution helper.
    try:
        from weirvern import sluice_store  # noqa: PLC0415
        rules = sluice_store.load_live_rules(client)
        rules, problems = sluice_store.attach_resolved_ips(client, rules)
        reasons.extend(problems)
        for rule in rules:
            if rule.mode == "alert" or not rule.enforcing:
                continue
            label = rule.describes()
            if rule.domain:
                for ip in rule.resolved_ips or []:
                    if ip in nodes:
                        blocked_by.setdefault(ip, []).append(label)
                continue
            for addr in nodes:
                if ((rule.src_cidr and _addr_in_cidr(addr, rule.src_cidr))
                        or (rule.dst_cidr and _addr_in_cidr(addr, rule.dst_cidr))):
                    blocked_by.setdefault(addr, []).append(label)
    except Exception as exc:  # noqa: BLE001
        available = False
        reasons.append(f"block rules could not be read: {type(exc).__name__}")

    # Anomaly windows. One grouped query, bounded by the same window as the graph.
    anomaly: dict[str, dict] = {}
    try:
        rows = _rows(
            client,
            "SELECT src_addr, count() AS n, max(detected_at) AS last_seen, "
            "       max(anomaly_score) AS score "
            "FROM weirvern.netflow_anomalies "
            # The Anomalies list is bounded by the WINDOW it describes, not by the
            # ingestion pass that noticed it. The graph must use the same boundary,
            # or a delayed detection makes the two views disagree about the range.
            "WHERE window_start >= %(since)s AND window_start <= %(until)s "
            "GROUP BY src_addr",
            {**timewindow.w(hours)},
            "connection graph (anomalies)",
        )
        if rows is None:
            available = False
            reasons.append("anomaly counts could not be read")
        else:
            for r in rows:
                anomaly[str(r[0])] = {
                    "count": int(r[1] or 0),
                    "last_seen": r[2].isoformat() if hasattr(r[2], "isoformat") else str(r[2] or ""),
                    "score": float(r[3] or 0.0),
                }
    except Exception as exc:  # noqa: BLE001
        available = False
        reasons.append(f"anomaly counts could not be read: {type(exc).__name__}")

    for addr, node in nodes.items():
        blocked = blocked_by.get(addr, [])
        anom = anomaly.get(addr)
        anomaly_count = int(anom["count"]) if anom else 0
        node["blocked"] = bool(blocked)
        node["alerted"] = anomaly_count > 0
        node["status"] = "blocked" if blocked else ("alerted" if node["alerted"] else "")
        node["status_reasons"] = (
            [f"block rule: {why}" for why in blocked]
            + ([f"{anomaly_count} anomaly window{'s' if anomaly_count != 1 else ''} in this range"]
               if anomaly_count else [])
        )
        if anom:
            node["anomaly_count"] = anom["count"]
            node["anomaly_last"] = anom["last_seen"]
            node["anomaly_score"] = anom["score"]

    for edge in edges:
        src = nodes.get(str(edge.get("source")), {})
        dst = nodes.get(str(edge.get("target")), {})
        edge["source_status"] = src.get("status", "")
        edge["target_status"] = dst.get("status", "")
        edge["status"] = (
            "blocked" if "blocked" in (edge["source_status"], edge["target_status"])
            else "alerted" if "alerted" in (edge["source_status"], edge["target_status"])
            else ""
        )
    return available, "; ".join(reasons)

def resolve_names(client, addrs: list[str], limit: int = 400) -> dict[str, str]:
    """Reverse-DNS names, as a mapping. Never a substitute for the address.

    REUSES `weirvern.admin.revdns` RATHER THAN QUERYING ZEEK's dns.log, and the reason is a
    measurement: on this segment the PTR answers are simply not in `weirvern.zeek_dns`. The
    23,422 qtype=12 rows are mDNS/SVCB service discovery (`_eero-ebid._tcp.local`,
    `_companion-link._tcp.local`) and their `answers` field is the `-` unset sentinel; the
    in-addr.arpa lookups carry no answer at all. Reading names from that table would have
    produced an empty name for every host while looking like a working query -- the exact
    "panel is empty and nobody knows why" failure this module exists to avoid.

    `revdns` already owns the whole policy: it resolves PRIVATE addresses by default so the
    lookup stays on the LAN, resolves public addresses only when WEIRVERN_REVERSE_DNS=all is
    set explicitly (each such lookup sends the address to a resolver), supports "off", caches
    positive AND negative results with different TTLs, and bounds each lookup with a socket
    timeout so a slow resolver cannot stall a page render. A host with no name keeps "" and
    the UI shows the address alone -- "" means "not seen", not "unknown host".

    The `client` argument is accepted for signature symmetry with the other helpers and is
    deliberately unused: names do not come from the database.
    """
    del client  # names are resolved live, not stored
    from weirvern.admin import revdns

    if not addrs:
        return {}
    out: dict[str, str] = {}
    for addr in addrs[:limit]:
        try:
            name = revdns.lookup(addr)
        except Exception as exc:  # noqa: BLE001 - a name is never worth failing a page for
            logger.debug("reverse lookup failed for %s: %s", addr, exc)
            continue
        if name:
            out[addr] = name
    return out


def host_zeek_activity(client, addr: str, hours: int = 24) -> dict:
    """Per-log event counts for ONE host, for the Host drill-down and the Zeek view.

    Separate from `asset_inventory` because the drill-down is per-host and does not want to
    pay for the whole segment's counts. A per-source filter on an indexed time column is
    cheap; counting sixteen tables for every host on every page load is not.
    """
    if not addr:
        return _unavailable("no address given")
    out: list[dict] = []
    unreadable: list[str] = []
    for table, addrcol in _ZEEK_HOST_TABLES:
        rows = _rows(
            client,
            f"SELECT count() AS n FROM weirvern.{table} "  # noqa: S608
            "WHERE ts >= %(since)s AND ts <= %(until)s AND toString(" + addrcol + ") = %(a)s",
            {**timewindow.w(hours), "a": addr},
            f"host zeek activity ({table})",
        )
        if rows is None:
            unreadable.append(table)
            continue
        n = int(rows[0][0] or 0)
        # A log the host never appears in is omitted rather than listed as zero: sixteen
        # zero rows would bury the three that matter.
        if n:
            out.append({"log": table.removeprefix("zeek_"), "table": table, "events": n})
    if not out and unreadable:
        return _unavailable(
            f"no Zeek log could be read for this host; failed: {', '.join(unreadable)}",
            unreadable=unreadable,
        )
    return {"available": True, "reason": "", "addr": addr, "hours": hours,
            "logs": sorted(out, key=lambda d: d["events"], reverse=True),
            "unreadable": unreadable}


def top_edges_for(client, addrs: list[str], hours: int = 24, limit: int = 200) -> dict:
    """Edges touching a chosen set of hosts, for "track only these hosts" on the Network view.

    FILTERING HAPPENS IN CLICKHOUSE, not in the browser. A busy segment has far more edges
    than a page should hold, and sending them all so the client can discard most is the
    pattern that makes a graph view get slower the more useful it becomes.

    An EMPTY selection is not a filter -- it means "no restriction", which is what an operator
    expects from a cleared multi-select. Returning nothing would make the graph vanish and
    read as a failure. The payload says which reading applied.
    """
    if not addrs:
        return _unavailable("no hosts selected (an empty selection shows the whole graph)",
                            nodes=[], edges=[])
    edges = _rows(
        client,
        "SELECT src_addr, dst_addr, src_port, dst_port, proto, "
        "       sum(bytes) AS bytes, count() AS flows, "
        "       min(timestamp) AS first_seen, max(timestamp) AS last_seen, "
        "       minIf(ip_ttl, ip_ttl > 0) AS ttl_min, maxIf(ip_ttl, ip_ttl > 0) AS ttl_max "
        "FROM weirvern.flows "
        "WHERE timestamp >= %(since)s AND timestamp <= %(until)s "
        "  AND src_addr != dst_addr "
        "  AND (src_addr IN %(a)s OR dst_addr IN %(a)s) "
        "  AND " + addressing.sql_host("src_addr") + " "
        "  AND " + addressing.sql_host("dst_addr") + " "
        "GROUP BY src_addr, dst_addr, src_port, dst_port, proto "
        "ORDER BY bytes DESC LIMIT %(n)s",
        {**timewindow.w(hours), "n": limit, "a": tuple(addrs)},
        "tracked-host edges",
    )
    if edges is None:
        return _unavailable("the tracked-host query failed")

    nodes: dict[str, dict] = {}

    def _n(a: str) -> dict:
        return nodes.setdefault(a, {"id": a, "degree": 0, "bytes": 0, "selected": a in set(addrs)})

    out: list[dict] = []
    for r in edges:
        src, dst = str(r[0]), str(r[1])
        sport, dport, proto = int(r[2] or 0), int(r[3] or 0), int(r[4] or 0)
        b, f = int(r[5] or 0), int(r[6] or 0)
        out.append({"source": src, "target": dst, "bytes": b, "flows": f,
                    "src_port": sport, "dst_port": dport, "proto": proto,
                    "ports": [dport] if dport else [], "src_ports": [sport] if sport else [],
                    "first_seen": r[7].isoformat() if hasattr(r[7], "isoformat") else str(r[7] or ""),
                    "last_seen": r[8].isoformat() if hasattr(r[8], "isoformat") else str(r[8] or ""),
                    "ttl_min": int(r[9] or 0), "ttl_max": int(r[10] or 0)})
        _n(src)["degree"] += 1
        _n(dst)["degree"] += 1
        _n(src)["bytes"] += b
        _n(dst)["bytes"] += b

    # The tracked graph uses the same direction model as the full graph; otherwise a filter
    # would change the arrows, which is the worst possible way to lose trust in a map.
    out = _coalesce_service_edges(_merge_direction_pairs(out))

    names = resolve_names(client, list(nodes))
    for a, node in nodes.items():
        node["name"] = names.get(a, "")

    # The TTL distance class rides the tracked-host path too, or a filtered graph would lose
    # its rings while the full graph keeps them -- the same fields, the same rule (see
    # connection_graph above for why source-side only and why the closest reading wins).
    for e in out:
        if e["ttl_max"] <= 0:
            continue
        src_node = nodes.get(e["source"])
        if src_node is None:
            continue
        hops = _hops_from_ttl(e["ttl_max"])
        if src_node.get("hops") is None or hops < src_node["hops"]:
            src_node["hops"] = hops
            src_node["ttl"] = e["ttl_max"]

    status_available, status_reason = attach_host_status(client, nodes, out, hours=hours)
    return {"available": True, "reason": "", "hours": hours, "tracked": list(addrs),
            "nodes": sorted(nodes.values(), key=lambda n: n["degree"], reverse=True),
            "edges": out, "status_available": status_available,
            "status_reason": status_reason}


def _iso(value: Any) -> str:
    """Render a ClickHouse timestamp as ISO text, including from an untyped query row."""
    fmt = getattr(value, "isoformat", None)
    return str(fmt()) if callable(fmt) else str(value or "")


def _asset_change_coverage(client, hours: int) -> dict:
    """What the ledger was actually watching, so an empty change list is not mistaken for
    a quiet network.

    The change count alone cannot distinguish "no differences" from "nothing was scanned".
    These two reads are deliberately separate from the change query: a missing history table
    must not turn a readable ledger into an unavailable one, and an empty history window is
    reported with its coverage rather than as a silent zero.
    """
    span = timewindow.w(hours)
    history = _rows(
        client,
        "SELECT count() AS observations, uniqExact(asset_key) AS observed_assets, "
        "       max(observed_at) AS last_observation "
        "FROM weirvern.asset_service_history "
        "WHERE observed_at >= %(since)s AND observed_at <= %(until)s",
        span,
        "asset-change observations",
    )
    registry = _rows(
        client,
        "SELECT count() AS assets, countIf(scan_state = 'done') AS scanned, "
        "       max(last_scan_at) AS last_scan "
        "FROM weirvern.asset_registry FINAL",
        {},
        "asset-change registry coverage",
    )
    if history is None or registry is None:
        return {"available": False, "reason": "the coverage query failed",
                "observations": 0, "observed_assets": 0, "assets": 0, "scanned": 0,
                "last_observation": "", "last_scan": ""}
    h = history[0] if history else (0, 0, None)
    r = registry[0] if registry else (0, 0, None)
    return {
        "available": True,
        "reason": "",
        "observations": int(h[0] or 0),
        "observed_assets": int(h[1] or 0),
        "last_observation": _iso(h[2]),
        "assets": int(r[0] or 0),
        "scanned": int(r[1] or 0),
        "last_scan": _iso(r[2]),
    }


def asset_posture_overview(client: Any) -> dict:
    """The shadow asset-posture scorer's own state, for the Models view.

    There is no trained classifier here yet: `asset-posture-1` is a deterministic scorer over
    observed service changes. The card must still say what it is and why it has no rows, rather
    than rendering an unexplained zero.
    """
    try:
        rows = _rows(
            client,
            "SELECT count() AS scored, countIf(band = 'expected') AS expected, "
            "       countIf(band = 'watch') AS watch, countIf(band = 'suspicious') AS suspicious, "
            "       countIf(band = 'high') AS high, max(scored_at) AS last_scored, "
            "       any(model_version) AS model_version "
            "FROM weirvern.asset_posture_scores FINAL",
            {},
            "asset posture overview",
        )
        changes = _rows(
            client,
            "SELECT count() AS total FROM weirvern.asset_changes FINAL",
            {},
            "asset posture change total",
        )
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"the asset-posture read failed: {exc}",
                "model_version": "asset-posture-1", "scored": 0, "total_changes": 0,
                "bands": {"expected": 0, "watch": 0, "suspicious": 0, "high": 0},
                "last_scored": ""}
    if rows is None or changes is None:
        return {"available": False, "reason": "the asset-posture tables could not be read",
                "model_version": "asset-posture-1", "scored": 0, "total_changes": 0,
                "bands": {"expected": 0, "watch": 0, "suspicious": 0, "high": 0},
                "last_scored": ""}
    r = rows[0] if rows else (0, 0, 0, 0, 0, None, "")
    c = changes[0] if changes else (0,)
    last = r[5]
    return {
        "available": True,
        "reason": "",
        "model_version": str(r[6] or "asset-posture-1"),
        "scored": int(r[0] or 0),
        "total_changes": int(c[0] or 0),
        "bands": {
            "expected": int(r[1] or 0), "watch": int(r[2] or 0),
            "suspicious": int(r[3] or 0), "high": int(r[4] or 0),
        },
        "last_scored": _iso(last),
    }


def asset_changes(client, hours: int = 24, limit: int = 100) -> dict:
    """Recent Nmap service changes, with the shadow posture score when one exists.

    This is a CHANGE LEDGER, not a second inventory: a row is the difference between two
    successful scans. The score is deliberately advisory (the module's band is `expected`,
    `watch`, `suspicious`, or `high`) and the payload says so; nothing here writes to a gate.
    """
    rows = _rows(
        client,
        "SELECT c.asset_key, c.ip, c.change_key, c.kind, c.port, c.protocol, "
        "c.old_value, c.new_value, c.confidence, c.evidence, c.first_seen, c.last_seen, "
        "c.review_state, s.score, s.band, s.reasons "
        "FROM (SELECT * FROM weirvern.asset_changes FINAL) c "
        "LEFT JOIN (SELECT * FROM weirvern.asset_posture_scores FINAL) s "
        "ON c.asset_key = s.asset_key AND c.change_key = s.change_key "
        "WHERE c.last_seen >= %(since)s AND c.last_seen <= %(until)s "
        "ORDER BY c.last_seen DESC LIMIT %(n)s",
        {**timewindow.w(hours), "n": max(1, min(int(limit), 500))},
        "asset changes",
    )
    if rows is None:
        return _unavailable("the asset-change query failed", hours=hours, changes=[])

    out = []
    for r in rows:
        out.append({
            "asset_key": str(r[0] or ""),
            "ip": str(r[1] or ""),
            "change_key": str(r[2] or ""),
            "kind": str(r[3] or ""),
            "port": int(r[4] or 0),
            "protocol": str(r[5] or "tcp"),
            "old_value": str(r[6] or ""),
            "new_value": str(r[7] or ""),
            "confidence": str(r[8] or ""),
            "evidence": str(r[9] or ""),
            "first_seen": r[10].isoformat() if hasattr(r[10], "isoformat") else str(r[10] or ""),
            "last_seen": r[11].isoformat() if hasattr(r[11], "isoformat") else str(r[11] or ""),
            "review_state": str(r[12] or "new"),
            "posture": {
                "score": float(r[13] or 0.0),
                "band": str(r[14] or "unscored"),
                "reasons": list(r[15] or []),
            },
        })
    return {"available": True, "reason": "", "hours": hours, "changes": out,
            "count": len(out), "coverage": _asset_change_coverage(client, hours)}
