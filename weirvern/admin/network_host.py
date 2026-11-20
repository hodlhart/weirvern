"""One host, answered for the Network tab: why is this address interesting?

WHY THIS MODULE EXISTS. The Network view could draw a host but not explain it. Clicking a dot
opened a panel built from the graph payload alone: peers and bytes, no names, no ripples, no
model detections, no notion of whether the address had ever been normalised. The operator had to
leave the tab to answer "why is this host interesting", which is the one question the map exists
to prompt.

THE READS ARE DELIBERATELY PER-SECTION AND INDIVIDUALLY GUARDED. A missing Zeek table, a host
with no DNS, a normalisation table that has never been written -- each degrades ITS section with
`available: false` and a reason, never the whole sheet and never a zero that reads as "nothing
happened". `unknown` and `zero` are different facts on this console and this module is where the
difference is first decided.

WINDOWS. Every windowed read uses `timewindow.w(hours)`, which honours the request's absolute
`from`/`to` when the console sent one. The payload echoes the window it answered for
(`window.since`/`window.until`) and the retention actually held by each source (`coverage`),
because a 7-day request against three days of raw flows must say so rather than draw three days
as seven.

MEASURED COVERAGE ON THIS DEPLOYMENT (2026-11-20, live):
  * `flows_window_endpoint` starts 2026-11-17 05:30 -- in/out bytes exist for ~3.3 days, not 7.
  * `flows_window` starts 2026-11-12 13:50 -- outbound totals and first-seen reach ~8 days.
  * `ml_ripple_evidence` starts 2026-11-19 14:00 -- ripple history is ~1 day, so a 7-day ripple
    count is a one-day reading and the sheet says which.
Those are read live (not hard-coded) and shipped in `coverage`.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from weirvern.admin import timewindow

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MODEL_ROWS = 12
PEER_ROWS = 12
NAME_ROWS = 12


def _iso(value: Any) -> str:
    return value.isoformat() if hasattr(value, "isoformat") else str(value or "")


def _worst(values) -> str:
    """The highest severity word in `values`, or "" when nothing was reported."""
    best = ""
    for value in values or ():
        word = str(value or "").lower()
        if SEVERITY_RANK.get(word, 0) > SEVERITY_RANK.get(best, 0):
            best = word
    return best


def _json_names(raw: Any) -> list[str]:
    """A JSON-array column as a bounded list of names.

    `hostnames_seen` / `ja4_seen` are stored as JSON arrays. A malformed value is NOT silently
    treated as empty: the caller receives [] and the section's `reason` is set where it matters.
    """
    if not raw:
        return []
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    return [str(v) for v in parsed if str(v or "").strip()][:40]


class _Reads:
    """Run one guarded query per section and remember which ones failed, and why."""

    def __init__(self, client: Any):
        self.client = client
        self.errors: dict[str, str] = {}

    def rows(self, key: str, sql: str, params: dict[str, Any] | None = None) -> list[Any] | None:
        try:
            res = self.client.query(sql, parameters=params or {})
            return list(getattr(res, "result_rows", None) or [])
        except Exception as exc:  # noqa: BLE001 - a section, never the sheet
            logger.warning("network host %s failed: %s", key, exc)
            self.errors[key] = f"{type(exc).__name__}: {str(exc)[:160]}"
            return None


def _coverage(client: Any, reads: _Reads) -> dict[str, Any]:
    """How much history each source ACTUALLY holds, measured, not inferred from TTL."""
    out: dict[str, Any] = {}
    for key, table, column in (
        ("flows_window", "weirvern.flows_window", "window_start"),
        ("flows_window_endpoint", "weirvern.flows_window_endpoint", "window_start"),
        ("ripple_evidence", "weirvern.ml_ripple_evidence", "window_start"),
        ("netflow_anomalies", "weirvern.netflow_anomalies", "window_start"),
    ):
        rows = reads.rows(f"coverage:{key}",
                          f"SELECT min({column}), max({column}) FROM {table}")
        if rows and rows[0]:
            out[key] = {"from": _iso(rows[0][0]), "to": _iso(rows[0][1])}
        else:
            out[key] = {"from": "", "to": "",
                        "reason": reads.errors.get(f"coverage:{key}", "no rows")}
    return out


def host_sheet(client: Any, addr: str, *, hours: int = 24) -> dict[str, Any]:
    """Everything the Network host sheet shows for ONE address, in the global window."""
    reads = _Reads(client)
    w = timewindow.w(hours)
    window = {"hours": int(hours), "since": _iso(w["since"]), "until": _iso(w["until"])}
    out: dict[str, Any] = {
        "available": True,
        "addr": addr,
        "window": window,
    }

    # ── identity and names ────────────────────────────────────────────────────────────────
    ptr = ""
    try:
        from weirvern.admin import revdns  # noqa: PLC0415

        ptr = revdns.lookup(addr) or ""
    except Exception as exc:  # noqa: BLE001 - a name is never worth failing the sheet
        logger.debug("network host reverse lookup failed for %s: %s", addr, exc)

    ident_rows = reads.rows(
        "identity",
        "SELECT hostnames_seen, ja4_seen, mac, os_label, confidence, toString(updated_at) "
        "FROM weirvern.host_identity WHERE host = %(a)s LIMIT 1",
        {"a": addr},
    )
    identity: dict[str, Any] = {
        "ptr": ptr,
        "hostnames": [],
        "ja4": [],
        "mac": "",
        "os": "",
        "confidence": None,
        "updated_at": "",
        "available": ident_rows is not None,
        "reason": reads.errors.get("identity", ""),
    }
    if ident_rows:
        hostnames, ja4, mac, os_label, confidence, updated = (
            list(ident_rows[0]) + ["", "", "", "", None, ""])[:6]
        identity.update({
            "hostnames": _json_names(hostnames),
            "ja4": _json_names(ja4),
            "mac": str(mac or ""),
            "os": str(os_label or ""),
            "confidence": confidence,
            "updated_at": str(updated or ""),
        })

    asset = reads.rows(
        "asset",
        "SELECT hostname, first_seen, last_seen, scan_state FROM weirvern.asset_registry "
        "WHERE ip = %(a)s LIMIT 1",
        {"a": addr},
    )
    if asset:
        identity["registered_hostname"] = str(asset[0][0] or "")
        identity["registry_first_seen"] = _iso(asset[0][1])
        identity["registry_last_seen"] = _iso(asset[0][2])
        identity["scan_state"] = str(asset[0][3] or "")

    role = reads.rows(
        "role",
        "SELECT role, scope, source, confidence FROM weirvern.host_roles "
        "WHERE host = %(a)s LIMIT 1",
        {"a": addr},
    )
    if role:
        identity["role"] = str(role[0][0] or "")
        identity["role_scope"] = str(role[0][1] or "")
        identity["role_source"] = str(role[0][2] or "")

    # NetBIOS names: NTLM's client hostname and DHCP's option-12 host name. Both are recorded
    # observations, not a guess derived from the address.
    ntlm = reads.rows(
        "netbios",
        "SELECT hostname, domainname, count() AS n FROM weirvern.zeek_ntlm "
        "WHERE src_addr = %(a)s AND ts >= %(since)s AND ts <= %(until)s AND hostname != '' "
        "GROUP BY hostname, domainname ORDER BY n DESC LIMIT 8",
        {"a": addr, **w},
    )
    if ntlm is not None:
        identity["netbios"] = [
            {"name": str(r[0]), "domain": str(r[1] or ""), "count": int(r[2] or 0)}
            for r in ntlm
        ]
    else:
        identity["netbios"] = []

    dhcp = reads.rows(
        "dhcp_name",
        "SELECT host_name, count() AS n FROM weirvern.zeek_dhcp "
        "WHERE client_addr = %(a)s AND ts >= %(since)s AND ts <= %(until)s AND host_name != '' "
        "GROUP BY host_name ORDER BY n DESC LIMIT 8",
        {"a": addr, **w},
    )
    if dhcp is not None:
        identity["dhcp_names"] = [{"name": str(r[0]), "count": int(r[1] or 0)} for r in dhcp]
    else:
        identity["dhcp_names"] = []

    # First/last seen: the retained flow window for this host, plus the source's own coverage.
    seen = reads.rows(
        "seen",
        "SELECT min(window_start), max(window_start) FROM weirvern.flows_window "
        "WHERE src_addr = %(a)s",
        {"a": addr},
    )
    if seen and seen[0] and seen[0][0] is not None:
        identity["first_seen"] = _iso(seen[0][0])
        identity["last_seen"] = _iso(seen[0][1])
        identity["first_seen_basis"] = "earliest retained flow window"
    else:
        identity["first_seen"] = ""
        identity["last_seen"] = ""
        identity["first_seen_basis"] = "not measured" if seen is not None else "read failed"
    out["identity"] = identity

    # ── traffic, in and out, for the selected window ─────────────────────────────────────
    endpoint = reads.rows(
        "traffic_in_out",
        "SELECT direction, countMerge(flow_count) AS flows, sumMerge(total_bytes) AS bytes, "
        "sumMerge(total_packets) AS packets, uniqMerge(unique_peer_ips) AS peers, "
        "min(window_start), max(window_start) "
        "FROM weirvern.flows_window_endpoint "
        "WHERE host_addr = %(a)s AND window_start >= %(since)s AND window_start <= %(until)s "
        "GROUP BY direction",
        {"a": addr, **w},
    )
    outbound = reads.rows(
        "traffic_outbound",
        "SELECT countMerge(flow_count) AS flows, sumMerge(total_bytes) AS bytes, "
        "sumMerge(total_packets) AS packets, uniqMerge(unique_dst_ips) AS peers, "
        "min(window_start), max(window_start) "
        "FROM weirvern.flows_window "
        "WHERE src_addr = %(a)s AND window_start >= %(since)s AND window_start <= %(until)s",
        {"a": addr, **w},
    )
    traffic: dict[str, Any] = {
        "in": None,
        "out": None,
        "outbound_flows": None,
        "available": endpoint is not None or outbound is not None,
        "reason": reads.errors.get("traffic_in_out") or reads.errors.get("traffic_outbound") or "",
    }
    for row in endpoint or []:
        direction = str(row[0] or "")
        if direction not in ("in", "out"):
            continue
        traffic[direction] = {
            "flows": int(row[1] or 0),
            "bytes": int(row[2] or 0),
            "packets": int(row[3] or 0),
            "peers": int(row[4] or 0),
            "first": _iso(row[5]),
            "last": _iso(row[6]),
        }
    if outbound:
        r = outbound[0]
        traffic["outbound_flows"] = {
            "flows": int(r[0] or 0),
            "bytes": int(r[1] or 0),
            "packets": int(r[2] or 0),
            "peers": int(r[3] or 0),
            "first": _iso(r[4]),
            "last": _iso(r[5]),
        }
    out["traffic"] = traffic

    # ── peers, services and ports from Zeek's connection log ────────────────────────────
    peers = reads.rows(
        "peers",
        "SELECT peer, sum(out_bytes) AS out_bytes, sum(in_bytes) AS in_bytes, "
        "sum(out_conns) AS out_conns, sum(in_conns) AS in_conns FROM ("
        "  SELECT dst_addr AS peer, orig_bytes + resp_bytes AS out_bytes, 0 AS in_bytes, "
        "         1 AS out_conns, 0 AS in_conns FROM weirvern.zeek_conn "
        "  WHERE src_addr = %(a)s AND ts >= %(since)s AND ts <= %(until)s"
        "  UNION ALL "
        "  SELECT src_addr AS peer, 0, orig_bytes + resp_bytes, 0, 1 FROM weirvern.zeek_conn "
        "  WHERE dst_addr = %(a)s AND ts >= %(since)s AND ts <= %(until)s"
        ") GROUP BY peer ORDER BY out_bytes + in_bytes DESC LIMIT %(n)s",
        {"a": addr, **w, "n": PEER_ROWS},
    )
    out["peers"] = {
        "available": peers is not None,
        "reason": reads.errors.get("peers", ""),
        "rows": [
            {"peer": str(r[0]), "out_bytes": int(r[1] or 0), "in_bytes": int(r[2] or 0),
             "out_conns": int(r[3] or 0), "in_conns": int(r[4] or 0)}
            for r in (peers or [])
        ],
    }

    services = reads.rows(
        "services",
        "SELECT service, count() AS conns FROM weirvern.zeek_conn "
        "WHERE (src_addr = %(a)s OR dst_addr = %(a)s) "
        "  AND ts >= %(since)s AND ts <= %(until)s AND service != '' "
        "GROUP BY service ORDER BY conns DESC LIMIT %(n)s",
        {"a": addr, **w, "n": PEER_ROWS},
    )
    # WHAT THE HOST OFFERS vs WHAT IT USES. A destination port on this host is a service it
    # listens on; a destination port it dialled is a service it consumed. Mixing the two made a
    # workstation's reply ports read as listening services (measured: 192.168.2.153's "inbound
    # ports" were its own ephemeral 34k-58k sockets).
    listening = reads.rows(
        "listening_ports",
        "SELECT src_port AS port, proto, count() AS conns FROM weirvern.zeek_conn "
        "WHERE dst_addr = %(a)s AND ts >= %(since)s AND ts <= %(until)s AND src_port > 0 "
        "GROUP BY src_port, proto ORDER BY conns DESC LIMIT %(n)s",
        {"a": addr, **w, "n": PEER_ROWS},
    )
    used = reads.rows(
        "used_ports",
        "SELECT dst_port AS port, proto, count() AS conns FROM weirvern.zeek_conn "
        "WHERE src_addr = %(a)s AND ts >= %(since)s AND ts <= %(until)s AND dst_port > 0 "
        "GROUP BY dst_port, proto ORDER BY conns DESC LIMIT %(n)s",
        {"a": addr, **w, "n": PEER_ROWS},
    )
    out["services"] = {
        "available": services is not None and listening is not None and used is not None,
        "reason": (reads.errors.get("services") or reads.errors.get("listening_ports")
                   or reads.errors.get("used_ports") or ""),
        "services": [{"service": str(r[0]), "conns": int(r[1] or 0)} for r in (services or [])],
        "listening_ports": [
            {"port": int(r[0] or 0), "proto": str(r[1] or ""), "conns": int(r[2] or 0)}
            for r in (listening or [])
        ],
        "used_ports": [
            {"port": int(r[0] or 0), "proto": str(r[1] or ""), "conns": int(r[2] or 0)}
            for r in (used or [])
        ],
    }

    # ── DNS names asked, TLS names offered ──────────────────────────────────────────────
    dns = reads.rows(
        "dns",
        "SELECT query, qtype, count() AS asks FROM weirvern.zeek_dns "
        "WHERE src_addr = %(a)s AND ts >= %(since)s AND ts <= %(until)s AND query != '' "
        "GROUP BY query, qtype ORDER BY asks DESC LIMIT %(n)s",
        {"a": addr, **w, "n": NAME_ROWS},
    )
    out["dns"] = {
        "available": dns is not None,
        "reason": reads.errors.get("dns", ""),
        "queries": [{"name": str(r[0]), "qtype": int(r[1] or 0), "asks": int(r[2] or 0)}
                    for r in (dns or [])],
    }
    tls = reads.rows(
        "tls",
        "SELECT server_name, count() AS sessions FROM weirvern.zeek_ssl "
        "WHERE src_addr = %(a)s AND ts >= %(since)s AND ts <= %(until)s "
        "  AND server_name != '' "
        "GROUP BY server_name ORDER BY sessions DESC LIMIT %(n)s",
        {"a": addr, **w, "n": NAME_ROWS},
    )
    ja4 = reads.rows(
        "ja4",
        "SELECT uniqExact(ja4) FROM weirvern.zeek_ssl "
        "WHERE src_addr = %(a)s AND ts >= %(since)s AND ts <= %(until)s AND ja4 != ''",
        {"a": addr, **w},
    )
    out["tls"] = {
        "available": tls is not None and ja4 is not None,
        "reason": reads.errors.get("tls") or reads.errors.get("ja4") or "",
        "names": [{"name": str(r[0]), "sessions": int(r[1] or 0)} for r in (tls or [])],
        "ja4_count": int(ja4[0][0] or 0) if ja4 and ja4[0] else 0,
    }

    # ── model detections, with their bands ──────────────────────────────────────────────
    model_rows = reads.rows(
        "models",
        "SELECT window_start, severity, anomaly_score, detected_by_models, attack_label "
        "FROM weirvern.netflow_anomalies "
        "WHERE src_addr = %(a)s AND window_start >= %(since)s AND window_start <= %(until)s "
        "ORDER BY window_start DESC, anomaly_score DESC LIMIT %(n)s",
        {"a": addr, **w, "n": MODEL_ROWS},
    )
    model_counts = reads.rows(
        "model_counts",
        "SELECT severity, count() AS n FROM weirvern.netflow_anomalies "
        "WHERE src_addr = %(a)s AND window_start >= %(since)s AND window_start <= %(until)s "
        "GROUP BY severity",
        {"a": addr, **w},
    )
    by_severity = {str(r[0]): int(r[1] or 0) for r in (model_counts or [])}
    out["models"] = {
        "available": model_rows is not None and model_counts is not None,
        "reason": reads.errors.get("models") or reads.errors.get("model_counts") or "",
        "count": sum(by_severity.values()),
        "worst": _worst(by_severity),
        "by_severity": by_severity,
        "rows": [
            {"window_start": _iso(r[0]), "severity": str(r[1] or ""),
             "score": float(r[2] or 0), "models": str(r[3] or ""),
             "attack": str(r[4] or "")}
            for r in (model_rows or [])
        ],
    }

    # ── ripples, from the SAME grouping the Alerts tab renders ──────────────────────────
    try:
        from weirvern.models import ripple_evidence  # noqa: PLC0415

        data = ripple_evidence.overview(client, hours=hours)
        rows = [r for r in (data.get("ripples") or []) if str(r.get("host") or "") == addr]
        out["ripples"] = {
            "available": bool(data.get("available")),
            "reason": data.get("reason") or "",
            "count": len(rows),
            "worst": _worst([r.get("severity") for r in rows]),
            "rows": rows,
            "window_hours": int(data.get("window_hours") or hours),
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("network host ripples failed: %s", exc)
        out["ripples"] = {"available": False,
                          "reason": f"{type(exc).__name__}: {str(exc)[:160]}",
                          "count": 0, "worst": "", "rows": [], "window_hours": int(hours)}

    # ── normalised patterns ─────────────────────────────────────────────────────────────
    normalized = reads.rows(
        "normalized",
        "SELECT channel, family, value, created_at, reason, review_after "
        "FROM weirvern.normal_ripple_signatures FINAL "
        "WHERE host_addr = %(a)s AND removed_at IS NULL ORDER BY created_at DESC LIMIT 50",
        {"a": addr},
    )
    out["normalized"] = {
        "available": normalized is not None,
        "reason": reads.errors.get("normalized", ""),
        "count": len(normalized or []),
        "rows": [
            {"channel": str(r[0]), "family": str(r[1]), "value": str(r[2]),
             "created_at": _iso(r[3]), "reason": str(r[4] or ""),
             "review_after": _iso(r[5])}
            for r in (normalized or [])
        ],
    }

    out["coverage"] = _coverage(client, reads)
    out["errors"] = reads.errors
    return out


def host_sheet_failure(exc: BaseException, *, addr: str, hours: int) -> dict[str, Any]:
    """The console's own failure shape: the section failed, and the sheet says so."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("network host sheet unavailable for %s: %s", addr, exc)
    reason = read_failure(exc)
    return {
        "available": False,
        "addr": addr,
        "window": {"hours": int(hours), "since": "", "until": ""},
        "reason": reason,
        "identity": {"available": False, "reason": reason, "hostnames": [], "ja4": [],
                     "ptr": "", "netbios": [], "dhcp_names": []},
        "traffic": {"available": False, "reason": reason, "in": None, "out": None,
                    "outbound_flows": None},
        "peers": {"available": False, "reason": reason, "rows": []},
        "services": {"available": False, "reason": reason, "services": [],
                     "listening_ports": [], "used_ports": []},
        "dns": {"available": False, "reason": reason, "queries": []},
        "tls": {"available": False, "reason": reason, "names": [], "ja4_count": 0},
        "models": {"available": False, "reason": reason, "count": 0, "worst": "",
                   "by_severity": {}, "rows": []},
        "ripples": {"available": False, "reason": reason, "count": 0, "worst": "",
                    "rows": [], "window_hours": int(hours)},
        "normalized": {"available": False, "reason": reason, "count": 0, "rows": []},
        "coverage": {},
        "errors": {"read": reason},
    }


__all__ = ["SEVERITY_RANK", "host_sheet", "host_sheet_failure"]
