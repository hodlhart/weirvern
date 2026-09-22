"""Ingestion — tail collector sinks and batch-insert into ClickHouse.

Two sources:
  * goflow2 JSONL  -> `flows`          (NetFlow/sFlow: volume + topology)
  * Zeek TSV logs  -> `zeek_conn`,     (packets: protocol behaviour)
                      `zeek_dns`, `zeek_ssl`, `zeek_notice`

Zeek writes one TSV file per log type and rotates them. Each file begins with a
`#separator` line and a `#fields` header naming the columns, followed by
`#types`; data lines then map positionally onto `#fields`. Fields that a given
Zeek build does not emit are absent from `#fields`, so we always parse against
the header rather than against a hardcoded column order — a hardcoded order
silently shifts every value when Zeek changes its schema.

Lesson from the legacy goflow2.yaml: the tailer was an inline bash+python
heredoc inside the Deployment manifest. It now lives in the worker image, is
tested, and shares the schema/config modules.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime
from ipaddress import ip_address
from typing import Any, Protocol

logger = logging.getLogger(__name__)

PROTO_MAP = {"ICMP": 1, "TCP": 6, "UDP": 17}
ETYPE_MAP = {"IPV4": 2048, "IPV6": 34525}
BATCH_SIZE = 10_000

# Zeek's "no value" sentinel.
ZEEK_NULL = "-"
# The OTHER sentinel. Zeek's header declares `#empty_field (empty)` as well as `#unset_field -`,
# and they mean different things: "-" is "not set", "(empty)" is "set to an empty value". Only
# ZEEK_NULL was being normalised, so `(empty)` reached the database as a literal 7-character
# string -- see zeek_value() for what that broke.
ZEEK_EMPTY = "(empty)"


class Inserter(Protocol):
    """What the tailer needs from ClickHouse — lets tests substitute a fake."""

    def insert(self, table: Any = None, data: Any = None, column_names: Any = None, **kwargs: Any) -> Any: ...  # noqa: ANN401

_COLUMNS = [
    "timestamp", "sampler_address", "time_flow_start", "time_flow_end", "src_addr",
    "dst_addr", "src_port", "dst_port", "proto", "etype", "bytes", "packets",
    "tcp_flags", "sampling_rate", "src_as", "dst_as", "src_vlan", "dst_vlan",
    "in_if", "out_if", "next_hop", "ip_tos", "ip_ttl", "frag_offset",
]


def _to_ip(value: Any) -> str:
    try:
        return str(ip_address(str(value)))
    except ValueError:
        return "0.0.0.0"


def _proto_num(val: Any) -> int:
    if isinstance(val, int):
        return val
    if isinstance(val, str) and val.isdigit():
        return int(val)
    return PROTO_MAP.get(str(val).upper(), 0)


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def _ts(epoch_ns: Any) -> datetime:
    try:
        return datetime.fromtimestamp(float(epoch_ns) / 1e9)
    except (TypeError, ValueError, OverflowError):
        return datetime.now()


def map_flow(raw: dict[str, Any]) -> dict[str, Any]:
    """goflow2 JSON record → flows row (legacy mapping, hardened)."""
    return {
        "timestamp": datetime.now(),
        "sampler_address": raw.get("sampler_address", ""),
        "time_flow_start": _ts(raw.get("time_flow_start_ns", 0)),
        "time_flow_end": _ts(raw.get("time_flow_end_ns", 0)),
        "src_addr": _to_ip(raw.get("src_addr", "0.0.0.0")),
        "dst_addr": _to_ip(raw.get("dst_addr", "0.0.0.0")),
        "src_port": _safe_int(raw.get("src_port", 0)),
        "dst_port": _safe_int(raw.get("dst_port", 0)),
        "proto": _proto_num(raw.get("proto", 0)),
        "etype": ETYPE_MAP.get(str(raw.get("etype", "IPv4")).upper(), 2048),
        "bytes": _safe_int(raw.get("bytes", 0)),
        "packets": _safe_int(raw.get("packets", 0)),
        "tcp_flags": _safe_int(raw.get("tcp_flags", 0)),
        "sampling_rate": _safe_int(raw.get("sampling_rate", 1), 1),
        "src_as": _safe_int(raw.get("src_as", 0)),
        "dst_as": _safe_int(raw.get("dst_as", 0)),
        "src_vlan": _safe_int(raw.get("src_vlan", 0)),
        "dst_vlan": _safe_int(raw.get("dst_vlan", 0)),
        "in_if": _safe_int(raw.get("in_if", 0)),
        "out_if": _safe_int(raw.get("out_if", 0)),
        "next_hop": _to_ip(raw.get("next_hop", "0.0.0.0")),
        "ip_tos": _safe_int(raw.get("ip_tos", 0)),
        "ip_ttl": _safe_int(raw.get("ip_ttl", 0)),
        "frag_offset": _safe_int(raw.get("fragment_offset", 0)),
    }


# The exclusion filter, set once by the worker at startup. Module-level rather than passed through
# every mapper because the mappers are pure functions used by tests, and threading a filter through
# twenty of them would make each one harder to call for no benefit. `None` means "nothing excluded",
# which is the behaviour every existing caller and test already expects.
class ExclusionFilter(Protocol):
    """What the ingester needs from a filter.

    A Protocol rather than the concrete class so this module does not import `exclude` -- the
    mappers are used standalone in tests and must not drag the whole exclusion stack in with them.
    """

    def excluded(self, *addrs: str | None) -> str | None: ...


_FILTER: ExclusionFilter | None = None


def set_traffic_filter(f: ExclusionFilter | None) -> None:
    """Install the exclusion filter for this process. Called once, at worker startup."""
    global _FILTER
    _FILTER = f


def traffic_filter() -> ExclusionFilter | None:
    """The installed filter, or None."""
    return _FILTER


def _excluded(row: dict[str, Any]) -> bool:
    """Whether this row names an excluded address. Counts the drop as a side effect."""
    f = _FILTER
    if f is None:
        return False
    return f.excluded(str(row.get("src_addr") or ""), str(row.get("dst_addr") or "")) is not None


def insert_batch(client: Inserter, rows: list[dict[str, Any]]) -> int:
    """Write flow rows, dropping any that name an excluded address.

    FILTERED HERE BECAUSE THIS IS THE FUNNEL. Every flow row reaches the store through this one
    function, so a filter here cannot be bypassed by a new caller the way a per-caller filter
    would be. It is also the last point where BOTH addresses are still available in Python: after
    this the row is a positional tuple.

    The drop is COUNTED by the filter (`TrafficFilter.excluded`), not silent. A quiet reduction in
    row count is indistinguishable from a broken ingester, and this project has already paid for
    that confusion once.
    """
    if not rows:
        return 0
    keep = [r for r in rows if not _excluded(r)]
    if not keep:
        return 0
    client.insert("weirvern.flows", [[r[c] for c in _COLUMNS] for r in keep], column_names=_COLUMNS)
    return len(keep)


# =============================================================================
# Zeek TSV parsing
# =============================================================================
def parse_zeek_header(lines: list[str]) -> tuple[str, list[str]]:
    """Extract (separator, field-names) from a Zeek log's header lines.

    Zeek emits:
        #separator \\x09
        #set_separator	,
        #empty_field	(empty)
        #unset_field	-
        #path	conn
        #open	2026-09-15-00-00-00
        #fields	ts	uid	id.orig_h	...
        #types	time	string	addr	...
    """
    separator = "\t"
    fields: list[str] = []
    for line in lines:
        if line.startswith("#separator"):
            sep = line.split(" ", 1)[1].strip() if " " in line else "\t"
            # Zeek prints it escaped, e.g. \x09
            separator = sep.replace("\\x09", "\t").replace("\\t", "\t") or "\t"
        elif line.startswith("#fields"):
            fields = line.split("\t")[1:]
            if len(fields) == 1:
                fields = line.split(" ", 1)[1].split(separator)
    return separator, fields


def zeek_value(val: str) -> str | None:
    """Zeek's unset sentinels mean 'no value' -> None.

    ZEEK EMITS *TWO* SENTINELS AND ONLY ONE OF THEM WAS HANDLED. The header declares
    `#empty_field (empty)` alongside `#unset_field -`, and they are different: `-` means "not
    set" and `(empty)` means "set, but to an empty value". Only `-` was normalised here, so
    `(empty)` was stored VERBATIM as a string.

    That mattered. `weirvern.zeek_ssl.ja4` held the literal 7-character string `(empty)` on rows
    where Zeek produced an empty fingerprint, so:
      * `uniqExactIf(ja4, ja4 != '') AS ja4_count` counted it as a REAL DISTINCT FINGERPRINT, and
        `zeek_ja4_count` -- a live ML feature -- reported 1 on hosts that had no fingerprint at all;
      * `ja4 != '-'` guards elsewhere were satisfied by it, so a TLS-downgrade rule could compare
        against the literal text "(empty)";
      * the same applies to every other column that can be empty, not just ja4.

    Normalising at the READ layer is the fix, matching how the `-` case was already handled.
    """
    if val == "" or val in (ZEEK_NULL, ZEEK_EMPTY):
        return None
    return val


def map_zeek_conn(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek conn.log record -> zeek_conn row. None if unusable."""
    src = zeek_value(rec.get("id.orig_h", ""))
    dst = zeek_value(rec.get("id.resp_h", ""))
    if not src or not dst:
        return None
    ts = _safe_float(rec.get("ts"), 0.0)
    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "uid": rec.get("uid") or "",
        "src_addr": _to_ip(src),
        "src_port": _safe_int(rec.get("id.orig_p"), 0),
        "dst_addr": _to_ip(dst),
        "dst_port": _safe_int(rec.get("id.resp_p"), 0),
        "proto": rec.get("proto") or "",
        "service": rec.get("service") or "",
        "duration": _safe_float(rec.get("duration"), 0.0),
        "orig_bytes": _safe_int(rec.get("orig_bytes"), 0),
        "resp_bytes": _safe_int(rec.get("resp_bytes"), 0),
        "orig_pkts": _safe_int(rec.get("orig_pkts"), 0),
        "resp_pkts": _safe_int(rec.get("resp_pkts"), 0),
        "conn_state": rec.get("conn_state") or "",
        "history": rec.get("history") or "",
    }


def map_zeek_dns(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek dns.log record -> zeek_dns row. Core input for DNS-tunnel detection."""
    src = zeek_value(rec.get("id.orig_h", ""))
    if not src:
        return None
    ts = _safe_float(rec.get("ts"), 0.0)
    query = rec.get("query") or ""
    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "uid": rec.get("uid") or "",
        "src_addr": _to_ip(src),
        "dst_addr": _to_ip(zeek_value(rec.get("id.resp_h", "")) or "0.0.0.0"),
        "proto": rec.get("proto") or "",
        "trans_id": _safe_int(rec.get("trans_id"), 0),
        "query": query,
        "qtype": _safe_int(rec.get("qtype"), 0),
        "rcode": _safe_int(rec.get("rcode"), 0),
        "answers": rec.get("answers") or "",
        "query_len": len(query),
        # Shannon entropy of the left-most label: high entropy with a long name
        # is the classic DNS-tunnelling shape.
        "query_entropy": _label_entropy(query),
    }


def map_zeek_ssl(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek ssl.log record -> zeek_ssl row. JA4 feeds TLS-client fingerprinting.

    JA4 identifies the CLIENT software from the TLS ClientHello, which is in the clear
    even under TLS 1.3 -- so it is what makes encrypted traffic analyzable without any
    decryption. The same ClientHello always yields the same value, so a fingerprint
    seen once can be hunted for later, and a client that rotates domains but keeps its
    TLS stack stays recognisable.

    Replaces ja3/ja3s, which were dead columns: Zeek 9.x core ships no ja3 policy.
    """

    src = zeek_value(rec.get("id.orig_h", ""))
    dst = zeek_value(rec.get("id.resp_h", ""))
    if not src or not dst:
        return None
    ts = _safe_float(rec.get("ts"), 0.0)
    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "uid": rec.get("uid") or "",
        "src_addr": _to_ip(src),
        "dst_addr": _to_ip(dst),
        "dst_port": _safe_int(rec.get("id.resp_p"), 0),
        "version": rec.get("version") or "",
        "cipher": rec.get("cipher") or "",
        "server_name": rec.get("server_name") or "",
        "ja4": rec.get("ja4") or "",
        "ja4_orig": rec.get("ja4_o") or rec.get("ja4_orig") or "",
        "validation_status": rec.get("validation_status") or "",
        "established": 1 if (rec.get("established") or "").lower() in {"t", "true"} else 0,
    }


def map_zeek_notice(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek notice.log record -> zeek_notice row.

    Zeek's own curated detections (scan detection, protocol anomalies). These are
    packet-level evidence that corroborates the ML ensemble — they are ingested
    as an independent signal, not as an alert source of their own.
    """
    src = zeek_value(rec.get("src", "")) or zeek_value(rec.get("id.orig_h", ""))
    ts = _safe_float(rec.get("ts"), 0.0)
    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "uid": rec.get("uid") or "",
        "src_addr": _to_ip(src or "0.0.0.0"),
        "dst_addr": _to_ip(zeek_value(rec.get("dst", "")) or "0.0.0.0"),
        "note": rec.get("note") or "",
        "msg": rec.get("msg") or "",
        "sub": rec.get("sub") or "",
        "peer_descr": rec.get("peer_descr") or "",
        "actions": rec.get("actions") or "",
        "suppress_for": _safe_float(rec.get("suppress_for"), 0.0),
    }


def _label_entropy(name: str) -> float:
    """Shannon entropy of the longest DNS label (tunnelling indicator)."""
    import math

    parts = [p for p in name.split(".") if p]
    if not parts:
        return 0.0
    label = max(parts, key=len)
    if not label:
        return 0.0
    counts: dict[str, int] = {}
    for ch in label:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(label)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# ── Tier 1 mappers ─────────────────────────────────────────────────────────────
#
# These four logs were being WRITTEN AND DISCARDED. The site policy loads
# known-hosts and known-services, so Zeek produced http, files, ssh and weird on
# every deployment while the ingester knew only conn/dns/ssl/notice. Measured over a
# few hours on the test cluster: 359 http, 324 files, 155 ssh, 78 weird records lost.
#
# Field names below are taken from the live #fields headers of each log, not from
# documentation, because Zeek's field sets vary by version and a wrong name produces
# an empty column rather than an error.


def map_zeek_http(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek http.log record -> zeek_http row.

    THE highest-signal log for web-based activity and the one whose absence was most
    conspicuous: it carries the method, host, full URI and user agent, so
    "what did that host actually request?" becomes answerable. Nothing in NetFlow
    aggregates can answer that.

    PRIVACY: `uri` can contain usernames, session tokens and query parameters. This is
    the most PII-dense table Weirvern stores, which is why its TTL is the shortest.
    `password` from http.log is deliberately NOT ingested -- `capture_password` stays
    off, and storing plaintext credentials in an analytics store would be a liability
    with no analytic value.
    """
    src = zeek_value(rec.get("id.orig_h", ""))
    dst = zeek_value(rec.get("id.resp_h", ""))
    if not src or not dst:
        return None
    ts = _safe_float(rec.get("ts"), 0.0)
    uri = rec.get("uri") or ""
    # Zeek uses "-" for unset; normalise so an absent host is empty rather than "-",
    # which would otherwise be indistinguishable from a literal "-" hostname.
    host = rec.get("host") or ""
    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "uid": rec.get("uid") or "",
        "src_addr": _to_ip(src),
        "src_port": _safe_int(rec.get("id.orig_p"), 0),
        "dst_addr": _to_ip(dst),
        "dst_port": _safe_int(rec.get("id.resp_p"), 0),
        "method": rec.get("method") or "",
        "host": "" if host == ZEEK_NULL else host,
        "uri": uri,
        "referrer": rec.get("referrer") or "",
        "user_agent": rec.get("user_agent") or "",
        "status_code": _safe_int(rec.get("status_code"), 0),
        "resp_mime": "" if (rec.get("resp_mime_types") or "") == ZEEK_NULL
                     else (rec.get("resp_mime_types") or ""),
        "resp_bytes": _safe_int(rec.get("response_body_len"), 0),
        # Long URIs and high-entropy query strings are the shape of data-in-URL
        # exfiltration. Computed at ingest so a hunt does not re-parse every URI.
        "uri_len": len(uri),
        "uri_entropy": _label_entropy(uri.split("?")[-1] if "?" in uri else uri),
    }


def map_zeek_files(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek files.log record -> zeek_files row.

    Ties a transfer to a filename and a hash, which is what makes "did anything
    matching this indicator move?" answerable. `sha256` is kept separately from
    `filename` because the hash can be compared against threat intel WITHOUT exposing
    the filename -- the two have different privacy properties and different lifetimes.
    """
    src = zeek_value(rec.get("id.orig_h", ""))
    dst = zeek_value(rec.get("id.resp_h", ""))
    if not src or not dst:
        return None
    ts = _safe_float(rec.get("ts"), 0.0)
    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "uid": rec.get("uid") or "",
        "fuid": rec.get("fuid") or "",
        "src_addr": _to_ip(src),
        "dst_addr": _to_ip(dst),
        "f_source": rec.get("source") or "",
        "filename": rec.get("filename") or "",
        "mime_type": rec.get("mime_type") or "",
        "sha256": rec.get("sha256") or "",
        "md5": rec.get("md5") or "",
        "seen_bytes": _safe_int(rec.get("seen_bytes"), 0),
        "total_bytes": _safe_int(rec.get("total_bytes"), 0),
        "missing": _safe_int(rec.get("missing_bytes"), 0),
    }


def map_zeek_ssh(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek ssh.log record -> zeek_ssh row.

    `auth_success`, `auth_attempts` and `direction` together are the brute-force and
    lateral-movement signal. Direction matters: an inbound failure is someone attacking
    us, an outbound success is one of our hosts logging in somewhere else, and those are
    a perimeter problem versus a compromised-host problem.

    No credentials are ingested. `capture_password` stays off.
    """
    src = zeek_value(rec.get("id.orig_h", ""))
    dst = zeek_value(rec.get("id.resp_h", ""))
    if not src or not dst:
        return None
    ts = _safe_float(rec.get("ts"), 0.0)
    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "uid": rec.get("uid") or "",
        "src_addr": _to_ip(src),
        "src_port": _safe_int(rec.get("id.orig_p"), 0),
        "dst_addr": _to_ip(dst),
        "dst_port": _safe_int(rec.get("id.resp_p"), 0),
        "version": _safe_int(rec.get("version"), 0),
        "auth_success": 1 if (rec.get("auth_success") or "").lower() in {"t", "true"} else 0,
        "auth_attempts": _safe_int(rec.get("auth_attempts"), 0),
        "direction": rec.get("direction") or "",
        "client": rec.get("client") or "",
        "server": rec.get("server") or "",
    }


def map_zeek_weird(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek weird.log record -> zeek_weird row.

    Protocol anomalies: the layer where malformed or unexpected traffic surfaces before
    anyone has written a signature for it. Cheap and PII-free, so it keeps the longest
    TTL of the four.

    `notice` is Zeek's own flag for whether the weird also raised a Notice -- kept as a
    separate column because "the protocol did something odd" and "Zeek thought it worth
    alerting on" are very different volumes, and collapsing them would swamp the signal.
    """
    src = zeek_value(rec.get("id.orig_h", ""))
    dst = zeek_value(rec.get("id.resp_h", ""))
    if not src or not dst:
        return None
    ts = _safe_float(rec.get("ts"), 0.0)
    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "uid": rec.get("uid") or "",
        "src_addr": _to_ip(src),
        "src_port": _safe_int(rec.get("id.orig_p"), 0),
        "dst_addr": _to_ip(dst),
        "dst_port": _safe_int(rec.get("id.resp_p"), 0),
        "name": rec.get("name") or "",
        "noticed": 1 if (rec.get("notice") or "").lower() in {"t", "true"} else 0,
        "peer": rec.get("peer") or "",
    }


def _epoch_or_zero(val: Any) -> datetime:
    """A Zeek `time` field -> datetime, with the epoch itself as the "unset" value.

    Zeek writes unset time fields as `unset_field`, which is a string, so it cannot be fed to
    `datetime.fromtimestamp` at all. It ALSO writes a literal 0 for some unset times, which
    would otherwise become 1970-01-01 and look like real data from a clock-skewed host --
    a Kerberos ticket that expired 56 years ago is not a finding, it is a missing value.

    Returning the epoch for both cases keeps the column non-null (the schema is not Nullable)
    while making "absent" obvious in a query: `ticket_till > now()` is simply false for both,
    which is the correct semantics for a ticket we have no expiry for.
    """
    v = zeek_value(val if isinstance(val, str) else "")
    if v is None:
        return datetime.fromtimestamp(0)
    f = _safe_float(v, 0.0)
    return datetime.fromtimestamp(f) if f > 0 else datetime.fromtimestamp(0)


def map_zeek_kerberos(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek kerberos.log record -> zeek_kerberos row.

    The only source for Kerberoasting and AS-REP roasting: `request_type` plus the service
    principal and the client principal together describe "who asked for a ticket to what",
    which conn.log cannot express at all -- it sees a TCP flow to port 88 and nothing more.

    TWO FIELDS ARE RENAMED HERE, and the rename is deliberate. Zeek declares these as
    `from` and `till`; the schema column names are `ticket_from` and `ticket_till` because
    `from` is a SQL keyword and a column named for it invites quoting bugs in every query
    written against the table. The mapping is the ONE place that has to know both names, so
    getting it wrong here is a permanently empty column -- verified against the `&log`
    declarations in the installed Zeek source rather than against documentation.
    """
    src = zeek_value(rec.get("id.orig_h", ""))
    dst = zeek_value(rec.get("id.resp_h", ""))
    if not src or not dst:
        return None
    ts = _safe_float(rec.get("ts"), 0.0)

    # Zeek writes "unset_field" or "-" for booleans it did not set; anything else means true.
    def _bool(key: str) -> int:
        v = zeek_value(rec.get(key, ""))
        if v is None:
            return 0
        return 0 if v.lower() in ("f", "false", "0") else 1

    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "uid": rec.get("uid") or "",
        "src_addr": _to_ip(src),
        "dst_addr": _to_ip(dst),
        "dst_port": _safe_int(rec.get("id.resp_p"), 0),
        "request_type": rec.get("request_type") or "",
        "client": rec.get("client") or "",
        "service": rec.get("service") or "",
        "success": _bool("success"),
        # `error_code` is NOT read: Zeek 9.0.0 declares it `&optional` without `&log`, so it
        # never reaches the log. `error_msg` carries the same signal as text.
        "error_msg": rec.get("error_msg") or "",
        "ticket_from": _epoch_or_zero(rec.get("from")),
        "ticket_till": _epoch_or_zero(rec.get("till")),
        "cipher": rec.get("cipher") or "",
        "forwardable": _bool("forwardable"),
        "renewable": _bool("renewable"),
    }


def map_zeek_dce_rpc(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek dce_rpc.log record -> zeek_dce_rpc row.

    PsExec, WMI and scheduled-task execution are the canonical lateral-movement paths, and all
    three arrive as DCE/RPC to a named pipe. In conn.log this is indistinguishable from
    ordinary SMB file traffic; `endpoint` + `operation` is what names the action.
    """
    src = zeek_value(rec.get("id.orig_h", ""))
    dst = zeek_value(rec.get("id.resp_h", ""))
    if not src or not dst:
        return None
    ts = _safe_float(rec.get("ts"), 0.0)
    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "uid": rec.get("uid") or "",
        "src_addr": _to_ip(src),
        "dst_addr": _to_ip(dst),
        "dst_port": _safe_int(rec.get("id.resp_p"), 0),
        # Zeek logs rtt as an `interval` -- seconds, possibly fractional.
        "rtt": _safe_float(rec.get("rtt"), 0.0),
        "named_pipe": rec.get("named_pipe") or "",
        "endpoint": rec.get("endpoint") or "",
        "operation": rec.get("operation") or "",
    }


def map_zeek_smb_mapping(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek smb_mapping.log record -> zeek_smb_mapping row.

    The SHARE PATH. conn.log reports `service=smb` and nothing else, so access to ADMIN$ or
    C$ -- the share-write primitive of nearly every lateral-movement tool -- is invisible
    without this. `path` includes hostnames and sometimes usernames, which is why the table
    carries a shorter TTL than the flow tables.
    """
    src = zeek_value(rec.get("id.orig_h", ""))
    dst = zeek_value(rec.get("id.resp_h", ""))
    if not src or not dst:
        return None
    ts = _safe_float(rec.get("ts"), 0.0)
    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "uid": rec.get("uid") or "",
        "src_addr": _to_ip(src),
        "dst_addr": _to_ip(dst),
        "path": rec.get("path") or "",
        "service": rec.get("service") or "",
        "native_file_system": rec.get("native_file_system") or "",
        "share_type": rec.get("share_type") or "",
    }


def map_zeek_smb_files(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek smb_files.log record -> zeek_smb_files row.

    Action-level file semantics: a WRITE followed by a remote service start is tool transfer;
    a burst of RENAME and DELETE across many files is ransomware. Those are facts about
    actions, and no byte-count feature can express them.

    FIELD NAME: Zeek declares the basename as `name`, not `filename` -- confirmed from the
    `&log` declaration in base/protocols/smb/main.zeek. The column is called `filename` for
    consistency with zeek_files, so the rename happens here. Reading `filename` from the
    record would have yielded a permanently empty basename column while `path` populated,
    which is the kind of defect that looks like "Zeek just isn't logging it".
    """
    src = zeek_value(rec.get("id.orig_h", ""))
    dst = zeek_value(rec.get("id.resp_h", ""))
    if not src or not dst:
        return None
    ts = _safe_float(rec.get("ts"), 0.0)
    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "uid": rec.get("uid") or "",
        "src_addr": _to_ip(src),
        "dst_addr": _to_ip(dst),
        "fuid": rec.get("fuid") or "",
        "action": rec.get("action") or "",
        "path": rec.get("path") or "",
        "filename": rec.get("name") or "",
        "size": _safe_int(rec.get("size"), 0),
        "prev_name": rec.get("prev_name") or "",
    }


def map_zeek_ntlm(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek ntlm.log record -> zeek_ntlm row.

    username + hostname + domainname is a bipartite identity graph, and pass-the-hash is
    visible only in its shape: ONE credential appearing against MANY hosts inside a short
    window. No single field shows that, which is why the aggregation (ntlm_identity_daily,
    fed by a materialized view) exists rather than a query over raw rows.
    """
    src = zeek_value(rec.get("id.orig_h", ""))
    dst = zeek_value(rec.get("id.resp_h", ""))
    if not src or not dst:
        return None
    ts = _safe_float(rec.get("ts"), 0.0)
    v = zeek_value(rec.get("success", ""))
    success = 0 if v is None or v.lower() in ("f", "false", "0") else 1
    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "uid": rec.get("uid") or "",
        "src_addr": _to_ip(src),
        "dst_addr": _to_ip(dst),
        "username": rec.get("username") or "",
        "hostname": rec.get("hostname") or "",
        "domainname": rec.get("domainname") or "",
        "success": success,
    }


def map_zeek_dhcp(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek dhcp.log record -> zeek_dhcp row.

    THE ONLY LOG WITH L2 IDENTITY. It converts an IP address into a MAC and a hostname, which is
    what makes every other log attributable after a lease expires -- and what lets a per-host
    baseline key on something stable, since a MAC persists across leases and an IP does not.

    A `server_addr` that is not this network's DHCP server is a rogue DHCP server, which is the
    whole detection for this log.

    NO ADDRESS PAIR IS REQUIRED, unlike every other mapper here: DHCP is broadcast, so
    `id.orig_h` is 0.0.0.0 in a DISCOVER and there is no meaningful source/destination pair. The
    row is keyed on the MAC instead, which is the field that identifies the client.
    """
    ts = _safe_float(rec.get("ts"), 0.0)
    mac = rec.get("mac") or ""
    # `client_addr` is 0.0.0.0 for a DISCOVER, which is legitimate, not missing -- so this
    # mapper does not reject on a zero address the way the identity mappers do.
    client = zeek_value(rec.get("client_addr", "")) or "0.0.0.0"
    server = zeek_value(rec.get("server_addr", "")) or "0.0.0.0"

    # `uids` is a SET in Zeek: one DHCP transaction can span several connections. Joined because
    # nothing needs per-element identity and a vector is awkward to query.
    uids = rec.get("uids") or ""
    if uids:
        uids = uids.replace("\x01", ",").replace(",", ",")  # Zeek's set separator is a comma

    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "uids": uids,
        "client_addr": _to_ip(client),
        "server_addr": _to_ip(server),
        "mac": mac,
        "host_name": rec.get("host_name") or "",
        "client_fqdn": rec.get("client_fqdn") or "",
        "domain": rec.get("domain") or "",
        "requested_addr": _to_ip(zeek_value(rec.get("requested_addr", "")) or "0.0.0.0"),
        "assigned_addr": _to_ip(zeek_value(rec.get("assigned_addr", "")) or "0.0.0.0"),
        # `lease_time` and `duration` are Zeek INTERVALS -- seconds, possibly fractional.
        "lease_time": _safe_float(rec.get("lease_time"), 0.0),
        "msg_types": (rec.get("msg_types") or "").replace("\x01", ","),
        "duration": _safe_float(rec.get("duration"), 0.0),
    }


def map_zeek_x509(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek x509.log record -> zeek_x509 row.

    WHAT ssl.log STRUCTURALLY CANNOT SAY. It carries `cert_chain_fps`, a vector of fingerprint
    strings -- so it can identify a certificate but not describe one. Whether that certificate is
    self-signed, a CA, expired, short-key, or carries a SAN contradicting the SNI exists only here.

    `subject == issuer` is the self-signed test, and it is a comparison between two stored columns,
    which is why both are kept verbatim rather than parsed.

    Zeek's x509 record is NESTED: certificate.subject, san.dns, basic_constraints.ca. The columns
    are flattened here so a query does not have to walk the nesting, and so the schema does not
    depend on a record layout that a Zeek upgrade could change.
    """
    ts = _safe_float(rec.get("ts"), 0.0)
    fingerprint = rec.get("fingerprint") or ""
    if not fingerprint:
        # Without the fingerprint this row cannot be joined to ssl.log, which is its only purpose.
        return None

    def _epoch(key: str) -> datetime:
        return _epoch_or_zero(rec.get(key))

    def _bool(key: str) -> int:
        # Zeek writes "T"/"F" for booleans, and `-` for unset. Anything not recognisably true is
        # false -- an unset CA flag must not read as "this is a CA", which is the opposite of safe.
        v = zeek_value(rec.get(key, ""))
        return 1 if v is not None and v.lower() in ("t", "true", "1") else 0

    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "fingerprint": fingerprint,
        "subject": rec.get("certificate.subject") or rec.get("subject") or "",
        "issuer": rec.get("certificate.issuer") or rec.get("issuer") or "",
        "common_name": rec.get("certificate.cn") or rec.get("certificate.common_name") or "",
        "not_valid_before": _epoch("certificate.not_valid_before"),
        "not_valid_after": _epoch("certificate.not_valid_after"),
        "key_alg": rec.get("certificate.key_alg") or "",
        "key_length": _safe_int(rec.get("certificate.key_length"), 0),
        "sig_alg": rec.get("certificate.sig_alg") or "",
        "is_ca": _bool("basic_constraints.ca"),
        # The SAN list joined: `server_name NOT IN san_dns` needs the whole list to mean anything.
        "san_dns": (rec.get("san.dns") or "").replace("\x01", ","),
        "host_cert": _bool("host_cert"),
        "client_cert": _bool("client_cert"),
    }


def map_zeek_tunnel(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek tunnel.log record -> zeek_tunnel row.

    THE EXISTENCE OF A ROW IS THE FINDING. Zeek's own documentation says an unexpected
    tunnel.log entry is worth investigating in its own right, which is unusual -- most logs need
    interpretation before they mean anything.

    conn.log carries `tunnel_parents`, a set of UIDs: it says a connection is related to a tunnel
    but never what KIND. The encapsulation type (GRE, TEREDO, VXLAN, IP-in-IP, ...) is only here,
    and it is the difference between "expected site-to-site" and "protocol tunnelling for evasion".
    """
    src = zeek_value(rec.get("id.orig_h", ""))
    dst = zeek_value(rec.get("id.resp_h", ""))
    if not src or not dst:
        # Both addresses are needed: a tunnel is a relationship, and half of one cannot be
        # reported or acted on.
        return None
    ts = _safe_float(rec.get("ts"), 0.0)
    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "uid": rec.get("uid") or "",
        "src_addr": _to_ip(src),
        "dst_addr": _to_ip(dst),
        "tunnel_type": rec.get("tunnel_type") or "",
        "action": rec.get("action") or "",
    }


def map_zeek_quic(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek quic.log record -> zeek_quic row.

    THE TLS BLIND SPOT. QUIC is encrypted at the transport layer and never reaches ssl.log, so a
    host that moves its C2 to QUIC is invisible to a corpus built on TLS records. This recovers
    the SNI (`server_name`) and the ALPN protocol, which is what makes the connection nameable
    rather than merely visible.

    `version` is kept because QUIC version distinguishes implementations, and the handshake
    `history` is deliberately NOT kept: it is Zeek's connection-state string, and the equivalent
    is already a conn.log feature.
    """
    src = zeek_value(rec.get("id.orig_h", ""))
    dst = zeek_value(rec.get("id.resp_h", ""))
    if not src or not dst:
        return None
    ts = _safe_float(rec.get("ts"), 0.0)
    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "uid": rec.get("uid") or "",
        "src_addr": _to_ip(src),
        "dst_addr": _to_ip(dst),
        "dst_port": _safe_int(rec.get("id.resp_p"), 0),
        "server_name": rec.get("server_name") or "",
        "client_protocol": rec.get("client_protocol") or "",
        "version": rec.get("version") or "",
    }


def map_zeek_ldap_search(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek ldap_search.log record -> zeek_ldap_search row.

    AD ENUMERATION IS DEFINED BY FILTER CONTENT. Nothing else in the corpus exposes directory
    queries at all -- no other log can say what was searched for. `result_count` is a clean numeric
    outlier feature (a search returning thousands of objects is enumeration), and the filter's
    NOVELTY is the BloodHound-style signal.

    NO CREDENTIAL IS STORED, and that is Zeek's default rather than a choice made here:
    `default_capture_password` is false, so bind arguments are redacted before they reach the log.
    Recorded because a reader seeing an LDAP table would reasonably ask.
    """
    src = zeek_value(rec.get("id.orig_h", ""))
    dst = zeek_value(rec.get("id.resp_h", ""))
    if not src or not dst:
        return None
    ts = _safe_float(rec.get("ts"), 0.0)
    return {
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "uid": rec.get("uid") or "",
        "src_addr": _to_ip(src),
        "dst_addr": _to_ip(dst),
        "dst_port": _safe_int(rec.get("id.resp_p"), 0),
        "ldap_filter": rec.get("filter") or "",
        "base_object": rec.get("base_object") or "",
        "scope": rec.get("scope") or "",
        "deref_aliases": rec.get("deref_aliases") or "",
        "result_count": _safe_int(rec.get("result_count"), 0),
        "result": rec.get("result") or "",
    }


def map_zeek_software(rec: dict[str, str]) -> dict[str, Any] | None:
    """Zeek software.log record -> host_identity observation, not a table row.

    WHY THIS ONE IS DIFFERENT FROM EVERY OTHER MAPPER. The other seventeen map a log to a TABLE
    the GUI reads. software.log is not a table -- it is the single best OS signal the sensor
    produces, because the banner NAMES the platform:

        OpenSSH_10.2p1 Ubuntu-2ubuntu3.6      -> Ubuntu, said by the build itself
        Mozilla/5.0 (Windows NT 10.0; ...)    -> Windows, said by the client

    So it feeds `host_fingerprints`, which is the OBSERVATION store, and classification happens
    in a separate pass (weirvern/host_identity.py). Recording the raw banner rather than a label
    is what lets a better reference table re-score history instead of only affecting new traffic.

    Returns the observation as a dict under a distinct shape so the caller can tell it apart from
    a table row; `None` when there is nothing usable.
    """
    host = zeek_value(rec.get("host", ""))
    if not host:
        return None
    # `unparsed_version` is the raw banner and is preferred; name+version is Zeek's parse of it.
    banner = zeek_value(rec.get("unparsed_version", "")) or ""
    name = zeek_value(rec.get("name", "")) or ""
    version = ".".join(
        part for part in (
            zeek_value(rec.get("version.major", "")),
            zeek_value(rec.get("version.minor", "")),
            zeek_value(rec.get("version.minor2", "")),
        ) if part and part != "-"
    )
    raw = banner or f"{name} {version}".strip()
    if not raw:
        return None
    ts = _safe_float(rec.get("ts"), 0.0)
    return {
        "_observation": True,
        "ts": datetime.fromtimestamp(ts) if ts else datetime.now(),
        "src_addr": host,
        # software.log carries no MAC. The DHCP path supplies it, and the identity pass joins
        # them by address -- a gap here is expected, not a defect.
        "mac": "",
        "source": "software",
        "raw": raw,
        "note": zeek_value(rec.get("software_type", "")) or "",
    }


ZEEK_MAPPERS = {
    "conn": ("weirvern.zeek_conn", map_zeek_conn),
    "dns": ("weirvern.zeek_dns", map_zeek_dns),
    "ssl": ("weirvern.zeek_ssl", map_zeek_ssl),
    "notice": ("weirvern.zeek_notice", map_zeek_notice),
    # Tier 1. Zeek already wrote these on every deployment and the ingester dropped
    # them, so the tables are new but the data has been flowing all along.
    "http": ("weirvern.zeek_http", map_zeek_http),
    "files": ("weirvern.zeek_files", map_zeek_files),
    "ssh": ("weirvern.zeek_ssh", map_zeek_ssh),
    "weird": ("weirvern.zeek_weird", map_zeek_weird),
    # Tier 2, the identity and lateral-movement set. The schema for these landed in
    # 004_zeek_identity.sql, and until a mapper exists the log file is read, discarded, and
    # the six tables stay empty -- which is exactly the failure mode a schema alone cannot
    # reveal, because an empty table looks like a quiet network.
    "kerberos": ("weirvern.zeek_kerberos", map_zeek_kerberos),
    "dce_rpc": ("weirvern.zeek_dce_rpc", map_zeek_dce_rpc),
    "smb_mapping": ("weirvern.zeek_smb_mapping", map_zeek_smb_mapping),
    "smb_files": ("weirvern.zeek_smb_files", map_zeek_smb_files),
    "ntlm": ("weirvern.zeek_ntlm", map_zeek_ntlm),
    # Tier 3: identity attributes, encapsulation, and the TLS blind spot. Chosen from two
    # independent research passes over every log Zeek 9.0.0 ships; see
    # weirvern/schema/006_zeek_tier3.sql for why these five and why not the other sixty-odd.
    "dhcp": ("weirvern.zeek_dhcp", map_zeek_dhcp),
    "x509": ("weirvern.zeek_x509", map_zeek_x509),
    "tunnel": ("weirvern.zeek_tunnel", map_zeek_tunnel),
    "quic": ("weirvern.zeek_quic", map_zeek_quic),
    "ldap_search": ("weirvern.zeek_ldap_search", map_zeek_ldap_search),
}

# LOGS THAT FEED THE IDENTITY STORE INSTEAD OF A TABLE.
#
# software.log has no table, and does not want one: it is the strongest passive OS signal the
# sensor produces (the banner names its own platform), so it goes to `host_fingerprints` as an
# OBSERVATION and classification happens in a separate pass. Keeping it in a SECOND registry
# rather than in ZEEK_MAPPERS is deliberate: the invariant "every mapper in ZEEK_MAPPERS targets
# a weirvern.zeek_* table" is then still true and still checked, instead of being weakened to
# admit one exception that a later reader would have to know about.
ZEEK_OBSERVATION_MAPPERS = {
    "software": map_zeek_software,
}

# Insert column order per Zeek table (first key is the row's identity column).
ZEEK_COLUMNS = {
    "conn": ["ts", "uid", "src_addr", "src_port", "dst_addr", "dst_port", "proto",
             "service", "duration", "orig_bytes", "resp_bytes", "orig_pkts",
             "resp_pkts", "conn_state", "history"],
    "dns": ["ts", "uid", "src_addr", "dst_addr", "proto", "trans_id", "query",
            "qtype", "rcode", "answers", "query_len", "query_entropy"],
    "ssl": ["ts", "uid", "src_addr", "dst_addr", "dst_port", "version", "cipher",
            "server_name", "ja4", "ja4_orig", "validation_status", "established"],
    "notice": ["ts", "uid", "src_addr", "dst_addr", "note", "msg", "sub",
               "peer_descr", "actions", "suppress_for"],
    # Order must match the INSERT in the writer and the CREATE TABLE column order.
    "http": ["ts", "uid", "src_addr", "src_port", "dst_addr", "dst_port", "method",
             "host", "uri", "referrer", "user_agent", "status_code", "resp_mime",
             "resp_bytes", "uri_len", "uri_entropy"],
    "files": ["ts", "uid", "fuid", "src_addr", "dst_addr", "f_source", "filename",
              "mime_type", "sha256", "md5", "seen_bytes", "total_bytes", "missing"],
    "ssh": ["ts", "uid", "src_addr", "src_port", "dst_addr", "dst_port", "version",
            "auth_success", "auth_attempts", "direction", "client", "server"],
    "weird": ["ts", "uid", "src_addr", "src_port", "dst_addr", "dst_port", "name",
              "noticed", "peer"],
    # Tier 2. These orders must match BOTH the mapper's dict and the CREATE TABLE column
    # order in 004_zeek_identity.sql -- the writer builds a positional INSERT from them.
    "kerberos": ["ts", "uid", "src_addr", "dst_addr", "dst_port", "request_type", "client",
                 "service", "success", "error_msg", "ticket_from", "ticket_till", "cipher",
                 "forwardable", "renewable"],
    "dce_rpc": ["ts", "uid", "src_addr", "dst_addr", "dst_port", "rtt", "named_pipe",
                "endpoint", "operation"],
    "smb_mapping": ["ts", "uid", "src_addr", "dst_addr", "path", "service",
                    "native_file_system", "share_type"],
    "smb_files": ["ts", "uid", "src_addr", "dst_addr", "fuid", "action", "path",
                  "filename", "size", "prev_name"],
    "ntlm": ["ts", "uid", "src_addr", "dst_addr", "username", "hostname", "domainname",
             "success"],
    # Tier 3. These MUST match the CREATE TABLE order in 006_zeek_tier3.sql -- the writer builds
    # a positional INSERT, so a mismatch writes values into the wrong columns silently.
    "dhcp": ["ts", "uids", "client_addr", "server_addr", "mac", "host_name", "client_fqdn",
             "domain", "requested_addr", "assigned_addr", "lease_time", "msg_types", "duration"],
    "x509": ["ts", "fingerprint", "subject", "issuer", "common_name", "not_valid_before",
             "not_valid_after", "key_alg", "key_length", "sig_alg", "is_ca", "san_dns",
             "host_cert", "client_cert"],
    "tunnel": ["ts", "uid", "src_addr", "dst_addr", "tunnel_type", "action"],
    "quic": ["ts", "uid", "src_addr", "dst_addr", "dst_port", "server_name", "client_protocol",
             "version"],
    "ldap_search": ["ts", "uid", "src_addr", "dst_addr", "dst_port", "ldap_filter", "base_object",
                    "scope", "deref_aliases", "result_count", "result"],
}


class ZeekTailState:
    """Cursor for one Zeek log: offset, file instance, and cached `#fields` header.

    The header must be cached: a Zeek data line is positional and meaningless
    without its `#fields` names, but a resumed read starts part-way through the
    file (we deliberately hold back a partial trailing line), so the header is no
    longer in front of the data. Without it the record that completed the partial
    line is silently dropped (verified).
    """

    __slots__ = ("offset", "inode", "identity", "separator", "fields")

    def __init__(self, offset: int = 0, inode: int = 0,
                 identity: tuple[int, int, int] | None = None,
                 separator: str = "\t", fields: list[str] | None = None) -> None:
        self.offset = offset
        self.inode = inode
        self.identity = identity
        self.separator = separator
        self.fields = fields or []

    def note_read(self, st: os.stat_result, end_offset: int) -> None:
        self.offset = end_offset
        self.inode = st.st_ino
        self.identity = _file_identity(st)

    def clear_header(self) -> None:
        self.separator, self.fields = "\t", []

    def reset_reason(self, st: os.stat_result, path: str | None = None) -> str:
        return "" if self.identity is None else TailState(
            self.offset, self.inode, self.identity
        ).reset_reason(st, path)


def _record_observations(client: Inserter, rows: list[dict[str, Any]]) -> int:
    """Write raw fingerprint observations with no interpretation.

    Deliberately dumb: it stores `raw` verbatim and leaves every judgement to the identity pass.
    Storing the raw string is what makes the reference tables correctable -- a label written here
    could never be re-derived, and a wrong label next to a correct raw value is unrecoverable.

    A failure here must NOT stop ingest. Identification is an enrichment; losing flow data
    because a fingerprint row could not be written would be trading the important thing for the
    useful one.
    """
    from weirvern.host_identity import record_observation

    written = 0
    for r in rows:
        try:
            record_observation(
                client,
                ts=r.get("ts") or datetime.now(),
                src_addr=str(r.get("src_addr") or ""),
                mac=str(r.get("mac") or ""),
                source=str(r.get("source") or ""),
                raw=str(r.get("raw") or ""),
                note=str(r.get("note") or ""),
            )
            written += 1
        except Exception as exc:  # noqa: BLE001
            logger.debug("fingerprint observation dropped (%s): %s", r.get("source"), exc)
    return written


def observations_from_dhcp(rec: dict[str, str], row: dict[str, Any]) -> list[dict[str, Any]]:
    """A DHCP record yields up to three observations: MAC vendor, hostname, and FQDN.

    DHCP is valuable out of proportion to its size because it arrives BEFORE any application
    traffic: a host that has just booted is identifiable from its lease, which is exactly when an
    unknown device on the segment is most interesting and least observable otherwise.

    The MAC is the stable identifier here. A baseline keyed on IP loses its subject the moment a
    lease turns over -- a re-imaged machine inherits the address and would otherwise look like
    the same host.
    """
    out: list[dict[str, Any]] = []
    ts = row.get("ts") or datetime.now()
    # `client_addr` is 0.0.0.0 in a DISCOVER, which is why the MAC carries the identity.
    addr = str(row.get("client_addr") or "") or ""
    if addr in {"0.0.0.0", ""}:
        # Fall back to the requested or assigned address so a DISCOVER is still attributable.
        addr = str(row.get("assigned_addr") or row.get("requested_addr") or "") or ""
    mac = zeek_value(rec.get("mac", "")) or ""
    if not addr:
        return out
    if mac:
        out.append({"ts": ts, "src_addr": addr, "mac": mac, "source": "oui",
                    "raw": mac, "note": "from dhcp"})
    for field, source in (("host_name", "dhcp_hostname"), ("client_fqdn", "dhcp_fqdn")):
        value = zeek_value(rec.get(field, "")) or ""
        if value:
            out.append({"ts": ts, "src_addr": addr, "mac": mac, "source": source,
                        "raw": value, "note": "from dhcp"})
    return out


def observations_from_ssl(rec: dict[str, str], row: dict[str, Any]) -> list[dict[str, Any]]:
    """A TLS record yields the JA4 fingerprint, when one was computed.

    THE EMPTY CASE IS THE COMMON ONE AND MUST NOT PRODUCE A ROW. Zeek writes `-` for a record it
    could not fingerprint, and storing that as an observation would put a row in the table that
    looks like evidence and carries none -- which is how a host ends up reported as "classified"
    on the strength of a dash.
    """
    out: list[dict[str, Any]] = []
    ja4 = zeek_value(rec.get("ja4", "")) or ""
    src = str(row.get("src_addr") or "")
    if not src or not ja4 or ja4 in {"-", "(empty)"}:
        return out
    out.append({"ts": row.get("ts") or datetime.now(), "src_addr": src, "mac": "",
                "source": "ja4", "raw": ja4, "note": "from ssl"})
    return out


def tail_zeek_log(client: Inserter, path: str, state: ZeekTailState | None = None,
                  offset: int | None = None, known_inode: int | None = None,
                  header: tuple[str, list[str]] | None = None
                  ) -> tuple[int, int, int, tuple[str, list[str]]]:
    """Read new records from one Zeek log file.

    Returns (inserted, final_offset, final_inode, (separator, fields)).

    Prefer passing the same `ZeekTailState` on every pass: it carries the file
    instance (for rotation) and the parsed header (required on a mid-file
    resume). The offset/inode/header parameters remain for compatibility.
    """
    if not os.path.exists(path):
        if state is not None:
            return 0, state.offset, state.inode, (state.separator, state.fields)
        return 0, offset or 0, known_inode or 0, header or ("\t", [])

    st = os.stat(path)

    if state is not None:
        start_offset = state.offset
        why = state.reset_reason(st, path)
        separator, fields = state.separator, list(state.fields)
    else:
        start_offset = offset or 0
        why = ""
        if known_inode is not None and st.st_ino != known_inode:
            why = f"inode {known_inode} -> {st.st_ino}"
        elif st.st_size < start_offset:
            why = f"truncated ({st.st_size} < {start_offset})"
        elif start_offset and not _offset_is_on_boundary(path, start_offset):
            why = "content replaced (offset is not on a record boundary)"
        separator, fields = header if header else ("\t", [])

    if why:
        logger.info("Re-reading %s from start (%s)", path, why)
        start_offset = 0
        separator, fields = "\t", []  # a new file brings its own header

    log_type = os.path.basename(path).split(".")[0]
    # An observation mapper is not a table row: it is routed to the identity store below, so it
    # must be recognised here or the log would be read and silently discarded.
    target = ZEEK_MAPPERS.get(log_type)
    if target is None and log_type not in ZEEK_OBSERVATION_MAPPERS:
        if state is not None:
            return 0, start_offset, st.st_ino, (state.separator, state.fields)
        return 0, start_offset, st.st_ino, (separator, fields)
    # AN OBSERVATION LOG HAS NO TABLE. Its rows are fingerprint observations for the identity
    # store, so they are collected here and written without a table tuple or a column list --
    # which is also why `software` is absent from ZEEK_COLUMNS.
    if log_type in ZEEK_OBSERVATION_MAPPERS:
        table, mapper, columns = None, ZEEK_OBSERVATION_MAPPERS[log_type], None
    else:
        assert target is not None, f"{log_type} is in neither mapper registry"
        table, mapper = target
        columns = ZEEK_COLUMNS[log_type]

    inserted = 0
    consumed = start_offset
    batch: list[list[Any]] = []

    with open(path, encoding="utf-8", errors="replace") as fh:
        fh.seek(start_offset)
        while True:
            raw = fh.readline()
            if not raw:
                break
            # Hold back a partial trailing line (async writer) — see the
            # goflow2 tailer for the verified data-loss mode this prevents.
            if not raw.endswith("\n"):
                break
            consumed = fh.tell()
            line = raw.rstrip("\n")
            if not line:
                continue
            if line.startswith("#"):
                sep, parsed = parse_zeek_header([line])
                if parsed:
                    fields = parsed
                    separator = sep
                elif line.startswith("#separator"):
                    separator = sep
                continue
            if not fields:
                # No header seen yet and none cached: cannot map this line
                # safely (a wrong positional mapping is worse than a gap).
                logger.warning("Zeek %s: data before header, skipping a line", log_type)
                continue
            values = line.split(separator)
            rec = dict(zip(fields, values, strict=False))
            # NORMALISE ZEEK'S UNSET SENTINEL BEFORE THE MAPPER SEES IT.
            #
            # Zeek writes `-` for any field it did not set. Storing that literally makes an
            # absent value indistinguishable from a value that IS a hyphen, and it is the
            # kind of thing that only shows up in answers: a hunt for "requests with no
            # Referer" returns nothing while "requests whose Referer is -" returns the real
            # set, and nobody notices which one they ran.
            #
            # This was a measured bug, not a hypothetical: `map_zeek_http` normalised `host`
            # and `resp_mime` explicitly, and left `referrer` and `user_agent` storing the
            # literal `-`, because each mapper had to remember to do it per field. Doing it
            # once here means a mapper cannot forget -- and the per-field normalisations were
            # left in place, since they are now no-ops that document the intent.
            rec = {k: ("" if v == "-" else v) for k, v in rec.items()}
            row = mapper(rec)
            if row is None:
                continue
            # EXCLUSION APPLIES TO ZEEK ROWS TOO. A scanner shows up in conn.log exactly as it
            # does in NetFlow, and the two paths must agree about what the sensor refuses to learn
            # from -- one filter, installed once, consulted by both. Counting happens inside the
            # filter, so a drop is reported rather than inferred from a smaller number.
            if _excluded(row):
                continue
            # AN OBSERVATION IS NOT A TABLE ROW. software.log feeds the identity store rather
            # than a table, because classification is a separate pass over raw evidence (see
            # weirvern/host_identity.py for why). The mapper marks its rows so this path cannot
            # mistake one for the other and insert a banner into a column that expects a label.
            if log_type in ZEEK_OBSERVATION_MAPPERS or row.get("_observation"):
                _record_observations(client, [row])
                continue
            # TWO TABLE-BACKED LOGS ARE ALSO IDENTITY SOURCES, and the extraction happens here
            # because this is the only point where the RAW Zeek record and the mapped row are
            # both in hand. Re-deriving the MAC or the FQDN from the table later would mean
            # querying it back for data we are already holding.
            if log_type == "dhcp":
                _record_observations(client, observations_from_dhcp(rec, row))
            elif log_type == "ssl":
                _record_observations(client, observations_from_ssl(rec, row))
            if columns is None:
                # Already written by the observation path above; nothing is batched here.
                continue
            batch.append([row.get(c) for c in columns])
            if len(batch) >= BATCH_SIZE:
                client.insert(table, batch, column_names=columns)
                inserted += len(batch)
                batch = []
        if batch:
            client.insert(table, batch, column_names=columns)
            inserted += len(batch)

    if state is not None:
        state.separator, state.fields = separator, fields
        state.note_read(st, consumed)

    return inserted, consumed, st.st_ino, (separator, fields)


def tail_zeek_dir(client: Inserter, log_dir: str,
                  state: dict[str, ZeekTailState] | None = None
                  ) -> tuple[int, dict[str, ZeekTailState]]:
    """Tail every Weirvern-relevant Zeek log in a directory, including rotated ones.

    `state` maps filename -> ZeekTailState; pass the returned dict back on the
    next pass so only new records are read.

    ROTATION HANDLING — the naming matters and was previously wrong. Zeek
    rotates hourly and names the finished file by TIMESTAMP:

        conn.log                        <- current
        conn.2026-09-15-00-00-00.log    <- rotated

    Verified against Zeek's own source: `Log::default_rotation_date_format =
    "%Y-%m-%d-%H-%M-%S"` (scripts/base/frameworks/logging/main.zeek:170, used at
    :719). The previous implementation globbed `conn.1.log`, `conn.2.log`, ...,
    which Zeek never produces — so on a real sensor every rotated file was
    ignored and only whatever happened to be in the live file at each 5s pass was
    ingested. With hourly rotation that is very close to nothing.

    Ordering: rotated files are read OLDEST FIRST so records land in roughly
    chronological order, which matters because the materialized views window on
    the flow/connection time.
    """
    state = state if state is not None else {}
    total = 0
    for log_type in ZEEK_MAPPERS:
        for name in _zeek_log_names(log_dir, log_type):
            path = os.path.join(log_dir, name)
            st = state.get(name) or ZeekTailState()
            state[name] = st
            n, _off, _ino, _hdr = tail_zeek_log(client, path, state=st)
            if n:
                logger.info("Ingested %d %s records from %s", n, log_type, name)
            total += n
    return total, state


def _zeek_log_names(log_dir: str, log_type: str, depth: int = 50) -> list[str]:
    """Existing files for a log type: rotated siblings first (oldest first),
    then the live file.

    Matches Zeek's real rotation naming (`<type>.<timestamp>.log`) AND the
    `.log.json` variant that `@load tuning/json-logs` would produce, because
    guessing wrong here silently ingests nothing.

    `depth` bounds how many rotated files are read per pass. Zeek rotates hourly
    and the shipped retention is 24h, so ~24 is the working set; the default of
    50 leaves headroom without being unbounded.
    """
    # (timestamp-from-name, mtime, filename). The name's timestamp is the sort
    # key; mtime is only a tiebreaker for same-second rotations.
    rotated: list[tuple[str, float, str]] = []
    try:
        entries = os.listdir(log_dir)
    except FileNotFoundError:
        return []
    except OSError as exc:
        logger.warning("Cannot list Zeek log dir %s: %s", log_dir, exc)
        return []

    live_variants = {f"{log_type}.log", f"{log_type}.log.json"}
    for name in entries:
        if name in live_variants:
            continue
        # <type>.<something>.log  or  <type>.<something>.log.json
        if not name.startswith(f"{log_type}."):
            continue
        rest = name[len(log_type) + 1:]
        if not (rest.endswith(".log") or rest.endswith(".log.json")):
            continue
        # Guard against matching a different log type's prefix, e.g. "conn" vs
        # "conn_summary": the character after the type must be a digit (the
        # timestamp) — the shipped types are all lowercase words followed by a
        # date, so anything else is not ours.
        if not rest[:1].isdigit():
            continue
        path = os.path.join(log_dir, name)
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        # Sort key: the TIMESTAMP IN THE NAME, with mtime only as a tiebreaker.
        #
        # The name is authoritative because Zeek embeds the rotation time in it
        # ('conn.2026-09-15-01-00-00.log'). mtime happens to correlate on a live
        # sensor, but it breaks the moment the directory is copied, restored from
        # backup, or rsynced: the names are preserved and the mtimes are not. An
        # mtime sort then reads the newest file first, which pushes records into
        # ClickHouse out of order and can close a window before its records
        # arrive. The timestamp format is fixed-width and zero-padded, so plain
        # lexicographic order IS chronological order.
        ts = rest[: len("2026-09-15-00-00-00")]
        rotated.append((ts, mtime, name))
        continue

    rotated.sort(key=lambda t: (t[0], t[1]))   # oldest first, by name then mtime
    rotated = rotated[-depth:]                 # keep the newest `depth`
    names = [n for _ts, _mtime, n in rotated]

    for live in (f"{log_type}.log", f"{log_type}.log.json"):
        if os.path.exists(os.path.join(log_dir, live)):
            names.append(live)
    return names


# =============================================================================
# goflow2 JSONL tailer
# =============================================================================
def _file_identity(st: os.stat_result) -> tuple[int, int, int]:
    """Identity of a file *instance* for rotation/replacement detection.

    Inode alone is NOT sufficient (verified failure): when a log is rotated with
    `copytruncate`, or a file is replaced and the filesystem reuses the inode
    number (overlayfs and ext4 both do this), the inode is unchanged while the
    content is entirely new. If the replacement happens to be *larger* than the
    stored offset, a size check cannot detect it either — records are silently
    skipped and a mid-record fragment gets parsed as data (measured: 5 records
    written, 4 inserted).

    Comparing (inode, size, mtime_ns) catches that case: a genuinely replaced
    file carries a fresh mtime even when inode and size coincide.
    """
    return (st.st_ino, st.st_size, getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))


class TailState:
    """Cursor for one tailed file: where we stopped, and how to validate it.

    Rotation/replacement cannot be detected from inode, size, or mtime alone
    (measured): a file replaced by a LARGER one — the `copytruncate` rotation
    style, and what happens when the filesystem reuses the inode — looks exactly
    like an append by every stat() field. Detection therefore uses the content:
    for a line-oriented log, a valid continuation offset is preceded by a
    newline. If the byte before our saved offset is not a newline, the file is
    not the one we were reading and we must re-read from the start.

    `identity` is kept for diagnostics and for the inode/size fast paths.
    """

    __slots__ = ("offset", "inode", "identity")

    def __init__(self, offset: int = 0, inode: int = 0,
                 identity: tuple[int, int, int] | None = None) -> None:
        self.offset = offset
        self.inode = inode
        self.identity = identity

    def __iter__(self):
        # Preserve the historical (offset, inode) unpacking used by callers.
        yield self.offset
        yield self.inode

    def note_read(self, st: os.stat_result, end_offset: int) -> None:
        """Record the instance we just read and where we stopped."""
        self.offset = end_offset
        self.inode = st.st_ino
        self.identity = _file_identity(st)

    def reset_reason(self, st: os.stat_result, path: str | None = None) -> str:
        """Why the stored offset cannot be trusted for the current file ("" = ok)."""
        if self.offset == 0:
            return ""
        if self.identity is not None:
            prev_inode, prev_size, _ = self.identity
            if st.st_ino != prev_inode:
                return f"inode {prev_inode} -> {st.st_ino}"
            if st.st_size < self.offset:
                return f"truncated ({st.st_size} < {self.offset})"
            if path and not _offset_is_on_boundary(path, self.offset):
                return "content replaced (offset is not on a record boundary)"
        elif path and not _offset_is_on_boundary(path, self.offset):
            return "content replaced (offset is not on a record boundary)"
        return ""


def _offset_is_on_boundary(path: str, offset: int) -> bool:
    """True if `offset` sits just after a newline (a valid record boundary).

    This is the reliable replacement test for line-oriented logs. It is cheap:
    one seek + one byte read. On any read error we return True (fail open) so a
    transient I/O problem cannot trigger an expensive full re-read.
    """
    if offset <= 0:
        return True
    try:
        with open(path, "rb") as fh:
            fh.seek(offset - 1)
            return fh.read(1) == b"\n"
    except OSError:
        return True


def tail_and_insert(client: Inserter, path: str, once: bool = False,
                    offset: int | None = None, known_inode: int | None = None,
                    state: TailState | None = None) -> tuple[int, int, int]:
    """Tail `path` (JSONL) and batch-insert new records.

    Returns (inserted, final_offset, final_inode).

    Pass the SAME `TailState` object back on every pass: it carries the file
    instance we last read, which is what makes rotation detection correct (see
    `_file_identity`). `offset`/`known_inode` remain supported for callers that
    only track a 3-tuple; in that case replacement detection degrades to
    inode+truncation checks.

    Only COMPLETE (newline-terminated) lines are consumed: a partial trailing
    line is a write in progress, and consuming it loses the record permanently
    once the write finishes (verified).
    """
    if not os.path.exists(path):
        logger.info("Waiting for %s to appear...", path)
        return 0, offset or 0, known_inode or 0

    st = os.stat(path)

    if state is not None:
        start_offset = state.offset
        why = state.reset_reason(st, path)
    else:
        start_offset = offset or 0
        why = ""
        if known_inode is not None and st.st_ino != known_inode:
            why = f"inode {known_inode} -> {st.st_ino}"
        elif st.st_size < start_offset:
            why = f"truncated ({st.st_size} < {start_offset})"
        elif start_offset and not _offset_is_on_boundary(path, start_offset):
            why = "content replaced (offset is not on a record boundary)"

    if why:
        logger.info("Re-reading %s from start (%s)", path, why)
        start_offset = 0

    inserted = 0
    batch: list[dict[str, Any]] = []
    consumed = start_offset
    with open(path, encoding="utf-8", errors="replace") as fh:
        fh.seek(start_offset)
        while True:
            raw = fh.readline()
            if not raw:
                break
            if not raw.endswith("\n"):
                break  # partial write; leave it for the next pass
            consumed = fh.tell()
            line = raw.strip()
            if not line:
                continue
            try:
                batch.append(map_flow(json.loads(line)))
            except json.JSONDecodeError:
                logger.warning("Skipping malformed JSON line (%.80s…)", line)
            except Exception:  # noqa: BLE001
                logger.warning("Skipping unparsable flow line")
            if len(batch) >= BATCH_SIZE:
                inserted += insert_batch(client, batch)
                batch = []
        if batch:
            inserted += insert_batch(client, batch)
    final_offset = consumed
    if state is not None:
        state.note_read(st, final_offset)
    logger.info("Ingested %d flow records from %s (offset %d)", inserted, path, final_offset)
    return inserted, final_offset, st.st_ino


def tail_forever(client: Inserter, path: str, interval_s: float = 5.0,
                 zeek_dir: str = "") -> None:
    """Block forever: tail NetFlow JSONL and (optionally) Zeek logs.

    Duplicate-insert failure mode of the first v20 pass: re-reading the whole
    file from offset 0 every pass inserted every row ~12x per minute into
    `flows`, corrupting aggregates and baselines.
    """
    state = TailState()
    zeek_state: dict[str, ZeekTailState] = {}
    while True:
        try:
            _, offset, inode = tail_and_insert(client, path, state=state)
            if zeek_dir:
                _, zeek_state = tail_zeek_dir(client, zeek_dir, zeek_state)
        except Exception as exc:  # noqa: BLE001
            logger.error("Ingest pass failed: %s", exc)
        time.sleep(interval_s)


if __name__ == "__main__":
    # Standalone mode (dev/test): tail once then exit.
    import weirvern.db as fdb
    from weirvern.config import get_settings

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    settings = get_settings()
    ch = fdb.connect(settings, retries=10, delay_s=2)
    n = tail_and_insert(ch, settings.tail_file, once=True)
    if settings.zeek_log_dir:
        z, _ = tail_zeek_dir(ch, settings.zeek_log_dir)
        print(f"zeek_records={z}")
    print(f"inserted={n}")
    sys.exit(0)
