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


def insert_batch(client: Inserter, rows: list[dict[str, Any]]) -> int:
    if not rows:
        return 0
    client.insert("weirvern.flows", [[r[c] for c in _COLUMNS] for r in rows], column_names=_COLUMNS)
    return len(rows)


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
    """Zeek's unset_field sentinel means 'no value' -> None."""
    if val == ZEEK_NULL or val == "":
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
    """Zeek ssl.log record -> zeek_ssl row. JA3/JA3S feed C2 fingerprinting."""
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
        "ja3": rec.get("ja3") or "",
        "ja3s": rec.get("ja3s") or "",
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


ZEEK_MAPPERS = {
    "conn": ("weirvern.zeek_conn", map_zeek_conn),
    "dns": ("weirvern.zeek_dns", map_zeek_dns),
    "ssl": ("weirvern.zeek_ssl", map_zeek_ssl),
    "notice": ("weirvern.zeek_notice", map_zeek_notice),
}

# Insert column order per Zeek table (first key is the row's identity column).
ZEEK_COLUMNS = {
    "conn": ["ts", "uid", "src_addr", "src_port", "dst_addr", "dst_port", "proto",
             "service", "duration", "orig_bytes", "resp_bytes", "orig_pkts",
             "resp_pkts", "conn_state", "history"],
    "dns": ["ts", "uid", "src_addr", "dst_addr", "proto", "trans_id", "query",
            "qtype", "rcode", "answers", "query_len", "query_entropy"],
    "ssl": ["ts", "uid", "src_addr", "dst_addr", "dst_port", "version", "cipher",
            "server_name", "ja3", "ja3s", "validation_status", "established"],
    "notice": ["ts", "uid", "src_addr", "dst_addr", "note", "msg", "sub",
               "peer_descr", "actions", "suppress_for"],
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
    target = ZEEK_MAPPERS.get(log_type)
    if target is None:
        if state is not None:
            return 0, start_offset, st.st_ino, (state.separator, state.fields)
        return 0, start_offset, st.st_ino, (separator, fields)
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
            row = mapper(rec)
            if row is None:
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

    Rotation handling: Zeek rotates hourly and names the finished files
    `conn.1.log`, `conn.2.log`, ... while `conn.log` stays current. Reading only
    the current file silently misses every record written to a file that rotated
    between passes, so each rotated sibling is tailed too (bounded by
    `ZEEK_ROTATION_DEPTH` to avoid unbounded growth over a long run).
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


def _zeek_log_names(log_dir: str, log_type: str, depth: int = 5) -> list[str]:
    """Existing files for a log type: current first, then rotated siblings.

    Zeek's rotation naming is `<type>.log`, `<type>.1.log`, `<type>.2.log`, ...
    with the highest number being the OLDEST retained file.
    """
    names: list[str] = []
    if os.path.exists(os.path.join(log_dir, f"{log_type}.log")):
        names.append(f"{log_type}.log")
    for i in range(1, depth + 1):
        candidate = f"{log_type}.{i}.log"
        if os.path.exists(os.path.join(log_dir, candidate)):
            names.append(candidate)
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
