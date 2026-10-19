"""Build host-identity verdicts from the observations already stored.

WHERE THIS SITS, AND WHY IT IS A READ-TIME PASS RATHER THAN AN INGEST-TIME ONE.

Ingest writes OBSERVATIONS (`host_fingerprints`) with no interpretation. This module reads them
back, classifies, and writes the VERDICT (`host_identity`). That ordering matters for three
reasons, each of which has already cost this project real time in an adjacent form:

  * THE REFERENCE TABLES CAN IMPROVE WITHOUT RE-INGEST. When `KNOWN_SOFTWARE` gains an entry,
    re-running this pass re-scores every stored banner. If the label had been decided at ingest,
    every historical row would keep the old (wrong) answer forever, and the fix would appear to
    work only on new traffic.
  * AN INGEST-TIME ERROR IS PERMANENT. A classifier bug during ingest writes a wrong label next
    to a correct raw string, and nothing later can tell which rows were affected.
  * THE SAME SHAPE AS THE REST OF THE PIPELINE. Flow aggregates are written raw and scored by
    the worker; this is that pattern, applied to identification.

ONE QUERY FOR THE WHOLE PASS, NOT ONE PER HOST. The previous version of this kind of report
would have issued a query per host, which on a 245-host segment is 245 round trips to produce
one screen. The aggregation is done in ClickHouse and the classification in Python, which is the
same split the detection path uses.
"""
from __future__ import annotations

import contextlib
import json
import logging
from datetime import datetime, timedelta
from typing import Any

from clickhouse_connect.driver.client import Client

from weirvern import db
from weirvern.fingerprint import (
    OS_UNKNOWN,
    Signal,
    signal_from_dhcp,
    signal_from_ja4,
    signal_from_mac,
    signal_from_names,
    signal_from_software,
    summarise,
)

from .clock import age_seconds, as_aware, utcnow

logger = logging.getLogger(__name__)

# How far back an observation still counts toward a verdict.
#
# 7 days, and the number is a judgement that should be visible: long enough that a host which
# made one TLS connection last week is still identifiable, short enough that a machine that was
# re-imaged last month does not keep its old identity. Identity that has genuinely gone stale is
# better represented by no verdict than by a confident stale one.
IDENTITY_WINDOW_DAYS = 7

# WHICH SOURCES CARRY A NAME. The verdict's `hostnames_seen` gathers every one of these
# (2026-10-16: it read ONLY dhcp_*, and the sensed segment has no DHCP, so the list was empty
# for every host while the DNS view held the names). tls_sni and dns_name carry no classifier
# weight -- they are for the reader, and signals_for_host never turns them into a Signal.
HOSTNAME_SOURCES = ("dhcp_hostname", "dhcp_fqdn", "tls_sni", "dns_name")


def is_display_name(name: str) -> bool:
    """Whether a name is one A READER SHOULD SEE. One definition, two callers.

    The ingester's DNS extractor consults this so artifacts are never STORED, and the verdict's
    gather consults it so rows stored BEFORE the rule existed cannot leak them either -- the
    first live run of the new DNS source (2026-10-16) put mDNS service-type lookups
    (`_companion-link._tcp.local`) and reverse names (`....ip6.arpa`) into hostnames_seen beside
    the real ones, and those rows carry a 90-day TTL.

    A name must be present, bounded, not a bare address, not a service-TYPE lookup (leading
    underscore -- the mDNS instance name `Owen's iPad._companion-link._tcp.local` IS a device
    name and stays), and not a reverse lookup (`.arpa`).
    """
    import ipaddress  # noqa: PLC0415 -- stdlib; the same check the extractors make

    n = str(name or "").strip().lower().rstrip(".")
    if not n or len(n) > 253 or n in {"-", "(empty)"}:
        return False
    if n.startswith("_") or n.endswith(".arpa"):
        return False
    try:
        ipaddress.ip_address(n)
    except ValueError:
        return True
    return False


def collect_observations(client: Client, days: int = IDENTITY_WINDOW_DAYS) -> list[dict[str, Any]]:
    """Read every distinct observation in the window, newest first.

    DISTINCT because a host that made 400 TLS connections to the same server produced 400
    identical rows, and the classifier needs the DISTINCT fingerprints, not the count. The count
    is interesting (a host presenting 40 distinct fingerprints is a finding) and is kept as `n` so it
    survives rather than being thrown away by the dedup.
    """
    rows = db.fetch_rows(
        client,
        """
        SELECT
            src_addr,
            argMax(mac, ts)   AS mac,
            source,
            raw,
            count()           AS n,
            max(ts)           AS last_seen,
            min(ts)           AS first_seen
        FROM weirvern.host_fingerprints
        WHERE ts >= now() - INTERVAL %(d)s DAY
        GROUP BY src_addr, source, raw
        ORDER BY last_seen DESC
        """,
        d=int(days),
    )
    out = []
    for addr, mac, source, raw, n, last_seen, first_seen in rows:
        out.append({
            "src_addr": str(addr), "mac": str(mac or ""), "source": str(source),
            "raw": str(raw or ""), "n": int(n or 0),
            "last_seen": last_seen, "first_seen": first_seen,
        })
    return out


def signals_for_host(host: str, obs: list[dict[str, Any]]) -> tuple[list[Signal], dict[str, Any] | None]:
    """Turn one host's raw observations into Signals plus any decoded JA4 structure.

    Every source is routed through the classifier's OWN constructors rather than re-implementing
    the matching here, so the reference tables exist in exactly one place. A second copy of the
    matching logic is the drift class this project has shipped before.
    """
    signals: list[Signal] = []
    ja4_structure: dict[str, Any] | None = None

    for o in obs:
        src, raw = o["source"], o["raw"]
        if src == "software":
            # Zeek stores the banner; `raw` may be "OpenSSH_10.2p1 Ubuntu-2ubuntu3.6" or a
            # User-Agent. Both are handled by the same constructor, which is why the banner is
            # checked before the parsed name/version.
            sig = signal_from_software(name="", version="", unparsed=raw)
            if sig:
                signals.append(sig)
        elif src in {"dhcp_hostname", "dhcp_fqdn"}:
            if src == "dhcp_fqdn":
                signals.extend(signal_from_dhcp(client_fqdn=raw))
            else:
                signals.extend(signal_from_dhcp(host_name=raw))
        elif src == "oui":
            sig = signal_from_mac(raw)
            if sig:
                signals.append(sig)
        elif src == "ja4":
            sig, struct = signal_from_ja4(raw)
            if sig:
                signals.append(sig)
            if struct and ja4_structure is None:
                ja4_structure = struct
        elif src == "dns_name":
            # What the host's own browsing says about its stack (mDNS service discovery);
            # display names stay display names otherwise.
            sig = signal_from_names(src, raw)
            if sig:
                signals.append(sig)
        elif src == "ja4_structure":
            # Already decoded when stored; keep the first so the GUI shows one shape.
            if ja4_structure is None:
                # A malformed stored JSON is skipped rather than fatal: one bad row must not take
                # down a whole classification pass.
                with contextlib.suppress(ValueError, TypeError):
                    ja4_structure = json.loads(raw)

    return signals, ja4_structure


def build_identity(client: Client, days: int = IDENTITY_WINDOW_DAYS,
                   dry_run: bool = False) -> list[dict[str, Any]]:
    """Derive a verdict per host from stored observations, and persist them.

    Returns the verdicts as dicts so a caller (the CLI, the worker, a test) can inspect what was
    decided without reading the table back.
    """
    obs = collect_observations(client, days)
    if not obs:
        logger.info("host identity: no observations in the last %d days", days)
        return []

    by_host: dict[str, list[dict[str, Any]]] = {}
    for o in obs:
        by_host.setdefault(o["src_addr"], []).append(o)

    verdicts: list[dict[str, Any]] = []
    for host, own in by_host.items():
        signals, ja4_structure = signals_for_host(host, own)
        summary = summarise(signals, ja4_structure)

        mac = next((o["mac"] for o in own if o["mac"]), "")
        # The raw values that fed the verdict, kept for the GUI's evidence panel. Bounded to 20
        # each: a host presenting 400 fingerprints would otherwise store a row nobody can read, and
        # the COUNT is preserved above so the volume is still visible.
        software = [o["raw"] for o in own if o["source"] == "software"][:20]

        # NAMES FROM EVERY SOURCE THAT CARRIES ONE, newest first, deduped case-insensitively:
        # the same name seen 400 times is one name, and collect_observations already ordered
        # `own` by last_seen DESC.
        hostnames: list[str] = []
        _seen: set[str] = set()
        for o in own:
            if o["source"] not in HOSTNAME_SOURCES or not is_display_name(o["raw"]):
                continue
            value = str(o["raw"]).strip()
            if value and value.lower() not in _seen:
                _seen.add(value.lower())
                hostnames.append(value)
        hostnames = hostnames[:20]

        ja4_values = [o["raw"] for o in own if o["source"] == "ja4"][:20]

        verdicts.append({
            "host": host,
            "mac": mac,
            **summary,
            "software_seen": software,
            "hostnames_seen": hostnames,
            "ja4_seen": ja4_values,
            "observation_count": len(own),
        })

    if not dry_run and verdicts:
        persist(client, verdicts)
    logger.info("host identity: %d hosts classified from %d observations",
                len(verdicts), len(obs))
    return verdicts


def persist(client: Client, verdicts: list[dict[str, Any]]) -> None:
    """Write the verdicts. Column order is pinned in ONE list beside the row builder.

    A positional INSERT is correct only while the row and the column names agree in length and
    order. That is not a hypothetical here: an arity mismatch in the anomaly insert meant every
    detection in this project raised silently for hours. So the two are checked against each
    other before the insert rather than trusted.
    """
    now = utcnow()
    rows = []
    for v in verdicts:
        rows.append([
            now,
            v["host"],
            v.get("mac", ""),
            v["os"],
            v["os_label"],
            v["confidence"],
            float(v["score"]),
            # The AGREEING count, not the count of all sources: the schema names this column
            # "how many independent SOURCES agreed", and `sources` includes disagreeing ones.
            int(v.get("agreeing_sources") or 0),
            json.dumps(v.get("signals") or []),
            json.dumps(v.get("disagreement") or []),
            json.dumps(v.get("ja4_structure") or {}),
            json.dumps(v.get("software_seen") or []),
            json.dumps(v.get("hostnames_seen") or []),
            json.dumps(v.get("ja4_seen") or []),
        ])
    for row in rows:
        if len(row) != len(IDENTITY_COLUMNS):
            raise ValueError(
                f"host_identity row has {len(row)} values but {len(IDENTITY_COLUMNS)} column "
                "names; a positional INSERT must agree in length and order"
            )
    client.insert("weirvern.host_identity", rows, column_names=list(IDENTITY_COLUMNS))


# Column names in ONE place, beside the guard that checks the row length against it.
IDENTITY_COLUMNS: tuple[str, ...] = (
    "updated_at", "host", "mac", "os", "os_label", "confidence", "score",
    "agreeing_sources", "signals", "disagreement", "ja4_structure",
    "software_seen", "hostnames_seen", "ja4_seen",
)


def record_observation(client: Client, ts: datetime, src_addr: str, mac: str,
                       source: str, raw: str, os_guess: str = OS_UNKNOWN,
                       os_label: str = "", confidence: str = "", detail: str = "",
                       weight: float = 0.0, note: str = "") -> None:
    """Store ONE observation, uninterpreted. The writer the ingest path calls.

    `raw` is required and is the whole point: it is what makes a later, better reference table
    able to re-score this row. A row with a verdict but no raw string is a row that can never be
    corrected.
    """
    if not raw or raw in {"-", "(empty)"}:
        # An empty observation is not an observation. Storing it would put a row in the table
        # that looks like evidence and carries none, which is how a "0 signals" host gets
        # reported as a classified one.
        return
    client.insert(
        "weirvern.host_fingerprints",
        [[ts, src_addr, mac or "", source, raw, os_guess, os_label, confidence,
          detail, float(weight), note]],
        column_names=[
            "ts", "src_addr", "mac", "source", "raw", "os_guess", "os_label",
            "confidence", "detail", "weight", "note",
        ],
    )


def _as_local(dt: datetime) -> datetime:
    """Make a ClickHouse datetime comparable to `datetime.now()` without inventing an offset.

    ClickHouse returns timezone-AWARE values; `datetime.now()` is naive. Mixing them raises
    TypeError, and because this happens inside a request handler it surfaces as "cannot read"
    rather than as a computation error -- so the panel reports a database problem while the
    database is perfectly readable.

    The label must be LOCAL, which is what a naive `now()` means. `.replace(tzinfo=UTC)` is the
    tempting shortcut and it is wrong: it relabels local time as UTC, which shifts every age by
    the host's offset and can make it NEGATIVE. In the sibling module that made a sensor dead for
    five minutes report as running, because `stale = age > threshold` is never true of a negative
    number. `.astimezone()` attaches the system zone, which is what the naive value genuinely
    means; aware values pass through untouched.
    """
    if dt is None:
        return dt
    return as_aware(dt)

def identity_for_hosts(client: Client, hosts: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Current verdicts for specific hosts, keyed by address. For enriching other views.

    Takes {addr: mac} so a caller that knows the MAC gets the MAC-keyed identity too -- the same
    host can appear under a new address after a lease change, and keying only on address would
    report it as a brand-new unknown device.
    """
    if not hosts:
        return {}
    addrs = [a for a in hosts if a]
    macs = [m for m in hosts.values() if m]
    if not addrs and not macs:
        return {}
    # THE MAC CLAUSE IS WHY THIS TAKES A DICT. The docstring promises that a host reappearing
    # under a new DHCP address is still recognised, and the code did not do it: only the keys were
    # read, `mac` was not even in the SELECT, so the values were collected and discarded and a
    # lease change produced "a brand-new unknown device" -- the exact failure the parameter exists
    # to prevent, silently.
    rows = db.fetch_rows(
        client,
        """
        SELECT host, mac, os, os_label, confidence, score, agreeing_sources,
               signals, disagreement, ja4_structure, updated_at
        FROM weirvern.host_identity FINAL
        WHERE (host IN %(h)s OR mac IN %(m)s)
        """,
        h=tuple(addrs) or ("",),
        m=tuple(macs) or ("",),
    )
    out: dict[str, dict[str, Any]] = {}
    for (host, mac, os_name, os_label, conf, score, n_src, signals, disagreement,
         ja4_raw, updated) in rows:
        out[str(host)] = {
            "mac": str(mac or ""),
            "os": str(os_name), "os_label": str(os_label), "confidence": str(conf),
            "score": float(score or 0), "agreeing_sources": int(n_src or 0),
            "signals": _load(signals), "disagreement": _load(disagreement),
            "ja4_structure": _load(ja4_raw),
            "updated_at": updated,
            # SAME TRAP AS admin/status.py DOCUMENTS, and it bit here too. ClickHouse returns
            # timezone-AWARE datetimes while `datetime.now()` is naive, so subtracting them raises
            # TypeError -- and it raises INSIDE the caller, where a route's except turns it into
            # "cannot read host identity" while the data is fine. `_as_local` applies the rule:
            # label a naive value with the SYSTEM's local zone (what it actually means), never
            # with UTC, because relabelling local as UTC yields NEGATIVE ages.
            "age_s": (age_seconds(updated) if updated else None),
        }
    return out


def _load(value: Any) -> Any:
    """Parse a stored JSON column, returning empty rather than raising on a bad row.

    A single malformed row must not take down a whole view; the caller renders what it has and
    the empty value is visible as absent rather than as a crash.
    """
    if not value:
        return None
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return None


def coverage(client: Client, days: int = IDENTITY_WINDOW_DAYS) -> dict[str, Any]:
    """How much of the segment this has actually identified, stated honestly.

    A classifier that labels 3 of 245 hosts and reports "3 hosts identified" is misleading by
    omission. This reports the denominator alongside the numerator, and separates HOSTS SEEN
    from HOSTS CLASSIFIED so an operator can tell "nothing to identify" from "the classifier
    found nothing".
    """
    row = db.fetch_rows(
        client,
        """
        SELECT
            (SELECT uniqExact(src_addr) FROM weirvern.flows
              WHERE timestamp >= now() - INTERVAL %(d)s DAY)          AS hosts_seen,
            -- WINDOWED LIKE THE DENOMINATOR. `FINAL` collapses versions per host, not history, so
            -- an unfiltered numerator counted every host EVER classified while the denominator was
            -- this window -- a ratio that can exceed one hundred percent. Measured: seen=50 with classified=200
            -- reported 400 pct, and seen=0 with classified=12 reported 1200 pct. A percentage above 100
            -- is nonsense on its face; the subtler harm is the normal-looking case, where a host
            -- classified last month inflates coverage of this week's segment.
            (SELECT uniqExact(host) FROM weirvern.host_identity FINAL
              WHERE updated_at >= now() - INTERVAL %(d)s DAY)           AS hosts_classified,
            (SELECT count() FROM weirvern.host_identity FINAL
              WHERE confidence = 'high'
                AND updated_at >= now() - INTERVAL %(d)s DAY)           AS high,
            (SELECT count() FROM weirvern.host_identity FINAL
              WHERE confidence = 'medium'
                AND updated_at >= now() - INTERVAL %(d)s DAY)           AS medium,
            (SELECT count() FROM weirvern.host_identity FINAL
              WHERE os = 'unknown'
                AND updated_at >= now() - INTERVAL %(d)s DAY)           AS unknown
        """,
        d=int(days),
    )
    if not row:
        return {"available": False, "reason": "coverage query returned no row"}
    seen, classified, high, medium, unknown = (int(x or 0) for x in row[0])
    return {
        "available": True,
        "hosts_seen": seen,
        "hosts_classified": classified,
        "high_confidence": high,
        "medium_confidence": medium,
        "unknown": unknown,
        # A PERCENTAGE WITH NO DENOMINATOR IS NOT A PERCENTAGE. `seen or 1` produced a number
        # measured against a phantom denominator of one: with no hosts seen it reported 0.0%,
        # which reads as "identified none of them" rather than as "there is no segment to
        # measure". None lets the panel say the honest thing.
        # CLAMPED AS WELL AS WINDOWED. The SQL window is the fix; this clamp is the invariant. A
        # percentage above 100 is not a number anyone can act on, and a reader who sees one stops
        # trusting the panel -- so the module refuses to emit one even if a future query change
        # makes the numerator larger than the denominator again.
        "coverage_pct": (min(100.0, round(100.0 * classified / seen, 1)) if seen else None),
        "window_days": int(days),
    }


def stale_before(days: int = IDENTITY_WINDOW_DAYS) -> datetime:
    """The cutoff an observation must postdate to still count. Exposed for the CLI and tests."""
    return utcnow() - timedelta(days=days)
