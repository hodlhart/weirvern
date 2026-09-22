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
    signal_from_software,
    summarise,
)

logger = logging.getLogger(__name__)

# How far back an observation still counts toward a verdict.
#
# 7 days, and the number is a judgement that should be visible: long enough that a host which
# made one TLS connection last week is still identifiable, short enough that a machine that was
# re-imaged last month does not keep its old identity. Identity that has genuinely gone stale is
# better represented by no verdict than by a confident stale one.
IDENTITY_WINDOW_DAYS = 7


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
        hostnames = [o["raw"] for o in own if o["source"].startswith("dhcp_")][:20]
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
    now = datetime.now()
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
            len(v.get("sources") or []),
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


def identity_for_hosts(client: Client, hosts: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Current verdicts for specific hosts, keyed by address. For enriching other views.

    Takes {addr: mac} so a caller that knows the MAC gets the MAC-keyed identity too -- the same
    host can appear under a new address after a lease change, and keying only on address would
    report it as a brand-new unknown device.
    """
    if not hosts:
        return {}
    addrs = list(hosts)
    rows = db.fetch_rows(
        client,
        """
        SELECT host, os, os_label, confidence, score, agreeing_sources,
               signals, disagreement, ja4_structure, updated_at
        FROM weirvern.host_identity FINAL
        WHERE host IN %(h)s
        """,
        h=tuple(addrs),
    )
    out: dict[str, dict[str, Any]] = {}
    for host, os_name, os_label, conf, score, n_src, signals, disagreement, ja4_raw, updated in rows:
        out[str(host)] = {
            "os": str(os_name), "os_label": str(os_label), "confidence": str(conf),
            "score": float(score or 0), "agreeing_sources": int(n_src or 0),
            "signals": _load(signals), "disagreement": _load(disagreement),
            "ja4_structure": _load(ja4_raw),
            "updated_at": updated,
            "age_s": (datetime.now() - updated).total_seconds() if updated else None,
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
            (SELECT uniqExact(host) FROM weirvern.host_identity FINAL) AS hosts_classified,
            (SELECT count() FROM weirvern.host_identity FINAL
              WHERE confidence = 'high')                               AS high,
            (SELECT count() FROM weirvern.host_identity FINAL
              WHERE confidence = 'medium')                             AS medium,
            (SELECT count() FROM weirvern.host_identity FINAL
              WHERE os = 'unknown')                                    AS unknown
        """,
        d=int(days),
    )
    if not row:
        return {"available": False, "reason": "coverage query returned no row"}
    seen, classified, high, medium, unknown = row[0]
    return {
        "available": True,
        "hosts_seen": int(seen or 0),
        "hosts_classified": int(classified or 0),
        "high_confidence": int(high or 0),
        "medium_confidence": int(medium or 0),
        "unknown": int(unknown or 0),
        # Stated as a fraction AND a count, because a bare percentage hides a small denominator.
        "coverage_pct": round(100.0 * int(classified or 0) / int(seen or 1), 1),
        "window_days": int(days),
    }


def stale_before(days: int = IDENTITY_WINDOW_DAYS) -> datetime:
    """The cutoff an observation must postdate to still count. Exposed for the CLI and tests."""
    return datetime.now() - timedelta(days=days)
