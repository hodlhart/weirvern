"""Domain blocklists: sources, their domains, and the matching the alert path uses.

THE OPERATOR'S ASK (2026-10-16): "Can we use https://github.com/hagezi/dns-blocklists or custom
lists or custom domains?" -- with the design already sketched: record DNS hits (alert-first),
resolve a listed name's addresses through the reverse cache (schema/016), and let the gate
block what resolves. This module owns the import half: fetch a source, parse its format, store
its domains, and answer "is this queried name listed".

WHAT A "MATCH" MEANS, AND WHY IT WALKS SUFFIXES. Lists cover a name and everything under it
(that is what a DNS block means in every resolver). `domain_in_set` checks the query and each
parent suffix -- first hit wins, and the caller learns WHICH listed name matched (the event
says what list entry the query hit, not just that it hit something). Wildcard forms
(`*.example.com`) are normalized to their base domain at parse time, so the walk is the only
matching rule.

FAILURES ARE STATES, NOT EXCEPTIONS: a fetch error lands in the source row's `last_error` so
the GUI can say "the last sync failed" instead of showing a quietly empty list. Parsing never
raises on a junk line -- lists are third-party text, and one bad line must not lose 300k good
ones -- but a fetch or parse problem never counts as "zero domains".
"""
from __future__ import annotations

import ipaddress
import logging
import time as _time
import urllib.request
from datetime import UTC, datetime, timedelta

from weirvern.sluice_store import validate_domain

logger = logging.getLogger(__name__)

DEFAULT_SOURCES: list[dict] = [
    {
        "source_id": "hagezi-light",
        "name": "HaGeZi Multi LIGHT",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/dnsmasq/light.txt",
        "format": "dnsmasq",
        "enabled": 1,
    },
    {
        "source_id": "hagezi-pro",
        "name": "HaGeZi Multi PRO",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/dnsmasq/pro.txt",
        "format": "dnsmasq",
        # LIGHT is the default that is ON. PRO is an order of magnitude larger and imports
        # ~300k names; that is the operator's call, so it ships listed and disabled.
        "enabled": 0,
    },
]

FETCH_TIMEOUT_S = 30
FETCH_MAX_BYTES = 64 * 1024 * 1024
SYNC_EVERY_H = 24
_DOMAINS_CACHE: dict = {"loaded_at": 0.0, "by_domain": {}}


def fetch_text(url: str, *, timeout_s: int = FETCH_TIMEOUT_S,
               max_bytes: int = FETCH_MAX_BYTES) -> str:
    """Fetch a list over HTTPS. Bounded in time and size; raises on any failure."""
    req = urllib.request.Request(url, headers={"User-Agent": "weirvern-blocklist-sync/1"})
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 -- fixed https URLs
        data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"list larger than {max_bytes} bytes; refusing")
    return data.decode("utf-8", errors="replace")


def _clean(name: str) -> str:
    return name.strip().lower().lstrip("*.").rstrip(".")


def _valid(name: str) -> bool:
    """A light syntactic gate. Stricter validation lives in validate_domain; this runs per
    line over hundreds of thousands of lines and must not raise."""
    if not name or "." not in name or len(name) > 253:
        return False
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return True
    return False


def parse_list(text: str, fmt: str) -> set[str]:
    """Third-party text -> normalized domains. Never raises on a junk line."""
    out: set[str] = set()
    fmt = (fmt or "").strip().lower()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!", ";", "[")):
            continue
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if fmt == "hosts":
            parts = line.split()
            candidate = parts[1] if len(parts) >= 2 else ""
        elif fmt == "dnsmasq":
            # "address=/domain/" and "local=/domain/" are the real shapes -- THE LEADING SLASH
            # IS PART OF THE SYNTAX, so the split must strip delimiters, not just split on the
            # first one (a first cut took split("/",1)[0] and got "" for every real line).
            if "=" in line and "/" in line:
                candidate = line.split("=", 1)[1].strip().strip("/").split("/", 1)[0]
            else:
                parts = line.split()
                candidate = parts[0] if parts else ""
        elif fmt in ("domains", "wildcard"):
            candidate = line.split()[0]
        else:
            candidate = ""
        cand = _clean(candidate)
        if _valid(cand):
            out.add(cand)
    return out


def ensure_default_sources(client) -> int:
    """Insert any missing DEFAULT_SOURCES rows. Idempotent; returns how many were added."""
    existing = {str(r[0]) for r in client.query(
        "SELECT source_id FROM weirvern.blocklist_sources FINAL").result_rows}
    added = 0
    now = datetime.now(UTC)
    for src in DEFAULT_SOURCES:
        if src["source_id"] in existing:
            continue
        client.insert(
            "weirvern.blocklist_sources",
            [[src["source_id"], src["name"], src["url"], src["format"], int(src["enabled"]),
              now, now, None, 0, ""]],
            column_names=["source_id", "name", "url", "format", "enabled", "added_at",
                          "updated", "fetched_at", "domain_count", "last_error"],
        )
        added += 1
    return added


def load_sources(client) -> list[dict]:
    rows = client.query(
        "SELECT source_id, name, url, format, enabled, fetched_at, domain_count, last_error "
        "FROM weirvern.blocklist_sources FINAL ORDER BY source_id").result_rows
    out = []
    for r in rows:
        out.append({
            "source_id": str(r[0]), "name": str(r[1]), "url": str(r[2]), "format": str(r[3]),
            "enabled": bool(r[4]),
            "fetched_at": r[5].isoformat() if hasattr(r[5], "isoformat") and r[5] else "",
            "domain_count": int(r[6] or 0), "last_error": str(r[7] or ""),
        })
    return out


def _write_source_state(client, src: dict, *, count: int, error: str) -> None:
    now = datetime.now(UTC)
    client.insert(
        "weirvern.blocklist_sources",
        [[src["source_id"], src["name"], src["url"], src["format"], int(src["enabled"]),
          now, now, (None if error else now), int(count), error[:500]]],
        column_names=["source_id", "name", "url", "format", "enabled", "added_at",
                      "updated", "fetched_at", "domain_count", "last_error"],
    )


def set_source_enabled(client, source_id: str, enabled: bool) -> dict:
    """Turn one imported list on or off (the operator, 2026-10-16: "allow me to click them to
    enable or disable them").

    Re-inserts the source row with the flipped flag -- the table is ReplacingMergeTree keyed on
    source_id -- PRESERVING count/fetch/error, because an enable is not a resync: the numbers on
    the row still describe the last real fetch. Off means off everywhere: `sync_due` skips
    disabled sources and `load_domains` leaves their names out, so the next gate pass drops them
    from the watch set. A source that does not exist is a refusal, never a silent no-op.
    """
    sid = str(source_id or "").strip()
    src = next((s for s in load_sources(client) if s["source_id"] == sid), None)
    if src is None:
        raise ValueError(f"no such blocklist source: {sid!r}")
    now = datetime.now(UTC)
    client.insert(
        "weirvern.blocklist_sources",
        [[src["source_id"], src["name"], src["url"], src["format"], int(bool(enabled)),
          now, now, src.get("fetched_at") or None,
          int(src.get("domain_count") or 0), str(src.get("last_error") or "")]],
        column_names=["source_id", "name", "url", "format", "enabled", "added_at",
                      "updated", "fetched_at", "domain_count", "last_error"],
    )
    logger.info("blocklists: source %s %s", sid, "enabled" if enabled else "disabled")
    return {**src, "enabled": bool(enabled)}


def sync_source(client, src: dict, *, fetch=fetch_text, now: datetime | None = None) -> dict:
    """Fetch + parse + store one source. The source row records the outcome either way."""
    now = now or datetime.now(UTC)
    try:
        text = fetch(str(src["url"]))
        domains = parse_list(text, str(src["format"]))
        if not domains:
            raise ValueError("the list parsed to zero domains; treating as a failed sync")
        # REPLACE, not append: a name REMOVED upstream must stop matching, or the list grows
        # forever and stale entries keep alerting. The delete is a ClickHouse mutation; it
        # settles within seconds and ReplacingMergeTree dedupes the (domain, source_id) overlap.
        client.command(
            "ALTER TABLE weirvern.blocklist_domains DELETE WHERE source_id = "
            + "'" + str(src["source_id"]) + "'"
        )
        rows = [[d, str(src["source_id"]), now] for d in sorted(domains)]
        for i in range(0, len(rows), 5000):
            client.insert("weirvern.blocklist_domains", rows[i:i + 5000],
                          column_names=["domain", "source_id", "added_at"])
        _write_source_state(client, src, count=len(domains), error="")
        logger.info("blocklists: %s synced, %d domains", src["source_id"], len(domains))
        return {"ok": True, "domains": len(domains), "error": ""}
    except Exception as exc:  # noqa: BLE001 -- the failure IS the outcome to record
        _write_source_state(client, src, count=int(src.get("domain_count") or 0),
                            error=str(exc))
        logger.warning("blocklists: %s sync failed: %s", src["source_id"], exc)
        return {"ok": False, "domains": 0, "error": str(exc)}


def sync_due(client, *, now: datetime | None = None, every_h: int = SYNC_EVERY_H) -> list[dict]:
    """Enabled sources whose last SUCCESSFUL fetch is older than `every_h` hours (or never).

    The cadence is a SETTING now (BLOCKLIST_SYNC_HOURS, 2026-10-16): every other cadence in this
    codebase is configurable, and the lists are the one the operator manages by hand -- the
    default stays 24h, so nothing changes until somebody says so.
    """
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(hours=max(1, int(every_h)))
    due = []
    for src in load_sources(client):
        if not src["enabled"] or src["source_id"] == "custom":
            continue
        fetched = src["fetched_at"]
        if not fetched:
            due.append(src)
            continue
        try:
            when = datetime.fromisoformat(fetched)
            if when.tzinfo is None:
                when = when.replace(tzinfo=UTC)
            if when < cutoff:
                due.append(src)
        except ValueError:
            due.append(src)
    return due


def load_domains(client, *, max_age_s: float = 300.0, force: bool = False) -> dict[str, str]:
    """domain -> source_id for every listed name, cached in-process for `max_age_s`.

    The cache is the "small" in the operator's "small cache": matching runs per DNS query, and
    a dictionary hit is the only cost this path should ever pay.
    """
    now = _time.monotonic()
    if (not force and _DOMAINS_CACHE["by_domain"]
            and now - float(_DOMAINS_CACHE["loaded_at"]) < max_age_s):
        return _DOMAINS_CACHE["by_domain"]
    rows = client.query(
        "SELECT domain, any(source_id) FROM weirvern.blocklist_domains FINAL "
        "GROUP BY domain").result_rows
    by_domain = {str(r[0]): str(r[1]) for r in rows}
    _DOMAINS_CACHE["by_domain"] = by_domain
    _DOMAINS_CACHE["loaded_at"] = now
    return by_domain


def domain_in_set(name: str, domains: dict[str, str] | set[str]) -> str | None:
    """Which listed name covers `name`, walking parent suffixes (a list entry covers its
    subdomains -- what a DNS block means in every resolver). Returns the matched listed name."""
    q = str(name or "").strip().lower().rstrip(".")
    if not q or "." not in q:
        return None
    parts = q.split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in domains:
            return candidate
    return None


def add_custom_domain(client, domain: str, *, now: datetime | None = None) -> str:
    """One operator-entered name. Validated by the SAME rules as a domain rule."""
    name = validate_domain(domain)
    client.insert("weirvern.blocklist_domains",
                  [[name, "custom", now or datetime.now(UTC)]],
                  column_names=["domain", "source_id", "added_at"])
    _DOMAINS_CACHE["by_domain"] = {}  # the next load sees it
    logger.info("blocklists: custom domain added: %s", name)
    return name


def remove_custom_domain(client, domain: str) -> str:
    """One operator-entered name goes away. Validated by the SAME rules as a domain rule.

    THE VALIDATOR IS ALSO THE GUARD (issue #11, 2026-10-16). This used to lowercase the input
    and CONCATENATE it into `ALTER ... DELETE WHERE domain = '<name>'`: a name carrying a quote
    widened the predicate and a value that could not be ADDED could still be removed, because
    only one of the two paths checked -- and one path checking is neither path checking. Both
    now come through `validate_domain`, and the name rides as a BOUND parameter, so a widened
    predicate is not expressible at all. Returns the normalized name, exactly as `add` does,
    so the route can report the name that was actually used.
    """
    name = validate_domain(domain)
    client.command(
        "ALTER TABLE weirvern.blocklist_domains DELETE WHERE source_id = 'custom' AND domain = %(name)s",
        parameters={"name": name},
    )
    _DOMAINS_CACHE["by_domain"] = {}
    logger.info("blocklists: custom domain removed: %s", name)
    return name
