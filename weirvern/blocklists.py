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

import hashlib
import ipaddress
import logging
import re
import time as _time
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta

from weirvern.sluice_store import validate_domain

logger = logging.getLogger(__name__)

DEFAULT_SOURCES: list[dict] = [
    {
        "source_id": "hagezi-light",
        "name": "HaGeZi Multi LIGHT — hand brush: basic protection",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt",
        "format": "domains",
        "enabled": 1,
        "tier": "light",
        "risk": "minimal",
        "recommended": False,
    },
    {
        "source_id": "hagezi-normal",
        "name": "HaGeZi Multi NORMAL — broom: all-round protection",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt",
        "format": "domains",
        "enabled": 0,
        "tier": "normal",
        "risk": "low",
        "recommended": False,
        "mini_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt",
    },
    {
        "source_id": "hagezi-pro",
        "name": "HaGeZi Multi PRO — big broom: extended protection (recommended)",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt",
        "format": "domains",
        "enabled": 0,
        "tier": "pro",
        "risk": "low to moderate",
        "recommended": True,
        "mini_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.mini-onlydomains.txt",
    },
    {
        "source_id": "hagezi-proplus",
        "name": "HaGeZi Multi PRO++ — sweeper: advanced protection (more aggressive)",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
        "format": "domains",
        "enabled": 0,
        "tier": "proplus",
        "risk": "moderate",
        "recommended": False,
        "mini_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus.mini-onlydomains.txt",
    },
    {
        "source_id": "hagezi-ultimate",
        "name": "HaGeZi Multi ULTIMATE — ultimate sweeper: maximum protection (most aggressive)",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt",
        "format": "domains",
        "enabled": 0,
        "tier": "ultimate",
        "risk": "high",
        "recommended": False,
        "mini_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate.mini-onlydomains.txt",
    },
]

# The five Multi versions build on each other: exactly one may be active. Turning one on turns
# the other four off in the same write, so the watch set cannot accidentally become a union.
TIER_SOURCE_IDS: tuple[str, ...] = tuple(s["source_id"] for s in DEFAULT_SOURCES)
SUPPORTED_FORMATS = ("domains", "wildcard", "hosts", "dnsmasq")
_DEFAULT_BY_ID = {s["source_id"]: s for s in DEFAULT_SOURCES}

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
    """Insert missing tiers and refresh their NAME/URL/FORMAT without touching operator state.

    The first release shipped Light and Pro with dnsmasq URLs. The tier update changes to the
    one-domain-per-line wildcard-onlydomains files; an existing row must move with it, or a
    deployment keeps importing the old format forever. `enabled`, fetch time, count and error
    are preserved: this is metadata migration, not a resync.
    """
    existing = {s["source_id"]: s for s in load_sources(client)}
    added = 0
    now = datetime.now(UTC)
    for src in DEFAULT_SOURCES:
        prior = existing.get(src["source_id"])
        if prior is None:
            client.insert(
                "weirvern.blocklist_sources",
                [[src["source_id"], src["name"], src["url"], src["format"],
                  int(src["enabled"]), now, now, None, 0, ""]],
                column_names=["source_id", "name", "url", "format", "enabled", "added_at",
                              "updated", "fetched_at", "domain_count", "last_error"],
            )
            added += 1
            continue
        if (prior.get("name"), prior.get("url"), prior.get("format")) == (
                src["name"], src["url"], src["format"]):
            continue
        client.insert(
            "weirvern.blocklist_sources",
            [[src["source_id"], src["name"], src["url"], src["format"],
              int(bool(prior.get("enabled"))), prior.get("added_at") or now, now,
              _dt_or_none(prior.get("fetched_at")), int(prior.get("domain_count") or 0),
              str(prior.get("last_error") or "")]],
            column_names=["source_id", "name", "url", "format", "enabled", "added_at",
                          "updated", "fetched_at", "domain_count", "last_error"],
        )
    return added


def _dt_or_none(value):
    """ClickHouse wants a datetime, not the ISO text the GUI payload carries."""
    if not value:
        return None
    if hasattr(value, "timestamp"):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def load_sources(client) -> list[dict]:
    rows = client.query(
        "SELECT source_id, name, url, format, enabled, fetched_at, domain_count, last_error "
        "FROM weirvern.blocklist_sources FINAL ORDER BY source_id").result_rows
    out = []
    for r in rows:
        sid = str(r[0])
        meta = _DEFAULT_BY_ID.get(sid) or {}
        out.append({
            "source_id": sid, "name": str(r[1]), "url": str(r[2]), "format": str(r[3]),
            "enabled": bool(r[4]),
            "fetched_at": r[5].isoformat() if hasattr(r[5], "isoformat") and r[5] else "",
            "domain_count": int(r[6] or 0), "last_error": str(r[7] or ""),
            "tier": str(meta.get("tier") or ""),
            "risk": str(meta.get("risk") or ""),
            "recommended": bool(meta.get("recommended")),
            "mini_url": str(meta.get("mini_url") or ""),
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
    # THE FIVE TIERS ARE ALTERNATIVES, NOT A UNION. Turning one on turns the other four off in
    # the same write; otherwise an operator who clicks PRO after LIGHT doubles the watch set
    # and the two lists' overlap hides which tier is actually in force.
    if enabled and sid in TIER_SOURCE_IDS:
        for other in load_sources(client):
            oid = str(other["source_id"])
            if oid == sid or oid not in TIER_SOURCE_IDS or not other["enabled"]:
                continue
            client.insert(
                "weirvern.blocklist_sources",
                [[oid, other["name"], other["url"], other["format"], 0, now, now,
                  _dt_or_none(other.get("fetched_at")), int(other.get("domain_count") or 0),
                  str(other.get("last_error") or "")]],
                column_names=["source_id", "name", "url", "format", "enabled", "added_at",
                              "updated", "fetched_at", "domain_count", "last_error"],
            )
    client.insert(
        "weirvern.blocklist_sources",
        [[src["source_id"], src["name"], src["url"], src["format"], int(bool(enabled)),
          now, now, _dt_or_none(src.get("fetched_at")),
          int(src.get("domain_count") or 0), str(src.get("last_error") or "")]],
        column_names=["source_id", "name", "url", "format", "enabled", "added_at",
                      "updated", "fetched_at", "domain_count", "last_error"],
    )
    logger.info("blocklists: source %s %s", sid, "enabled" if enabled else "disabled")
    return {**src, "enabled": bool(enabled)}


def add_source(client, url: str, *, name: str = "", fmt: str = "domains") -> dict:
    """Add an operator URL, with the format stated and enforced.

    The most portable format is one domain per line (the HaGeZi wildcard-onlydomains shape);
    hosts and dnsmasq are accepted because third-party lists commonly use them. Adblock and
    RPZ rules are REFUSED by name rather than parsed as garbage or imported as zero domains:
    a format a reader cannot interpret is not a success.
    """
    fmt = str(fmt or "domains").strip().lower()
    aliases = {"domain": "domains", "domain-list": "domains", "domainlist": "domains",
               "wildcard-domains": "domains", "wildcard_domains": "domains",
               "host": "hosts", "dnsmasq-list": "dnsmasq"}
    fmt = aliases.get(fmt, fmt)
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(
            f"format {fmt!r} is not supported; use one domain per line (domains), hosts, "
            "or dnsmasq. Adblock and RPZ lists are not parsed — export them as a domain list.")
    parsed = urllib.parse.urlsplit(str(url or "").strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("an http(s) URL is required")
    uid = hashlib.sha1(str(url).encode("utf-8")).hexdigest()[:10]
    label = re.sub(r"[^a-z0-9]+", "-", (name or parsed.netloc).lower()).strip("-")[:40]
    sid = f"custom-{label or 'list'}-{uid}"
    title = str(name or "").strip() or f"{parsed.netloc}{parsed.path}"[:80]
    existing = {s["source_id"] for s in load_sources(client)}
    if sid in existing:
        raise ValueError(f"that list is already added as {sid}")
    now = datetime.now(UTC)
    client.insert(
        "weirvern.blocklist_sources",
        [[sid, title, str(url).strip(), fmt, 1, now, now, None, 0, ""]],
        column_names=["source_id", "name", "url", "format", "enabled", "added_at",
                      "updated", "fetched_at", "domain_count", "last_error"],
    )
    logger.info("blocklists: custom source added: %s (%s)", sid, fmt)
    return {"source_id": sid, "name": title, "url": str(url).strip(), "format": fmt,
            "enabled": True, "domain_count": 0, "last_error": ""}


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
