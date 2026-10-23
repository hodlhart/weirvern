"""Host role/scope proposals from observations the deployment already has.

The role is context for calibration and severity, not an alert by itself. Only an operator
override is authoritative; an auto row is a proposal with its evidence attached.
"""
from __future__ import annotations

import logging

from clickhouse_connect.driver.client import Client

from weirvern.clock import utcnow
from weirvern.config import Settings

logger = logging.getLogger(__name__)

# Ordered: the first match wins. These are NAME observations from DHCP, not an address denylist.
ROLE_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("gateway", ("gateway", "router", "udm", "ucg", "usg", "dream machine", "er-x", "edge router")),
    ("media", ("sonarr", "radarr", "prowlarr", "overseerr", "plex", "jellyfin", "emby",
               "tautulli", "bazarr", "lidarr", "readarr")),
    ("server", ("umbrel", "unraid", "proxmox", "truenas", "synology", "nas", "docker",
                "homeassistant", "home assistant")),
    ("iot", ("camera", "doorbell", "thermostat", "roku", "chromecast", "apple tv", "echo",
             "alexa", "printer", "plug", "sensor")),
)


def classify(host: str, name: str, *, private: bool) -> tuple[str, float, str]:
    """(role, confidence, evidence) for one observed host. Never raises on missing name."""
    if not private:
        return "external", 0.9, "address is not in a private range"
    clean = (name or "").strip()
    low = clean.lower()
    for role, needles in ROLE_RULES:
        if any(n in low for n in needles):
            return role, 0.8, f"DHCP name {clean!r} matches {role}"
    if clean:
        return "workstation", 0.35, f"DHCP name {clean!r} has no role pattern"
    return "unknown", 0.0, "no name observed; role not inferred"


def _private(host: str) -> bool:
    # revdns owns the project's private-address definition (RFC1918 + CGNAT + ULA).
    from weirvern.admin.revdns import is_private  # noqa: PLC0415

    return bool(is_private(host))


def run(client: Client, settings: Settings) -> list[dict]:
    """Write auto role proposals for hosts observed in DHCP/identity/flow tables.

    Operator rows are never overwritten. A read failure propagates to the caller's guard; a
    single unknown host is a row with role=unknown and its reason, not a guess.
    """
    names: dict[str, str] = {}
    try:
        for row in client.query(
            "SELECT toString(client_addr) AS host, argMax(host_name, ts) AS name "
            "FROM weirvern.zeek_dhcp GROUP BY host"
        ).result_rows:
            if row[0] and str(row[0]) != "-":
                names[str(row[0])] = str(row[1] or "")
    except Exception as exc:  # noqa: BLE001
        logger.warning("host_roles: DHCP names unavailable, proposing from identity/flows only: %s", exc)
    for row in client.query(
        "SELECT host, os FROM weirvern.host_identity FINAL"
    ).result_rows:
        if row[0] and str(row[0]) not in names:
            names[str(row[0])] = str(row[1] or "")
    # Hosts that moved bytes but never appeared in DHCP/identity still exist; propose unknown.
    for row in client.query(
        "SELECT DISTINCT src_addr FROM weirvern.flows_aggregated "
        "WHERE window_start >= now() - INTERVAL 7 DAY LIMIT 5000"
    ).result_rows:
        if row[0]:
            names.setdefault(str(row[0]), "")

    existing: dict[str, str] = {}
    try:
        for row in client.query("SELECT host, source FROM weirvern.host_roles FINAL").result_rows:
            existing[str(row[0])] = str(row[1] or "")
    except Exception:  # noqa: BLE001
        existing = {}

    rows: list[dict] = []
    for host, name in names.items():
        if existing.get(host) == "operator":
            continue
        private = _private(host)
        role, confidence, evidence = classify(host, name, private=private)
        rows.append({
            "host": host,
            "role": role,
            "scope": "monitored" if private else "external",
            "source": "auto",
            "confidence": confidence,
            "evidence": evidence,
            "updated_at": utcnow(),
        })
    if not rows:
        return []
    cols = ["host", "role", "scope", "source", "confidence", "evidence", "updated_at"]
    client.insert("weirvern.host_roles", [[r[c] for c in cols] for r in rows], column_names=cols)
    return rows


__all__ = ["ROLE_RULES", "classify", "run"]
