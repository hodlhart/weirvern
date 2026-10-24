"""Operator-declared network scopes.

WHY THIS EXISTS. A per-host anomaly model needs a stable population of hosts. The source
address on a NetFlow aggregate is not automatically such a host: on a real deployment it is
often an internet peer, a scanner, or a VPN client that happened to talk once. The old code
had no scope at all, so every external address got its own behavioural baseline -- measured on
the live box at 9,620 of 10,973 alerts in twelve hours.

THE RULE IS DECLARED, NOT GUESSED. There is no RFC1918 test here. An operator declares CIDRs
and labels them `internal`, `vpn`, `dmz` or `external`; `monitored` is a separate decision.
Unmatched addresses are `unclassified`, which is a visible configuration gap rather than an
implicit "external" or "internal" answer.

LONGEST-PREFIX MATCH. Overlapping scopes are allowed (a /16 internal network can contain a
/24 DMZ), and the most specific scope wins. Ties are resolved deterministically by the scope's
id so a reload cannot change an address's label.

The module is pure except for the two database helpers at the bottom, so resolution and
validation are testable without ClickHouse.
"""
from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

LABELS = ("internal", "vpn", "dmz", "external")
POLICIES = ("full", "aggregate", "observe", "off")
DEFAULT_POLICY = {"internal": "full", "vpn": "full", "dmz": "full", "external": "observe"}


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Scope:
    id: str
    cidr: str
    label: str
    monitored: bool
    policy: str
    description: str = ""
    source: str = "operator"
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    warning: str = ""

    @property
    def prefixlen(self) -> int:
        return self.network.prefixlen if self.network is not None else 0

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "cidr": self.cidr,
            "label": self.label,
            "monitored": bool(self.monitored),
            "policy": self.policy,
            "description": self.description,
            "source": self.source,
            "warning": self.warning,
        }


def normalize_scope(cidr: str, *, label: str = "internal", monitored: bool = True,
                    policy: str = "", description: str = "",
                    source: str = "operator", scope_id: str = "") -> Scope:
    """Validate one declaration and return a Scope.

    Invalid addresses are rejected here rather than stored and silently skipped at read time:
    a scope that does not parse is a configuration error, not a quiet "no opinion".
    """
    text = str(cidr or "").strip()
    if not text:
        raise ValueError("a CIDR is required")
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ValueError(f"not a valid IPv4 or IPv6 CIDR: {text}") from exc
    label = str(label or "").strip().lower()
    if label not in LABELS:
        raise ValueError(f"label must be one of {', '.join(LABELS)}")
    policy = str(policy or DEFAULT_POLICY.get(label, "observe")).strip().lower()
    if policy not in POLICIES:
        raise ValueError(f"policy must be one of {', '.join(POLICIES)}")
    is_on = bool(monitored) and policy != "off"
    warning = ""
    if net.prefixlen == 0 and is_on:
        warning = ("catch-all network: monitoring it would alert on every unclassified "
                   "address, which recreates the flood this scope feature exists to prevent")
    return Scope(
        id=scope_id or uuid.uuid4().hex,
        cidr=str(net),
        label=label,
        monitored=is_on,
        policy=policy,
        description=str(description or "").strip()[:300],
        source=str(source or "operator").strip()[:32],
        network=net,
        warning=warning,
    )


def parse_row(row: dict[str, Any]) -> Scope:
    return normalize_scope(
        str(row.get("cidr") or ""),
        label=str(row.get("label") or "internal"),
        monitored=_bool(row.get("monitored")),
        policy=str(row.get("policy") or ""),
        description=str(row.get("description") or ""),
        source=str(row.get("source") or "operator"),
        scope_id=str(row.get("id") or ""),
    )


def resolve(addr: str, scopes: Iterable[Scope]) -> Scope | None:
    """The most specific scope containing `addr`, or None (unclassified)."""
    try:
        ip = ipaddress.ip_address(str(addr).strip())
    except ValueError:
        return None
    best: Scope | None = None
    for scope in scopes:
        net = scope.network
        if net is None or net.version != ip.version or ip not in net:
            continue
        if best is None or scope.prefixlen > best.prefixlen or (
                scope.prefixlen == best.prefixlen and scope.id < best.id):
            best = scope
    return best


def is_monitored(scope: Scope | None) -> bool:
    """A scope is alertable only when the operator marked it and its policy is not observe/off."""
    return bool(scope is not None and scope.monitored
                and scope.policy in ("full", "aggregate"))


def filter_monitored(rows: Iterable[dict[str, Any]], scopes: Iterable[Scope]) -> tuple[list[dict], dict]:
    """Attach scope labels and return only monitored rows, with an honest coverage summary.

    The caller decides what to do with the summary; this function never silently drops a
    host without reporting how many it dropped.
    """
    scopes = list(scopes)
    kept: list[dict] = []
    labels: dict[str, int] = {}
    unclassified = 0
    for row in rows:
        scope = resolve(str(row.get("src_addr") or ""), scopes)
        label = scope.label if scope else "unclassified"
        row = dict(row)
        row["_network_scope"] = label
        row["_network_monitored"] = is_monitored(scope)
        labels[label] = labels.get(label, 0) + 1
        if scope is None:
            unclassified += 1
        if is_monitored(scope):
            kept.append(row)
    return kept, {"seen": len(labels) and sum(labels.values()), "by_label": labels,
                  "unclassified": unclassified, "kept": len(kept)}



# ── database helpers ──────────────────────────────────────────────────────────────────────
def load_scopes(client) -> list[Scope]:
    """Read the live table. A missing table means "not configured", not a silent zero scope."""
    try:
        result = client.query(
            "SELECT id, cidr, label, monitored, policy, description, source "
            "FROM weirvern.network_scopes FINAL WHERE deleted = 0 ORDER BY id"
        ).result_rows
    except Exception:  # noqa: BLE001 - pre-035 deployments and ClickHouse outages both degrade
        return []
    out: list[Scope] = []
    for row in result:
        try:
            out.append(parse_row(dict(zip(
                ("id", "cidr", "label", "monitored", "policy", "description", "source"),
                row, strict=False))))
        except ValueError:
            # A bad stored row is a configuration defect. Skip it, but do not turn the whole
            # table into "no scopes" -- the other declarations are still valid.
            continue
    return out


def save_scope(client, body: dict[str, Any]) -> Scope:
    scope_id = str(body.get("id") or "").strip()
    scope = normalize_scope(
        str(body.get("cidr") or ""), label=str(body.get("label") or "internal"),
        monitored=_bool(body.get("monitored")), policy=str(body.get("policy") or ""),
        description=str(body.get("description") or ""), source="operator",
        scope_id=scope_id,
    )
    # Exact duplicate CIDRs would make the label depend on row order; reject them unless the
    # operator is updating that same row.
    for existing in load_scopes(client):
        if existing.cidr == scope.cidr and existing.id != scope.id:
            raise ValueError(f"{scope.cidr} is already declared as {existing.label}")
    client.insert(
        "weirvern.network_scopes",
        [[scope.id, scope.cidr, scope.label, int(scope.monitored), scope.policy,
          scope.description, scope.source, 0]],
        column_names=["id", "cidr", "label", "monitored", "policy", "description",
                      "source", "deleted"],
    )
    return scope


def delete_scope(client, scope_id: str) -> bool:
    scope_id = str(scope_id or "").strip()
    if not scope_id:
        raise ValueError("an id is required")
    found = any(s.id == scope_id for s in load_scopes(client))
    if not found:
        return False
    # A tombstone, not a DELETE mutation: ReplacingMergeTree(updated_at) needs a newer row to
    # suppress the old one, and the tombstone is visible in the audit trail until FINAL merges.
    client.insert(
        "weirvern.network_scopes",
        [[scope_id, "", "", 0, "off", "", "operator", 1]],
        column_names=["id", "cidr", "label", "monitored", "policy", "description",
                      "source", "deleted"],
    )
    return True


def overview(client, hours: int = 24) -> dict[str, Any]:
    """A read-only coverage view: one row per declared scope, plus unclassified traffic.

    COUNTS ARE NAMED, NOT FABRICATED. A failed count is `None` with `counts_available=false`;
    zero would be indistinguishable from a scope that genuinely saw no traffic. The UI must
    render that distinction rather than showing a calm empty card after a query failure.
    """
    scopes = load_scopes(client)
    rows: list[dict[str, Any]] = []
    counts_ok = True
    for scope in scopes:
        item = scope.public()
        try:
            # `cidr` is normalized by ipaddress at declaration time; it is an identifier,
            # not untrusted text. ClickHouse's isIPAddressInRange takes the literal CIDR.
            host = client.query(
                f"SELECT uniqExact(src_addr), max(window_start) "
                f"FROM weirvern.flows_aggregated "
                f"WHERE window_start >= now() - INTERVAL {int(hours)} HOUR "
                f"AND isIPAddressInRange(src_addr, '{scope.cidr}')"
            ).result_rows
            alerts = client.query(
                f"SELECT count(), uniqExact(src_addr) FROM weirvern.netflow_anomalies "
                f"WHERE detected_at >= now() - INTERVAL {int(hours)} HOUR "
                f"AND isIPAddressInRange(src_addr, '{scope.cidr}')"
            ).result_rows
            item["hosts"] = int(host[0][0]) if host else 0
            item["last_seen"] = (str(host[0][1]) if host and host[0][1] else "")
            item["alerts"] = int(alerts[0][0]) if alerts else 0
            item["alert_hosts"] = int(alerts[0][1]) if alerts else 0
        except Exception:  # noqa: BLE001
            counts_ok = False
            item["hosts"] = None
            item["last_seen"] = ""
            item["alerts"] = None
            item["alert_hosts"] = None
        rows.append(item)

    unclassified: dict[str, Any] = {"hosts": None, "alerts": None}
    if scopes:
        params = {f"c{i}": s.cidr for i, s in enumerate(scopes)}
        not_in = " AND ".join(f"NOT isIPAddressInRange(src_addr, %({k})s)"
                              for k in params)
        try:
            h = client.query(
                f"SELECT uniqExact(src_addr) FROM weirvern.flows_aggregated "
                f"WHERE window_start >= now() - INTERVAL {int(hours)} HOUR AND {not_in}",
                parameters=params,
            ).result_rows
            a = client.query(
                f"SELECT count() FROM weirvern.netflow_anomalies "
                f"WHERE detected_at >= now() - INTERVAL {int(hours)} HOUR AND {not_in}",
                parameters=params,
            ).result_rows
            unclassified["hosts"] = int(h[0][0]) if h else 0
            unclassified["alerts"] = int(a[0][0]) if a else 0
        except Exception:  # noqa: BLE001
            counts_ok = False
        try:
            peers = client.query(
                f"SELECT src_addr, sum(total_bytes) AS bytes, count() AS windows, "
                f"max(window_start) AS last_seen FROM weirvern.flows_aggregated "
                f"WHERE window_start >= now() - INTERVAL {int(hours)} HOUR AND {not_in} "
                f"GROUP BY src_addr ORDER BY bytes DESC LIMIT 8",
                parameters=params,
            ).result_rows
            external_peers = [
                {"src_addr": str(r[0]), "bytes": int(r[1] or 0), "windows": int(r[2] or 0),
                 "last_seen": str(r[3]) if r[3] else ""} for r in peers
            ]
        except Exception:  # noqa: BLE001
            counts_ok = False
            external_peers = []
    else:
        external_peers = []

    return {
        "available": True,
        "scopes": rows,
        "summary": {
            "total": len(rows),
            "monitored": sum(1 for s in rows if s["monitored"] and s["policy"] in ("full", "aggregate")),
            "observed": sum(1 for s in rows if not (s["monitored"] and s["policy"] in ("full", "aggregate"))),
            "unclassified_hosts": unclassified["hosts"],
            "unclassified_alerts": unclassified["alerts"],
        },
        "counts_available": counts_ok,
        "external_peers": external_peers,
        "unconfigured": not rows,
        "hours": int(hours),
    }


def training_filter_sql(scopes: Iterable[Scope], alias: str = "a") -> str:
    """The SQL predicate that keeps model training on the monitored host population.

    NO SCOPES MEANS LEGACY: an upgrade with no declarations must train exactly as it did,
    so this returns an empty string. Once declarations exist, training follows the same
    monitored decision as scoring. A declaration set with no monitored scope returns
    `AND 0` rather than silently training on everything -- that state is an explicit
    no-detection configuration, and the resulting "not enough data" is the honest answer.
    """
    scopes = list(scopes)
    if not scopes:
        return ""
    monitored = [s for s in scopes if is_monitored(s)]
    if not monitored:
        return "AND 0"
    terms = " OR ".join(f"isIPAddressInRange({alias}.src_addr, '{s.cidr}')" for s in monitored)
    return f"AND ({terms})"


def training_filter(client, alias: str = "a") -> str:
    """Load the declarations and return the predicate for a detector's training query."""
    return training_filter_sql(load_scopes(client), alias=alias)


def _env_json(name: str) -> dict:
    try:
        value = json.loads(os.environ.get(name) or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def suggested_monitored_scopes(plans: dict | None = None,
                               interface_names: dict | None = None) -> list[Scope]:
    """Scopes inferred ONLY from already-configured monitored networks.

    `INTERCEPT_PLANS` is operator configuration: each plan names a segment the sensor was
    explicitly told to monitor. Those segments are therefore safe to PROPOSE as internal,
    monitored scopes. Nothing here reads observed traffic or private address space, and the
    caller must still persist/approve the proposal -- this function does not write.

    `INTERFACE_NETWORKS` supplies human labels (`eth1=Servers`); a label is descriptive, never
    a private-address test. A segment with no valid CIDR is skipped rather than guessed.
    """
    from_env = plans is None
    plans = _env_json("INTERCEPT_PLANS") if plans is None else plans
    if interface_names is None:
        names: dict[str, str] = {}
        for item in (os.environ.get("INTERFACE_NETWORKS") or "").split(","):
            if "=" in item:
                iface, name = item.split("=", 1)
                names[iface.strip()] = name.strip()
    else:
        names = {str(k): str(v) for k, v in interface_names.items()}
    single = (os.environ.get("INTERCEPT_SEGMENT") or "").strip() if from_env else ""
    out: list[Scope] = []
    seen: set[str] = set()
    for iface, plan in plans.items():
        if not isinstance(plan, dict):
            continue
        segment = str(plan.get("segment") or "").strip()
        if not segment:
            continue
        try:
            scope = normalize_scope(segment, label="internal", monitored=True, policy="full",
                                    description=f"monitored network on {iface}"
                                                + (f" ({names[iface]})" if names.get(iface) else ""),
                                    source="monitored-net")
        except ValueError:
            continue
        if scope.cidr in seen:
            continue
        seen.add(scope.cidr)
        out.append(scope)
    if not out and single:
        with contextlib.suppress(ValueError):
            out.append(normalize_scope(single, label="internal", monitored=True, policy="full",
                                       description="monitored network from INTERCEPT_SEGMENT",
                                       source="monitored-net"))
    return out
