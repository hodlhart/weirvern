"""The identity/lateral specialist: coverage first, then protocol-shape evidence.

The live identity tables are the binding constraint: Kerberos, NTLM, SMB mapping, DCE/RPC and
LDAP have had zero rows in production. A detector trained on zero-row tables would learn
nothing and then report a confident zero, so this module refuses to score until every source
has coverage and returns the missing names instead.

The pure feature functions are implemented and tested on synthetic rows. They deliberately
never put usernames, paths or LDAP filters into the evidence: the features are counts and
ratios, not PII.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from clickhouse_connect.driver.client import Client

from weirvern import __version__

MODEL_NAME = "IdentitySpecialist"

COVERAGE_TABLES = {
    "kerberos": "weirvern.zeek_kerberos",
    "ntlm": "weirvern.zeek_ntlm",
    "smb_mapping": "weirvern.zeek_smb_mapping",
    "smb_files": "weirvern.zeek_smb_files",
    "dce_rpc": "weirvern.zeek_dce_rpc",
    "ldap_search": "weirvern.zeek_ldap_search",
}


def _ratio(num: float, den: float) -> float:
    return float(num) / float(den) if den else 0.0


def coverage(client: Client, *, hours: int = 24) -> dict[str, Any]:
    """Per-table row counts for the last `hours`; no training on a zero-row source."""
    hours = max(1, min(int(hours), 24 * 30))
    counts: dict[str, int] = {}
    errors: dict[str, str] = {}
    for key, table in COVERAGE_TABLES.items():
        try:
            rows = client.query(
                f"SELECT count() FROM {table} WHERE ts >= now() - INTERVAL {hours} HOUR"
            ).result_rows
            counts[key] = int(rows[0][0]) if rows else 0
        except Exception as exc:  # noqa: BLE001
            errors[key] = type(exc).__name__
            counts[key] = 0
    zero = [key for key, count in counts.items() if count == 0]
    return {
        "available": not zero and not errors,
        "counts": counts,
        "zero_tables": zero,
        "errors": errors,
        "reason": ("identity coverage complete" if not zero and not errors else
                   "identity coverage gap: " + ", ".join(zero + sorted(errors))),
        "hours": hours,
    }


def features_from_events(
    events: Sequence[dict],
    *,
    seen_services: set[str] | None = None,
    seen_operations: set[str] | None = None,
    seen_filters: set[str] | None = None,
) -> dict[str, Any]:
    """Pure identity-graph features. Raw usernames/filters never leave this function.

    `events` are dicts with `kind` in kerberos/ntlm/smb_mapping/dce_rpc/ldap_search. A host
    with no events is absent, not a zero vector.
    """
    if not events:
        return {"present": False, "event_count": 0.0}
    count = len(events)
    kerberos = [e for e in events if e.get("kind") == "kerberos"]
    ntlm = [e for e in events if e.get("kind") == "ntlm"]
    smb = [e for e in events if e.get("kind") == "smb_mapping"]
    rpc = [e for e in events if e.get("kind") == "dce_rpc"]
    ldap = [e for e in events if e.get("kind") == "ldap_search"]
    services = {str(e.get("service") or "") for e in kerberos if e.get("service")}
    operations = {str(e.get("operation") or "") for e in rpc if e.get("operation")}
    filters = {str(e.get("ldap_filter") or "") for e in ldap if e.get("ldap_filter")}
    kerberos_novelty = 0.0
    if seen_services is not None:
        kerberos_novelty = _ratio(sum(1 for s in services if s not in seen_services),
                                  len(services) or 1)
    rpc_novelty = 0.0
    if seen_operations is not None:
        rpc_novelty = _ratio(sum(1 for o in operations if o not in seen_operations),
                             len(operations) or 1)
    ldap_novelty = 0.0
    if seen_filters is not None:
        ldap_novelty = _ratio(sum(1 for f in filters if f not in seen_filters),
                              len(filters) or 1)
    admin_paths = [str(e.get("path") or "") for e in smb]
    admin_share = sum(1 for path in admin_paths
                      if any(marker in path.upper() for marker in ("ADMIN$", "C$", "IPC$")))
    ntlm_hosts = {str(e.get("hostname") or "") for e in ntlm if e.get("hostname")}
    return {
        "present": True,
        "event_count": float(count),
        "kerberos_spn_novelty": kerberos_novelty,
        "kerberos_novelty_known": seen_services is not None,
        "ntlm_failure_ratio": _ratio(sum(1 for e in ntlm if not int(e.get("success", 0))),
                                     len(ntlm)),
        "ntlm_host_diversity": _ratio(len(ntlm_hosts), len(ntlm)),
        "smb_admin_share_ratio": _ratio(admin_share, len(smb)),
        "rpc_operation_novelty": rpc_novelty,
        "rpc_novelty_known": seen_operations is not None,
        "ldap_filter_novelty": ldap_novelty,
        "ldap_novelty_known": seen_filters is not None,
    }


def score(features: dict, *, use_identity_shape: bool = True) -> tuple[float, str]:
    """Bounded 0..1 score with count/ratio-only evidence; absent scores 0 and says so."""
    if not features.get("present"):
        return 0.0, "no identity events in this window (host absent)"
    count = float(features.get("event_count", 0.0))
    if not use_identity_shape:
        return (round(min(1.0, count / 100.0) * 0.25, 4),
                f"count-only: events={int(count)} (identity shape ablated)")
    kerberos = float(features.get("kerberos_spn_novelty", 0.0))
    ntlm = max(float(features.get("ntlm_failure_ratio", 0.0)),
               float(features.get("ntlm_host_diversity", 0.0)))
    admin = float(features.get("smb_admin_share_ratio", 0.0))
    rpc = float(features.get("rpc_operation_novelty", 0.0))
    ldap = float(features.get("ldap_filter_novelty", 0.0))
    value = (0.20 * kerberos + 0.25 * ntlm + 0.20 * admin
             + 0.20 * rpc + 0.15 * ldap)
    value = round(min(1.0, value), 4)
    evidence = (
        f"events={int(count)}; kerberos_novelty={kerberos:.2f}"
        f"{'' if features.get('kerberos_novelty_known') else ' (unknown)'}; "
        f"ntlm_failure={float(features.get('ntlm_failure_ratio', 0.0)):.2f}; "
        f"smb_admin_share={admin:.2f}; rpc_novelty={rpc:.2f}"
        f"{'' if features.get('rpc_novelty_known') else ' (unknown)'}; "
        f"ldap_novelty={ldap:.2f}"
        f"{'' if features.get('ldap_novelty_known') else ' (unknown)'}"
    )
    return value, evidence


def score_events(events: Iterable[dict], **kwargs: Any) -> list[dict]:
    """Pure scoring over synthetic/read rows, for tests and the future shadow path."""
    out: list[dict] = []
    for event in events:
        features = features_from_events([event], **kwargs)
        value, evidence = score(features)
        out.append({"src_addr": event.get("src_addr", ""), "score": value,
                    "evidence": evidence, "features": features})
    return sorted(out, key=lambda r: (-r["score"], str(r["src_addr"])))


def run(client: Client, *, hours: int = 24) -> dict:
    """Coverage-gated shadow status; it never trains or alerts on a zero-row source."""
    cov = coverage(client, hours=hours)
    if not cov["available"]:
        return {
            "available": False,
            "reason": cov["reason"],
            "coverage": cov,
            "rows": 0,
            "model_version": __version__,
            "source": "identity tables (coverage gate)",
        }
    # Coverage exists. The candidate scoring path is deliberately not enrolled until a
    # non-zero fixture has been reviewed; the coverage report is the evidence this card owes.
    return {
        "available": True,
        "reason": "identity coverage complete; scoring path awaits a reviewed fixture",
        "coverage": cov,
        "rows": 0,
        "model_version": __version__,
        "source": "identity tables (coverage gate)",
    }


__all__ = ["COVERAGE_TABLES", "MODEL_NAME", "coverage", "features_from_events", "run",
           "score", "score_events"]
