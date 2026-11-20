"""The detector registry: who owns each detector, its runbook, and whether it may page a human.

THE RULE (BF-12; SRE alert budgets, incident.io's fatigue data): a detector ships QUIET. Its
findings land in the console and the audit trail; paging a phone is a decision somebody makes
ON PURPOSE, by giving the detector an owner and a runbook first. A detector nobody has
registered -- a new one, fresh out of development -- is therefore quiet BY CONSTRUCTION, not
by someone remembering a flag. `may_page` is the one gate the alert path consults.

The names are load-bearing: they are the exact strings the ensemble joins into a verdict's
`detected_by_models` (a comma-joined list of the model names below), so a rename in the
ensemble without a rename here turns the alert quiet -- visible in the console as an
unregistered detector, never as a silent gap.
"""
from __future__ import annotations

#: model name -> its registry entry. `loud` is the permission to page; owner and runbook are
#: what make it meaningful ("loud" without either would be exactly the alert nobody can act on).
DETECTORS: dict[str, dict] = {
    "Isolation Forest": {
        "owner": "ops",
        "runbook": "Open the anomaly and read the evidence panel first -- the contributing "
                   "features say which measurements moved. Recognise the host and the "
                   "destination before anything else; then block, watch, or dismiss.",
        "rule": "IsolationForest scored this window above the strong-signal floor",
        "loud": True,
    },
    "Gradient Boosting": {
        "owner": "ops",
        "runbook": "Open the anomaly and read the evidence panel first. GradientBoosting leans "
                   "on supervised history, so a hit on a host with no recorded history is the "
                   "weakest case -- check the host drill-down before acting.",
        "rule": "GradientBoosting scored this window above the strong-signal floor",
        "loud": True,
    },
    "KNN distance": {
        "owner": "ops",
        "runbook": "The k-th-neighbour distance says this host-window sits far from every other "
                   "window with the same measured columns. Open the evidence panel: a host that "
                   "is new, rebuilt or running a new service is far from the population without "
                   "being an incident -- check first-seen before acting.",
        "rule": "KNN distance placed the window outside the population of host-windows",
        "loud": True,
    },
    "LOF": {
        "owner": "ops",
        "runbook": "The local outlier factor says this window's neighbourhood is far sparser than "
                   "its neighbours' -- a local density anomaly, not a global one. It is the most "
                   "independent score in the ensemble, so a hit here with no corroboration is a "
                   "lead: read the evidence panel before acting, and expect it on hosts whose "
                   "traffic mix changes rather than on volume.",
        "rule": "LOF found the window in a sparser local neighbourhood than its peers",
        "loud": True,
    },
    "Adaptive Baseline": {
        "owner": "ops",
        "runbook": "The adaptive baseline saw a z-score deviation past the strong-signal floor. "
                   "Open the evidence panel: baseline deviations decay as the window ages, so "
                   "check whether the 'why' sentence names a measurement you recognise.",
        "rule": "the adaptive baseline's z-score deviation passed the strong-signal floor",
        "loud": True,
    },
}


def detector_status(name: str) -> dict:
    """One detector's entry, never missing: an unregistered detector reads as unowned+quiet."""
    clean = str(name or "").strip()
    entry = DETECTORS.get(clean)
    if entry is None:
        return {"name": clean, "owner": "", "runbook": "", "rule": "", "loud": False,
                "known": False}
    return {"name": clean, "owner": entry["owner"], "runbook": entry["runbook"],
            "rule": entry["rule"], "loud": bool(entry["loud"]), "known": True}


def involved(detected_by_models: str) -> list[str]:
    """The detector names inside a verdict's comma-joined `detected_by_models` string."""
    return [part.strip() for part in str(detected_by_models or "").split(",") if part.strip()]


def may_page(detected_by_models: str) -> tuple[bool, str]:
    """Whether a verdict carried by these detectors may page a phone, and why not when not.

    Quiet is not an error: it is the default state of every detector until somebody owns it.
    The console and the audit trail still record the finding; only the page is withheld.
    """
    names = involved(detected_by_models)
    if not names:
        return False, "the verdict names no detector"
    unknown = sorted({n for n in names if not detector_status(n)["known"]})
    if unknown:
        return False, "unregistered detector(s): " + ", ".join(unknown)
    unowned = sorted({n for n in names
                      if not detector_status(n)["owner"] or not detector_status(n)["runbook"]
                      or not detector_status(n)["loud"]})
    if unowned:
        return False, "no owner, runbook, or loud permission yet: " + ", ".join(unowned)
    return True, ""


def row_ownership(detected_by_models: str) -> tuple[str, str]:
    """(owner, matched-rule) for one anomaly row, for the triage table's fixed contract.

    An unregistered detector's row says so plainly -- "unowned" and its own name as the rule
    -- because the operator's next action there is registering it, not reading a blank.
    """
    names = involved(detected_by_models)
    if not names:
        return "", ""
    owners = sorted({detector_status(n)["owner"] or "unowned" for n in names})
    if len(names) == 1:
        return owners[0], detector_status(names[0])["rule"] or f"matched by {names[0]}"
    rules = "; ".join(f"{n}: {detector_status(n)['rule'] or 'matched'}" for n in names)
    return ", ".join(owners), rules
