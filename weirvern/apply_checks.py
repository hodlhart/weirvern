"""Apply-time assertions: the named checks that run BETWEEN a staged plan and the write.

WHENCE (BF-14, research #6): Tailscale's tests gate saves; Splunk's projected-noise number;
the CrowdStrike RCA, where a wildcard nobody tested against real data took down fleets. The
contract: every check is NAMED, runs at apply time, and a FAIL BLOCKS the write and names
itself. A check that cannot run is SKIPPED WITH ITS REASON -- never a silent pass. The UI
answers "4 tests pass, 1 skipped - why?" from this payload, so the skip reasons are prose.

Three checks ship -- the card's own three examples:
  * 'the interconnect plan stays complete' -- the effective INTERCEPT_* values validated as
    ONE plan by the SAME make_plan() the sensor's supervisor uses (a second copy of the
    rules would drift, and the one that drifts is the one nobody tests).
  * 'the capture interface is one the sensors report' -- a change to the capture interface
    is refused when no reporting sensor lists it (live evidence, not a promise).
  * 'the threshold does not fire on yesterday's baseline' -- a BASE_THRESHOLD change is
    refused when the proposed value would have fired on more rows in the last 24h than a
    day's noise budget (the alert-budget rule applied to tuning itself).
"""
from __future__ import annotations

import datetime as dt
import logging

from weirvern import fleet as fleet_mod

logger = logging.getLogger(__name__)

#: how many rows in 24h a threshold may fire on before the change is refused. A queue a
#: person can actually work is the point (SRE alert budgets); the number is stated in the
#: refusal so the operator tunes against a visible line, not a mood.
NOISE_BUDGET_PER_DAY = 50

#: ConfigMap key -> the plan field make_plan() validates it as.
PLAN_FROM_SETTINGS = {
    "INTERCEPT_MODE": "mode",
    "INTERCEPT_IFACE": "iface",
    "INTERCEPT_SEGMENT": "segment",
    "INTERCEPT_ADDR": "addr",
    "INTERCEPT_GATEWAY": "gateway",
    "INTERCEPT_TARGETS": "targets",
}


def _r(name: str, status: str, detail: str = "") -> dict:
    return {"name": name, "status": status, "detail": detail}


def run_apply_checks(*, changes: dict, current: dict, ch_client=None, now=None) -> dict:
    """Run every apply-time assertion against the EFFECTIVE (merged) configuration.

    `changes` is keyed by ConfigMap keys (the route normalises before calling); `current` is
    the ConfigMap's own data. Merging before judging is the same contract the settings plan
    uses: a change is judged in the context of the configuration it will produce.
    """
    upper = {str(k).strip().upper(): "" if v is None else str(v) for k, v in (changes or {}).items()}
    merged = {str(k).strip().upper(): "" if v is None else str(v)
              for k, v in (current or {}).items()}
    merged.update(upper)
    now = now or dt.datetime.now(dt.UTC)
    results: list[dict] = []

    # ── 1. the interconnect plan stays complete ──────────────────────────────────────────
    name = "the interconnect plan stays complete"
    if not (set(upper) & set(PLAN_FROM_SETTINGS)):
        results.append(_r(name, "skip", "this change does not touch the interconnect plan"))
    else:
        effective = {field: merged.get(key, "") for key, field in PLAN_FROM_SETTINGS.items()}
        try:
            plan = fleet_mod.make_plan(**effective)
            results.append(_r(name, "pass",
                              f"validated as one plan (mode={plan.mode or 'not set'}, "
                              f"interface={plan.iface or 'not set'}, "
                              f"targets={plan.targets or 'not set'})"))
        except fleet_mod.FleetError as exc:
            results.append(_r(name, "fail", str(exc)))
        except Exception as exc:  # noqa: BLE001
            results.append(_r(name, "skip", f"the plan could not be validated ({type(exc).__name__})"))

    # ── 1b. the per-NIC plan set is valid and never names the management port ───────────
    name = "the per-NIC plans are valid"
    if "INTERCEPT_PLANS" not in upper:
        results.append(_r(name, "skip", "this change does not touch the per-NIC plans"))
    else:
        from weirvern.nic_plans import NicPlanError, NicPlanSet  # noqa: PLC0415

        try:
            plans = NicPlanSet.from_json(upper.get("INTERCEPT_PLANS", ""))
            problems = plans.validate(mgmt_iface=merged.get("MGMT_IFACE", ""))
            if problems:
                results.append(_r(name, "fail", "; ".join(problems)))
            else:
                results.append(_r(
                    name, "pass",
                    f"{len(plans.plans)} NIC(s): "
                    f"capture={','.join(plans.capture_ifaces()) or 'none'}, "
                    f"siphon={','.join(plans.siphon_ifaces()) or 'none'}, "
                    f"sluice={','.join(plans.sluice_ifaces()) or 'none'}"))
        except (NicPlanError, ValueError) as exc:
            results.append(_r(name, "fail", str(exc)))
        except Exception as exc:  # noqa: BLE001
            results.append(_r(name, "skip", f"the per-NIC plans could not be validated ({type(exc).__name__})"))

    # ── 2. the capture interface is one the sensors report ───────────────────────────────
    name = "the capture interface is one the sensors report"
    # CAPTURE_IFACE is the setting the GUI writes; INTERCEPT_IFACE is the older plan key.
    # Reading only the latter made a real CAPTURE_IFACE change skip this check and report
    # "the change does not name a capture interface" -- a skipped check explaining nothing
    # about the interface the operator had just chosen.
    touched = set(upper) & {"CAPTURE_IFACE", "INTERCEPT_IFACE"}
    chosen = (upper.get("CAPTURE_IFACE", "").strip()
              or upper.get("INTERCEPT_IFACE", "").strip()
              or merged.get("CAPTURE_IFACE", "").strip()
              or merged.get("INTERCEPT_IFACE", "").strip())
    if not touched:
        results.append(_r(name, "skip", "the change does not name a capture interface"))
    elif not chosen:
        results.append(_r(name, "skip", "the capture interface is empty"))
    elif ch_client is None:
        results.append(_r(name, "skip", "no live connection to the heartbeat store"))
    else:
        try:
            from weirvern import fleet_store  # noqa: PLC0415

            heartbeats, hb_error = fleet_store.read_heartbeats(ch_client)
            if hb_error:
                results.append(_r(name, "skip", f"heartbeats are unreadable ({hb_error})"))
            else:
                reported: dict[str, list[str]] = {}
                for hb in heartbeats or []:
                    sid = str(hb.get("sensor_id") or "?")
                    for i in (hb.get("interfaces") or []):
                        reported.setdefault(str(i), []).append(sid)
                if not reported:
                    results.append(_r(name, "skip", "no sensor is reporting its interfaces"))
                elif chosen in reported:
                    results.append(_r(name, "pass",
                                      f"{chosen} is reported by " + ", ".join(reported[chosen])))
                else:
                    heard = "; ".join(f"{i} ({', '.join(s)})"
                                      for i, s in sorted(reported.items()))
                    results.append(_r(
                        name, "fail",
                        f"no reporting sensor lists {chosen!r}. Heard: {heard}. A sensor "
                        f"cannot capture on an interface it does not have."))
        except Exception as exc:  # noqa: BLE001
            results.append(_r(name, "skip", f"heartbeats could not be read ({type(exc).__name__})"))

    # ── 3. the threshold does not fire on yesterday's baseline ───────────────────────────
    name = "the threshold does not fire on yesterday's baseline"
    if "BASE_THRESHOLD" not in upper:
        results.append(_r(name, "skip", "the change does not move the alert threshold"))
    elif ch_client is None:
        results.append(_r(name, "skip", "no live connection to the anomaly store"))
    else:
        try:
            proposed = float(merged.get("BASE_THRESHOLD", ""))
        except (TypeError, ValueError):
            results.append(_r(name, "skip",
                              f"the proposed threshold {merged.get('BASE_THRESHOLD')!r} is not a number"))
        else:
            try:
                since = (now - dt.timedelta(hours=24)).replace(tzinfo=None)
                rows = ch_client.query(
                    "SELECT count() FROM weirvern.netflow_anomalies "
                    "WHERE detected_at >= %(since)s AND anomaly_score >= %(thr)s",
                    parameters={"since": since, "thr": proposed},
                ).result_rows
                n = int(rows[0][0] or 0) if rows else 0
                if n > NOISE_BUDGET_PER_DAY:
                    results.append(_r(
                        name, "fail",
                        f"threshold {proposed} would have fired on {n} rows in the last 24h "
                        f"(the day's budget is {NOISE_BUDGET_PER_DAY}). Raise it, or change "
                        f"your mind on purpose."))
                else:
                    results.append(_r(
                        name, "pass",
                        f"threshold {proposed} would have fired on {n} of the last 24h's rows "
                        f"(budget {NOISE_BUDGET_PER_DAY})"))
            except Exception as exc:  # noqa: BLE001
                results.append(_r(name, "skip",
                                  f"the last 24h could not be counted ({type(exc).__name__})"))

    passed = sum(1 for r in results if r["status"] == "pass")
    skipped = sum(1 for r in results if r["status"] == "skip")
    failed = [r["name"] for r in results if r["status"] == "fail"]
    summary = f"{passed} passed, {skipped} skipped" + (f", {len(failed)} failed" if failed else "")
    return {"results": results, "blocked": bool(failed), "failed": failed, "summary": summary}
