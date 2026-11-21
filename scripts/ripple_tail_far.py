#!/usr/bin/env python3
"""Measure the fitted ripple tail's realised false-alarm rate on held-out windows.

WHY THIS EXISTS. A fitted negative binomial is a model, and a model can be miscalibrated. The
ripple layer uses it only where the empirical rank test cannot resolve the 0.01 family bar, so
the failure mode this script exists to catch is a coarse scale that looks statistically
significant because its tail is too thin -- manufacturing ripples. The acceptance rule is
explicit: a scale is usable only when its realised FAR on held-out normal windows is at or below
`MAX_ACCEPTABLE_FAR` (3x nominal), with the Wilson interval reported beside it.

WHAT IS MEASURED. For each channel and scale, the baseline is the host's own trailing windows.
The held-out window is the NEXT one (index 0 in the query's own numbering): fit on indices >= 1,
score index 0. That is exactly the production direction -- no peeking, no in-sample scoring. The
same measurement is repeated with the baseline truncated to the most recent 35 windows, which is
the sample size the 7d scale would have at this deployment's retention, so small-n behaviour is
measured rather than assumed.

WHAT IT REPORTS, per scale: the windows available (expected from the lookback and observed in the
data), the method each fit selected (negbin/poisson/insufficient), the FAR at 0.01 and 0.001 with
a Wilson 95% interval, the empirical test's FAR for comparison, and the fitted tail's resolution
(the count at which each tail reaches 0.01). Scales with too little live history are reported as
NOT MEASURABLE rather than silently omitted, and a model-based replay may accompany them but is
labelled SYNTHETIC.

HOW TO RUN (inside the worker pod, where ClickHouse credentials and the shipping package exist):

    kubectl -n weirvern exec deploy/weirvern-worker -- python3 /tmp/ripple_tail_far.py \
        --out /tmp/ripple_tail_far.json

Run it from a checkout with the same environment to use a local ClickHouse. It imports the
SHIPPING query builders and fit, never a re-typed copy.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from datetime import UTC, datetime
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from weirvern import db, monitored  # noqa: E402
from weirvern.config import Settings  # noqa: E402
from weirvern.models import ripple_evidence as rev  # noqa: E402
from weirvern.models import ripple_tail  # noqa: E402

#: The nominal family bar the tail is asked to resolve.
ALPHA = 0.01

#: A scale is accepted when its realised FAR is at or below this. Three times the nominal rate is
#: the line between "a fitted model with ordinary small-sample error" and "a detector that will
#: cry wolf"; the Wilson interval is reported beside it so a reader can see the uncertainty.
MAX_ACCEPTABLE_FAR = 0.03

#: The small-baseline replay size. 35 is the number of 7d windows a 234-day-retention deployment
#: holds; it is also the lower end of the live 6h baseline, so the replay is not a fantasy size.
SMALL_N = 35

#: One representative channel per independent family that carries a count statistic. A second
#: view of the same family would add correlated tests, not evidence.
CHANNELS = (
    "flow_volume",
    "conn_volume",
    "dns_volume",
    "kerberos_volume",
    "tls_fingerprint_diversity",
    "http_host_diversity",
    "http_ua_novelty",
    "zeek_notice_volume",
)


def wilson(successes: int, total: int, z: float = 1.96) -> dict[str, float] | None:
    """Wilson score interval: the honest interval for a proportion near zero."""
    if total <= 0:
        return None
    p = successes / total
    denominator = 1.0 + z * z / total
    centre = (p + z * z / (2.0 * total)) / denominator
    half = z * math.sqrt(p * (1.0 - p) / total + z * z / (4.0 * total * total)) / denominator
    return {"low": round(max(0.0, centre - half), 6), "high": round(min(1.0, centre + half), 6)}


def _median(values: list[float]) -> float | None:
    clean = sorted(value for value in values if math.isfinite(value))
    if not clean:
        return None
    middle = len(clean) // 2
    if len(clean) % 2:
        return round(clean[middle], 6)
    return round((clean[middle - 1] + clean[middle]) / 2.0, 6)


def _spec(channel: str):
    for spec in rev.SPECS:
        if spec.channel == channel:
            return spec
    raise SystemExit(f"unknown channel: {channel}")


def _series(client: Any, spec: Any, scale: str, moment: datetime, lookback: int,
            cidrs: tuple[str, ...]) -> dict[str, dict[int, tuple[float, float, float]]]:
    """The per-host buckets at `scale`, folded exactly as the production pass folds them."""
    return rev._buckets(client, spec, scale=scale, moment=moment, lookback_days=lookback,
                        scope_cidrs=cidrs)


def _score_host(by_index: dict[int, tuple[float, float, float]], spec: Any, *, scale: str,
                limit_reference: int | None, force_tail: bool = False) -> dict[str, Any] | None:
    """One held-out measurement: fit on the windows older than the held-out one.

    THE SELECTION RULE IS THE PRODUCTION RULE. At 100+ baseline windows the empirical rank p is
    used and no fit is made; below 100 the fitted tail is used. A validation that always fitted
    would report a method the detector never uses, which is exactly the kind of silent drift this
    script exists to catch.

    `force_tail=True` measures the TAIL ITSELF at whatever sample the history holds, including
    100+ windows where production would prefer the rank test. That is how a scale's tail is
    re-measured as history grows: the question "would this fit have cried wolf on a window the
    assumption-free test called ordinary" does not stop being askable at n=100, and a tail that
    is only validated at n=9 has not been validated at all.

    The held-out window is the most recent window the host has (production scores the window
    ending at `now`, which is the same one when the feed is current). `limit_reference` truncates
    the baseline to the most recent N windows for the small-n replay.
    """
    if not by_index:
        return None
    current_index = max(by_index)
    current = by_index[current_index]
    history = {index: bucket for index, bucket in by_index.items() if index < current_index}
    if len(history) < max(rev.MIN_BASELINE_SAMPLES, 2):
        return None
    ordered = sorted(history, reverse=True)  # newest first
    if limit_reference is not None:
        ordered = ordered[:limit_reference]
    reference = [rev._value(spec, history[index]) for index in ordered]
    value = rev._value(spec, current)
    if not math.isfinite(value):
        return None
    count = len(reference)
    empirical = rev.empirical_pvalue_two_sided(value, reference)
    fit = None
    tail_eligible = (spec.kind in rev.TAIL_KINDS if force_tail
                     else rev.tail_supported(scale, spec.kind))
    if count >= rev.EMPIRICAL_MIN_WINDOWS and not force_tail:
        method = "empirical"
        p = empirical
    elif tail_eligible:
        fit = ripple_tail.fit_counts(reference)
        method = fit.method
        p = ripple_tail.tail_pvalue(value, fit) if fit.usable else float("nan")
    else:
        method = "insufficient"
        p = float("nan")
    thresholds = (ripple_tail.p01_thresholds(fit, ALPHA) if fit is not None
                  else {"upper": None, "lower": None})
    return {
        "n": count,
        "method": method,
        "p": p,
        "p_empirical": empirical,
        "value": value,
        "fit_mean": fit.mean if fit is not None else float("nan"),
        "fit_variance": fit.variance if fit is not None else float("nan"),
        "fit_size": fit.size if fit is not None else float("nan"),
        "p01_upper": thresholds["upper"],
        "p01_lower": thresholds["lower"],
    }


def _verdict(report: dict[str, Any], *, scale: str, total: int, normal_total: int,
             normal_fires: int) -> None:
    """Set `method`, `usable` and `reason` from the numbers, never from a wish.

    THE PRODUCTION RULE DECIDES. A scale is usable at a sample below 100 only when its fitted
    tail is ENABLED (`TAIL_ENABLED`): otherwise `_measure` writes 'insufficient' for every row
    and the scale produces no evidence at all. Reporting 'parametric, usable' from the window
    count alone would claim a capability the detector does not have -- the 24h scale on
    2026-11-21 held 30 windows and one held-out fit while producing zero evidence rows.

    A WINDOW COUNT IS NOT A MEASUREMENT. Even an enabled scale is refused here when no held-out
    baseline produced a usable fit, because there is then no realised FAR to accept.
    """
    observed = int(report["observed_max_windows"])
    if observed >= rev.EMPIRICAL_MIN_WINDOWS:
        report["method"] = "empirical"
        report["usable"] = True
        report["reason"] = "the empirical test resolves the bar at the observed window count"
        return
    if observed < rev.MIN_BASELINE_SAMPLES:
        report["method"] = "insufficient"
        report["usable"] = False
        report["reason"] = (f"the data holds {observed} window(s); "
                            f"{rev.MIN_BASELINE_SAMPLES} are required for a fit")
        return
    if total == 0:
        report["method"] = "insufficient"
        report["usable"] = False
        report["reason"] = "no host had a complete held-out measurement"
        return
    if not rev.tail_supported(scale, "count"):
        report["method"] = "insufficient"
        report["usable"] = False
        report["reason"] = (
            f"the data holds {observed} window(s); its empirical p floor is {report['p_floor']}, "
            f"above the {ALPHA:g} bar. The fitted tail is disabled at this scale: "
            f"{rev.TAIL_DISABLED_REASON.get(scale, 'not validated at this deployment')}")
        return
    if report["tail_only"]["tests"] == 0:
        report["method"] = "insufficient"
        report["usable"] = False
        report["reason"] = (
            f"the data holds {observed} window(s), but no held-out baseline produced a usable "
            f"fitted tail; there is no measured FAR to accept")
        return
    report["method"] = "parametric"
    far = report["far"] or 0.0
    normal_far = report["far_on_normal"]
    # THE ACCEPTANCE RULE IS ABOUT MANUFACTURED RIPPLES. A tail that fires only on windows the
    # assumption-free rank test already saw as extreme (empirical p <= 0.05) is doing its job; a
    # tail that fires on windows the rank test calls ordinary is inventing significance. The raw
    # FAR is reported beside it, because a reader is entitled to both.
    if normal_far is None:
        report["usable"] = far <= MAX_ACCEPTABLE_FAR
        report["reason"] = (
            f"realised FAR {far:.2%} on {total} held-out window(s); no window was ordinary by "
            f"the empirical test, so the manufactured-ripple rate is unmeasured")
        return
    report["usable"] = normal_far <= MAX_ACCEPTABLE_FAR
    report["reason"] = (
        f"realised FAR {far:.2%} on {total} held-out window(s); on the {normal_total} window(s) "
        f"the empirical test calls ordinary (p>0.05) the tail fired {normal_fires} time(s) "
        f"({normal_far:.2%}), {'at or below' if report['usable'] else 'above'} the "
        f"{MAX_ACCEPTABLE_FAR:.0%} acceptance line")


def measure_scale(client: Any, scale: str, *, moment: datetime, retention: int,
                  channels: tuple[str, ...], max_hosts: int,
                  cidrs: tuple[str, ...]) -> dict[str, Any]:
    """Every representative channel at one scale, held out one window at a time."""
    lookback = rev.scale_lookback_days(scale, retention)
    expected = rev.baseline_windows(scale, lookback)
    report: dict[str, Any] = {
        "scale": scale,
        "lookback_days": lookback,
        "expected_windows": expected,
        "observed_max_windows": 0,
        "method": "insufficient",
        "usable": False,
        "reason": "",
        "p_floor": None,
        "channels": {},
        "tests": 0,
        "fires_001": 0,
        "fires_001_extreme": 0,
        "fires_empirical_001": 0,
        "method_counts": {},
        "fit_mean_median": None,
        "fit_size_median": None,
        "p01_upper_median": None,
        "p01_lower_median": None,
        # THE TAIL MEASURED ON ITS OWN, not through the production selection rule. At a scale
        # that now holds 100+ windows production uses the rank test, so the production numbers
        # cannot say whether the FIT is still calibrated; this block can.
        "tail_only": {
            "tests": 0, "fires": 0, "far": None, "far_interval": None,
            "normal_tests": 0, "fires_on_normal": 0, "far_on_normal": None,
            "far_on_normal_interval": None, "method_counts": {},
            "fit_mean_median": None, "fit_size_median": None,
            "p01_upper_median": None, "p01_lower_median": None,
        },
    }
    total = fires = fires_extreme = emp_fires = 0
    normal_total = normal_fires = 0
    small_total = small_fires = 0
    small_methods: dict[str, int] = {}
    tail_total = tail_fires = tail_normal = tail_normal_fires = 0
    tail_methods: dict[str, int] = {}
    tail_means: list[float] = []
    tail_sizes: list[float] = []
    tail_uppers: list[float] = []
    tail_lowers: list[float] = []
    means: list[float] = []
    sizes: list[float] = []
    uppers: list[float] = []
    lowers: list[float] = []
    for channel in channels:
        spec = _spec(channel)
        if spec.kind not in rev.TAIL_KINDS:
            continue
        try:
            buckets = _series(client, spec, scale, moment, lookback, cidrs)
        except Exception as exc:  # noqa: BLE001 - one unreadable channel must not hide the rest
            report["channels"][channel] = {"error": f"{type(exc).__name__}: {str(exc)[:160]}"}
            continue
        row: dict[str, Any] = {
            "hosts": 0, "windows_max": 0, "n": 0, "fires": 0, "fires_extreme": 0,
            "empirical_fires": 0, "method_counts": {},
            "normal_tests": 0, "fires_on_normal": 0,
            "small_n": {"n": 0, "fires": 0, "method_counts": {}},
            "tail_only": {"n": 0, "fires": 0, "fires_on_normal": 0, "normal_tests": 0,
                          "method_counts": {}},
            "fit_mean_median": None, "fit_size_median": None,
            "p01_upper_median": None, "p01_lower_median": None,
        }
        row_means: list[float] = []
        row_sizes: list[float] = []
        row_uppers: list[float] = []
        row_lowers: list[float] = []
        for index, (_host, by_index) in enumerate(sorted(buckets.items())):
            if index >= max_hosts:
                break
            row["windows_max"] = max(row["windows_max"], len(by_index) - 1)
            scored = _score_host(by_index, spec, scale=scale, limit_reference=None)
            if scored is None:
                continue
            row["hosts"] += 1
            row["n"] += 1
            row["method_counts"][scored["method"]] = (
                row["method_counts"].get(scored["method"], 0) + 1)
            tail_fired = math.isfinite(scored["p"]) and scored["p"] <= ALPHA
            if tail_fired:
                row["fires"] += 1
            if math.isfinite(scored["p"]) and scored["p"] <= 0.001:
                row["fires_extreme"] += 1
            if math.isfinite(scored["p_empirical"]) and scored["p_empirical"] <= ALPHA:
                row["empirical_fires"] += 1
            # THE FALSE-ALARM TEST THAT MATTERS. A window the empirical test calls ordinary
            # (p > 0.05) is not an event the rank test could see; if the tail fires there, it
            # manufactured a ripple. Extreme windows where the empirical p is small are the
            # tail's intended resolution gain, not a false alarm.
            if math.isfinite(scored["p_empirical"]) and scored["p_empirical"] > 0.05:
                row["normal_tests"] += 1
                if tail_fired:
                    row["fires_on_normal"] += 1
            if scored["method"] == ripple_tail.NEGBIN:
                row_means.append(scored["fit_mean"])
                row_sizes.append(scored["fit_size"])
            for key, bucket in (("p01_upper", row_uppers), ("p01_lower", row_lowers)):
                if scored[key] is not None:
                    bucket.append(float(scored[key]))
            small = _score_host(by_index, spec, scale=scale, limit_reference=SMALL_N)
            if small is not None:
                row["small_n"]["n"] += 1
                row["small_n"]["method_counts"][small["method"]] = (
                    row["small_n"]["method_counts"].get(small["method"], 0) + 1)
                if math.isfinite(small["p"]) and small["p"] <= ALPHA:
                    row["small_n"]["fires"] += 1
            tail = _score_host(by_index, spec, scale=scale, limit_reference=None,
                               force_tail=True)
            if tail is not None and math.isfinite(tail["p"]):
                row["tail_only"]["n"] += 1
                row["tail_only"]["method_counts"][tail["method"]] = (
                    row["tail_only"]["method_counts"].get(tail["method"], 0) + 1)
                tail_fired = tail["p"] <= ALPHA
                if tail_fired:
                    row["tail_only"]["fires"] += 1
                if math.isfinite(tail["p_empirical"]) and tail["p_empirical"] > 0.05:
                    row["tail_only"]["normal_tests"] += 1
                    if tail_fired:
                        row["tail_only"]["fires_on_normal"] += 1
                if tail["method"] == ripple_tail.NEGBIN:
                    tail_means.append(tail["fit_mean"])
                    tail_sizes.append(tail["fit_size"])
                for key, bucket in (("p01_upper", tail_uppers), ("p01_lower", tail_lowers)):
                    if tail[key] is not None:
                        bucket.append(float(tail[key]))
        if row["n"]:
            row["far"] = round(row["fires"] / row["n"], 6)
            row["far_interval"] = wilson(row["fires"], row["n"])
            row["empirical_far"] = round(row["empirical_fires"] / row["n"], 6)
            row["small_n"]["far"] = round(row["small_n"]["fires"] / row["small_n"]["n"], 6)
            row["small_n"]["far_interval"] = wilson(row["small_n"]["fires"],
                                                    row["small_n"]["n"])
            if row["tail_only"]["n"]:
                row["tail_only"]["far"] = round(
                    row["tail_only"]["fires"] / row["tail_only"]["n"], 6)
                row["tail_only"]["far_interval"] = wilson(
                    row["tail_only"]["fires"], row["tail_only"]["n"])
                row["tail_only"]["far_on_normal"] = (
                    round(row["tail_only"]["fires_on_normal"]
                          / row["tail_only"]["normal_tests"], 6)
                    if row["tail_only"]["normal_tests"] else None)
                row["tail_only"]["far_on_normal_interval"] = wilson(
                    row["tail_only"]["fires_on_normal"], row["tail_only"]["normal_tests"])
            row["fit_mean_median"] = _median(row_means)
            row["fit_size_median"] = _median(row_sizes)
            row["p01_upper_median"] = _median(row_uppers)
            row["p01_lower_median"] = _median(row_lowers)
            means.extend(row_means)
            sizes.extend(row_sizes)
            uppers.extend(row_uppers)
            lowers.extend(row_lowers)
            total += row["n"]
            fires += row["fires"]
            fires_extreme += row["fires_extreme"]
            emp_fires += row["empirical_fires"]
            normal_total += row["normal_tests"]
            normal_fires += row["fires_on_normal"]
            small_total += row["small_n"]["n"]
            small_fires += row["small_n"]["fires"]
            for method, count in row["small_n"]["method_counts"].items():
                small_methods[method] = small_methods.get(method, 0) + count
            tail_total += row["tail_only"]["n"]
            tail_fires += row["tail_only"]["fires"]
            tail_normal += row["tail_only"]["normal_tests"]
            tail_normal_fires += row["tail_only"]["fires_on_normal"]
            for method, count in row["tail_only"]["method_counts"].items():
                tail_methods[method] = tail_methods.get(method, 0) + count
        report["observed_max_windows"] = max(report["observed_max_windows"], row["windows_max"])
        report["channels"][channel] = row
    report["tests"] = total
    report["fires_001"] = fires
    report["fires_001_extreme"] = fires_extreme
    report["fires_empirical_001"] = emp_fires
    report["far"] = round(fires / total, 6) if total else None
    report["far_interval"] = wilson(fires, total)
    report["empirical_far"] = round(emp_fires / total, 6) if total else None
    report["normal_tests"] = normal_total
    report["fires_on_normal"] = normal_fires
    report["far_on_normal"] = round(normal_fires / normal_total, 6) if normal_total else None
    report["far_on_normal_interval"] = wilson(normal_fires, normal_total)
    # THE EMPIRICAL FLOOR AT THIS SAMPLE: 1/(n+1) for the widest baseline the data holds. It is
    # the reason a scale with 30-99 windows needs a fitted tail at all.
    report["p_floor"] = (round(1.0 / (report["observed_max_windows"] + 1.0), 6)
                         if report["observed_max_windows"] else None)
    report["small_n"] = {
        "size": SMALL_N, "tests": small_total, "fires": small_fires,
        "far": round(small_fires / small_total, 6) if small_total else None,
        "far_interval": wilson(small_fires, small_total),
        "method_counts": small_methods,
    }
    report["tail_only"].update({
        "tests": tail_total, "fires": tail_fires,
        "far": round(tail_fires / tail_total, 6) if tail_total else None,
        "far_interval": wilson(tail_fires, tail_total),
        "normal_tests": tail_normal, "fires_on_normal": tail_normal_fires,
        "far_on_normal": (round(tail_normal_fires / tail_normal, 6) if tail_normal else None),
        "far_on_normal_interval": wilson(tail_normal_fires, tail_normal),
        "method_counts": tail_methods,
        "fit_mean_median": _median(tail_means), "fit_size_median": _median(tail_sizes),
        "p01_upper_median": _median(tail_uppers), "p01_lower_median": _median(tail_lowers),
    })
    report["fit_mean_median"] = _median(means)
    report["fit_size_median"] = _median(sizes)
    report["p01_upper_median"] = _median(uppers)
    report["p01_lower_median"] = _median(lowers)
    for channel_row in report["channels"].values():
        for method, count in (channel_row.get("method_counts") or {}).items():
            report["method_counts"][method] = report["method_counts"].get(method, 0) + count
    _verdict(report, scale=scale, total=total, normal_total=normal_total,
             normal_fires=normal_fires)
    # THE SMALL HELD-OUT SAMPLE IS A PROVISIONAL ANSWER, not a certification. The interval is the
    # honest part; this flag keeps a caller from reading 0/8 as proof of a 0% rate.
    report["provisional"] = total < 30
    # THE TAIL'S OWN ACCEPTANCE, on the same rule as a scale's: the manufactured-ripple rate (on
    # windows the assumption-free test calls ordinary) must be at or below the line when it can
    # be measured, otherwise the raw rate decides. Reported separately from `usable`, because a
    # scale can be empirically usable while its fitted tail is not, and vice versa.
    tail_rate = report["tail_only"]["far_on_normal"]
    if tail_rate is None:
        tail_rate = report["tail_only"]["far"]
    # A 0/1 IS NOT AN ACCEPTANCE. The scale-level rule refuses to certify a rate on fewer than
    # 30 held-out windows; the tail uses the same bar, so a single lucky window cannot put a
    # scale on the board.
    report["tail_only"]["provisional"] = report["tail_only"]["tests"] < 30
    report["tail_only"]["accepted"] = (
        None if tail_rate is None or report["tail_only"]["tests"] < 30
        else bool(tail_rate <= MAX_ACCEPTABLE_FAR))
    return report


def synthetic_scale(*, scale: str, windows: int, mean: float, size: float,
                    draws: int, seed: int = 20261120) -> dict[str, Any]:
    """A model-based calibration check for a scale with no live history.

    It is explicitly SYNTHETIC: the draws come from the same negative binomial the fit assumes,
    so it measures the estimator's small-sample behaviour, not the live world's. It is reported
    beside the live result, never in place of one.
    """
    import numpy as np

    rng = np.random.default_rng(seed)
    prob = size / (size + mean)
    fires = empirical_fires = 0
    for _ in range(draws):
        values = rng.negative_binomial(size, prob, size=windows + 1)
        reference = [float(item) for item in values[1:]]
        current = float(values[0])
        fit = ripple_tail.fit_counts(reference)
        p = ripple_tail.tail_pvalue(current, fit)
        if math.isfinite(p) and p <= ALPHA:
            fires += 1
        if rev.empirical_pvalue_two_sided(current, reference) <= ALPHA:
            empirical_fires += 1
    return {
        "scale": scale,
        "synthetic": True,
        "windows": windows,
        "mean": round(mean, 6),
        "size": round(size, 6),
        "draws": draws,
        "far": round(fires / draws, 6),
        "far_interval": wilson(fires, draws),
        "empirical_far": round(empirical_fires / draws, 6),
        "note": ("draws are negative binomial by construction; this measures the estimator, "
                 "not the live deployment"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="/tmp/ripple_tail_far.json")
    parser.add_argument("--max-hosts", type=int, default=120)
    parser.add_argument("--synthetic-draws", type=int, default=2000)
    parser.add_argument("--channels", default=",".join(CHANNELS))
    args = parser.parse_args()

    settings = Settings()
    client = db.connect(settings, retries=3, delay_s=2.0)
    networks = monitored.networks(client)
    cidrs = tuple(str(net) for net in networks)
    if not cidrs:
        raise SystemExit("no monitored networks: no subject can be attributed")
    moment = datetime.now(UTC).replace(second=0, microsecond=0)
    retention = int(rev.retention_in_force(client)["days"])
    channels = tuple(name.strip() for name in args.channels.split(",") if name.strip())
    out: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "retention_days": retention,
        "anchor": moment.isoformat(),
        "alpha": ALPHA,
        "max_acceptable_far": MAX_ACCEPTABLE_FAR,
        "monitored_networks": [str(net) for net in networks],
        "scales": {},
    }
    for scale in ("1h", "6h", "24h", "7d"):
        out["scales"][scale] = measure_scale(
            client, scale, moment=moment, retention=retention, channels=channels,
            max_hosts=args.max_hosts, cidrs=cidrs)
    # THE 7d QUESTION, ANSWERED AS FAR AS THIS DEPLOYMENT CAN. If live 7d has no windows, the
    # synthetic replay states the estimator's FAR at that sample size, using the median live 6h
    # fit's parameters. The live 7d verdict remains 'insufficient', because a simulation is not
    # history.
    week = out["scales"]["7d"]
    if week["method"] == "insufficient":
        six = out["scales"]["6h"]
        mean, size = six.get("fit_mean_median"), six.get("fit_size_median")
        if mean and size:
            out["synthetic"] = synthetic_scale(
                scale="7d", windows=week["expected_windows"] or SMALL_N,
                mean=float(mean), size=float(size), draws=args.synthetic_draws)
        else:
            out["synthetic"] = {
                "scale": "7d", "synthetic": True, "unavailable": True,
                "reason": "no live negative-binomial fit was available to parameterise it",
            }
    text = json.dumps(out, indent=2, sort_keys=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
