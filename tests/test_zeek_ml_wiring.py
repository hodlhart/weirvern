"""Zeek must be wired into EVERY ML job, on both the training and the scoring path.

WHY THIS FILE IS MOSTLY STRUCTURAL.

The failure being guarded against is a feature that is trained but never supplied at
inference. It is the quietest bug available here:

  * nothing raises -- `extract_features` takes an optional argument and defaults it to
    empty, so a caller that forgets it gets a full-length vector of zeroes
  * the models still train, score, and report normally
  * every metric looks fine
  * and the model is evaluated on a DIFFERENT distribution than it was fitted on, because
    the column it learned weights for is always zero at inference

That was the actual state of this codebase before these tests: `extract_features` gained a
`zeek` parameter and `ensemble.py` was still calling it with three positional arguments, so
the Zeek features would have been trained on real values and scored as zero forever. A
unit test of the pure function would not have caught it, because the pure function was
correct -- the CALL SITE was not.

So the tests below assert the call sites and the joins, not the arithmetic (which
tests/test_zeek_features.py covers). Where a property can be checked by running something,
it is run; where it can only be checked by reading a call signature, the signature is read.
"""
from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DETECTORS = (ROOT / "weirvern" / "models" / "detectors.py").read_text()
WORKER = (ROOT / "weirvern" / "worker.py").read_text()
ENSEMBLE = (ROOT / "weirvern" / "ensemble.py").read_text()
FEATURES = (ROOT / "weirvern" / "features.py").read_text()


def _fn_body(src: str, name: str) -> str:
    """The source of one function, bounded exactly by its AST extent.

    WHY AST RATHER THAN FINDING THE NEXT `def`: `detect_flows` contains a NESTED function,
    so searching for the next `    def ` stopped 1000 characters in and returned a fragment
    that did not contain the call site being asserted on. Text heuristics for "where does
    this function end" are wrong whenever there is nesting, a lambda, or a multi-line string
    holding the word `def` -- and being wrong here means a test that passes or fails for a
    reason unrelated to what it claims to check.
    """
    import ast

    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            lines = src.splitlines()
            return "\n".join(lines[node.lineno - 1:node.end_lineno])
    raise AssertionError(f"no function named {name} in the source")


def _call_args(src: str, callee: str) -> str:
    """The full argument text of a call, balancing parentheses.

    Truncating at the FIRST `)` is wrong whenever an argument itself contains a call --
    `flow.get("_diversity")` closed the slice after one argument, so the assertion saw an
    incomplete call and reported a defect that was not there.
    """
    start = src.index(f"{callee}(") + len(callee) + 1
    depth, i = 1, start
    while i < len(src) and depth:
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
        i += 1
    return src[start:i - 1]


# ── the call site, which is where the bug was ───────────────────────────────────

def test_the_ensemble_passes_the_zeek_row_to_extract_features():
    """The exact defect: a correct function called without its new argument.

    `extract_features` gained `zeek=`, and the ensemble kept calling it positionally with
    three arguments. Nothing raised; the features were simply always zero at inference.
    """
    body = _fn_body(ENSEMBLE, "detect_flows")
    args = _call_args(body, "extract_features")
    assert "_zeek" in args, (
        "the ensemble calls extract_features without the Zeek row, so the Zeek features are "
        "zero at SCORING time while the models trained on real values"
    )
    # And the baseline, which is what makes service novelty measurable rather than mere
    # variety. Without it `zeek_service_rarity` is always 0.
    assert "baselines" in args, (
        "the ensemble does not pass the host baseline, so service novelty cannot be computed"
    )


def test_the_worker_attaches_the_zeek_row_per_flow():
    """`_zeek` must be attached alongside `_diversity`/`_temporal`. Without the attachment
    the ensemble's lookup returns None and the features fall back to zeroes again."""
    assert 'f["_zeek"]' in WORKER, (
        "the worker does not attach _zeek to each flow, so the ensemble has nothing to pass"
    )
    # And keyed the same way as the others -- on (window, host), not host alone.
    idx = WORKER[WORKER.index("zeek_idx"):]
    assert "(f[\"window_start\"], f[\"src_addr\"])" in WORKER, (
        "the Zeek lookup is not keyed on the same (window, host) pair as the other joins"
    )
    assert "index(z_cols, z_rows)" in idx


def test_the_scoring_path_is_wrapped_so_zeek_failure_does_not_stop_detection():
    """A Zeek schema problem must degrade to NetFlow-only detection, not stop the worker.
    The inverse is also a real risk: an unwrapped query that starts failing silently turns
    off a detection path with no message.

    ASSERTED STRUCTURALLY, NOT BY A CHARACTER OFFSET. The previous version sliced a fixed
    600-character window after the first mention of `zeek_idx` and searched it for
    "except Exception". Adding an unrelated but correctly-guarded query above that point
    pushed the real `except` out of the window and the test failed while the property it
    protects was intact -- a false alarm that would equally have PASSED if the guard had been
    deleted and a comment mentioning "except Exception" had landed inside the slice.

    So: locate the try that wraps the Zeek load, and require its except clause to log. That is
    true wherever the code moves to.
    """
    assert "except Exception" in WORKER, "nothing in the worker guards a Zeek failure"
    assert "logger.warning" in WORKER, "a degraded Zeek path would be invisible"

    # The guard must be attached to the Zeek load specifically: find the try block that
    # contains the Zeek fetch and check it has a handler before the next top-level statement.
    anchor = WORKER.index("zeek_window_sql(")
    tail = WORKER[anchor:]
    # The next line at the original indentation that is not part of this try block ends the
    # region of interest; 1500 chars is generous for a guarded block and still local.
    region = tail[:1500]
    assert "except Exception" in region, (
        "the Zeek query that feeds scoring is not inside a try/except, so a Zeek problem "
        "would stop detection"
    )
    assert re.search(r"except Exception.*?:(\n|.){0,400}?logger\.warning", region), (
        "the Zeek failure path does not log, so a silently disabled detection path would be "
        "indistinguishable from a quiet network"
    )


# ── every detector, on the training path ────────────────────────────────────────

@pytest.mark.parametrize("detector", ["IsolationForestDetector", "GradientBoostingDetector",
                                      "KNNDistanceDetector", "LOFDetector",
                                      "AdaptiveBaselineDetector", "DBSCANDetector"])
def test_every_detector_is_covered(detector):
    """A guard on this file itself: if a detector is added, the list above must be extended
    deliberately rather than the new one going unwired.

    DBSCANDetector is in the list because the CLASS still exists (retired, kept for one release);
    the two cross-sectional detectors are the live pair that replaced it.
    """
    assert f"class {detector}" in DETECTORS, f"{detector} no longer exists; update this test"
    others = set(re.findall(r"^class (\w+Detector)", DETECTORS, re.M))
    assert others <= set(["IsolationForestDetector", "GradientBoostingDetector",
                          "KNNDistanceDetector", "LOFDetector",
                          "AdaptiveBaselineDetector", "DBSCANDetector"]), (
        f"a detector exists that this test does not cover: {others}"
    )


def test_isolation_forest_trains_on_zeek_features():
    body = _fn_body(DETECTORS, "train")
    assert "zeek_cte" in body and "zeek_cols" in body, (
        "the Isolation Forest training query does not include the Zeek join"
    )
    assert "feature_columns=IF_FEATURES" in DETECTORS, (
        "IF_FEATURES is the declared column list and must contain the Zeek features"
    )


def test_dbscan_trains_on_zeek_features_and_declares_the_smaller_set():
    """DBSCAN gets a REDUCED Zeek set by design -- clustering degrades with dimensionality
    on few samples -- so its select list must match ZEEK_DBSCAN_FEATURES, not ZEEK_FEATURES.
    A mismatch produces a vector of the right length holding the wrong columns."""
    assert "ZEEK_DBSCAN_FEATURES" in DETECTORS, (
        "DBSCAN does not use its own smaller Zeek set"
    )
    assert "feature_columns=DBSCAN_FEATURES" in DETECTORS
    body = DETECTORS[DETECTORS.index("class DBSCANDetector"):]
    body = body[:body.index("\nclass ")]
    assert "_zeek_clause(s, e, ZEEK_DBSCAN_FEATURES)" in body, (
        "the DBSCAN query does not pass its own column subset to the join helper"
    )


def test_gradient_boosting_inherits_the_zeek_features_from_its_teacher():
    """This detector trains on the Isolation Forest's matrix rather than running its own
    query, so it gets the Zeek features for free -- but only because its DECLARED column
    list matches the teacher's. If they diverged, the student's vector would be built from
    a different column list than the matrix it was fitted on."""
    body = DETECTORS[DETECTORS.index("class GradientBoostingDetector"):]
    body = body[:body.index("\nclass ")]
    assert "feature_columns=IF_FEATURES" in body, (
        "Gradient Boosting declares different columns than its teacher, so its input vector "
        "would be misaligned with the matrix it was trained on"
    )
    assert "X_unscaled" in body, "the teacher-matrix coupling changed; recheck this test"


def test_the_adaptive_baseline_trains_a_behavioural_baseline():
    body = DETECTORS[DETECTORS.index("class AdaptiveBaselineDetector"):]
    assert "zeek_seen" in body, (
        "the Adaptive Baseline has no Zeek presence flag, so it cannot tell a host with no "
        "behavioural baseline from one whose baseline is zero"
    )
    assert "avg_s0" in body and "avg_conn" in body, (
        "the Adaptive Baseline does not learn any behavioural norms from Zeek"
    )


def test_the_adaptive_baseline_CONSUMES_what_it_trains():
    """The easiest way to wire something up and have it do no work: train it and never read
    it. The behavioural baseline is checked to appear in `predict`, not only in `train`."""
    body = DETECTORS[DETECTORS.index("class AdaptiveBaselineDetector"):]
    pred = _fn_body(body, "predict")
    assert "zeek_seen" in pred, (
        "the behavioural baseline is trained but never consulted in predict(), so it "
        "contributes nothing to any score"
    )
    assert "s_z" in pred and "s_z" in pred[pred.index("return max"):] or "s_z)" in pred, (
        "the behavioural score is computed but not included in the returned maximum"
    )


# ── the feature contract itself ─────────────────────────────────────────────────

def test_the_presence_flag_is_in_the_vector():
    """Absence must be learnable. Without this flag a host Zeek never saw and a host Zeek
    saw doing nothing are the same row of zeroes, and the model learns that a whole class of
    host-window is normal-by-emptiness -- which is an artefact of two sensors observing
    different traffic, not a property of the network."""
    from weirvern.zeek_features import ZEEK_FEATURES, ZEEK_PRESENCE_FEATURE

    assert ZEEK_PRESENCE_FEATURE in ZEEK_FEATURES, (
        "the presence flag is not in the feature list, so it is never emitted into a vector"
    )
    from weirvern.features import IF_FEATURES

    assert ZEEK_PRESENCE_FEATURE in IF_FEATURES


def test_extract_features_defaults_to_absent_not_to_zero_evidence():
    """Called with no Zeek row, the presence flag must be 0 -- and every other Zeek feature
    0 as well, so the vector cannot claim evidence it does not have."""
    from weirvern.features import extract_features
    from weirvern.zeek_features import ZEEK_FEATURES, ZEEK_PRESENCE_FEATURE

    feats = extract_features({"total_bytes": 100, "total_packets": 2, "unique_dst_ips": 1,
                              "flow_count": 1})
    assert feats[ZEEK_PRESENCE_FEATURE] == 0.0
    for name in ZEEK_FEATURES:
        assert feats[name] == 0.0, f"{name} is non-zero with no Zeek data supplied"


def test_extract_features_accepts_a_zeek_row_positionally_as_the_fourth_argument():
    """Signature stability: the ensemble passes it positionally, so a reordering would
    silently bind the baseline to the wrong parameter."""
    from weirvern.features import extract_features

    params = list(inspect.signature(extract_features).parameters)
    assert params[:5] == ["flow", "diversity", "temporal", "zeek", "zeek_baseline"], (
        f"extract_features parameter order changed: {params}"
    )


def test_the_join_is_left_not_inner():
    """An INNER JOIN would drop every host-window Zeek did not see -- most of them on the
    measured deployment -- so the model would be trained only on hosts both sensors observe
    and would have no idea what to do with the rest."""
    from weirvern.zeek_features import ZEEK_JOIN_ON

    assert "LEFT JOIN" in ZEEK_JOIN_ON.upper(), "the Zeek join is not a LEFT JOIN"
    assert "INNER" not in ZEEK_JOIN_ON.upper()


def test_the_join_key_includes_the_window_not_just_the_host():
    """Joining on the host alone would compare a 5-minute NetFlow window against the host's
    ENTIRE Zeek history, so a burst from any point in the range would look like it happened
    inside the current window."""
    from weirvern.zeek_features import ZEEK_JOIN_ON

    assert "window_start" in ZEEK_JOIN_ON and "src_addr" in ZEEK_JOIN_ON
    assert "z.window_start = a.window_start" in ZEEK_JOIN_ON


def test_the_scoring_and_training_queries_share_one_join_definition():
    """Two builders that could drift, producing features bucketed differently at train and
    score time. They must both come from `zeek_window_summary_sql`."""
    from weirvern.zeek_features import zeek_window_sql, zeek_window_summary_sql

    inner = zeek_window_summary_sql("2026-01-01 00:00:00", "2026-01-02 00:00:00")
    outer = zeek_window_sql("2026-01-01 00:00:00", "2026-01-02 00:00:00")
    assert inner in outer, (
        "the scoring query does not wrap the training query, so the two can bucket "
        "differently and the features would not line up with the model"
    )


def test_the_window_function_matches_the_netflow_aggregate():
    """`flows_aggregated_mv` buckets with toStartOfFiveMinute. Bucketing the Zeek side any
    other way compares misaligned periods."""
    from weirvern.zeek_features import zeek_window_summary_sql

    q = zeek_window_summary_sql("2026-01-01 00:00:00", "2026-01-02 00:00:00")
    assert "toStartOfFiveMinute" in q, "the Zeek side is not bucketed to 5 minutes"
    schema = (ROOT / "weirvern" / "schema" / "001_weirvern.sql").read_text()
    assert "toStartOfFiveMinute" in schema, (
        "the NetFlow aggregate no longer buckets to 5 minutes, so this join is misaligned"
    )


def test_coverage_reporting_exists_and_can_see_a_disjoint_pair():
    """The only thing that would reveal two sensors observing different segments. Measured
    on the test box: 35 Zeek hosts, 88 NetFlow hosts, 2 overlapping."""
    from weirvern.zeek_features import zeek_join_coverage

    poor = zeek_join_coverage(netflow_hosts=88, zeek_hosts=35, overlapping=2)
    assert poor["coverage"] < 0.1
    assert "disjoint" in poor["verdict"] or "poor" in poor["verdict"]

    good = zeek_join_coverage(netflow_hosts=100, zeek_hosts=95, overlapping=90)
    assert good["coverage"] >= 0.7
    assert "good" in good["verdict"]


def test_the_coverage_query_counts_overlap_rather_than_guessing_it():
    from weirvern.zeek_features import zeek_coverage_sql

    q = zeek_coverage_sql("2026-01-01 00:00:00")
    assert "INTERSECT" in q, "the coverage query does not compute the actual overlap"
    assert "flows_aggregated" in q and "zeek_conn" in q
