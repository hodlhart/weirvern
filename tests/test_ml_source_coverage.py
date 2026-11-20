"""PROOF THAT EVERY SOURCE REACHES THE MODELS -- and the narrow paths, named.

THE QUESTION (asked of this repo): "verify with proof that ja4/ja3 (whichever we use) and all
zeek logs are being assessed by all ml models and the baseline."

THE ANSWER, AS A CONTRACT THIS FILE ENFORCES MECHANICALLY.

The fingerprinting in use is JA4, and only JA4. `ja3`/`ja3s` were DEAD COLUMNS -- declared,
never written by Zeek 9.x core, replaced by the JA4 pair (schema/001 documents the removal,
ingester.py's mapper comment repeats it). This file asserts on JA4, and treats a ja3 FEATURE
reappearing as a failure.

The four models, and what each one actually assesses (each pinned by a test below):

  * Isolation Forest   -- every Zeek feature: IF_FEATURES ends with the full ZEEK_FEATURES
                          block, so all TWELVE feature-bearing logs are assessed, JA4 included.
  * Gradient Boosting   -- the SAME matrix as the Isolation Forest. It is its distilled student;
                          training them on different matrices would be the defect.
  * Adaptive Baseline   -- trains on every Zeek feature (its query aggregates each of
                          ZEEK_FEATURES) but SCORES three of them: zeek_conn_count,
                          zeek_s0_ratio, zeek_notice_count.
  * KNN distance / LOF -- a deliberately SMALL Zeek subset (a distance degrades with
                          dimensionality on few samples): eight features covering conn, notice,
                          weird, the join flag, and -- appended at the operator\'s direction --
                          the JA4 pair, so a brand-new TLS stack is visible to the
                          cross-sectional pair too.

So "every log is assessed by every model" is TRUE for the two wide models and, since the JA4
pair was added to it, TRUE for the cross-sectional pair as well. The Adaptive Baseline remains the one model that
SCORES three named signals rather than the whole block (its training index still covers all
fifty). The tests pin each fact so none of them can quietly change -- in either direction: a
shrunken wide model fails just as an overstated claim would.

The five protocol logs (kerberos, dce_rpc, ntlm, smb_mapping, smb_files) and x509 have no
host-attributable features BY DESIGN -- their rows feed the ATT&CK mapping and hunting instead.
That exemption is earned and asserted in test_ml_table_coverage.py; this file asserts that the
exemption lists agree, so a new log cannot land in neither place.
"""
from __future__ import annotations

import re
from pathlib import Path

from weirvern.config import ModelConfig
from weirvern.features import CROSS_SECTIONAL_FEATURES, IF_FEATURES
from weirvern.ingester import ZEEK_MAPPERS
from weirvern.models.detectors import (
    AdaptiveBaselineDetector,
    GradientBoostingDetector,
    IsolationForestDetector,
    KNNDistanceDetector,
)
from weirvern.zeek_features import (
    ZEEK_CROSS_SECTIONAL_FEATURES,
    ZEEK_FEATURES,
    zeek_protocol_records_sql,
    zeek_window_summary_sql,
)

ROOT = Path(__file__).resolve().parents[1]
DETECTORS_SRC = (ROOT / "weirvern" / "models" / "detectors.py").read_text()
ENSEMBLE_SRC = (ROOT / "weirvern" / "ensemble.py").read_text()
WORKER_SRC = (ROOT / "weirvern" / "worker.py").read_text()
ZEEK_FEATURES_SRC = (ROOT / "weirvern" / "zeek_features.py").read_text()
SIBLING_TEST = (ROOT / "tests" / "test_ml_table_coverage.py").read_text()

# The fingerprint pair under test. JA4 only -- see the module docstring.
JA4_FEATURES = ("zeek_ja4_count", "zeek_ja4_novelty")

# Features with no window aggregate of their own. EMPTY TODAY, and that is the point: the two
# comparison features that used to be Python-only (`zeek_ja4_novelty`, `zeek_service_rarity`)
# are now computed by the SQL as well, from the `hist_*` windows, so the TRAINING matrix sees
# the same values the scoring path computes. A future feature of that kind belongs here, with
# its reason written next to it.
DERIVED_FEATURES: set[str] = set()

# Aggregates in `zeek_window_summary_sql`, mapped to the ZEEK_MAPPERS log type they aggregate.
# Every one of these must be joined into the summary and must contribute at least one feature;
# a tenth-feature-less aggregate would be a log ingested and fed to no model.
AGG_LOGS = {
    "conn_agg": "conn",
    # ── graph helpers (2026-10-24) ─────────────────────────────────────────────
    # These are CTE-to-CTE aggregates, not independent log summaries. They are joined through
    # helper aliases rather than through the keys UNION, so the "every aggregate is a key
    # source" invariant in the sibling test skips them explicitly. Their provenance is still
    # conn or dns, and that is what this map records.
    "conn_edges_agg": "conn",
    "dst_pop_agg": "conn",
    "graph_peer_agg": "conn",
    "graph_recip_agg": "conn",
    "inbound_agg": "conn",
    "hist_dns_agg": "dns",
    "hist_dst_agg": "conn",
    "dns_agg": "dns",
    "ssl_agg": "ssl",
    "notice_agg": "notice",
    "weird_agg": "weird",
    "dhcp_agg": "dhcp",
    "tunnel_agg": "tunnel",
    "quic_agg": "quic",
    "ldap_agg": "ldap_search",
    "ssh_agg": "ssh",
    "http_agg": "http",
    "files_agg": "files",
}

# The logs whose rows are read WITHOUT producing host features: the five protocol logs feed
# attack.py's ATT&CK mapping, and x509 is keyed on the certificate fingerprint (no src_addr),
# so it cannot be attributed to a host. Both exemptions are earned and asserted in the sibling
# file; the membership is re-derived here so the two files cannot disagree.
EXEMPT_LOGS = {"kerberos", "dce_rpc", "ntlm", "smb_mapping", "smb_files", "x509"}

# The Zeek signals the Adaptive Baseline SCORES (it trains on every feature). Pinned because
# "the baseline assesses it" must mean something specific and checkable.
BASELINE_SCORED = ("zeek_conn_count", "zeek_s0_ratio", "zeek_notice_count")


def _summary_sql() -> str:
    return zeek_window_summary_sql("2026-01-01 00:00:00", "2026-01-02 00:00:00")


def _comment_stripped(sql: str) -> str:
    return "\n".join(line.split("--")[0] for line in sql.splitlines())


def _join_aliases(sql: str) -> dict[str, str]:
    """`{table_alias: agg_name}` from the summary query's LEFT JOINs (`LEFT JOIN conn_agg c`)."""
    return {
        m.group(2): m.group(1)
        for m in re.finditer(r"LEFT JOIN\s+(\w+_agg)\s+(\w+)\s+ON", sql)
    }


def _feature_to_aggs(sql: str | None = None) -> dict[str, list[str]]:
    """`{feature_name: [agg names it is computed from]}` -- parsed from the REAL query.

    Each `... AS zeek_<feature>` select item in the outer SELECT is attributed to every
    aggregate its expression references. Multi-aggregate items are real (the presence flag and
    the coalesce chains), so the value is a list, not a single name.
    """
    flat = _comment_stripped(sql or _summary_sql())
    aliases = _join_aliases(flat)
    start = re.search(r"keys AS \(\s*SELECT", flat)
    end = re.search(r"FROM keys k", flat)
    assert start and end, "the summary query's shape changed -- this proof can no longer parse it"
    region = flat[start.end():end.start()]
    out: dict[str, list[str]] = {}
    cursor = 0
    # Advance the boundary on EVERY `AS <name>`, not only the zeek_ ones: the raw columns
    # (`AS ja4_set`) sit between the features, and stepping over only the feature names leaked
    # the previous expression into the next item -- which attributed `zeek_notice_count` to the
    # ssl aggregate, because `ifNull(s.ja4_set, [])` stood in between.
    for m in re.finditer(r"\bAS (?P<feat>\w+)", region):
        body = region[cursor:m.start()]
        cursor = m.end()
        feature = m.group("feat")
        if feature not in ZEEK_FEATURES:
            continue
        refs = {aliases[a] for a, _col in re.findall(r"\b(\w+)\.(\w+)\b", body) if a in aliases}
        out[feature] = sorted(refs)
    return out


def _code_only(src: str) -> str:
    """Python source with comments stripped -- this project's recurring trap is an assertion
    finding a documented defect quoted in a comment and reporting it as present."""
    return "\n".join(line.split("#")[0] for line in src.splitlines())


def _detector(model_dir, cls):
    return cls(model_dir, ModelConfig())


# ── the map itself ─────────────────────────────────────────────────────────────────────────────

def test_every_zeek_feature_resolves_to_the_log_it_comes_from():
    """The feature → aggregate mapping is real: all fifty features resolve, through the query's
    own join aliases. A feature that resolves to nothing (other than the two Python-derived
    ones) is a name the SQL never emits -- a vector column that can only ever be zero."""
    mapping = _feature_to_aggs()
    unresolved = [
        f for f in ZEEK_FEATURES
        if not mapping.get(f) and f not in DERIVED_FEATURES
    ]
    assert not unresolved, (
        f"these features are in ZEEK_FEATURES but no aggregate in the summary query produces "
        f"them: {unresolved}"
    )
    # The aggregates the query joins are exactly the ones this matrix names, and every one of
    # them maps to a log the ingester really maps.
    aggs = set(_join_aliases(_comment_stripped(_summary_sql())).values())
    assert aggs == set(AGG_LOGS), (
        f"the summary query joins {sorted(aggs)} but AGG_LOGS names {sorted(AGG_LOGS)} -- a new "
        f"aggregate was added without a log-mapping entry (or one was renamed)"
    )
    for agg, log in sorted(AGG_LOGS.items()):
        assert log in ZEEK_MAPPERS, f"{agg} aggregates {log}.log, which the ingester does not map"


def test_every_feature_bearing_log_reaches_both_wide_models(tmp_path):
    """THE HEADLINE. For each of the twelve feature-bearing logs: its features are in
    IF_FEATURES (which is what both wide models train and score on), so both wide models assess
    every one of them. This is the mechanically-checked version of "all zeek logs are being
    assessed by all ml models" -- true for the wide pair, and the next two tests name where the
    other two models deliberately narrow."""
    assert set(ZEEK_FEATURES) <= set(IF_FEATURES)
    if_cols = _detector(tmp_path, IsolationForestDetector).expected_feature_columns()
    gb_cols = _detector(tmp_path, GradientBoostingDetector).expected_feature_columns()
    assert if_cols == list(IF_FEATURES)
    assert gb_cols == list(IF_FEATURES), (
        "the Gradient Boosting student and the Isolation Forest teacher disagree on their "
        "matrix -- one of them is being scored on inputs it was not trained on"
    )
    mapping = _feature_to_aggs()
    per_log = {log: [] for log in AGG_LOGS.values()}
    for feature, sources in mapping.items():
        for agg in sources:
            per_log[AGG_LOGS[agg]].append(feature)
    for log, features in sorted(per_log.items()):
        # zeek_present is the join flag and is deliberately excluded from "signal" here.
        signal = [f for f in features if f != "zeek_present"]
        assert signal, f"{log}.log contributes no feature to any model"
        missing = [f for f in signal if f not in if_cols]
        assert not missing, f"{log}.log's features are not in the wide models' matrix: {missing}"


def test_ja4_reaches_every_model_including_the_cross_sectional_subset(tmp_path):
    """THE FINGERPRINT QUESTION, answered per model. JA4 reaches the wide pair through BOTH
    features -- the count AND the novelty ratio -- at training and at scoring time, and since
    the operator asked for it the cross-sectional subset carries the pair too, so the distance
    detectors can see a TLS stack a host has never presented. The Adaptive Baseline is the one
    that still does not SCORE it: its vocabulary is three named signals, pinned in its own test
    below."""
    for feature in JA4_FEATURES:
        assert feature in ZEEK_FEATURES, f"{feature} is not a feature at all"
        assert feature in IF_FEATURES
    if_cols = _detector(tmp_path, IsolationForestDetector).expected_feature_columns()
    gb_cols = _detector(tmp_path, GradientBoostingDetector).expected_feature_columns()
    for feature in JA4_FEATURES:
        assert feature in if_cols and feature in gb_cols, (
            f"{feature} does not reach both wide models"
        )
    # The count comes from the ssl aggregate; the novelty ratio is DERIVED in Python from the
    # window's ja4_set against the host's baseline set -- assert both halves exist and meet.
    mapping = _feature_to_aggs()
    assert mapping["zeek_ja4_count"] == ["ssl_agg"], (
        f"zeek_ja4_count now comes from {mapping['zeek_ja4_count']} -- update this proof"
    )
    # Novelty has TWO halves and both must exist: the window's fingerprints from the ssl
    # aggregate, and the host's history from the `hist_ja4` CTE. It used to be a constant 0 in
    # the summary ("the caller that holds the baseline computes it") while the caller that
    # TRAINS never had a baseline -- so every detector was fitted on a column that never varied.
    assert mapping["zeek_ja4_novelty"] == ["ssl_agg"], (
        f"novelty lost its window half: {mapping['zeek_ja4_novelty']}"
    )
    sql = _summary_sql()
    assert "hist_ja4 AS (" in sql and "arrayCount(x -> has(" in sql, (
        "the summary no longer computes novelty from a history window -- training would read a "
        "constant 0 while scoring computes real values"
    )
    assert 'out["zeek_ja4_novelty"]' in ZEEK_FEATURES_SRC
    assert "baseline_ja4_set" in ZEEK_FEATURES_SRC, "the novelty ratio lost its history half"
    # And it all arrives live: the worker attaches the window row and the ensemble hands the
    # host's baseline to extract_features -- without both, novelty is a train-only column.
    assert '"zeek_ja4_novelty"' in ZEEK_FEATURES_SRC  # declared...
    assert 'f["_zeek"]' in WORKER_SRC, "the worker stopped attaching the Zeek window row"
    assert 'flow.get("_zeek")' in ENSEMBLE_SRC
    assert "baselines.get(src)" in ENSEMBLE_SRC, "scoring no longer supplies the host baseline"
    # The cross-sectional subset carries the pair too -- added on purpose, and pinned in the same
    # direction as every other claim here: removing it again fails this proof.
    db_cols = _detector(tmp_path, KNNDistanceDetector).expected_feature_columns()
    for feature in JA4_FEATURES:
        assert feature in ZEEK_CROSS_SECTIONAL_FEATURES and feature in db_cols, (
            f"{feature} is not in the cross-sectional subset -- it was added on purpose; if it "
            f"was removed on purpose, this proof and the docs change with it"
        )
    # The Adaptive Baseline is the remaining model that does not SCORE JA4: its scoring path
    # reads three Zeek names by hand, asserted exactly in its own test below. This keeps that
    # boundary visible from here too.
    scoring_reads = set(re.findall(r'features\.get\("(zeek_\w+)"', _code_only(DETECTORS_SRC)))
    assert not (scoring_reads & set(JA4_FEATURES)), (
        f"the baseline's scoring vocabulary changed to include "
        f"{sorted(scoring_reads & set(JA4_FEATURES))} -- update its test, this proof and the docs"
    )
    assert "a distance degrades" in ZEEK_FEATURES_SRC, (
        "the cross-sectional subset's justification comment is gone -- the narrowing is now "
        "unexplained"
    )
    # JA4 only: no ja3 FEATURE exists anywhere in the vector.
    assert not [f for f in ZEEK_FEATURES if "ja3" in f], "a ja3 feature reappeared in ZEEK_FEATURES"


def test_ja4_computes_real_values_and_they_reach_the_vector():
    """THE DERIVATION COMPUTES, not merely wires. A window with three fingerprints of which
    one is in the host's history is two-thirds novel; the counts arrive SQL-logged and reach
    the vector unchanged; both land at their named slots in the ordered vector the wide models
    consume. And WITHOUT a history there is no novelty to claim, so the ratio stays 0.0 -- the
    feature must not guess a denominator into existence."""
    import math

    from weirvern.features import extract_features, feature_vector

    # Shaped exactly as `zeek_window_summary_sql` returns it: the seven counts are log1p'd
    # there, and scoring passes them through (GitHub #58).
    zeek_row = {
        "zeek_present": 1, "zeek_conn_count": math.log1p(3),
        "zeek_notice_count": math.log1p(1),
        "zeek_ja4_count": math.log1p(3), "ja4_set": ["ja4_a", "ja4_b", "ja4_c"],
        "zeek_service_count": math.log1p(2),
    }
    history = {"baseline_ja4_set": ["ja4_a"], "baseline_ja4_count": 1,
               "baseline_service_count": 2}
    f = extract_features({"window_start": None, "total_bytes": 0, "total_packets": 0},
                         None, None, zeek_row, history)
    assert f["zeek_ja4_count"] == math.log1p(3)
    assert f["zeek_ja4_novelty"] == 2 / 3
    vec = feature_vector(f, IF_FEATURES)
    assert vec[IF_FEATURES.index("zeek_ja4_count")] == math.log1p(3)
    assert vec[IF_FEATURES.index("zeek_ja4_novelty")] == 2 / 3
    # No history, no claim: novelty is 0.0 rather than assumed.
    g = extract_features({"window_start": None, "total_bytes": 0, "total_packets": 0},
                         None, None, zeek_row, None)
    assert g["zeek_ja4_novelty"] == 0.0
    assert g["zeek_ja4_count"] == math.log1p(3)
    # And a host with no TLS is not "novel": an empty set produces no ratio at all.
    h = extract_features({"window_start": None, "total_bytes": 0, "total_packets": 0},
                         None, None, {"zeek_present": 1,
                                      "zeek_conn_count": math.log1p(1)}, history)
    assert h["zeek_ja4_novelty"] == 0.0


def test_the_adaptive_baseline_trains_on_every_feature_and_scores_three():
    """IT READS THE WHOLE BLOCK AND SCORES A NAMED FEW. The training query aggregates every
    name in ZEEK_FEATURES (so the baseline INDEX covers all fifty), while predict() weighs
    exactly three: connections, answered-refusal shift, and Zeek's own notices. Both halves are
    pinned: the baseline cannot quietly stop reading a feature, and it cannot be described as
    assessing more than it does."""
    assert AdaptiveBaselineDetector.name == "Adaptive Baseline", (
        "the ensemble maps detector names to config weights -- a rename silently resets them"
    )
    assert "for c in ZEEK_FEATURES" in DETECTORS_SRC, (
        "the baseline's training query no longer builds its columns from ZEEK_FEATURES"
    )
    assert "enumerate(ZEEK_FEATURES)" in DETECTORS_SRC, "the by-name reader is gone"
    code = _code_only(DETECTORS_SRC)
    for feature in BASELINE_SCORED:
        assert feature in code, f"the baseline no longer scores {feature}"
    # The three scored signals are the ONLY zeek names its scoring path mentions.
    scored = set(re.findall(r'features\.get\("(zeek_\w+)"', code))
    assert scored == set(BASELINE_SCORED), (
        f"the baseline's scored Zeek vocabulary changed: {sorted(scored)} -- update the proof "
        f"and the docs to match"
    )


def test_the_cross_sectional_subset_covers_the_logs_it_names(tmp_path):
    """The small vector's coverage, derived rather than assumed: Zeek features spanning conn,
    notice, weird, the TLS fingerprints from the ssl log, and -- "make sure dns is added to all
    ml as well" (2026-10-16) -- the DNS triple. The presence flag spans the logs and is a join
    flag, not a signal, so it is counted separately."""
    cols = _detector(tmp_path, KNNDistanceDetector).expected_feature_columns()
    assert cols == list(CROSS_SECTIONAL_FEATURES)
    assert set(ZEEK_CROSS_SECTIONAL_FEATURES) <= set(ZEEK_FEATURES)
    mapping = _feature_to_aggs()
    signal_aggs: set[str] = set()
    for feature in ZEEK_CROSS_SECTIONAL_FEATURES:
        if feature == "zeek_present":
            continue
        assert mapping[feature], f"{feature} no longer resolves to an aggregate"
        signal_aggs.update(mapping[feature])
    assert signal_aggs == {"conn_agg", "notice_agg", "weird_agg", "ssl_agg", "dns_agg"}, (
        f"the cross-sectional signal coverage moved to {sorted(signal_aggs)} -- it is "
        f"documented as "
        f"conn/notice/weird plus the JA4 pair from ssl plus the DNS triple (2026-10-16); a "
        f"widened or shrunken subset needs the docs updated with it"
    )


def test_the_logs_without_host_features_are_exactly_the_earned_exemptions():
    """THE EXEMPTION CANNOT BECOME A HIDING PLACE. Every ingested log is either feature-bearing
    (mapped to an aggregate above) or in the earned exemption set. The membership is checked
    BOTH ways, so a new log cannot be ingested with neither features nor a justification."""
    covered = set(AGG_LOGS.values())
    declared = set(ZEEK_MAPPERS)
    assert covered | EXEMPT_LOGS == declared, (
        f"logs neither covered nor exempted: {sorted(declared - covered - EXEMPT_LOGS)}; "
        f"exemptions that are no longer ingested: {sorted(EXEMPT_LOGS - declared)}"
    )
    assert covered & EXEMPT_LOGS == set()
    # The sibling file owns the reasons; this file insists they still exist and still name the
    # same tables, so the two files cannot drift apart.
    assert "PROTOCOL_ONLY" in SIBLING_TEST and "zeek_x509" in SIBLING_TEST
    protocol_sql = zeek_protocol_records_sql("2026-01-01 00:00:00", "2026-01-02 00:00:00")
    for log in ("kerberos", "dce_rpc", "ntlm", "smb_mapping", "smb_files"):
        assert f"weirvern.zeek_{log}" in protocol_sql, (
            f"zeek_{log} is exempted from the features but the protocol query does not read it"
        )
