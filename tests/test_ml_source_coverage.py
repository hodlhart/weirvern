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
  * DBSCAN              -- a deliberate six-feature Zeek SUBSET (clustering degrades with
                          dimensionality on few samples), touching three logs: conn, notice,
                          weird.

So "every log is assessed by every model" is TRUE for the two wide models, TRUE for the
baseline only within its three named signals, and DELIBERATELY NARROW for DBSCAN. The tests pin
each fact so none of them can quietly change -- in either direction: a shrunken wide model
fails just as an overstated claim would.

The five protocol logs (kerberos, dce_rpc, ntlm, smb_mapping, smb_files) and x509 have no
host-attributable features BY DESIGN -- their rows feed the ATT&CK mapping and hunting instead.
That exemption is earned and asserted in test_ml_table_coverage.py; this file asserts that the
exemption lists agree, so a new log cannot land in neither place.
"""
from __future__ import annotations

import re
from pathlib import Path

from weirvern.config import ModelConfig
from weirvern.features import DBSCAN_FEATURES, IF_FEATURES
from weirvern.ingester import ZEEK_MAPPERS
from weirvern.models.detectors import (
    AdaptiveBaselineDetector,
    DBSCANDetector,
    GradientBoostingDetector,
    IsolationForestDetector,
)
from weirvern.zeek_features import (
    ZEEK_DBSCAN_FEATURES,
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

# Features that are DERIVED in Python from the per-window row plus the host's baseline rather
# than aliased in the summary query. They resolve to no aggregate by construction.
DERIVED_FEATURES = {"zeek_ja4_novelty", "zeek_service_rarity"}

# Aggregates in `zeek_window_summary_sql`, mapped to the ZEEK_MAPPERS log type they aggregate.
# Every one of these must be joined into the summary and must contribute at least one feature;
# a tenth-feature-less aggregate would be a log ingested and fed to no model.
AGG_LOGS = {
    "conn_agg": "conn",
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


def test_ja4_is_assessed_by_both_wide_models_and_by_neither_of_the_narrow_ones(tmp_path):
    """THE FINGERPRINT QUESTION, answered per model. JA4 reaches the wide pair through BOTH
    features -- the count AND the novelty ratio -- at training and at scoring time; DBSCAN's
    documented subset and the baseline's three named signals do not carry it, which is the
    honest reading of "assessed by all models" on this deployment."""
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
    assert not mapping["zeek_ja4_novelty"], "novelty is derived, not aliased"
    assert 'out["zeek_ja4_novelty"]' in ZEEK_FEATURES_SRC
    assert "baseline_ja4_set" in ZEEK_FEATURES_SRC, "the novelty ratio lost its history half"
    # And it all arrives live: the worker attaches the window row and the ensemble hands the
    # host's baseline to extract_features -- without both, novelty is a train-only column.
    assert '"zeek_ja4_novelty"' in ZEEK_FEATURES_SRC  # declared...
    assert 'f["_zeek"]' in WORKER_SRC, "the worker stopped attaching the Zeek window row"
    assert 'flow.get("_zeek")' in ENSEMBLE_SRC
    assert "baselines.get(src)" in ENSEMBLE_SRC, "scoring no longer supplies the host baseline"
    # Neither narrow model assesses JA4, and that is asserted in the same direction as the
    # positive claims: a silent addition would change behaviour without changing this proof.
    for feature in JA4_FEATURES:
        assert feature not in ZEEK_DBSCAN_FEATURES and feature not in DBSCAN_FEATURES
        assert feature not in _code_only(DETECTORS_SRC), (
            f"{feature} now appears in the detector code -- if a narrow model started to score "
            f"JA4, update this file's matrix and its docstring"
        )
    assert "clustering degrades with" in ZEEK_FEATURES_SRC, (
        "the DBSCAN subset's justification comment is gone -- the narrowing is now unexplained"
    )
    # JA4 only: no ja3 FEATURE exists anywhere in the vector.
    assert not [f for f in ZEEK_FEATURES if "ja3" in f], "a ja3 feature reappeared in ZEEK_FEATURES"


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


def test_dbscan_touches_conn_notice_and_weird_by_design(tmp_path):
    """The smallest model's coverage, derived rather than assumed: six Zeek features spanning
    three logs. The presence flag spans five logs and is a join flag, not a signal, so it is
    counted separately."""
    cols = _detector(tmp_path, DBSCANDetector).expected_feature_columns()
    assert cols == list(DBSCAN_FEATURES)
    assert set(ZEEK_DBSCAN_FEATURES) <= set(ZEEK_FEATURES)
    mapping = _feature_to_aggs()
    signal_aggs: set[str] = set()
    for feature in ZEEK_DBSCAN_FEATURES:
        if feature == "zeek_present":
            continue
        assert mapping[feature], f"{feature} no longer resolves to an aggregate"
        signal_aggs.update(mapping[feature])
    assert signal_aggs == {"conn_agg", "notice_agg", "weird_agg"}, (
        f"DBSCAN's signal coverage moved to {sorted(signal_aggs)} -- it is documented as "
        f"conn/notice/weird; a widened or shrunken subset needs the docs updated with it"
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
