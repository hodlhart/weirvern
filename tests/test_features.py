from datetime import datetime
from pathlib import Path

from weirvern.features import (
    DBSCAN_FEATURES,
    HOST_FEATURES,
    IF_FEATURES,
    extract_features,
    feature_vector,
)
from weirvern.zeek_features import ZEEK_DBSCAN_FEATURES, ZEEK_FEATURES

ROOT = Path(__file__).resolve().parent.parent


def _flow(**overrides):
    f = {
        "window_start": datetime(2026, 9, 14, 10, 30),
        "total_bytes": 1_000_000,
        "total_packets": 10_000,
        "unique_dst_ips": 5,
        "flow_count": 50,
        "avg_bytes": 20000.0,
    }
    f.update(overrides)
    return f


def test_basic_features_shape():
    feats = extract_features(_flow())
    # 10 host + 4 diversity + 2 temporal + the Zeek set. Asserted as a SUM rather than a
    # literal, so appending a feature does not need this line edited -- but a feature that
    # silently went missing still fails here.
    assert len(feats) == len(HOST_FEATURES) + 4 + 2 + len(ZEEK_FEATURES)
    assert feats["log_bytes"] > 0
    assert feats["bytes_per_packet"] == 100.0
    assert feats["is_business_hours"] == 1.0  # Tue 10:30
    assert abs(feats["hour_sin"] ** 2 + feats["hour_cos"] ** 2 - 1.0) < 1e-9


def test_business_hours_night():
    feats = extract_features(_flow(window_start=datetime(2026, 9, 14, 2, 0)))
    assert feats["is_business_hours"] == 0.0


def test_no_diversity_defaults():
    feats = extract_features(_flow())
    assert feats["port_entropy"] == 0.0
    assert feats["activity_regularity"] == 1.0
    assert feats["burstiness"] == 1.0
    assert feats["connection_density"] == 1.0


def test_diversity_populated():
    feats = extract_features(_flow(), diversity={
        "unique_dst_ports": 100, "port_entropy": 3.2, "bytes_stddev": 5000.0,
        "unique_connections": 40,
    })
    assert feats["log_unique_dst_ports"] > 0
    assert feats["port_entropy"] == 3.2
    assert abs(feats["bytes_stddev_norm"] - 0.005) < 1e-9
    assert abs(feats["connection_density"] - 0.8) < 1e-9


def test_temporal_populated():
    feats = extract_features(_flow(), temporal={"activity_regularity": 0.1, "burstiness": 4.0})
    assert feats["activity_regularity"] == 0.1
    assert feats["burstiness"] == 4.0


def test_feature_vectors_match_train_order():
    feats = extract_features(_flow(), diversity={
        "unique_dst_ports": 10, "port_entropy": 1.0, "bytes_stddev": 1.0,
        "unique_connections": 5,
    }, temporal={"activity_regularity": 0.5, "burstiness": 2.0})
    # The vector length must equal the declared feature list, which is the property that
    # actually matters: `feature_vector` rebuilds a model's input BY POSITION, so a vector
    # whose length disagrees with its column list is silently misaligned.
    assert len(feature_vector(feats, IF_FEATURES)) == len(IF_FEATURES)
    assert len(feature_vector(feats, DBSCAN_FEATURES)) == len(DBSCAN_FEATURES)
    # The Zeek features must actually be in those lists, or the wiring did nothing.
    assert "zeek_present" in IF_FEATURES, "the Zeek presence flag is not in the IF vector"
    assert ZEEK_FEATURES[0] in IF_FEATURES

    # AND the lists must end with the Zeek block in the SAME ORDER as ZEEK_FEATURES. A model
    # records its feature_columns and rebuilds its vector by name, so an order mismatch
    # produces a vector of the right length holding the wrong values -- nothing raises.
    assert IF_FEATURES[-len(ZEEK_FEATURES):] == ZEEK_FEATURES
    assert DBSCAN_FEATURES[-len(ZEEK_DBSCAN_FEATURES):] == ZEEK_DBSCAN_FEATURES


# ── TRAIN AND SCORE ENCODED THE DAY OF WEEK DIFFERENTLY (the train/score scale mismatch) ─────
#
# The training queries in models/detectors.py encode the day with ClickHouse's `toDayOfWeek`, which
# is Monday=1 .. Sunday=7. `extract_features` encoded the SAME window with Python's
# `datetime.weekday()`, which is Monday=0 .. Sunday=6 -- a constant off-by-one on the day index.
#
# MEASURED against the cluster for a Wednesday window:
#
#     from ClickHouse: dow_sin  0.4338837  dow_cos -0.9009689
#     from this module: dow_sin  0.9749279  dow_cos -0.2225209
#
# So the model learned one point on the weekly circle and was asked to score another. Every score
# rested on a vector that did not mean what the training row meant: the model was not wrong, it was
# answering a different question. Nothing raised, because the vector has the right length and every
# value is a valid number -- which is what made it silent.
#
# THESE TESTS DO NOT RE-DERIVE THE EXPECTED VALUES. Re-deriving them in Python would compare the
# module against the same mistake a second time; the whole defect is that two languages disagree
# about what day it is. ClickHouse is the authority, so the expected values are the ones its own
# expressions produce, quoted from a live query.


def test_the_day_encoding_matches_CLICKHOUSE_for_every_day_of_the_week():
    """All seven days, not just the one that was measured.

    A single-day check would pass for a formula that happened to agree on that day; the off-by-one
    only shows on six of seven. These are ClickHouse's own outputs for
    `sin(2*pi()*toDayOfWeek(d)/7)` and `cos(...)`, for the week of 2026-09-21 (a Monday):
    """
    import math

    # (date, ClickHouse toDayOfWeek, sin, cos, business) -- TRANSCRIBED VERBATIM from
    #   SELECT toString(d), toDayOfWeek(d), sin(2*pi()*toDayOfWeek(d)/7),
    #          cos(2*pi()*toDayOfWeek(d)/7), if(toDayOfWeek(d) < 6, 1, 0)
    #   FROM (SELECT toDate('2026-09-21') + number AS d FROM numbers(7))
    # run against the cluster. The digits are ClickHouse's output, including the ones it prints to
    # 8 significant figures and the 1e-16 residue on Sunday -- NOT re-derived in Python, which would
    # compare this module against the same mistake a second time. My first transcription of days 4
    # and 5 was wrong in the last two digits and the test passed anyway, because the tolerance is
    # 1e-9; that is why they are quoted rather than computed.
    ch = [
        ("2026-09-21", 1, 0.7818314824680298, 0.6234898018587336, 1),
        ("2026-09-22", 2, 0.9749279121818236, -0.22252093395631434, 1),
        ("2026-09-23", 3, 0.43388373911755823, -0.900968867902419, 1),
        ("2026-09-24", 4, -0.433883739117558, -0.9009688679024191, 1),
        ("2026-09-25", 5, -0.9749279121818236, -0.2225209339563146, 1),
        ("2026-09-26", 6, -0.7818314824680299, 0.6234898018587334, 0),
        ("2026-09-27", 7, -2.4492935982947064e-16, 1.0, 0),
    ]
    for date_s, ch_dow, want_sin, want_cos, want_business in ch:
        y, m, d = (int(x) for x in date_s.split("-"))
        dt = datetime(y, m, d, 13, 5)
        assert dt.isoweekday() == ch_dow, (
            f"Python's isoweekday() and ClickHouse's toDayOfWeek disagree about {date_s}: "
            f"{dt.isoweekday()} vs {ch_dow}"
        )
        feats = extract_features(_flow(window_start=dt))
        assert math.isclose(feats["dow_sin"], want_sin, abs_tol=1e-9), (
            f"dow_sin for {date_s} ({dt.strftime('%A')}) is {feats['dow_sin']} but ClickHouse's "
            f"toDayOfWeek encoding gives {want_sin}. The model trains on ClickHouse's value and "
            f"scores on this one"
        )
        assert math.isclose(feats["dow_cos"], want_cos, abs_tol=1e-9), (
            f"dow_cos for {date_s} ({dt.strftime('%A')}) is {feats['dow_cos']} but ClickHouse's "
            f"toDayOfWeek encoding gives {want_cos}"
        )
        # The SAME table pins the business-hours predicate, so moving one half of the encoding
        # without the other cannot pass.
        assert feats["is_business_hours"] == float(want_business), (
            f"is_business_hours for {date_s} ({dt.strftime('%A')}) is "
            f"{feats['is_business_hours']} but the training query's `toDayOfWeek(...) < 6` gives "
            f"{want_business}"
        )


def test_business_hours_covers_the_same_DAYS_as_the_training_query():
    """The training query says `toDayOfWeek(...) < 6` -> Monday..Friday, because 6 is Saturday.

    In Python's `weekday()` numbering the same five days are `< 5`. Both spellings exclude exactly
    Saturday and Sunday, so either could look right in isolation -- but a change that moves the
    sine to ClickHouse's numbering and leaves this predicate on Python's puts the two halves of one
    time encoding on different calendars. This asserts the DAYS, for all seven.
    """
    weekday_flags = {}
    for offset in range(7):
        dt = datetime(2026, 9, 21 + offset, 12, 0)  # Mon .. Sun
        feats = extract_features(_flow(window_start=dt))
        weekday_flags[dt.strftime("%A")] = feats["is_business_hours"]

    assert weekday_flags["Saturday"] == 0.0, "Saturday counted as business hours"
    assert weekday_flags["Sunday"] == 0.0, "Sunday counted as business hours"
    for dayname in ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday"):
        assert weekday_flags[dayname] == 1.0, f"{dayname} was not counted as business hours"


def test_a_SINGLE_day_slide_is_not_reported_as_the_same_time():
    """THE DEFECT ITSELF, as a property rather than a table.

    A Wednesday and a Tuesday must encode differently, and the Wednesday encoding must equal the one
    a Wednesday PRODUCES -- not the one a Tuesday does. Under the old off-by-one the Wednesday value
    was byte-identical to what the module produced for a Tuesday, which is exactly the wrong-row
    failure: the model trained on Wednesday's row and was handed Tuesday's.
    """
    wed = extract_features(_flow(window_start=datetime(2026, 9, 23, 13, 5)))
    tue = extract_features(_flow(window_start=datetime(2026, 9, 22, 13, 5)))

    assert (wed["dow_sin"], wed["dow_cos"]) != (tue["dow_sin"], tue["dow_cos"]), (
        "a Wednesday and a Tuesday encode identically, so the weekly cycle is not represented"
    )
    # And the measured ClickHouse value for Wednesday must be Wednesday's, not Tuesday's.
    assert abs(wed["dow_sin"] - 0.43388373911755823) < 1e-9, (
        "Wednesday is encoding as another day"
    )
    assert abs(wed["dow_sin"] - tue["dow_sin"]) > 1e-6, (
        "Wednesday's sine is exactly Tuesday's sine -- the off-by-one is back"
    )


def test_the_TRAINING_SQL_and_this_module_agree_about_the_day():
    """THE CROSS-FILE ASSERTION, which is what was missing.

    Every test above compares this module against ClickHouse's OUTPUT. That catches the defect, but
    only for the days someone thought to quote. The real invariant is that the training query and
    this module encode the same window the same way -- and those live in two different files, in two
    different languages, which is exactly how they drifted apart unnoticed.

    This reads `models/detectors.py`, extracts the day-indexing call the training queries use, and
    asserts it is the numbering Python's `isoweekday()` produces. A change to either side fails here.
    """
    import re

    src = (ROOT / "weirvern" / "models" / "detectors.py").read_text()
    calls = re.findall(r"(toDayOfWeek|toISOWeek|toDayOfMonth)\s*\(\s*a\.window_start\s*\)", src)
    assert calls, (
        "no day-indexing call found in the training queries. If the encoding was removed, this test "
        "is now vacuous -- check what replaced it before deleting this assertion."
    )
    assert set(calls) == {"toDayOfWeek"}, (
        f"the training query indexes the day with {sorted(set(calls))}; ClickHouse's toDayOfWeek is "
        f"Monday=1..Sunday=7, which is what `datetime.isoweekday()` returns. Any other function has "
        f"a different numbering and the scoring side must be changed to match it"
    )

    # And the scoring side must still be on that numbering: Wednesday is 3, not 2.
    assert datetime(2026, 9, 23).isoweekday() == 3
    feats = extract_features(_flow(window_start=datetime(2026, 9, 23, 13, 5)))
    assert abs(feats["dow_sin"] - 0.43388373911755823) < 1e-9, (
        "the training query says Wednesday is day 3; this module does not encode it as day 3"
    )


def test_the_business_hours_predicate_in_SQL_and_here_describe_the_same_days():
    """The SQL says `toDayOfWeek(...) < 6`; this module must exclude the SAME two days.

    Asserted as a day set rather than as a numeric comparison, because the two sides use different
    spellings of the same threshold (6 on ClickHouse's numbering, 5 on Python's), and an assertion
    on the literal would lock in one spelling without checking the meaning.
    """
    import re

    src = (ROOT / "weirvern" / "models" / "detectors.py").read_text()
    m = re.search(r"toDayOfWeek\(a\.window_start\)\s*<\s*(\d+)", src)
    assert m, "the training query's business-hours predicate changed shape; re-verify by hand"
    bound = int(m.group(1))
    # ClickHouse: Saturday is 6, so `< 6` means Monday..Friday.
    assert bound == 6, f"the SQL bound changed to {bound}; does it still mean Monday..Friday?"

    # This module must agree on which days those are, checked across a full week.
    days = {datetime(2026, 9, 21 + i).strftime("%A"):
            extract_features(_flow(window_start=datetime(2026, 9, 21 + i, 12, 0)))["is_business_hours"]
            for i in range(7)}
    sql_days = sorted(d for d, v in days.items() if v == 1.0)
    assert sql_days == ["Friday", "Monday", "Thursday", "Tuesday", "Wednesday"], (
        f"the training query's `toDayOfWeek(...) < {bound}` means Monday..Friday, but this module "
        f"treats {sql_days} as business hours"
    )
