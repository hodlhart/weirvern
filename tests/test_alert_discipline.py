"""BF-12: the alert discipline -- quiet by default, the closed vocabulary, the gate.

The registry's names are LOAD-BEARING: they are exactly what the ensemble joins into a
verdict's detected_by_models. A rename in the ensemble without a rename here must turn the
alert quiet rather than let an unowned detector page -- these tests pin both directions.
"""
from datetime import datetime

from weirvern import detector_registry as dr

ENSEMBLE_NAMES = ("Isolation Forest", "Gradient Boosting", "KNN distance", "LOF",
                  "Adaptive Baseline")


def test_every_ensemble_detector_is_registered_with_owner_and_runbook():
    for name in ENSEMBLE_NAMES:
        st = dr.detector_status(name)
        assert st["known"], name
        assert st["owner"], name
        assert st["runbook"], name
        assert st["rule"], name
        assert st["loud"] is True, name


def test_an_unregistered_detector_cannot_page():
    ok, why = dr.may_page("Mystery Net, KNN distance")
    assert ok is False
    assert "unregistered" in why
    assert "Mystery Net" in why


def test_a_verdict_with_no_detector_cannot_page():
    ok, why = dr.may_page("")
    assert ok is False and "no detector" in why


def test_a_registered_verdict_pages_and_says_nothing():
    ok, why = dr.may_page("Isolation Forest,KNN distance")
    assert ok is True and why == ""


def test_row_ownership_reads_the_same_table_the_gate_reads():
    owner, rule = dr.row_ownership("Adaptive Baseline")
    assert owner == dr.DETECTORS["Adaptive Baseline"]["owner"]
    assert rule == dr.DETECTORS["Adaptive Baseline"]["rule"]
    owner_mix, rules = dr.row_ownership("Isolation Forest, Mystery Net")
    assert "ops" in owner_mix and "unowned" in owner_mix
    assert "Mystery Net" in rules


def test_the_push_gate_audits_quiet_and_never_calls_pushover(monkeypatch):
    """A quiet verdict is refused BEFORE the rate limiter and before any HTTP call: the
    audit row still lands (the decision is recorded), the phone stays silent."""
    from weirvern import alerts as al
    from weirvern.config import Settings

    calls = []

    def _no_http(*a, **k):  # pragma: no cover - must never run
        calls.append(a)
        raise AssertionError("pushover was contacted for a quiet detector")

    monkeypatch.setattr(al.requests, "post", _no_http)

    audits = []

    class _Client:
        def insert(self, table, rows, column_names=None):
            audits.append((table, rows, column_names))

    settings = Settings(
        pushover_enabled=True, pushover_user_key="u", pushover_api_token="t",
        pushover_cooldown_s=0, pushover_max_per_hour=99,
    )
    verdict = {
        "src_addr": "198.51.100.9", "anomaly_score": 0.9, "model_agreement": 0.9,
        "severity": "high", "detected_by_models": "Mystery Net",
        "isolation_forest_score": 0.9, "gradient_boosting_score": 0.9,
        "dbscan_score": 0.9, "baseline_score": 0.9,
        "window_start": datetime(2026, 10, 17, 3, 0),
    }
    delivered, reason = al.push_alert(verdict, settings, al.AlertState(), _Client())
    assert delivered is False
    assert reason.startswith("quiet:")
    assert not calls
    assert audits and audits[0][0] == "weirvern.alert_events"
    assert audits[0][1][0][7] == "quiet"   # the reason column records the decision
