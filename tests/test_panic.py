"""BF-14: the degraded-console fallback -- it must render with JavaScript off, carry the
staleness stamp, and say why for every section it could not read."""
from weirvern.admin import web_api

_FLEET = {"available": True, "reason": None, "heartbeats_available": True,
          "data_as_of": "2026-10-17T12:00:00+00:00",
          "sensors": [
              {"sensor_id": "weirvern", "state": "alive", "age_s": 4.0, "enabled": True},
              {"sensor_id": "edge-stale", "state": "stale", "age_s": 5400.0, "enabled": True},
          ]}
_AUDIT = {"available": True, "reason": "", "findings": [
    {"class": "silent_sensor", "subject": "edge-stale", "detail": "silent for 1h"}],
    "errors": {"stuck_rules": "RuntimeError"}}
_ALERTS = {"available": True, "reason": "", "fired": 831, "acted": 12}


def test_the_fallback_renders_with_no_script_tag_whatsoever():
    page = web_api.panic_page(fleet=_FLEET, audit=_AUDIT, alerts=_ALERTS,
                              rendered_at="2026-10-17 12:00:00")
    assert "<script" not in page.lower()
    assert "<!doctype html>" in page.lower()


def test_the_fallback_carries_liveness_with_the_staleness_stamp():
    page = web_api.panic_page(fleet=_FLEET, audit=_AUDIT, alerts=_ALERTS,
                              rendered_at="2026-10-17 12:00:00")
    assert "weirvern" in page and "edge-stale" in page
    assert "data as of 2026-10-17 12:00:00 UTC" in page
    assert "rendered at 2026-10-17 12:00:00 (UTC)" in page


def test_an_offset_stamp_is_normalised_not_mislabelled():
    """A heartbeat carrying -05:00 must print as UTC, not wear a UTC label over local time."""
    fleet = dict(_FLEET, data_as_of="2026-10-17T13:27:22-05:00")
    page = web_api.panic_page(fleet=fleet, audit=_AUDIT, alerts=_ALERTS, rendered_at="t")
    assert "data as of 2026-10-17 18:27:22 UTC" in page
    assert "-05:00" not in page


def test_the_fallback_carries_counts_and_the_audit_findings():
    page = web_api.panic_page(fleet=_FLEET, audit=_AUDIT, alerts=_ALERTS,
                              rendered_at="2026-10-17 12:00:00")
    assert "831" in page and "12" in page
    assert "silent_sensor" in page and "edge-stale" in page
    assert "stuck_rules (RuntimeError)" in page     # a check that could not run is said so


def test_an_unreadable_section_says_so_with_its_reason_never_silently_vanishes():
    page = web_api.panic_page(fleet={"available": False, "reason": "clickhouse down"},
                              audit=None, alerts=None, rendered_at="2026-10-17 12:00:00")
    assert "clickhouse down" in page
    assert "The self-audit could not be read" in page
    assert "The counts could not be read" in page


def test_the_page_escapes_its_inputs():
    page = web_api.panic_page(
        fleet={"available": True, "heartbeats_available": True, "data_as_of": "",
               "sensors": [{"sensor_id": "<img src=x onerror=boom>", "state": "alive",
                            "age_s": 1, "enabled": True}]},
        audit=None, alerts=None, rendered_at="t")
    assert "<img src=x" not in page
    assert "&lt;img" in page
