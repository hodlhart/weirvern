"""The two controls, and the health probe that reports their verdict.

The point of these tests is the FAILURE direction: a control that cannot fail is decoration.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

from weirvern.admin import status
from weirvern.models import controls, scopes

# ── exfil_fires: departure must beat volume ────────────────────────────────────────────────────

def test_a_100x_departure_outranks_a_BIGGER_ordinary_transfer():
    """The ranking must order by departure, not bytes. The fixture's ordinary host sends 20x the
    exfil host's volume and must still lose."""
    check = controls.exfil_fires()
    assert check.ok is True, check.detail
    assert "100" in check.detail


def test_the_exfil_control_notices_a_ranking_that_orders_by_VOLUME(monkeypatch):
    """If someone 'simplifies' the rule to sort by bytes, this control must fail."""

    def by_volume(profiles, recent, now_hour, *, limit=12, key="host"):
        rows = [{"host": h, "state": "scored", "bytes": r["bytes"], "ratio": r["bytes"] / 100_000.0}
                for h, r in recent.items()]
        return sorted(rows, key=lambda r: r["ratio"], reverse=True)[:limit]

    monkeypatch.setattr(scopes, "rank_from", by_volume)
    check = controls.exfil_fires()
    assert check.ok is False, "a volume ranking passed the exfil control"
    assert "volume" in check.detail


# ── umbrel_quiet: the widest-peer host must not read as news ───────────────────────────────────

def test_the_chatty_host_at_2x_and_sixth_of_seven_PASSES():
    """Measured live 2026-11-17: 2.18x, sixth of seven, 155 peers."""
    rows = [{"host": f"h{i}", "ratio": r, "median_peers": p} for i, (r, p) in enumerate([
        (45.0, 2), (30.0, 3), (12.0, 1), (9.0, 4), (4.0, 2), (2.18, 155), (1.0, 6)])]
    check = controls.umbrel_quiet(rows)
    assert check.ok is True, check.detail


def test_the_chatty_host_LEADING_the_ranking_FAILS():
    rows = [{"host": "umbrel", "ratio": 40.0, "median_peers": 155},
            {"host": "laptop", "ratio": 3.0, "median_peers": 4}]
    check = controls.umbrel_quiet(rows)
    assert check.ok is False, "a fleet-baseline collapse passed the quiet control"
    assert "155" in check.detail


def test_with_no_scored_hosts_the_control_says_NOT_APPLICABLE_rather_than_passing():
    assert controls.umbrel_quiet([]).ok is None
    assert controls.umbrel_quiet([{"host": "h", "ratio": None, "median_peers": 3}]).ok is None


def test_a_broken_client_makes_the_control_N_A_not_a_crash():
    class _Boom:
        def query(self, *a, **kw):
            raise RuntimeError("clickhouse is away")

    checks = controls.run_controls(_Boom())
    assert checks[0].name == "exfil_fires" and checks[0].ok is True
    assert checks[1].name == "umbrel_quiet" and checks[1].ok is None
    assert "clickhouse is away" in checks[1].detail


def test_describe_names_every_control_and_its_state():
    checks = [controls.Control("a", True, "ok"), controls.Control("b", False, "bad"),
              controls.Control("c", None, "unknown")]
    text = controls.describe(checks)
    assert "a=PASS" in text and "b=FAIL" in text and "c=N/A" in text, text
    assert [c.name for c in controls.degraded(checks)] == ["b"]


# ── the probe: the panel must read the last verdict, and treat silence as unknown ──────────────

def _write(tmp_path, monkeypatch, *, age_s=30.0, checks=None, ok=None):
    path = tmp_path / "models" / "detection_controls.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    checks = checks if checks is not None else [
        {"name": "exfil_fires", "ok": True, "detail": "100x ranked first"},
        {"name": "umbrel_quiet", "ok": True, "detail": "2.18x, sixth of seven"},
    ]
    payload = {
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() - age_s)),
        "ok": ok if ok is not None else not any(c["ok"] is False for c in checks),
        "checks": checks,
    }
    path.write_text(json.dumps(payload))
    monkeypatch.setattr(status, "Path", Path, raising=False)
    return SimpleNamespace(model_dir=str(path.parent))


def test_a_fresh_passing_verdict_is_GREEN(tmp_path, monkeypatch):
    settings = _write(tmp_path, monkeypatch)
    probe = status._controls_probe(settings)
    assert probe.ok is True, probe.detail
    assert "exfil_fires" in probe.detail


def test_a_FAILED_control_is_RED_and_names_the_check(tmp_path, monkeypatch):
    settings = _write(tmp_path, monkeypatch, checks=[
        {"name": "exfil_fires", "ok": False, "detail": "a 100x departure ranked behind a 2x"}])
    probe = status._controls_probe(settings)
    assert probe.ok is False
    assert "DEGRADED" in probe.detail and "exfil_fires" in probe.detail


def test_a_STALE_verdict_is_RED_even_if_it_passed(tmp_path, monkeypatch):
    settings = _write(tmp_path, monkeypatch, age_s=3 * 300 + 60)
    probe = status._controls_probe(settings)
    assert probe.ok is False
    assert "stopped checking itself" in probe.detail


def test_NO_verdict_is_NOT_APPLICABLE_never_a_silent_pass(tmp_path, monkeypatch):
    settings = SimpleNamespace(model_dir=str(tmp_path / "empty"))
    probe = status._controls_probe(settings)
    assert probe.ok is None, "a worker that never ran controls reported them as passing"
    assert "no detection sweep has recorded one" in probe.detail


def test_a_CORRUPT_verdict_is_RED(tmp_path, monkeypatch):
    path = tmp_path / "models" / "detection_controls.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ not json")
    probe = status._controls_probe(SimpleNamespace(model_dir=str(path.parent)))
    assert probe.ok is False
    assert "could not be read" in probe.detail
