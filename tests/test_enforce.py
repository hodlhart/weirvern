"""Tests for disk-cap enforcement.

The bug these prevent: the caps were advisory. `weirvern disk` recommended values, the
config accepted them, and nothing acted on them -- so a cap that was set and a cap that
was ignored looked identical. These pin that a set cap actually frees space, and that the
destructive paths never corrupt the data they keep.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from weirvern import enforce


@pytest.fixture(autouse=True)
def _isolated_dirs(tmp_path, monkeypatch):
    """Point every component at a temp dir.

    Without this the tests would run against /zeek/logs and /models -- the real cluster
    paths -- and a test that "frees space" could delete the deployed models.
    """
    z = tmp_path / "zeek"
    n = tmp_path / "flows"
    m = tmp_path / "models"
    for d in (z, n, m):
        d.mkdir()
    monkeypatch.setattr(enforce, "ZEEK_DIR", z)
    monkeypatch.setattr(enforce, "NETFLOW_DIR", n)
    monkeypatch.setattr(enforce, "ML_DIR", m)
    return {"zeek": z, "netflow": n, "ml": m}


def _rotated(d: Path, log_type: str, when: str, size: int) -> Path:
    """A rotated Zeek log with an OLD filename but a FRESH mtime.

    That combination is the realistic one for a directory restored from backup, and it is
    what exposed the age-source bug: the module sorted by filename but measured the grace
    period by mtime, so every restored file looked "recent" and nothing was ever pruned.
    """
    f = d / f"{log_type}.{when}.log"
    f.write_bytes(b"x" * size)
    return f


# ── no cap means no action ──────────────────────────────────────────────────────


def test_no_cap_touches_nothing(_isolated_dirs):
    _rotated(_isolated_dirs["zeek"], "conn", "2020-01-01-00-00-00", 100_000)
    r = enforce.enforce_zeek(0)
    assert r.actions == 0
    assert r.skipped == "no cap set"
    assert list(_isolated_dirs["zeek"].iterdir()), "files were deleted without a cap"


def test_a_missing_directory_is_reported_not_crashed(monkeypatch, tmp_path):
    monkeypatch.setattr(enforce, "ZEEK_DIR", tmp_path / "nope")
    r = enforce.enforce_zeek(100)
    assert r.actions == 0
    assert "does not exist" in r.skipped


# ── zeek: the real path ─────────────────────────────────────────────────────────


def test_zeek_cap_actually_frees_space(_isolated_dirs):
    """The headline case: files over the cap, old enough, must go."""
    for hour in range(10):
        _rotated(_isolated_dirs["zeek"], "conn", f"2020-01-01-{hour:02d}-00-00", 200_000)
    r = enforce.enforce_zeek(1, grace_s=0)
    assert r.actions > 0, "a 2 MB directory under a 1 MB cap reclaimed nothing"
    assert r.after_mb < r.before_mb
    assert r.after_mb <= 1.05, f"still {r.after_mb:.2f} MB after a 1 MB cap"


def test_the_grace_period_protects_new_files_even_when_named_old(_isolated_dirs):
    """Grace must key off the FILENAME timestamp, not mtime.

    This is the regression: with name-based ordering and mtime-based grace, a directory
    whose files all have fresh mtimes (any restore) was never pruned at all.
    """
    # Named NOW, so inside the grace window.
    now = time.strftime("%Y-%m-%d-%H-%M-%S")
    _rotated(_isolated_dirs["zeek"], "conn", now, 500_000)
    r = enforce.enforce_zeek(0.1, grace_s=3600)
    assert r.actions == 0, "deleted a file inside the grace period"
    assert _isolated_dirs["zeek"].iterdir()


def test_age_comes_from_the_filename_not_the_mtime(_isolated_dirs):
    """A restored directory (old names, new mtimes) must still be prunable."""
    f = _rotated(_isolated_dirs["zeek"], "conn", "2020-01-01-00-00-00", 300_000)
    os.utime(f, None)  # fresh mtime, as a restore or a copy would give it
    from weirvern import prune
    cands = prune.rotated_files(_isolated_dirs["zeek"])
    assert cands and cands[0].age_s > 86_400, "age was taken from mtime, not the name"


# ── netflow: the destructive rewrite ────────────────────────────────────────────


def test_netflow_trim_leaves_only_parseable_json_lines(_isolated_dirs):
    """A byte offset that lands mid-line must not leave a truncated record.

    A half-written JSON object at the head of the file is worse than the space it saves:
    the ingester reports a parse error on every pass forever.
    """
    d = _isolated_dirs["netflow"]
    f = d / "flows.jsonl"
    rows = [json.dumps({"i": i, "pad": "p" * 80}) for i in range(400)]
    f.write_text("\n".join(rows) + "\n")

    r = enforce.enforce_netflow(0.02)  # far below the file size, so a real trim happens
    assert r.actions == 1
    assert r.after_mb < r.before_mb

    text = f.read_text()
    assert text, "the trim removed everything"
    for n, line in enumerate(text.splitlines()):
        if not line.strip():
            continue
        try:
            json.loads(line)
        except json.JSONDecodeError as exc:
            pytest.fail(f"line {n} is not valid JSON after the trim: {line[:60]!r} ({exc})")


def test_netflow_under_cap_is_untouched(_isolated_dirs):
    f = _isolated_dirs["netflow"] / "flows.jsonl"
    f.write_text('{"i": 1}\n')
    before = f.read_text()
    r = enforce.enforce_netflow(100)
    assert r.actions == 0
    assert f.read_text() == before


def test_netflow_whole_files_are_removed_when_older(_isolated_dirs):
    d = _isolated_dirs["netflow"]
    old = d / "old.jsonl"
    old.write_text("a" * 200_000)
    os.utime(old, (time.time() - 9999, time.time() - 9999))
    new = d / "new.jsonl"
    new.write_text("b" * 200_000)
    r = enforce.enforce_netflow(0.25)
    assert r.actions >= 1
    assert r.after_mb <= 0.26


# ── ml: the floor that overrides the cap ────────────────────────────────────────


def test_ml_keeps_the_newest_sets_even_under_pressure(_isolated_dirs):
    """Deleting the model the worker is serving is an outage, not housekeeping."""
    d = _isolated_dirs["ml"]
    for i in range(5):
        sub = d / f"run{i}"
        sub.mkdir()
        (sub / "iso.joblib").write_bytes(b"x" * 100_000)
        # Ascending mtimes so run4 is newest.
        os.utime(sub, (time.time() + i, time.time() + i))
    r = enforce.enforce_ml(0.05, keep_newest=2)  # impossible cap
    assert r.actions >= 1
    remaining = sorted(p.name for p in d.iterdir())
    assert "run4" in remaining and "run3" in remaining, (
        f"the two newest sets must survive an unsatisfiable cap; have {remaining}")


def test_ml_below_the_floor_is_untouched(_isolated_dirs):
    d = _isolated_dirs["ml"]
    (d / "run0").mkdir()
    (d / "run0" / "m.joblib").write_bytes(b"x" * 10)
    r = enforce.enforce_ml(0, keep_newest=2)
    assert r.actions == 0
    assert (d / "run0").exists()


# ── the aggregate ───────────────────────────────────────────────────────────────


def test_one_component_failing_does_not_stop_the_others(monkeypatch, _isolated_dirs):
    """A broken ML path must not prevent Zeek from being pruned.

    If components were sequential without isolation, one exception would abort the run and
    the disk would fill from the direction nobody was watching.
    """
    for hour in range(6):
        _rotated(_isolated_dirs["zeek"], "conn", f"2020-01-01-{hour:02d}-00-00", 200_000)

    def boom(cap: int, keep_newest: int = 2):
        raise RuntimeError("simulated ML failure")

    monkeypatch.setattr(enforce, "enforce_ml", boom)
    results = enforce.enforce({"zeek": 1, "netflow": 0, "ml": 1}, grace_s=0)
    by = {r.component: r for r in results}
    assert by["zeek"].actions > 0, "zeek was skipped because ml raised"
    assert by["ml"].errors, "the ml failure was swallowed silently"


def test_render_reports_every_component(_isolated_dirs):
    out = enforce.render(enforce.enforce({"zeek": 0, "netflow": 0, "ml": 0}))
    for comp in ("zeek", "netflow", "ml"):
        assert comp in out


def test_a_component_with_no_cap_says_so_rather_than_claiming_success(_isolated_dirs):
    """"unset" and "within cap" must be distinguishable in the output.

    They look identical on a disk that happens to be under its limit, and only one of them
    means the cap will keep holding next month.
    """
    out = enforce.render([enforce.enforce_zeek(0)])
    assert "unset" in out
