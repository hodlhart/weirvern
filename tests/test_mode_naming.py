"""Guard against the in-path mode's old name creeping back.

The mode was renamed `weir` -> `siphon`. The old spelling survives in exactly two
PLACES ON PURPOSE, both of them input acceptance so a deployment configured before the
rename keeps working:

  * `mode.normalise` accepts it and stores `siphon`
  * the sensor's startup `case` accepts it and announces the new name

Everything else -- config values, module names, the overlay directory, docs, scripts --
must use `siphon`. The subtlety that makes a naive scan wrong: `weir` is a PREFIX of the
product name (`weirvern`) and of `weirnet`'s replacement (`siphonnet`), so only the
whole word is flagged, matched with non-letter boundaries.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# The old name, as a word: `weir` not followed by a letter (`weirvern`, `weirnet`) and
# not preceded by one. Plus the two identifier forms that underscore-boundaries hide.
OLD = re.compile(r"(?<![A-Za-z])weir(?![A-Za-z])|MODE_WEIR\b|(?<![A-Za-z])weirnet(?![A-Za-z])")

# A line is allowed to name the old spelling when it is ABOUT the old spelling: an
# acceptance construct (it also names `siphon`), a migration note, or the changelog entry
# that records the rename itself. Anything else is a stale rename.
ALLOWED = re.compile(r"former|legacy|renam|siphon", re.IGNORECASE)

# This file necessarily contains the thing it forbids.
SELF_EXEMPT = {"tests/test_mode_naming.py"}

TEXT_SUFFIXES = {
    ".py", ".md", ".yaml", ".yml", ".toml", ".sql", ".cfg", ".example",
    ".txt", ".zeek", ".json", ".js", ".html", ".css", ".sh",
}


def _tracked_files() -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.split()
        return [ROOT / f for f in out]
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        skip = {".git", ".venv", "build", "dist", "__pycache__", ".ruff_cache",
                ".mypy_cache", ".pytest_cache", "node_modules", ".env"}
        found = []
        for path in sorted(ROOT.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(ROOT)
            if set(rel.parts) & skip or rel.name in skip or rel.name.startswith(".env."):
                continue
            found.append(path)
        return found


def test_no_stale_old_mode_name_in_any_tracked_file():
    """The single most valuable rename test: only the acceptance constructs may keep it."""
    problems: list[str] = []
    for path in _tracked_files():
        rel = str(path.relative_to(ROOT))
        if rel in SELF_EXEMPT:
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.suffix != "":
            continue
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not OLD.search(line):
                continue
            if ALLOWED.search(line):
                continue
            problems.append(f"{rel}:{lineno}: {line.strip()[:110]}")

    assert not problems, (
        "the old mode name survives outside the documented acceptance points; a partial "
        "rename ships a config value the sensor refuses or a doc that contradicts the "
        "code:\n  " + "\n  ".join(problems)
    )


def test_the_guard_actually_scans_the_tree():
    """A guard that silently scans nothing always passes. (The product rename shipped
    broken exactly that way once, and the fix was this assertion.)"""
    scanned = [
        p for p in _tracked_files()
        if str(p.relative_to(ROOT)) not in SELF_EXEMPT and p.is_file()
    ]
    assert len(scanned) > 40, f"guard is scanning only {len(scanned)} files"


def test_the_old_name_is_still_ACCEPTED_on_input():
    """The acceptance is the reason the guard has exemptions -- verify it end to end, so
    the exemptions describe a real behaviour rather than a permission."""
    from weirvern.admin import mode as mode_mod

    assert mode_mod.normalise("weir") == mode_mod.MODE_SIPHON
    assert mode_mod.normalise("WEIR") == mode_mod.MODE_SIPHON
    # And a pre-rename ConfigMap value validates as a live, capable mode.
    v = mode_mod.validate("weir", has_net_admin=True, has_net_raw=True, watchdog_available=True)
    assert v.ok and v.mode == mode_mod.MODE_SIPHON


def test_the_sensor_startup_accepts_the_old_name():
    """The startup script must not crash-loop a pre-rename deployment: `weir` reaches the
    in-path branch, announces the NEW name, and says why the old spelling is tolerated."""
    script = (ROOT / "k8s" / "32-zeek.yaml").read_text()
    assert "siphon|weir)" in script, "the startup case does not accept the former name"
    assert "former name" in script, "the acceptance does not say why it exists"


# ── the overlay must set the mode it grants the capability for ─────────────────────────────────
#
# MEASURED DEFECT (verified against the tree, 2026-09-23). `kubectl apply -k overlays/siphon/`
# granted every capability siphon needs -- hostNetwork, NET_RAW, NET_ADMIN, the forwarding
# sysctls and their save/restore -- and left `SENSOR_MODE: "loch"`. The overlay was named
# "siphon", its comments described siphon, and the sensor it produced reported itself as passive.
#
# Three consequences, and the first two are why this is worth a test rather than a note:
#
#   1. `weirvern status` reads the CONFIGURED mode to decide whether to run the loud check for "a
#      siphon sensor with no live intercept" -- the state where every surface says "in-path" while
#      nothing is redirected. Reading "loch", that check is skipped, so the one warning about a
#      half-applied in-path setup is silent by construction.
#   2. The Sluice Gate refuses to claim ARMED while the sensor is not in the traffic path. With the
#      mode stuck at loch, an operator who APPLIED THE SIPHON OVERLAY is told the deployment
#      cannot enforce -- wrong, and it teaches them to distrust a warning that is right elsewhere.
#   3. An operator reading "loch" in Settings has to decide whether to believe the overlay they
#      applied or the label. The overlay is the thing they did.
#
# These assertions are on the RENDERED output, not on the patch file: a patch that exists but is
# not referenced by the kustomization changes nothing, which is how the first version of this fix
# was written and why the render is the only trustworthy thing to assert on.
def _rendered(kustomize_dir: str) -> dict:
    from weirvern.admin import cli  # noqa: F401  (import-time side effects are not needed)

    out = subprocess.run(
        ["kustomize", "build", kustomize_dir],
        cwd=ROOT, capture_output=True, text=True,
    )
    if out.returncode != 0:
        import pytest

        pytest.skip(f"kustomize is not available or failed: {out.stderr.strip()[:120]}")
    import yaml

    for doc in yaml.safe_load_all(out.stdout):
        if doc and doc.get("kind") == "ConfigMap" \
                and doc.get("metadata", {}).get("name") == "weirvern-env":
            return doc.get("data") or {}
    raise AssertionError(f"no weirvern-env ConfigMap in the render of {kustomize_dir}")


def test_the_siphon_overlay_sets_the_mode_it_grants_the_capability_for():
    data = _rendered("overlays/siphon/")
    assert data.get("SENSOR_MODE") == "siphon", (
        f"the siphon overlay renders SENSOR_MODE={data.get('SENSOR_MODE')!r}; a deployment built "
        "for in-path interception reports itself as passive, which silences the no-live-intercept "
        "warning and makes the Sluice Gate report DEGRADED on a deployment meant to enforce"
    )


def test_the_overlay_patch_is_wired_into_the_kustomization():
    """A patch FILE that the kustomization does not reference changes nothing.

    THIS IS THE FAILURE THE FIRST VERSION OF THE FIX MADE: the patch was written, and
    `kustomize build overlays/siphon/` still rendered `SENSOR_MODE: "loch"` because nothing
    referenced it. The rendered output is the only trustworthy artefact, which is why
    test_the_siphon_overlay_sets_the_mode_it_grants_the_capability_for asserts on it.

    This test adds the DIAGNOSIS when that fails: it distinguishes "the patch is not wired in"
    from "the patch says the wrong thing", which are different mistakes with different fixes.
    """
    text = (ROOT / "overlays" / "siphon" / "kustomization.yaml").read_text()
    assert "configmap-siphon-mode.yaml" in text, (
        "the siphon-mode patch exists but is not referenced by the kustomization, so applying the "
        "overlay does not set the mode"
    )
    assert (ROOT / "overlays" / "siphon" / "configmap-siphon-mode.yaml").exists(), (
        "the kustomization references a patch file that does not exist"
    )


def test_the_overlay_merge_does_not_replace_the_configmap():
    """A ConfigMap resource in a patch merges per key; its data must not be a full replacement.

    MEASURED while writing this: kustomize merges a same-named ConfigMap with OR WITHOUT a
    `target:` stanza, so removing the target does NOT drop keys -- the first version of this test
    claimed it would, and mutation testing showed it survived. What actually matters is that the
    patch file is a MERGE (a bare ConfigMap carrying only the key it sets), because a patch that
    restated the whole data map would silently pin every other setting to the values in the file
    and revert later changes to them.

    So this asserts the property rather than the mechanism: the patch must be small. A patch naming
    every key is the defect this guards.
    """
    import yaml

    doc = yaml.safe_load(
        (ROOT / "overlays" / "siphon" / "configmap-siphon-mode.yaml").read_text())
    data = doc.get("data") or {}
    assert set(data) == {"SENSOR_MODE"}, (
        f"the siphon-mode patch sets {sorted(data)}; it must set only the mode, or it will pin "
        "every other ConfigMap key to whatever this file happens to say"
    )


def test_the_base_deployment_still_defaults_to_passive():
    """The converse, and it is the important half.

    `loch` is the correct default: passive capture cannot break a network. If a change to the
    overlay ever leaked into the base, every new deployment would come up in-path on first boot,
    which is the surprise the default exists to prevent.
    """
    assert _rendered("k8s/").get("SENSOR_MODE") == "loch", (
        "the base deployment no longer defaults to passive capture"
    )
