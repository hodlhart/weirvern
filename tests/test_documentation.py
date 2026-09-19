"""The documentation must describe the code that exists.

WHY THIS IS A TEST AND NOT A REVIEW CHECKLIST.

Every defect these guard against has actually happened in this project, and none of them was
visible without looking for it specifically:

  * the README listed `zeek/zeek:lts` as the sensor image long after it became the derived
    `weirvern-zeek:0.4.0` -- so the documented build step built the WRONG image, and the
    operator would never get JA4
  * the build instructions described ONE image when there are two, and the second has a
    different build context (`zeek/`, not the repo root)
  * the workload table omitted the GUI, the prune CronJob and the schema Job entirely
  * nothing documented the sensor modes, so `loch` and `weir` were discoverable only by
    reading `mode.py`
  * `redef FINGERPRINT::JA4*_enabled = F` was still in the README's own description of the
    licensing after the options were deleted -- instructions that would crash the sensor

A doc that describes a previous version of the software is worse than no doc, because it is
followed. These assertions are cheap and they run in CI, which is the only way this stays
true as the code moves.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text()
ZEEK_POLICY = (ROOT / "k8s" / "zeek" / "weirvern-local.zeek").read_text()
DOCKERFILES = (ROOT / "Containerfile").read_text() + (ROOT / "zeek" / "Containerfile").read_text()


def _slug(heading: str) -> str:
    """The anchor GitHub generates from a heading."""
    s = re.sub(r"[^\w\s-]", "", heading.strip().lower())
    return re.sub(r"\s+", "-", s).strip("-")


def _headings(text: str) -> set[str]:
    return {_slug(m.group(1)) for m in re.finditer(r"^#{2,4} (.+)$", text, re.M)}


# ── links ───────────────────────────────────────────────────────────────────────

def test_every_internal_link_resolves():
    """A broken anchor in a table of contents is worse than no contents: it looks
    authoritative and goes nowhere."""
    heads = _headings(README)
    links = re.findall(r"\]\(#([^)]+)\)", README)
    missing = sorted({link for link in links if link not in heads})
    assert not missing, f"README links to headings that do not exist: {missing}"


def test_the_contents_lists_every_top_level_section():
    """A section nobody can navigate to may as well not exist."""
    contents = README[README.index("## Contents"):README.index("---", README.index("## Contents"))]
    listed = set(re.findall(r"\]\(#([^)]+)\)", contents))
    # Every H2, since those are what the index is for.
    h2 = {_slug(m.group(1)) for m in re.finditer(r"^## (.+)$", README, re.M)}
    h2.discard("contents")
    missing = sorted(h2 - listed)
    assert not missing, f"H2 sections absent from the Contents list: {missing}"


# ── the images, which is where the doc was most wrong ────────────────────────────

def test_the_documented_sensor_image_is_the_one_the_manifests_use():
    """The README said `zeek/zeek:lts` long after the sensor became a derived image. An
    operator following it would build the upstream image and get no JA4 at all."""
    manifest = (ROOT / "k8s" / "32-zeek.yaml").read_text()
    match = re.search(r"image:\s*(\S+)", manifest)
    expected = (match.group(1) if match else "").strip()
    assert expected, "no image found in the zeek manifest"

    # The upstream base is fine to MENTION (the Containerfile derives FROM it), but the
    # manifest's image must appear in the deploy instructions.
    build_section = README[README.index("Build and push the images"):]
    build_section = build_section[:build_section.index("### 4.")]
    assert expected in build_section, (
        f"the manifests use {expected} but the build instructions never mention it"
    )


def test_the_documented_image_names_match_the_manifests():
    """Both image names, so a rename in the manifests cannot leave the doc behind."""
    for manifest in ("33-worker.yaml", "34-gui.yaml", "35-prune-cronjob.yaml"):
        text = (ROOT / "k8s" / manifest).read_text()
        for image in set(re.findall(r"image:\s*(weirvern-\S+)", text)):
            assert image in README, f"{image} is used by {manifest} but absent from the README"


def test_both_build_commands_are_documented_with_the_right_contexts():
    """The worker builds from the repo root; the Zeek image builds from `zeek/` because its
    COPY lines reference files there. Getting the context wrong fails the build with
    "file not found", which is at least loud -- but only if the command is in the doc."""
    assert "kustomize edit set image weirvern-worker" in README
    assert "kustomize edit set image weirvern-zeek" in README
    assert "zeek/Containerfile" in README, "the derived sensor build is not documented"
    # The context argument, which is the part that is easy to get wrong.
    assert re.search(r"-f\s+zeek/Containerfile\s+zeek/", README), (
        "the documented Zeek build does not pass zeek/ as the build context"
    )


def test_every_workload_kind_is_described():
    """The workload table omitted the GUI, the CronJob and the schema Job."""
    for kind, name in (("Deployment", "weirvern-gui"), ("CronJob", "weirvern-prune"),
                       ("Job", "weirvern-schema")):
        assert name in README, f"{kind}/{name} is not described in the README"
        assert kind in README, f"the {kind} kind is not named for {name}"


# ── licensing instructions that would crash the sensor ──────────────────────────

def test_the_readme_does_not_instruct_an_operator_to_disable_deleted_options():
    """THE REGRESSION THAT ACTUALLY BIT: after the FoxIO options were deleted, the ConfigMap
    still told Zeek to redefine them and the sensor crash-looped with

        "redef" used but not previously defined (FINGERPRINT::JA4S_enabled)

    Documentation repeating that instruction would reproduce it on the next deployment.
    """
    for name in ("JA4S_enabled", "JA4H_enabled", "JA4X_enabled", "JA4SSH_enabled",
                 "JA4T_enabled", "JA4L_enabled", "JA4D_enabled"):
        # Mentioning the name while explaining the licence split is fine; a `redef` on it is
        # an instruction to configure something that no longer exists.
        assert f"redef FINGERPRINT::{name}" not in README, (
            f"the README shows a redef of {name}, which no longer exists in the image and "
            f"aborts Zeek at startup"
        )


def test_the_policy_and_the_readme_agree_that_disabling_is_gone():
    """Both surfaces must say the same thing, because an operator reads one and edits the
    other."""
    # Comments are stripped first. The policy DELIBERATELY quotes the removed
    # `redef FINGERPRINT::JA4*_enabled = F` line while explaining why it is gone, and a
    # naive substring search reads that explanation as the thing it warns about. Assert on
    # the executable code, not the prose about the code.
    code = "\n".join(ln.split("#")[0] for ln in ZEEK_POLICY.splitlines())
    assert "redef FINGERPRINT" not in code, (
        "the site policy still carries a disable list, which the image no longer supports"
    )
    assert "prune-ja4plus.sh" in README, "the README does not point at the removal mechanism"
    assert "prune-ja4plus.sh" in ZEEK_POLICY, "the policy does not point at it either"


def test_the_readme_states_that_image_and_policy_ship_together():
    """The one deployment fact that caused a crash-loop. It belongs in the doc, not only in a
    commit message."""
    assert "crash-loop" in README.lower() or "crash loop" in README.lower(), (
        "the README does not warn that the sensor image and the site policy must be deployed "
        "together"
    )


# ── the features that exist must be findable ────────────────────────────────────

def test_the_sensor_modes_are_documented():
    """`loch` and `weir` were discoverable only by reading mode.py. The difference between
    them is whether Weirvern can take the network down, so it is not a detail."""
    assert "`loch`" in README and "`weir`" in README
    section = README[README.index("Sensor modes"):]
    section = section[:section.index("### ")]
    assert "SENSOR_MODE" in section
    assert "watchdog" in section.lower(), (
        "the weir section does not mention the watchdog, which is what makes in-path "
        "interception defensible"
    )
    assert "CAP_NET_ADMIN" in section, "the privilege requirement is not stated"


def test_the_readme_says_weir_does_not_decrypt():
    """The single most likely misconception about in-path interception. Someone deciding
    whether this is acceptable on their network needs it stated, not inferred."""
    section = README[README.index("Sensor modes"):]
    section = section[:section.index("### ")]
    assert "not a TLS intercept" in section or "Nothing is decrypted" in section


def test_the_readme_documents_the_zeek_features_the_models_use():
    """The models gained a whole second sensor's worth of features; a reader of the detection
    section would otherwise not know Zeek contributes to scoring at all."""
    assert "zeek_present" in README, (
        "the README does not describe the presence flag, which is the part an operator "
        "misreading the numbers would get wrong"
    )
    section = README[README.index("What the models see"):]
    assert "NetFlow" in section and "Zeek" in section


def test_the_readme_documents_the_gui_views():
    for view in ("Overview", "Anomalies", "Host drill-down", "Models", "Evidence"):
        assert view in README, f"the GUI's {view} view is undocumented"
    assert "30088" in README, "the GUI's port is not stated"


# ── the docs must not describe dead things ──────────────────────────────────────

def test_the_readme_does_not_advertise_a_feature_that_was_removed():
    """`dam` was a reserved mode name the user asked to have removed entirely, verbiage and
    all. A doc mentioning it would resurrect a name that no longer exists in `mode.py`."""
    from weirvern.admin import mode as mode_mod

    known = {mode_mod.MODE_LOCH, mode_mod.MODE_WEIR}
    mentioned = set(re.findall(r"`(loch|weir|dam|pool|reservoir|cistern)`", README))
    stale = {m for m in mentioned if m in ("dam",)}
    assert not stale, f"the README mentions removed mode names: {stale}"
    # And the modes it does describe must be the ones the code knows.
    assert mentioned & known, "the README mentions no mode the code actually implements"
