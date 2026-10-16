"""The documentation must describe the code that exists.

WHY THIS IS A TEST AND NOT A REVIEW CHECKLIST.

Every defect these guard against has actually happened in this project, and none of them was
visible without looking for it specifically:

  * the DOCS listed `zeek/zeek:lts` as the sensor image long after it became the derived
    `weirvern-zeek:0.4.0` -- so the documented build step built the WRONG image, and the
    operator would never get JA4
  * the build instructions described ONE image when there are two, and the second has a
    different build context (`zeek/`, not the repo root)
  * the workload table omitted the GUI, the prune CronJob and the schema Job entirely
  * nothing documented the sensor modes, so `loch` and `siphon` were discoverable only by
    reading `mode.py`
  * `redef FINGERPRINT::JA4*_enabled = F` was still in the DOCS's own description of the
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
# THE DOCUMENTATION SET. The README is a front page now (what the tool does) and the detail lives
# in docs/*.md, so a claim that moved is still a claim: these tests assert what a reader is TOLD,
# not which file says it. The one thing checked against the README itself is that it links every
# document -- see test_the_readme_links_every_document_in_the_set.
DOCS = "\n".join([README] + [p.read_text() for p in sorted((ROOT / "docs").glob("*.md"))])
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
    heads = _headings(DOCS)
    links = re.findall(r"\]\(#([^)]+)\)", DOCS)
    missing = sorted({link for link in links if link not in heads})
    assert not missing, f"DOCS links to headings that do not exist: {missing}"


def test_the_readme_links_every_document_in_the_set():
    """THE NAVIGATION CONTRACT, after the split.

    The README used to carry everything under a Contents list; it now leads with what the tool
    does and hands the detail to `docs/*.md`. What must stay true is that every document in the
    set is reachable from the front page -- a document nobody can navigate to may as well not
    exist -- and that the front page still states the one thing every reader needs first (the
    modes: loch, siphon, the gate).
    """
    files = sorted(p.name for p in (ROOT / "docs").glob("*.md"))
    assert files, "there are no per-topic documents, so this test proves nothing"
    missing = [f for f in files if f"docs/{f}" not in README]
    assert not missing, f"document(s) not linked from the README: {missing}"

    # The front page still leads with the feature set; these are the words a reader arrives with.
    for word in ("loch", "siphon", "Sluice Gate", "console"):
        assert word in README, f"the README no longer mentions {word}"
    # And the screenshots are a stated placeholder until publishing, never claimed as done.
    assert "Placeholder" in README and "screenshots" in README.lower()


# ── the images, which is where the doc was most wrong ────────────────────────────

def test_the_documented_sensor_image_is_the_one_the_manifests_use():
    """The DOCS said `zeek/zeek:lts` long after the sensor became a derived image. An
    operator following it would build the upstream image and get no JA4 at all."""
    manifest = (ROOT / "k8s" / "32-zeek.yaml").read_text()
    match = re.search(r"image:\s*(\S+)", manifest)
    expected = (match.group(1) if match else "").strip()
    assert expected, "no image found in the zeek manifest"

    # The upstream base is fine to MENTION (the Containerfile derives FROM it), but the
    # manifest's image must appear in the deploy instructions.
    build_section = DOCS[DOCS.index("Build and push the images"):]
    build_section = build_section[:build_section.index("### 4.")]
    assert expected in build_section, (
        f"the manifests use {expected} but the build instructions never mention it"
    )


def test_the_documented_image_names_match_the_manifests():
    """Both image names, so a rename in the manifests cannot leave the doc behind."""
    for manifest in ("33-worker.yaml", "34-gui.yaml", "35-prune-cronjob.yaml"):
        text = (ROOT / "k8s" / manifest).read_text()
        for image in set(re.findall(r"image:\s*(weirvern-\S+)", text)):
            assert image in DOCS, f"{image} is used by {manifest} but absent from the DOCS"


def test_both_build_commands_are_documented_with_the_right_contexts():
    """The worker builds from the repo root; the Zeek image builds from `zeek/` because its
    COPY lines reference files there. Getting the context wrong fails the build with
    "file not found", which is at least loud -- but only if the command is in the doc."""
    assert "kustomize edit set image weirvern-worker" in DOCS
    assert "kustomize edit set image weirvern-zeek" in DOCS
    assert "zeek/Containerfile" in DOCS, "the derived sensor build is not documented"
    # The context argument, which is the part that is easy to get wrong.
    assert re.search(r"-f\s+zeek/Containerfile\s+zeek/", DOCS), (
        "the documented Zeek build does not pass zeek/ as the build context"
    )


def test_every_workload_kind_is_described():
    """The workload table omitted the GUI, the CronJob and the schema Job."""
    for kind, name in (("Deployment", "weirvern-gui"), ("CronJob", "weirvern-prune"),
                       ("Job", "weirvern-schema")):
        assert name in DOCS, f"{kind}/{name} is not described in the DOCS"
        assert kind in DOCS, f"the {kind} kind is not named for {name}"


# ── licensing instructions that would crash the sensor ──────────────────────────

def test_the_readme_does_not_instruct_an_operator_to_disable_deleted_options():
    """THE REGRESSION THAT ACTUALLY BIT: after the unused fingerprinting options were
    removed, the ConfigMap still told Zeek to redefine them and the sensor crash-looped
    with "redef used but not previously defined". Documentation repeating that
    instruction would reproduce it on the next deployment.
    """
    for name in ("JA4S_enabled", "JA4H_enabled", "JA4X_enabled", "JA4SSH_enabled",
                 "JA4T_enabled", "JA4L_enabled", "JA4D_enabled"):
        assert f"redef FINGERPRINT::{name}" not in DOCS, (
            f"the DOCS shows a redef of {name}, which no longer exists in the image "
            f"and aborts Zeek at startup"
        )


def test_the_policy_and_the_readme_agree_that_the_module_is_vendored():
    """Both surfaces must say the same thing, because an operator reads one and edits
    the other."""
    # Comments are stripped first: the policy documents the vendoring in prose and a
    # naive substring search over the whole file would read prose as configuration.
    code = "\n".join(ln.split("#")[0] for ln in ZEEK_POLICY.splitlines())
    assert "redef FINGERPRINT" not in code, (
        "the site policy still carries a disable list, which the vendored module does not need"
    )
    assert "zeek/vendor/ja4-zeek-scripts" in DOCS, (
        "the DOCS does not point at the vendored module"
    )
    assert "zeek/vendor/ja4-zeek-scripts" in ZEEK_POLICY, (
        "the policy does not point at it either"
    )


def test_the_readme_states_that_image_and_policy_ship_together():
    """The one deployment fact that caused a crash-loop. It belongs in the doc, not only in a
    commit message."""
    assert "crash-loop" in DOCS.lower() or "crash loop" in DOCS.lower(), (
        "the DOCS does not warn that the sensor image and the site policy must be deployed "
        "together"
    )


# ── the features that exist must be findable ────────────────────────────────────

def test_the_sensor_modes_are_documented():
    """`loch` and `siphon` were discoverable only by reading mode.py. The difference between
    them is whether Weirvern can take the network down, so it is not a detail."""
    assert "`loch`" in DOCS and "`siphon`" in DOCS
    section = DOCS[DOCS.index("Sensor modes"):]
    section = section[:section.index("### ")]
    assert "SENSOR_MODE" in section
    assert "watchdog" in section.lower(), (
        "the siphon section does not mention the watchdog, which is what makes in-path "
        "interception defensible"
    )
    assert "CAP_NET_ADMIN" in section, "the privilege requirement is not stated"


def test_the_readme_says_siphon_does_not_decrypt():
    """The single most likely misconception about in-path interception. Someone deciding
    whether this is acceptable on their network needs it stated, not inferred."""
    section = DOCS[DOCS.index("Sensor modes"):]
    section = section[:section.index("### ")]
    assert "not a TLS intercept" in section or "Nothing is decrypted" in section


def test_the_readme_documents_the_zeek_features_the_models_use():
    """The models gained a whole second sensor's worth of features; a reader of the detection
    section would otherwise not know Zeek contributes to scoring at all."""
    assert "zeek_present" in DOCS, (
        "the DOCS does not describe the presence flag, which is the part an operator "
        "misreading the numbers would get wrong"
    )
    section = DOCS[DOCS.index("What the models see"):]
    assert "NetFlow" in section and "Zeek" in section


def test_the_readme_documents_the_gui_views():
    # The list must cover EVERY tab in index.html, not a remembered subset: a view added to the
    # nav and never documented is exactly what this test exists to catch, and it cannot catch it
    # from a hand-maintained list. The nav is the source of truth, and the DOCS must name every
    # entry in it.
    from pathlib import Path

    nav = (Path(__file__).resolve().parent.parent
           / "weirvern" / "admin" / "web" / "index.html").read_text()
    tabs = re.findall(r'data-view="([\w-]+)">([^<]+)</button>', nav)
    assert tabs, "no tabs were parsed from index.html -- this test can no longer see the nav"

    # A tab whose label is a single word is documented under that word; the two views that need a
    # longer phrase are listed explicitly rather than guessed at.
    documented_as = {
        "host": "Assets",          # the inventory, renamed from "Host drill-down"
        "network": "Network",
        "zeek": "Zeek",
        "netflow": "Netflow",
        "models": "Models",
        "health": "Health",
        "anomalies": "Anomalies",
        "evidence": "Evidence",
        "settings": "Settings",   # added; Overview was removed
    }
    for key, label in tabs:
        phrase = documented_as.get(key, label.strip())
        assert phrase in DOCS, (
            f"the GUI's {label.strip()} view (data-view={key!r}) is in the nav but undocumented. "
            f"Either document it in the DOCS's GUI view table or remove the tab."
        )
    assert "30088" in DOCS, "the GUI's port is not stated"
    assert "30088" in DOCS, "the GUI's port is not stated"


# ── the docs must not describe dead things ──────────────────────────────────────

def test_the_readme_does_not_advertise_a_feature_that_was_removed():
    """`dam` was a reserved mode name the user asked to have removed entirely, verbiage and
    all. A doc mentioning it would resurrect a name that no longer exists in `mode.py`."""
    from weirvern.admin import mode as mode_mod

    known = {mode_mod.MODE_LOCH, mode_mod.MODE_SIPHON}
    mentioned = set(re.findall(r"`(loch|siphon|dam|pool|reservoir|cistern)`", DOCS))
    stale = {m for m in mentioned if m in ("dam",)}
    assert not stale, f"the DOCS mentions removed mode names: {stale}"
    # And the modes it does describe must be the ones the code knows.
    assert mentioned & known, "the DOCS mentions no mode the code actually implements"


def test_the_linter_is_pinned_to_an_exact_version():
    """THE FAILURE THAT MOTIVATED THIS: a green local `ruff check` and a RED CI on the same commit.

    `ruff>=0.6,<1` let CI resolve a newer ruff than the one used locally, and the two disagree --
    F601 (duplicate dictionary key in a test fixture) fires in 0.16 but was not reported by the
    older version installed here. The failure therefore surfaced only after a push, which is the
    worst place to discover a build-tool difference.

    A linter is part of the build, so its version is part of the build. Pinned exactly.
    """
    pyproject = (ROOT / "pyproject.toml").read_text()
    m = re.search(r'"(ruff[^"]*)"', pyproject)
    assert m, "ruff is not declared as a dependency"
    assert re.fullmatch(r"ruff==\d+\.\d+\.\d+", m.group(1)), (
        f"ruff is declared as {m.group(1)!r}. A range lets CI and a developer's environment "
        f"resolve different versions, and they do not always agree on the same code."
    )


def test_the_ci_workflow_runs_the_same_checks_as_the_gate():
    """The gate is ruff + mypy + pytest. CI must run all three, or a local pass means nothing."""
    workflows = list((ROOT / ".github" / "workflows").glob("*.yml"))
    assert workflows, "no workflow found"
    text = "\n".join(w.read_text() for w in workflows)
    assert "ruff check" in text, "CI does not lint"
    assert "mypy" in text, "CI does not type-check"
    assert "pytest" in text, "CI does not run the tests"


def test_changelog_references_resolve_to_real_files():
    """A path in the CHANGELOG that does not exist makes a reader think THEY broke something.

    The research reports that justify which Zeek logs were added were kept outside the repository
    while the CHANGELOG cited them, so the citations were unresolvable from a clone. They are now
    under `docs/research/` and the schema audit under `scripts/`, and this asserts the references
    keep pointing at real files.
    """
    changelog = (ROOT / "CHANGELOG.md").read_text()
    # Paths in backticks that look like repository paths.
    cited = set(re.findall(r"`((?:docs|scripts|tests|weirvern|k8s|overlays|zeek)/[\w./{}-]+)`", changelog))
    unresolved: list[str] = []
    for ref in cited:
        # A brace glob like `research/x-{a,b}.md` names several files.
        m = re.match(r"^(.*)\{(.+)\}(.*)$", ref)
        candidates = (
            [m.group(1) + part + m.group(3) for part in m.group(2).split(",")] if m else [ref]
        )
        for candidate in candidates:
            if (ROOT / candidate).exists():
                continue
            # A CHANGELOG legitimately names files that were DELETED -- that is what a changelog
            # records. Such a line says so in the surrounding sentence, and the check requires
            # that wording rather than an exemption list: a list would need updating for every
            # future deletion, and a reader cannot tell a listed name from a live one.
            # The phrasing varies: "was deleted", "shipped placeholder values" (a past state),
            # "was included in the kustomization" (past tense about a live-at-the-time file). What
            # they share is a PAST-TENSE verb within a sentence or two of the path. A live
            # reference is written in the present ("the manifest lives in k8s/..."), so this
            # separates the two without an exemption list.
            window = changelog[max(0, changelog.find(candidate) - 40):][:260]
            if re.search(
                r"\b(?:was|were|shipped|had|deleted|removed|dropped|replaced|introduced)\b",
                window, re.IGNORECASE,
            ):
                continue
            unresolved.append(candidate)
    assert not unresolved, (
        "the CHANGELOG cites files that are not in the repository, so a reader cannot follow "
        f"them: {sorted(unresolved)}"
    )


def test_the_image_tag_is_declared_once_and_applies_everywhere():
    """The tag lives in ONE `images:` transformer, and every manifest uses the bare name.

    WHY THIS IS TESTED. `kubectl set image deploy/... worker=weirvern-worker:0.4.3` appears to work,
    and then the next `kubectl apply -k` silently reverts the deployment to whatever this transformer
    pins. Measured on the deployed box: after rolling forward, re-applying the siphon overlay put the
    worker back on an older tag, so the pod lost `intercept --all` and refused to run. The only
    symptom was "unrecognized arguments: --all" from inside the container -- a version mismatch
    presenting as a code bug.

    So: the tag must be declared in the transformer, and the manifests must NOT hardcode a tag of
    their own, or a bump would have to be made in several places and one would be missed.
    """
    kustomization = (ROOT / "k8s" / "kustomization.yaml").read_text()
    m = re.search(r"name:\s+weirvern-worker\s*\n\s*newTag:\s*[\"']?([\w.]+)", kustomization)
    assert m, "the worker image tag is not declared in the kustomization `images:` transformer"
    tag = m.group(1)

    # Every manifest must reference the tagless name, so the transformer is the only source of truth.
    pinned = []
    for path in sorted((ROOT / "k8s").glob("*.yaml")):
        if path.name == "kustomization.yaml":
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if "image:" in line and "weirvern-worker:" in line:
                pinned.append(f"{path.name}:{lineno}: {line.strip()}")
    assert not pinned, (
        "a manifest hardcodes the worker tag, so bumping the transformer would leave it behind:\n  "
        + "\n  ".join(pinned)
    )

    # And the rendered output must actually carry the transformer's tag.
    import subprocess
    rendered = subprocess.run(
        ["kustomize", "build", "k8s/"], cwd=ROOT, capture_output=True, text=True
    ).stdout
    assert f"weirvern-worker:{tag}" in rendered, (
        f"the transformer declares {tag} but the rendered output does not use it"
    )
