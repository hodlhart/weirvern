"""Issue #21: the eight-item document/consistency sweep must stay swept.

Each assertion below couples a corrected claim to the thing that makes it true, so the drift
cannot silently return: the worker's (non-)exposure, the README cross-references, the extras
actually shipped, the DaemonSet's real lifecycle, the example tags, and the sizing numbers
against the script that derives them.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_the_deployment_notes_attribute_port_8080_to_the_collector():
    """Item 1: the worker has no listeners; 8080 is the collector's metrics port."""
    security = (ROOT / "SECURITY.md").read_text()
    assert "port 8080 of the worker" not in security, (
        "the worker was again credited with an inbound port it does not have"
    )
    assert "8080" in security and "collector" in security.lower()


def test_the_k8s_readme_points_at_sections_that_exist():
    """Item 2: the references must resolve in TODAY's tree."""
    readme = (ROOT / "k8s" / "README.md").read_text()
    main = (ROOT / "README.md").read_text()
    assert '"Deploy", step 4' not in readme, "the removed 'Deploy, step 4' reference is back"
    assert "Quick start" in readme and "## Quick start" in main
    assert "The deployment Secret" in main
    # The scaling pointer must name the file that actually carries the section.
    assert "`docs/architecture.md`" in readme
    arch = (ROOT / "docs" / "architecture.md").read_text()
    assert "## Scaling and limitations" in arch
    assert "Scaling and limitations" not in main, (
        "the main README now has a section the k8s README no longer points at -- repoint it"
    )


def test_the_development_extras_and_the_harness_shape_match_reality():
    """Item 3: the extra set exists in pyproject; the harness runs serverless."""
    dev = (ROOT / "docs" / "development.md").read_text()
    pyproject = (ROOT / "pyproject.toml").read_text()
    tail = pyproject.split("[project.optional-dependencies]", 1)[1]
    nxt = re.search(r"^\[", tail, flags=re.M)
    extras_block = tail[:nxt.start()] if nxt else tail
    declared = set(re.findall(r"^(\w+) = \[", extras_block, flags=re.M))
    line = next((l for l in dev.splitlines() if "pip install -e" in l), "")
    assert ".[" in line, "the development install line lost its extras"
    extras = [e.strip() for e in line[line.index(".[") + 2:line.index("]")].split(",")
              if e.strip()]
    assert extras, "the install line names no extras"
    for extra in extras:
        assert extra in declared, f"the docs install .[{extra}] but pyproject does not declare it"
    assert "npm ci" in dev and "needs a served GUI" not in dev, (
        "the harness instructions describe a served-GUI workflow it no longer has"
    )
    assert "http://127.0.0.1:30088" not in dev, "the harness takes no URL"
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "npm ci" in ci and "node scripts/jsdom_render.js" in ci


def test_the_architecture_page_does_not_scale_a_daemonset_to_zero():
    arch = (ROOT / "docs" / "architecture.md").read_text()
    assert "Scale the Zeek sensor to zero" not in arch
    assert "cannot be scaled to zero" in arch, (
        "the corrected sentence must say WHY the scale-to-zero phrasing was wrong"
    )


def test_no_example_tags_remain_at_retired_versions():
    for f, needle in (("zeek/Containerfile", "weirvern-zeek:0.4."),
                      ("k8s/kustomization.yaml", ":v0.4.")):
        text = (ROOT / f).read_text()
        assert needle not in text, f"{f} still shows a retired-version example ({needle})"


def test_the_zeek_tag_is_consistent_across_the_places_operators_copy_from():
    manifest = (ROOT / "k8s" / "32-zeek.yaml").read_text()
    tag = re.search(r"weirvern-zeek:([0-9.]+)", manifest)
    assert tag, "the manifest no longer names a zeek tag"
    for f in ("zeek/Containerfile", "docs/deployment.md"):
        text = (ROOT / f).read_text()
        seen = set(re.findall(r"weirvern-zeek:([0-9.]+)", text))
        assert seen == {tag.group(1)}, f"{f} shows {seen}, the manifest says {tag.group(1)}"


def test_the_published_sizing_numbers_are_reproducible():
    """Item 7: the numbers and the method are the same fact, so this runs the method."""
    if not shutil.which("kustomize"):
        pytest.skip("kustomize not installed")
    out = subprocess.run(["sh", "scripts/measure_sizing.sh"], cwd=ROOT,
                         capture_output=True, text=True, timeout=180)
    assert out.returncode == 0, out.stderr
    m = re.search(r"requests ([\d.]+) CPU / ([\d.]+) GiB; limits ([\d.]+) CPU / ([\d.]+) GiB",
                  out.stdout)
    assert m, out.stdout
    reqs_cpu, reqs_mem, lim_cpu, lim_mem = m.groups()
    doc = (ROOT / "docs" / "deployment.md").read_text()
    assert f"{reqs_cpu} CPU / {reqs_mem} GiB of requests" in doc
    assert f"{lim_cpu} CPU /" in doc and f"{lim_mem} GiB of limits" in doc
    assert "scripts/measure_sizing.sh" in doc, "the method must be named beside the numbers"


def test_the_dead_collector_knob_stays_removed():
    env = (ROOT / ".env.example").read_text()
    assert "EXPOSE_COLLECTORS" not in env, (
        "the knob nothing reads is back; either wire it or leave it out"
    )
