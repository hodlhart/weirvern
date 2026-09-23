"""The manifest reference checker must see EVERY reference shape, and be proven to.

THE DEFECT THIS GUARDS. `.github/workflows/ci.yml` renders the kustomize output and verifies that
every ConfigMap a workload references actually exists in the render. Its `refs()` helper matched
`configMap`, `configMapRef`, `secretRef` and `secretKeyRef` -- but NOT `configMapKeyRef`.

MEASURED (2026-09-23): the tree contains 7 `configMapKeyRef` uses and 1 `secretKeyRef`, so the
checker was examining the rare shape and ignoring the common one. Renaming a `configMapKeyRef` to a
name that does not exist produced `problems: NONE` -- CI would pass a manifest whose pod cannot
start, failing at CreateContainerConfigError on the operator's cluster, with the check that exists
to catch it reporting green. That is this project's named failure mode ("a green reading over work
that did not happen") in the CI gate itself.

WHY THIS IS A TEST AND NOT A WORKFLOW EDIT ALONE. The checker lives inside a heredoc in a YAML
workflow file, where nothing imports it and no test exercises it. A one-word gap in it was invisible
for as long as it existed. These tests extract the real function from the workflow file and drive it
with fixtures -- so the checker cannot silently narrow again, and a mutation to it fails here rather
than passing in CI.

WHAT IS ASSERTED, and the reasoning for each:
  * every reference SHAPE Kubernetes allows is discovered, driven by fixtures rather than by a
    reading of the regex -- because a reading is what missed the gap;
  * a reference to a name that does not exist is REPORTED, which is the property that makes the
    check worth having;
  * a reference that DOES resolve is not reported, so the fix cannot pass by flagging everything.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def _extract_refs_function() -> str:
    """Pull `def refs(o)` out of the workflow's inline python.

    Extracting rather than reimplementing: the point of the test is to exercise the SHIPPING
    checker, and a copy of it here would drift the moment the workflow changed -- which is exactly
    the class of bug being guarded.
    """
    text = WORKFLOW.read_text()
    start = text.index("def refs(o):")
    # The function ends at the next top-level statement in the heredoc, `problems, secret_names`.
    end = text.index("problems, secret_names", start)
    return text[start:end]


@pytest.fixture(scope="module")
def refs_fn():
    import yaml  # noqa: F401

    src = _extract_refs_function()
    ns: dict = {}
    exec(compile(src, "<ci-refs>", "exec"), ns)  # noqa: S102
    return ns["refs"]


# Every shape Kubernetes actually uses. `configMapKeyRef` is the one that was missing, so it is
# first -- a test that only checks the shapes the checker already knew proves nothing.
SHAPES = [
    ("configMap", {"configMap": {"name": "cm-a"}}, "cm-a"),
    ("configMapRef", {"configMapRef": {"name": "cm-b"}}, "cm-b"),
    ("configMapKeyRef", {"configMapKeyRef": {"name": "cm-c", "key": "K"}}, "cm-c"),
    ("secretRef", {"secretRef": {"name": "sec-a"}}, "sec-a"),
    ("secretKeyRef", {"secretKeyRef": {"name": "sec-b", "key": "K"}}, "sec-b"),
]


@pytest.mark.parametrize(("label", "node", "expected"), SHAPES)
def test_every_reference_shape_is_discovered(refs_fn, label, node, expected):
    kinds = set(refs_fn(node))
    assert any(name == expected for _t, name in kinds), (
        f"{label} was NOT discovered by the checker: {sorted(kinds)}. A reference shape the "
        "checker cannot see is a reference that can point anywhere without CI noticing"
    )


def test_configmap_key_ref_specifically_is_not_missed(refs_fn):
    """The exact shape that was missing, named in its own test for the failure message.

    Kept separate from the parametrised case so a regression reports WHICH shape broke, rather
    than only that "some shape" did.
    """
    found = list(refs_fn({"configMapKeyRef": {"name": "weirvern-env", "key": "ZEEK_IFACE"}}))
    assert ("configmap", "weirvern-env") in found, f"configMapKeyRef invisible: {found}"


def test_a_broken_reference_is_reported_and_a_good_one_is_not(refs_fn):
    """Both halves, because a checker that flags everything is as useless as one that flags none."""
    docs = [
        {"kind": "ConfigMap", "metadata": {"name": "weirvern-env"}, "data": {"A": "1"}},
        {"kind": "Deployment", "metadata": {"name": "good"},
         "spec": {"template": {"spec": {"containers": [
             {"env": [{"name": "X", "valueFrom": {"configMapKeyRef": {"name": "weirvern-env"}}}]}]}}}},
        {"kind": "Deployment", "metadata": {"name": "bad"},
         "spec": {"template": {"spec": {"containers": [
             {"env": [{"name": "X", "valueFrom": {"configMapKeyRef": {"name": "does-not-exist"}}}]}]}}}},
    ]
    cms = {d["metadata"]["name"] for d in docs if d.get("kind") == "ConfigMap"}
    problems = [
        f"{d.get('kind')}/{d.get('metadata', {}).get('name')}: unresolved ConfigMap {ref}"
        for d in docs for rtype, ref in refs_fn(d)
        if rtype == "configmap" and ref not in cms
    ]
    assert problems == ["Deployment/bad: unresolved ConfigMap does-not-exist"], (
        f"expected exactly the broken reference to be reported, got {problems}"
    )


def test_the_shipping_tree_has_no_unresolved_references():
    """The real manifests must pass the real checker.

    Uses the rendered output rather than the source files, because the render is what the cluster
    receives -- and because kustomize can rename a ConfigMap via a namePrefix or suffix, which the
    source files would not show.
    """
    import subprocess

    import yaml

    build = subprocess.run(["kustomize", "build", "k8s/"], cwd=ROOT, capture_output=True, text=True)
    if build.returncode != 0:
        pytest.skip(f"kustomize unavailable: {build.stderr.strip()[:120]}")
    docs = [d for d in yaml.safe_load_all(build.stdout) if d]
    cms = {d["metadata"]["name"] for d in docs if d.get("kind") == "ConfigMap"}

    src = _extract_refs_function()
    ns: dict = {}
    exec(compile(src, "<ci-refs>", "exec"), ns)  # noqa: S102
    refs = ns["refs"]

    problems = [
        f"{d.get('kind')}/{d.get('metadata', {}).get('name')}: unresolved ConfigMap {ref}"
        for d in docs for rtype, ref in refs(d)
        if rtype == "configmap" and ref not in cms
    ]
    examined = sum(1 for d in docs for rtype, _ in refs(d) if rtype == "configmap")
    assert examined >= 10, (
        f"only {examined} ConfigMap references were examined; the checker has narrowed again"
    )
    assert not problems, f"the shipping manifests reference missing ConfigMaps: {problems}"


def test_the_extraction_itself_finds_a_real_function():
    """Guards the fixture: if the workflow is refactored, this fails loudly instead of silently
    passing every test above against an empty function."""
    src = _extract_refs_function()
    assert "def refs(o):" in src
    assert "yield" in src, "the extracted source has no yields, so it is not the real function"
    assert re.search(r"configMap", src), "the extracted source mentions no configMap shapes"
