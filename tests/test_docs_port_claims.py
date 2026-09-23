"""The documentation's network-exposure claims must match the manifests.

THE DEFECT THIS GUARDS. `SECURITY.md` stated that the collector's container ports (2055/6343) "are
cluster-internal and are not reachable from outside", and `README.md` said the same in two places
and went further: that an exporter aimed at 2055 "sends its packets nowhere".

All three were WRONG, and had been for as long as the collector has run with `hostNetwork: true` --
which was added deliberately, because a real router was observed sending NetFlow to 2055 while the
listener was at 32055 and the packets vanished with NOTHING logged. Measured on the running
deployment:

    $ ss -lunp | grep -E ':2055|:6343'
    UNCONN  *:2055  users:(("goflow2",pid=3228,fd=6))
    UNCONN  *:6343  users:(("goflow2",pid=3228,fd=8))

`*` is every interface. So the docs described a deployment that no longer existed, and they did it
in the security document -- where a reader goes specifically to learn what is exposed. An operator
following SECURITY.md would believe the collector was unreachable from the LAN and would not
consider an allow-list or a firewall rule.

WHY THIS IS A TEST AND NOT A DOC FIX. The claim lived in three files and drifted because a manifest
changed and nothing connected the two. A test can read both, so the coupling is asserted rather
than remembered. The rule is narrow on purpose: it checks the SHAPE of the claim (does any doc say
these ports are cluster-internal / unreachable?) against the SHAPE of the deployment (does the
collector run with hostNetwork?). Both sides are easy to state and hard to get subtly wrong, which
is what makes it worth automating rather than a broader prose audit that would need constant tuning.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
DOCS = ["SECURITY.md", "README.md", ".env.example"]

# The claim, in the forms it actually appeared in. Narrow phrases rather than a broad reading of
# prose: a documentation audit that tries to understand intent gets disabled the first time it
# objects to something true.
UNREACHABLE_CLAIMS = re.compile(
    r"cluster-internal|not reachable from outside|only reachable from inside"
    r"|sends its packets nowhere",
    re.IGNORECASE,
)
# The port numbers the claim is about.
COLLECTOR_PORTS = re.compile(r"\b(2055|6343)\b")


def _collector_uses_host_network() -> bool:
    """Does the goflow2 workload run with hostNetwork?

    Read from the RENDER rather than the source file so a kustomize patch that turns it on is seen.
    """
    import subprocess

    build = subprocess.run(["kustomize", "build", "k8s/"], cwd=ROOT, capture_output=True, text=True)
    if build.returncode != 0:
        pytest.skip(f"kustomize unavailable: {build.stderr.strip()[:120]}")
    # THE WORKLOAD, not the Service. Both are named `goflow2`, and a Service has no pod spec -- so
    # matching on the name alone returns `None` for the Service and fails the assertion. The first
    # version of this helper did exactly that.
    for doc in yaml.safe_load_all(build.stdout):
        if not doc or doc.get("kind") not in ("Deployment", "DaemonSet", "StatefulSet"):
            continue
        name = doc.get("metadata", {}).get("name", "")
        if "goflow" not in str(name):
            continue
        pod = doc.get("spec", {}).get("template", {}).get("spec", {})
        return bool(pod.get("hostNetwork"))
    pytest.skip("no goflow2 workload in the render")


def test_the_collector_really_does_use_host_network():
    """The premise of the whole check, asserted directly.

    If the collector ever stops using hostNetwork, the docs SHOULD say the ports are
    cluster-internal again -- so this test failing is the signal to update them deliberately
    rather than a reason to weaken the check below.
    """
    assert _collector_uses_host_network(), (
        "the goflow2 collector no longer uses hostNetwork. If that is deliberate, the port claims "
        "in SECURITY.md and README.md must be revisited: with hostNetwork they listen on every "
        "node interface, and without it they are only reachable via the NodePort."
    )


# A line may QUOTE the old claim in order to correct it. That is the opposite of the defect, and
# the exemption has to be explicit: loosening the regex to avoid these lines would also stop
# catching the claim itself, which is how a guard becomes decorative.
CORRECTION_MARKERS = re.compile(
    r"previously|was WRONG|became WRONG|once said|no longer|used to say|corrected",
    re.IGNORECASE,
)


@pytest.mark.parametrize("doc", DOCS)
def test_no_document_claims_the_collector_ports_are_unreachable(doc: str):
    """No doc may say the collector ports are internal while the collector is on every interface.

    A line is exempt when it is explicitly marking the statement as a corrected one, because the
    docs SHOULD record what they used to say -- an operator who read the old version needs to find
    out it changed.
    """
    if not _collector_uses_host_network():
        pytest.skip("the collector is not on hostNetwork, so the claim is not false")
    text = (ROOT / doc).read_text()
    lines = text.splitlines()
    offenders = []
    for i, line in enumerate(lines):
        if not (UNREACHABLE_CLAIMS.search(line) and COLLECTOR_PORTS.search(line)):
            continue
        # Look at this line and the two before it for a correction marker: the quoting usually
        # sits mid-sentence with the correction introduced just above.
        window = " ".join(lines[max(0, i - 2): i + 1])
        if CORRECTION_MARKERS.search(window):
            continue
        offenders.append((i + 1, line.strip()))
    assert not offenders, (
        f"{doc} claims the collector ports are unreachable while the collector runs with "
        f"hostNetwork and listens on EVERY node interface:\n"
        + "\n".join(f"  line {n}: {txt}" for n, txt in offenders)
        + "\nMeasured: `ss -lunp` shows `*:2055` and `*:6343`. An operator reading this would not "
        "consider an allow-list or a firewall rule."
    )


def test_the_security_document_names_the_two_controls():
    """The docs must not merely stop being wrong; they must say what to do.

    A corrected claim that removes the danger without naming the mitigation leaves the reader
    knowing something is exposed and nothing about what to do about it.
    """
    text = (ROOT / "SECURITY.md").read_text()
    assert "WEIRVERN_FLOW_EXPORTER_ALLOW" in text, (
        "SECURITY.md describes the collector's exposure but not the allow-list that restricts it"
    )
    assert re.search(r"unauthenticated", text, re.IGNORECASE), (
        "SECURITY.md does not say that NetFlow carries no authentication, which is the reason the "
        "exposure matters"
    )


def test_the_readme_agrees_that_both_port_forms_listen():
    """The README told operators 2055 'sends its packets nowhere'. Both forms now work."""
    text = (ROOT / "README.md").read_text()
    assert "hostNetwork" in text, (
        "the README does not explain why the conventional ports also listen, so the next reader "
        "will re-derive the old (wrong) conclusion"
    )
