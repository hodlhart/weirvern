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


def test_the_documented_tunnel_commands_match_the_real_service():
    """The mitigation must be RUNNABLE, or it is advice rather than a control.

    `kubectl port-forward svc/<name> <port>:<port>` fails if the Service name or port is wrong,
    and a failure here is worse than no advice: an operator who tries the documented command, sees
    an error, and concludes TLS is unavailable has lost the mitigation AND some trust.

    MEASURED against the live cluster while writing this: `weirvern-gui  NodePort  port=8088
    nodePort=30088`. The assertions below keep the doc pinned to the manifest, which is the half
    that can be checked without a cluster.
    """
    import yaml

    docs = [d for d in yaml.safe_load_all((ROOT / "k8s" / "34-gui.yaml").read_text()) if d]
    svc = next((d for d in docs if d.get("kind") == "Service"), None)
    assert svc is not None, "no Service in k8s/34-gui.yaml"
    name = svc["metadata"]["name"]
    port = svc["spec"]["ports"][0]["port"]
    node_port = svc["spec"]["ports"][0]["nodePort"]

    text = (ROOT / "SECURITY.md").read_text()
    assert f"port-forward svc/{name}" in text, (
        f"SECURITY.md's tunnel advice does not name the real Service ({name})"
    )
    assert f"{port}:{port}" in text, (
        f"SECURITY.md's port-forward does not use the Service's real port ({port})"
    )
    assert f"ssh -L {port}:localhost:{port}" in text, (
        f"SECURITY.md's ssh tunnel does not use the Service's real port ({port})"
    )
    # The NodePort is what an operator actually types in a browser; the doc should not send them
    # to a port nothing listens on.
    assert str(node_port) in text or "NodePort" in text, (
        "SECURITY.md does not mention the NodePort the GUI is served on"
    )


def test_security_md_states_there_is_no_tls():
    """The boundary must be in the OPERATOR document, not only in a module docstring.

    gui_auth.py's threat model has said "there is no TLS here" for some time, and an operator
    reading SECURITY.md could not find out. A limitation documented only where developers look is
    not a stated boundary.
    """
    text = (ROOT / "SECURITY.md").read_text()
    assert re.search(r"no TLS|plain HTTP|cleartext", text, re.IGNORECASE), (
        "SECURITY.md does not state that the GUI is served over plain HTTP with no TLS"
    )


# ── the break-glass token must be provisionable, or the recovery path is decoration ────────────
#
# MEASURED DEFECT (2026-09-23). The sign-in screen carries a "Lost the admin password? Use the
# operator token instead." door -- index.html:37-57, where the code even explains why it lives on
# the LOCKED screen rather than behind it -- and the README names it as the recovery path for a
# password that was never captured.
#
# But `WEIRVERN_GUI_TOKEN` appeared NOWHERE: not in install.sh, not in the README's commands, not in
# any manifest. `weirvern-secrets` was created with a ClickHouse password and two empty Pushover
# values, and the token simply was not there. So the documented recovery path led to a door with no
# key, and an operator who lost the admin password had: no password (a scrypt hash, unrecoverable),
# no token, and no CLI command to set either.
#
# It surfaced as exactly that during this session, which is the only reason it was found: the
# account existed, the door was visible, and nobody could walk through it.
def test_the_installer_creates_the_break_glass_token():
    """The installer must SET the token, not just rely on it being mentioned in prose."""
    text = (ROOT / "install.sh").read_text()
    assert "WEIRVERN_GUI_TOKEN" in text, (
        "install.sh never sets WEIRVERN_GUI_TOKEN, so the sign-in screen's recovery door cannot "
        "accept anything on a fresh deployment"
    )
    # It must be part of the Secret creation, so it exists the moment the GUI starts.
    secret_block = text[text.index("create secret generic weirvern-secrets"):]
    secret_block = secret_block[: secret_block.index("fi")]
    assert "WEIRVERN_GUI_TOKEN" in secret_block, (
        "the token is mentioned but not written into weirvern-secrets, so it would never exist"
    )


def test_the_installer_SHOWS_the_token_because_a_secret_nobody_knows_is_useless():
    """Generating a credential and not telling anyone is the same as not generating it.

    The admin password is printed once for exactly this reason; the token needs the same
    treatment, or an operator has a recovery door whose key is only in a Secret they were never
    told to read.
    """
    text = (ROOT / "install.sh").read_text()
    assert "operator token:" in text, (
        "the install summary does not print the operator token, so a fresh install leaves the "
        "operator with a credential they do not know"
    )
    assert "jsonpath='{.data.WEIRVERN_GUI_TOKEN}'" in text, (
        "the installer does not tell the operator how to read the token again later"
    )


def test_the_readme_documents_reading_and_setting_the_token():
    """The README names the recovery path, so it must also name the credential and how to make one.

    A recovery procedure that references a value with no way to obtain it is worse than silence:
    it tells the operator a way out exists and then fails to provide it.
    """
    text = (ROOT / "README.md").read_text()
    assert "WEIRVERN_GUI_TOKEN" in text, (
        "the README describes the operator-token recovery door but never names the variable"
    )
    assert "base64 -d" in text, (
        "the README does not show how to read the existing token out of the Secret"
    )
    # Setting one must be documented too, for installs that predate the provisioning.
    assert "patch secret weirvern-secrets" in text, (
        "the README does not document how to SET a token on a deployment that has none"
    )


def test_the_last_resort_recovery_command_uses_real_api_names():
    """THE COMMAND I GOT WRONG TWICE, now pinned.

    I first wrote `ClusterUserStore`, which does not exist; then `UserStore(ClusterConfig())`
    without `load()`, which read `exists: False` because the store had not been loaded. Both would
    have failed in an operator's hands, at the moment they were already locked out.

    A command in the documentation is a claim that it works, and the only way to keep that true is
    to execute it against the real objects.
    """
    import inspect

    from weirvern.admin import cluster_config, users

    assert hasattr(users, "UserStore"), "the README names a store class that does not exist"
    assert not hasattr(users, "ClusterUserStore"), "the name I first used is not in the module"
    assert hasattr(users.UserStore, "set_password")
    assert hasattr(users.UserStore, "load"), (
        "the store has a load() step; a command omitting it reads nothing"
    )
    # THE CONSTRUCTOR TAKES A CLIENT -- the mistake that produced `exists: False`.
    sig = inspect.signature(users.UserStore.__init__)
    required = [
        p.name for p in sig.parameters.values()
        if p.name != "self" and p.default is inspect.Parameter.empty
        and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
    ]
    assert required == ["client"], (
        f"UserStore now takes {required}; the documented command passes a client "
        "(ClusterConfig(configmap=USERS_CONFIGMAP))"
    )
    # And the README's command must build the client with the account store's own ConfigMap name.
    text = (ROOT / "README.md").read_text()
    assert "ClusterConfig(configmap=users.USERS_CONFIGMAP)" in text, (
        "the README's command does not bind the client to the account store's ConfigMap"
    )
    assert "store.load()" in text, "the README's command omits the load() step"
    assert hasattr(cluster_config, "ClusterConfig")
