"""F091: interface names are the only free-text inputs that reach a privileged context.

CONFIRMED BY RUNNING IT, on a rig that had to be built correctly first. The finding was already
in the ledger, and my first reproduction was DEFECTIVE: `read_mac` appends `/address`, so a
traversal string alone does nothing -- the target must be a DIRECTORY containing a file named
`address`. With the rig built properly:

    mkdir /tmp/x; printf 'de:ad:be:ef:00:01\n' > /tmp/x/address
    read_mac('../../../tmp/x')  ->  'de:ad:be:ef:00:01'

That is a MAC read out of a file outside /sys/class/net, from a request body field. Separately,
`build_job(... 'eth0; echo pwned')` put that string verbatim into a root / hostNetwork / NET_RAW
Job's env -- a privileged workload given arbitrary text with no input contract at all.

Not command injection (the value lands in an env var and in argv, never a shell), but the two
properties that matter are: a path built from the name escapes a fixed directory, and a string
that no layer validated flows into the most privileged thing this product creates.

WHAT THIS FILE PINS:
  * the escape itself, with the working rig, because a regression here is silent;
  * that the rule is the KERNEL's own (IFNAMSIZ), not a stricter invention -- every real
    interface name must still pass, and the boundary is pinned at exactly 15 bytes;
  * that a refusal is a REASON, not a bare bool, so the operator learns which rule they broke;
  * that a malformed name is never reported as "this interface has no MAC" -- that would send
    the operator to inspect hardware that is fine.
"""
from __future__ import annotations

import os
import pathlib

import pytest

from weirvern.admin import siphonnet, sonar

# ── the escape ────────────────────────────────────────────────────────────────────────────────

def test_a_traversal_name_can_no_longer_read_a_file_outside_sys_class_net(tmp_path):
    """THE FINDING. A directory outside /sys/class/net holding a file named `address` is what a
    path built from an unvalidated name reaches."""
    victim = tmp_path / "address"
    victim.write_text("de:ad:be:ef:00:01\n")
    traversal = os.path.relpath(tmp_path, "/sys/class/net")

    with pytest.raises(ValueError) as exc:
        siphonnet.read_mac(traversal)

    assert "path separator" in str(exc.value), (
        f"the escape was refused, but not for the reason expected: {exc.value}"
    )
    # And prove the rig would have worked: the file IS readable by the path the old code built.
    assert pathlib.Path(f"/sys/class/net/{traversal}/address").resolve() == victim.resolve(), (
        "the rig does not actually point outside /sys/class/net, so this test proves nothing"
    )


def test_build_job_refuses_a_name_that_would_reach_a_privileged_env():
    """The Job is root, hostNetwork, NET_RAW. It accepted arbitrary text before."""
    for bad in ("eth0; echo pwned", "../../etc/passwd", "eth0$(id)", "eth 0", ".", "..", ""):
        with pytest.raises(ValueError):
            sonar.build_job("j", "weirvern-worker:1", bad, "")


def test_build_job_refuses_a_bad_mgmt_interface_too():
    """Optional, but it rides in the same privileged env and drives the two-port warning."""
    with pytest.raises(ValueError):
        sonar.build_job("j", "weirvern-worker:1", "eth0", "../../etc")
    # An ABSENT mgmt interface stays legal: it is genuinely optional.
    job = sonar.build_job("j", "weirvern-worker:1", "eth0", "")
    env = {e["name"]: e["value"] for e in job["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["SONAR_MGMT_IFACE"] == ""


def test_the_privileged_entrypoint_validates_its_own_environment(monkeypatch):
    """DEFENCE IN DEPTH: the job must not trust a check made by the process that created it.

    The env var is an input like any other, and this is the code that runs with the capabilities.

    ── WHY THIS TEST STUBS `survey` (the mutation that survived) ────────────────────────────────

    `main()` validates the env, and then calls `survey()`, which validates again. A mutation that
    removed ONLY main's check therefore changed nothing observable, and this test still passed --
    which is the correct signal for redundant code and the wrong one for code that is supposed to
    be an independent layer.

    Patching `survey` out is what makes the layers separable: with it gone, the ONLY thing standing
    between a malformed env var and the privileged work is main's own check. If that check is
    deleted, this test now fails.
    """
    monkeypatch.setenv("SONAR_IFACE", "../../etc")
    monkeypatch.delenv("SONAR_MGMT_IFACE", raising=False)

    # A RECORDER, not a raiser. `main()` wraps the call in a broad `except Exception` that returns
    # 2 for ANY failure, so an assertion raised from inside the stub is swallowed and the exit code
    # looks identical either way -- the first version of this test used a raiser and the mutation
    # survived because of it. Recording the CALL and asserting on the record cannot be swallowed.
    calls: list[tuple] = []
    monkeypatch.setattr(sonar, "survey", lambda *a, **k: calls.append((a, k)) or {"ok": True})
    rc = sonar.main()
    assert calls == [], (
        "survey() was reached with a malformed SONAR_IFACE -- main() did not validate the "
        "environment it was handed"
    )
    assert rc == 2, "the privileged entrypoint accepted a path as an interface name"


def test_the_privileged_entrypoint_refuses_a_bad_MGMT_interface(monkeypatch):
    """The second env var, which is what the two-port warning is built from."""
    monkeypatch.setenv("SONAR_IFACE", "eth0")
    monkeypatch.setenv("SONAR_MGMT_IFACE", "../../etc")

    calls: list[tuple] = []
    monkeypatch.setattr(sonar, "survey", lambda *a, **k: calls.append((a, k)) or {"ok": True})
    assert sonar.main() == 2
    assert calls == [], "survey() ran with a malformed SONAR_MGMT_IFACE"


def test_survey_refuses_a_bad_name_even_with_an_injected_mac_reader():
    """A caller that injects its own mac_reader would bypass read_mac's own check, so survey()
    checks the name itself -- and it does so BEFORE the MAC read, so a malformed name is never
    reported as a missing NIC."""
    calls: list[str] = []

    def _mac_reader(name):  # noqa: ANN001
        calls.append(name)
        return "aa:bb:cc:dd:ee:ff"

    with pytest.raises(sonar.SonarError) as exc:
        sonar.survey("../../etc", mac_reader=_mac_reader)

    assert "cannot survey" in str(exc.value) and "path separator" in str(exc.value), str(exc.value)
    assert calls == [], (
        "the MAC reader ran before the name was validated, so a malformed name is reported as a "
        "missing interface"
    )


# ── the rule is the kernel's, not a stricter invention ────────────────────────────────────────

@pytest.mark.parametrize("good", [
    "eth0", "eth1", "ens18", "ens19", "enp3s0", "eno1", "wlan0", "wlp2s0",
    "br-lan", "br-1a2b3c4d5e6f", "veth1a2b3c", "docker0", "tailscale0", "lo",
])
def test_every_real_interface_name_is_still_accepted(good):
    """A validator that refuses a real NIC would break deployment on contact with a host."""
    assert siphonnet.iface_name_error(good) == "", f"{good!r} was refused"


def test_the_length_boundary_is_the_kernels_IFNAMSIZ():
    """15 bytes is the kernel's limit (IFNAMSIZ-1 = 15). Pinned on both sides: a validator that is
    one byte too strict refuses a legal name, and one that is a byte too lax lets a 16-byte name
    through that the kernel itself would truncate."""
    assert siphonnet.iface_name_error("a" * 15) == "", "a legal 15-byte name was refused"
    assert siphonnet.iface_name_error("a" * 16) != "", "a 16-byte name was accepted"


def test_the_rule_is_about_path_components_and_single_tokens():
    """The properties that actually matter, named individually so a rewrite cannot lose one."""
    for bad, why_fragment in [
        ("eth/0", "path separator"),
        ("..", "path, not an interface"),
        (".", "path, not an interface"),
        ("", "empty"),
        (None, "no interface name"),
        # A trailing newline is caught by the WHITESPACE rule, which fires before the character
        # rule -- the more specific reason, and the one an operator should see.
        ("eth0\n", "whitespace"),
        ("eth 0", "not allowed"),
        ("eth0;ls", "not allowed"),
        ("eth0|ls", "not allowed"),
        ("eth0`id`", "not allowed"),
        ("eth0$(id)", "not allowed"),
        ("eth0&&ls", "not allowed"),
    ]:
        why = siphonnet.iface_name_error(bad)
        assert why, f"{bad!r} was accepted"
        assert why_fragment in why, f"{bad!r} gave {why!r}, expected to mention {why_fragment!r}"


def test_whitespace_is_refused_rather_than_silently_trimmed():
    """`build_job` receives an already-stripped name from the route, so a padded one arriving here
    is a caller bug -- and silently trimming it would hide that."""
    why = siphonnet.iface_name_error(" eth0")
    assert why and "whitespace" in why, why


# ── the refusal tells the operator what to do ─────────────────────────────────────────────────

def test_the_refusal_names_the_rule_that_was_broken():
    """A survey that refuses must say why: "invalid interface name" alone does not tell an
    operator whether they typed a dash wrong or named a NIC that does not exist."""
    with pytest.raises(sonar.SonarError) as exc:
        sonar.survey("x" * 40, mac_reader=lambda _n: "aa:bb:cc:dd:ee:ff")
    msg = str(exc.value)
    assert "40 bytes" in msg and "15" in msg, (
        f"the length refusal did not state the limit: {msg}"
    )
    assert "ip link" in msg, "the refusal does not say how to find the right name"


# ── THE ROUTE: the refusal an operator actually sees ─────────────────────────────────────────
#
# Tested by DRIVING THE REAL ROUTE, not by grepping web.py. A source-grep here would pin the
# shape of the text rather than the behaviour -- the recurring failure mode in this project's
# lowest-severity findings -- and it would keep passing if the check were moved behind an early
# return or wired to the wrong variable.
#
# The route lives on the Flask surface now, and `create_app(ctx)` closes over ctx, so a Flask test
# client is the way to drive it against a context a test controls. The write gate is passed
# through, exactly as the old driver passed `_authorize`: it has its own tests, and this file is
# about the interface-name contract.

class _Auth:
    enabled = True
    reason = ""


class _Ctx:
    settings = None
    backend = None
    auth = _Auth()
    config_client = None      # unreachable: a valid request never gets this far (it has no cluster)
    user_store = None
    sessions = None


def _drive_sonar_route(body, monkeypatch):
    """POST a body to the real Flask route; return (status, payload)."""
    import json

    from weirvern.admin import flask_app, requestauth

    # The gate has its own tests; this file is about the interface-name contract. Patched where
    # the view looks it up, so the shipping view and the shared payload layer both still run.
    monkeypatch.setattr(requestauth, "write_refusal", lambda *a, **kw: (True, None))
    client = flask_app.create_app(_Ctx()).test_client()
    resp = client.post("/api/settings/sonar", data=json.dumps(body),
                       content_type="application/json")
    return resp.status_code, resp.get_json()


def test_the_route_refuses_a_traversal_interface_with_a_400(monkeypatch):
    """The operator's own view of the fix: a 400 and a sentence, not a 500 and an exception."""
    code, payload = _drive_sonar_route({"interface": "../../etc"}, monkeypatch)
    assert code == 400, f"expected a 400 refusal, got {code}: {payload}"
    assert payload.get("ok") is False
    err = payload.get("error", "")
    assert "path separator" in err, f"the refusal does not name the rule: {err!r}"
    assert "ip link" in err, f"the refusal does not say how to fix it: {err!r}"


def test_the_route_refuses_a_malformed_MGMT_interface_too(monkeypatch):
    """Checked even though the route would have accepted a good capture interface."""
    code, payload = _drive_sonar_route({"interface": "eth0", "mgmt_interface": "eth0; id"},
                                       monkeypatch)
    assert code == 400, f"expected a 400, got {code}: {payload}"
    assert "mgmt_interface" in payload.get("error", ""), payload


def test_the_route_refuses_before_it_reaches_the_cluster(monkeypatch):
    """ORDER MATTERS. The refusal must happen BEFORE the handler tries to build a cluster client:
    a malformed name is a request problem, and reporting it as 'cannot reach Kubernetes' would send
    the operator to debug their cluster instead of their typo.

    `config_client` is None and no ClusterConfig can be built here, so if the validation ran after
    the client check this test would see the 503-shaped cluster error instead.
    """
    code, payload = _drive_sonar_route({"interface": "../.."}, monkeypatch)
    assert code == 400, (
        f"a malformed interface reached the cluster path and came back as {code}: {payload}"
    )
    assert "Kubernetes" not in payload.get("error", "") and "cluster" not in payload.get(
        "error", "").lower(), f"a typo in an interface name was reported as a cluster failure: {payload}"


def test_a_good_interface_passes_the_route_check(monkeypatch):
    """The other direction, so the check cannot be 'everything is refused'. With a valid name the
    handler proceeds past validation -- here it then fails to find a cluster, which is a DIFFERENT
    answer and proves the name check allowed it through."""
    code, payload = _drive_sonar_route({"interface": "eth1", "mgmt_interface": "eth0"}, monkeypatch)
    assert code != 400 or "interface" not in str(payload.get("error", "")).lower()[:40], (
        f"a valid interface name was refused by the shape check: {payload}"
    )
