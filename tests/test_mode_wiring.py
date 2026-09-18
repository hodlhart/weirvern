"""The startup script must know its mode, and must not pretend when it cannot comply.

The mode decides whether the sensor is a passive observer or a router. Both are valid;
the consequences are not comparable. So the startup script states the mode and its
failure mode on every boot, and REFUSES to start in weir mode when the sysctls that
make the relay work are missing.

Why refusing is correct: intercepting traffic without the ability to forward it drops
that traffic. A sensor that does not start is a monitoring gap; a sensor that starts and
blackholes the LAN is an outage. The strict-greater harm justifies the hard failure.

The script is extracted from the kustomize RENDER, not read from the source manifest, so
what is tested is exactly what the cluster receives.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
K8S = REPO / "k8s"


@pytest.fixture(scope="module")
def startup_script() -> str:
    """The zeek container's startup script, as rendered."""
    import yaml

    exe = Path.home() / ".local" / "bin" / "kustomize"
    if not exe.exists():
        pytest.skip("kustomize not installed")
    r = subprocess.run([str(exe), "build", str(K8S)],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        pytest.fail(f"kustomize build failed: {r.stderr[:300]}")
    docs = [d for d in yaml.safe_load_all(r.stdout) if d]
    ds = next((d for d in docs if d.get("kind") == "DaemonSet"
               and d["metadata"]["name"] == "zeek"), None)
    assert ds, "the zeek DaemonSet is not in the render"
    return "\n".join(ds["spec"]["template"]["spec"]["containers"][0]["args"])


def _code_only(script: str) -> str:
    """Executable lines, comments excluded.

    A comment documenting the mode logic (or explaining a past bug) legitimately
    contains the same words; an earlier version of a similar test fired on its own
    documentation.
    """
    return "\n".join(ln for ln in script.splitlines()
                     if ln.strip() and not ln.strip().startswith("#"))


def test_the_script_reads_the_mode(startup_script):
    code = _code_only(startup_script)
    assert 'MODE="${SENSOR_MODE' in code, "the startup script ignores SENSOR_MODE"


def test_the_script_states_the_mode_and_its_failure_mode(startup_script):
    """An operator should never have to infer from a config file whether the sensor in
    front of them is passive or in-path."""
    code = _code_only(startup_script)
    assert "mode loch" in code, "loch mode is not announced"
    assert "mode weir" in code, "weir mode is not announced"
    # The consequence must be stated, not just the label.
    assert re.search(r"weir.*(relayed|OUTAGE|outage|lose)", code, re.I), (
        "weir mode is announced without saying that traffic flows through it"
    )


def test_loch_is_the_default_when_unset(startup_script):
    """A sensor with no mode configured must be the SAFE one. Defaulting to in-path
    would make an unanswered question into a network-wide behaviour change."""
    code = _code_only(startup_script)
    assert 'MODE="${SENSOR_MODE:-loch}"' in code


def test_an_unknown_mode_is_fatal(startup_script):
    """Silently treating a typo as loch would hide the mistake; treating it as weir
    would be dangerous. Neither is acceptable, so it must fail."""
    code = _code_only(startup_script)
    assert "unknown SENSOR_MODE" in code
    # And the failing branch must exit, not warn.
    m = re.search(r"unknown SENSOR_MODE.*?\n(.*?);;", code, re.S)
    assert m and "exit 1" in m.group(1), "an unknown mode must exit, not continue"


@pytest.mark.parametrize("sysctl,value,why", [
    ("net/ipv4/ip_forward", "1", "relayed traffic would be dropped"),
    ("net/ipv4/conf/all/rp_filter", "0", "the relay would be filtered out"),
    ("net/ipv4/conf/all/send_redirects", "0", "redirects would undo the intercept"),
])
def test_weir_mode_refuses_to_start_without_each_sysctl(startup_script, sysctl, value, why):
    """Each sysctl was verified necessary in a sandbox, and each has a specific symptom.
    The script must check all three and refuse — with the reason, not just a failure."""
    code = _code_only(startup_script)
    assert f"/proc/sys/{sysctl}" in code, f"{sysctl} is never checked"
    assert f'!= "{value}"' in code, f"{sysctl} is not compared against {value}"
    # The FATAL message must name the consequence, otherwise the operator is left to
    # work out why the sensor refuses to start.
    m = re.search(rf'FATAL: mode weir requires [^\n]*{value.replace("/", "/")}', code)
    assert m, f"missing the refusal message for {sysctl}"


def test_the_sysctl_checks_live_in_the_weir_branch(startup_script):
    """Checking them in loch mode would refuse to start a sensor that is perfectly
    safe, which would be its own bug."""
    code = _code_only(startup_script)
    weir_start = code.find("weir)")
    loch_start = code.find("loch)")
    unknown = code.find("*)")
    assert -1 not in (weir_start, loch_start, unknown)
    weir_branch = code[weir_start:unknown]
    assert "/proc/sys/net/ipv4/ip_forward" in weir_branch
    assert "/proc/sys/net/ipv4/ip_forward" not in code[loch_start:weir_start], (
        "loch mode must not be gated on forwarding sysctls — it does not forward"
    )


def test_sensor_mode_is_injected_into_the_pod(startup_script):
    """The ConfigMap key existing is not enough; the container must receive it, which is
    a bug that already shipped once with MGMT_IFACE."""
    import yaml

    exe = Path.home() / ".local" / "bin" / "kustomize"
    r = subprocess.run([str(exe), "build", str(K8S)],
                       capture_output=True, text=True, timeout=120)
    docs = [d for d in yaml.safe_load_all(r.stdout) if d]
    ds = next(d for d in docs if d.get("kind") == "DaemonSet"
              and d["metadata"]["name"] == "zeek")
    names = {e.get("name") for e in
             ds["spec"]["template"]["spec"]["containers"][0].get("env") or []}
    assert "SENSOR_MODE" in names, (
        "SENSOR_MODE is read by the startup script but not declared in env:, so it is "
        "empty at runtime and every mode check silently falls back to the default"
    )


def test_the_mode_command_reports_and_gates():
    """`weirvern mode` must exist, report by default, and refuse an unavailable mode."""
    from weirvern.admin import cli

    src = __import__("inspect").getsource(cli)
    assert "def cmd_mode" in src
    assert "EXIT_NOTREADY" in src[src.find("def cmd_mode"):src.find("def _ok_or_bad")], (
        "cmd_mode must return NOTREADY (3) when a mode cannot be enabled, so a script "
        "can distinguish 'refused' from 'broke'"
    )


def test_weir_mode_cannot_share_the_management_interface():
    """Weir mode relays on the capture interface. If that is also the management port,
    the sensor can intercept the cluster API traffic that manages it and cut itself
    off — a self-inflicted outage."""
    import inspect as _inspect

    from weirvern.admin import cli

    src = _inspect.getsource(cli.cmd_mode)
    assert "ZEEK_IFACE and MGMT_IFACE are both" in src
    assert "capture_iface and mgmt_iface" in src
