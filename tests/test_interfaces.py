"""Capture-port selection: the two-port model, and the traps we measured.

WHY THIS EXISTS
---------------
Choosing the capture interface is the one setup decision whose failure is INVISIBLE.
Every wrong answer produces a running, healthy-looking sensor:

  * the management port  -> a capture of this host's own traffic plus broadcast,
    which looks busy and contains no view of the network
  * a bridge member      -> measured 73% broadcast/multicast and no unicast from
    other hosts (our live deployment, inside a container)
  * a bridge device      -> only what traverses the bridge
  * a veth or tunnel     -> only what the host itself sends or receives

None of these makes Zeek complain. So the selection logic is tested here against
synthetic hosts rather than trusted: these tests encode the exact configurations we
observed failing, and the ones that must pass.
"""
from __future__ import annotations

import json

import pytest

from weirvern.admin import interfaces as if_mod


def host(*records, default_route: str = "eth0") -> if_mod.ProbeResult:
    """Build a ProbeResult from concise interface specs."""
    defs = []
    for r in records:
        rec = {
            "name": r["name"],
            "operstate": r.get("operstate", "up"),
            # IFF_UP is 0x1, IFF_PROMISC is 0x100.
            "flags": r.get("flags", "0x1003"),
            "address": r.get("address", "aa:bb:cc:dd:ee:ff"),
            "has_device": r.get("has_device", True),
            "is_bridge": r.get("is_bridge", False),
            "is_bridge_port": r.get("is_bridge_port", False),
            "driver": r.get("driver", ""),
            "rx_packets": str(r.get("rx_packets", 1000)),
            "rx_dropped": str(r.get("rx_dropped", 0)),
            "rx_errors": str(r.get("rx_errors", 0)),
        }
        defs.append(rec)
    return if_mod.parse_probe(json.dumps({
        "interfaces": defs, "default_route_iface": default_route, "hostname": "sensor",
    }))


# --- the intended shape -------------------------------------------------------
def test_a_dedicated_physical_mirror_port_is_accepted():
    """The configuration the whole feature exists to enable."""
    p = host(
        {"name": "eth0", "driver": "igb"},                      # mgmt, default route
        {"name": "eth1", "driver": "igb", "flags": "0x1103"},   # capture, PROMISC
        default_route="eth0",
    )
    v = if_mod.validate_capture_iface(p, "eth1", "eth0")
    assert v.ok and not v.fatal
    assert if_mod.recommend(p, "eth0") == "eth1"


# --- the traps, each one observed or derived from an observed failure ----------
def test_management_port_is_rejected_with_the_reason():
    """The default-route interface sees only this host's traffic. It is the most
    tempting wrong choice because the name looks normal and it is definitely up."""
    p = host(
        {"name": "eth0", "driver": "igb"},
        {"name": "eth1", "driver": "igb", "flags": "0x1103"},
        default_route="eth0",
    )
    v = if_mod.validate_capture_iface(p, "eth0", "eth0")
    assert v.warnings, "capturing on the default-route port must be flagged"
    joined = " ".join(v.warnings)
    assert "MANAGEMENT" in joined
    assert "broadcast" in joined, "the warning must name the actual symptom"
    assert "eth1" in joined, "and point at the right interface"


def test_bridge_member_is_fatal_not_a_warning():
    """THE MEASURED FAILURE. A port enslaved to a bridge receives only flooded
    traffic. In our deployment this produced 73% broadcast/multicast and nothing
    from other hosts, with a completely healthy-looking Zeek."""
    p = host(
        {"name": "eth0", "driver": "igb"},
        {"name": "eth1", "is_bridge_port": True, "driver": "igb"},
        default_route="eth0",
    )
    v = if_mod.validate_capture_iface(p, "eth1", "eth0")
    assert not v.ok, "a bridge member must be fatal, not advisory"
    joined = " ".join(v.fatal)
    assert "enslaved to a bridge" in joined
    assert "73%" in joined, "the warning should cite the measured symptom"
    assert if_mod.recommend(p, "eth0") == "", "must not recommend a bridge member"


def test_bridge_device_is_fatal():
    p = host(
        {"name": "eth0", "driver": "igb"},
        {"name": "vmbr0", "is_bridge": True, "flags": "0x1003"},
        default_route="eth0",
    )
    v = if_mod.validate_capture_iface(p, "vmbr0", "eth0")
    assert not v.ok
    assert "bridge DEVICE" in " ".join(v.fatal)


@pytest.mark.parametrize("name", ["veth0abc", "docker0", "tun0", "wg0", "tailscale0",
                                  "flannel.1", "cni0", "dummy0"])
def test_virtual_interfaces_are_fatal(name):
    """Covered by name AND by lacking a backing device, because either signal alone
    is wrong: a renamed physical NIC still has a device, while a veth sometimes has
    a device path too."""
    p = host(
        {"name": "eth0", "driver": "igb"},
        {"name": name, "has_device": False},
        default_route="eth0",
    )
    v = if_mod.validate_capture_iface(p, name, "eth0")
    assert not v.ok, f"{name} must not be usable as a capture port"
    assert if_mod.recommend(p, "eth0") == ""


def test_loopback_is_fatal():
    p = host({"name": "lo", "flags": "0x9", "has_device": False}, default_route="lo")
    v = if_mod.validate_capture_iface(p, "lo")
    assert not v.ok
    assert "loopback" in " ".join(v.fatal)


def test_missing_interface_lists_what_does_exist():
    """A typo in ZEEK_IFACE is the most common cause of 'the sensor captures
    nothing', so the error must show the valid names."""
    p = host({"name": "eth0", "driver": "igb"}, {"name": "eth1", "driver": "igb"},
             default_route="eth0")
    v = if_mod.validate_capture_iface(p, "eth9", "eth0")
    assert not v.ok
    assert "does not exist" in " ".join(v.fatal)
    assert any("eth1" in n for n in v.notes), "must list the interfaces that do exist"


def test_the_same_interface_for_both_roles_is_flagged():
    """The two-port model requires them separate; using one NIC for both is the
    configuration that yields a noisy capture with no network view."""
    p = host({"name": "eth0", "driver": "igb"}, default_route="eth0")
    v = if_mod.validate_capture_iface(p, "eth0", "eth0")
    assert any("both" in w or "MGMT_IFACE names it too" in w for w in v.warnings), (
        "the same-interface configuration must be stated"
    )


def test_the_same_interface_case_is_not_reported_twice():
    """REG RESSION: the condition was reached by two clauses, so the operator got two
    near-identical warnings and the output looked broken. One statement per problem.
    """
    p = host({"name": "eth0", "driver": "igb"}, default_route="eth0")
    v = if_mod.validate_capture_iface(p, "eth0", "eth0")
    mentioning_mgmt = [w for w in v.warnings if "MGMT_IFACE" in w]
    assert len(mentioning_mgmt) <= 1, (
        f"the MGMT_IFACE conflict is reported {len(mentioning_mgmt)} times: "
        f"{mentioning_mgmt}"
    )


def test_non_interface_entries_in_sysfs_are_ignored():
    """/sys/class/net holds `bonding_masters` as a plain FILE, not an interface. It has
    no flags or operstate, so reporting it as a virtual NIC is misleading noise that
    buries the real list -- it appeared in a live run against the test node.
    """
    # The probe must filter non-directories. Assert the intent directly, since the
    # probe reads the real sysfs and cannot be fed synthetic entries here.
    src = if_mod._probe_source()
    assert "is_dir()" in src, (
        "the probe does not filter /sys/class/net entries by directory, so files like "
        "bonding_masters will be reported as interfaces"
    )


def test_not_promiscuous_is_a_warning_with_the_fix():
    """Weirvern cannot set promisc itself -- the Zeek container deliberately has no
    NET_ADMIN -- so the operator must be told the exact command."""
    p = host(
        {"name": "eth0", "driver": "igb"},
        {"name": "eth1", "driver": "igb", "flags": "0x1003"},  # UP but no PROMISC
        default_route="eth0",
    )
    v = if_mod.validate_capture_iface(p, "eth1", "eth0")
    assert v.ok, "a non-promiscuous mirror port is usable, just unusual"
    joined = " ".join(v.warnings)
    assert "promiscuous" in joined
    assert "ip link set eth1 promisc on" in joined, "must give the literal command"
    assert "NET_ADMIN" in joined, "and explain why Weirvern does not do it"


def test_down_interface_is_fatal_but_still_suggestible():
    """A cabled-but-down NIC is a normal intermediate state while configuring, so it
    must be reported as unusable yet remain a suggestion -- excluding it made the
    command claim no capture port existed on a host that had an unused physical NIC."""
    p = host(
        {"name": "eth0", "driver": "igb"},
        {"name": "eth1", "driver": "igb", "operstate": "down", "flags": "0x1002",
         "rx_packets": 0},
        default_route="eth0",
    )
    v = if_mod.validate_capture_iface(p, "eth1", "eth0")
    assert not v.ok
    assert "not UP" in " ".join(v.fatal)
    assert if_mod.recommend(p, "eth0") == "eth1", (
        "a down physical NIC is still the right answer; the operator brings it up"
    )


def test_zero_rx_packets_is_noted_not_fatal():
    """A mirror port that has never received a packet may just not be configured on
    the switch yet. Worth saying; not a reason to refuse to deploy."""
    p = host(
        {"name": "eth0", "driver": "igb"},
        {"name": "eth1", "driver": "igb", "flags": "0x1103", "rx_packets": 0},
        default_route="eth0",
    )
    v = if_mod.validate_capture_iface(p, "eth1", "eth0")
    assert v.ok
    assert any("0 packets" in n for n in v.notes)


def test_kernel_drops_are_surfaced():
    """Drops before Zeek sees a packet mean capture loss, which silently corrupts the
    anomaly baseline. It must appear even though nothing is structurally wrong."""
    p = host(
        {"name": "eth0", "driver": "igb"},
        {"name": "eth1", "driver": "igb", "flags": "0x1103", "rx_dropped": 500 },
        default_route="eth0",
    )
    v = if_mod.validate_capture_iface(p, "eth1", "eth0")
    assert v.ok
    assert any("dropped 500" in n for n in v.notes)


# --- recommendation ordering --------------------------------------------------
def test_recommendation_prefers_promiscuous_then_non_mgmt():
    p = host(
        {"name": "eth0", "driver": "igb"},
        {"name": "eth1", "driver": "igb"},                      # no promisc
        {"name": "eth2", "driver": "igb", "flags": "0x1103"},   # promisc
        default_route="eth0",
    )
    assert if_mod.recommend(p, "eth0") == "eth2"


def test_recommendation_never_returns_the_management_port():
    p = host(
        {"name": "eth0", "driver": "igb", "flags": "0x1103"},
        {"name": "eth1", "is_bridge_port": True, "driver": "igb"},
        default_route="eth0",
    )
    assert if_mod.recommend(p, "eth0") == "", (
        "with no valid candidate the answer is nothing, not the mgmt port -- a wrong "
        "recommendation that gets accepted is worse than none"
    )


def test_recommendation_excludes_a_second_interface_on_the_mgmt_path():
    """`is_default_route` marks only one NIC, but a host may have several on the same
    subnet. Preferring a NIC that is not the mgmt one is the point; the mgmt one is
    excluded explicitly."""
    p = host(
        {"name": "ens18", "driver": "virtio", "flags": "0x1103"},
        {"name": "ens19", "driver": "igb", "flags": "0x1103"},
        default_route="ens18",
    )
    assert if_mod.recommend(p, "ens18") == "ens19"
    assert if_mod.recommend(p, "ens19") == "ens18" or if_mod.recommend(p, "ens18") != "ens18"


# --- probe parsing ------------------------------------------------------------
def test_probe_parsing_reads_flags_and_roles():
    p = host(
        {"name": "eth0", "flags": "0x1003", "driver": "igb"},
        {"name": "eth1", "flags": "0x1103", "is_bridge_port": True},
        default_route="eth0",
    )
    assert p.mgmt is not None and p.mgmt.name == "eth0"
    eth0, eth1 = p.by_name("eth0"), p.by_name("eth1")
    assert eth0 is not None and eth1 is not None
    assert eth1.promiscuous is True
    assert eth0.promiscuous is False
    assert eth1.can_be_capture_port is False


def test_probe_rejects_non_json_output():
    with pytest.raises(ValueError):
        if_mod.parse_probe("not json at all")


def test_describe_labels_every_interface_with_a_role():
    p = host(
        {"name": "eth0", "driver": "igb"},
        {"name": "eth1", "driver": "igb", "flags": "0x1103"},
        {"name": "vmbr0", "is_bridge": True},
        {"name": "tailscale0", "has_device": False},
        default_route="eth0",
    )
    roles = dict((name, role) for name, role, _ in if_mod.describe(p))
    assert roles["eth0"] == "mgmt"
    assert roles["eth1"] == "CAPTURE?"
    assert roles["vmbr0"] == "bridge"
    assert roles["tailscale0"] == "virtual"


def test_probe_source_is_stdlib_only():
    """The probe runs inside arbitrary images. A previous bug in this project was an
    interface check that failed because `ip` was not installed, and reported it as a
    missing interface -- so the probe must not shell out to `ip`, `ethtool`, or `awk`.
    """
    src = if_mod._probe_source()
    for banned in ("ip link", "ethtool", "awk", "grep", "subprocess.run([\"ip\""):
        assert banned not in src, f"the probe must not depend on {banned!r}"
    assert "/sys/class/net" in src
    assert "/proc/net/route" in src


def test_probe_source_is_valid_python():
    """It is shipped as a string and executed with `python -c`, so a syntax error
    would only surface at runtime on someone else's host."""
    compile(if_mod._probe_source(), "<probe>", "exec")


def test_probe_runs_against_this_machine():
    """The probe must work on a real host, not just against synthetic input. Skips
    rather than fails if /sys/class/net is unavailable."""
    import pathlib

    if not pathlib.Path("/sys/class/net").is_dir():
        pytest.skip("/sys/class/net not available")
    p = if_mod.probe_local()
    assert not p.error, p.error
    assert p.interfaces, "the probe found no interfaces on a machine that has some"
    assert p.default_route_iface, "every real machine here has a default route"
    # Sanity: the loopback interface must be recognised as unusable.
    lo = p.by_name("lo")
    assert lo is not None and not lo.can_be_capture_port


# --- the hex-parsing trap ------------------------------------------------------
def test_flags_are_parsed_as_hex_not_decimal():
    """THE BUG: /sys/class/net/<if>/flags stores a HEX string ("1103"), and shell
    arithmetic reads bare digits as DECIMAL, so computing on the raw value gives 0
    instead of 256 and INVERTS the promiscuity test. The Python side must not repeat
    it by parsing without a base.

    These values are chosen because decimal interpretation flips every one:
        0x1003 (no promisc) -> decimal 1003 has the bit SET
        0x1103 (promisc)    -> decimal 1103 has the bit CLEAR
        0x1002 (no promisc) -> decimal 1002 has the bit SET
        0x3                 -> neither
    """
    cases = {"1003": False, "1103": True, "1002": False, "3": False}
    for raw, expected in cases.items():
        flags = if_mod._flags_int(raw)
        assert bool(flags & if_mod.IFF_PROMISC) is expected, (
            f"flags='{raw}' parsed as {flags}; expected promisc={expected}. "
            f"The value was probably read as decimal."
        )


def test_flags_parsing_tolerates_garbage():
    """One unreadable interface must not fail the whole probe, and a malformed value
    must not make arithmetic error out under `set -e` in the container."""
    for bad in ("", "   ", "0xZZ", "not-hex", None):
        assert if_mod._flags_int(bad) == 0


def test_promiscuity_distinguishes_the_two_real_values():
    """Regression for the specific inversion: 0x1003 and 0x1103 differ only in bit 8,
    and a low-nibble glob reports them identically."""
    p = host(
        {"name": "eth0", "flags": "1003"},
        {"name": "eth1", "flags": "1103"},
        default_route="eth0",
    )
    up, cap = p.by_name("eth0"), p.by_name("eth1")
    assert up is not None and cap is not None
    assert up.promiscuous is False, "0x1003 must not read as promiscuous"
    assert cap.promiscuous is True, "0x1103 must read as promiscuous"


def test_manifest_shell_checks_are_posix_and_hex_safe():
    """The Zeek startup snippet runs in the image's /bin/sh. It must not use process
    substitution (a bashism that dash rejects) and must not apply the decimal trap.

    Uses plain string checks rather than a regex with `&` so the intent stays obvious.
    """
    import pathlib

    manifest = (pathlib.Path(__file__).resolve().parent.parent
                / "k8s" / "32-zeek.yaml").read_text()
    # Check EXECUTABLE lines only. A comment explaining the bashism (and why it was
    # removed) legitimately contains the offending text; an earlier version of this
    # test fired on its own documentation.
    code_lines = [ln for ln in manifest.splitlines()
                  if ln.strip() and not ln.strip().startswith("#")]
    code = "\n".join(code_lines)
    assert "< <(" not in code, (
        "process substitution found in executable shell; dash in the zeek image "
        "rejects it (this is how an interface check previously reported a missing "
        "interface)"
    )
    # The promiscuous test must concatenate the hex prefix onto the value, because
    # shell arithmetic reads bare digits as decimal.
    assert "0x$iflags" in manifest, (
        "the flags arithmetic does not prefix the value with 0x; shell reads bare "
        "digits as decimal, so 0x1103 and 0x1003 both give the wrong answer"
    )
    assert "MGMT_IFACE" in manifest, "the manifest does not know about the mgmt port"
    assert "brport" in manifest, "the manifest does not check for bridge membership"


def test_env_example_documents_both_interfaces():
    """The two-port model is useless if the template still points both at eth0."""
    import pathlib

    env = (pathlib.Path(__file__).resolve().parent.parent / ".env.example").read_text()
    assert "MGMT_IFACE=" in env, "the template does not set MGMT_IFACE"
    assert "ZEEK_IFACE=" in env
    zeek_line = [ln for ln in env.splitlines() if ln.startswith("ZEEK_IFACE=")][0]
    mgmt_line = [ln for ln in env.splitlines() if ln.startswith("MGMT_IFACE=")][0]
    assert zeek_line != mgmt_line, (
        "the template points the capture and management ports at the same interface, "
        "which is the configuration that produces a broadcast-only capture"
    )
    # The old advice told operators to sniff the router interface. That is the trap.
    assert "run Zeek directly on the router/host interface" not in env, (
        "the template still recommends sniffing the management/router interface"
    )
