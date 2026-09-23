"""A whole-segment intercept must not forge mappings for the sensor's own lifelines.

── WHY THIS FILE EXISTS (audit F098, CONFIRMED BY RUNNING IT) ───────────────────────────────────

`never_intercept_hits` derives the roles a target must never hold -- the resolver the sensor uses,
its management address, the Kubernetes API server it reports to -- from `KUBERNETES_SERVICE_HOST`,
`MGMT_ADDR` and `/etc/resolv.conf`. It was consulted ONLY under `if only:`, the named-host path.

The whole-segment path skipped just `{our_ip, gateway_ip}`, so every other derivable role stayed in
the candidate list. Measured on a /24 that contains them:

    K8s API server (.55) in the intercept targets: YES
    sensor mgmt addr (.44) in the intercept targets: YES
    hosts in plan: 252

So the SAFER-LOOKING path -- a whole segment, no explicit names -- was the one that could poison
the mapping for the control plane the sensor reports to while it relays. Forging that mapping does
not degrade gracefully: the sensor loses its own path exactly when it is holding the segment's
traffic.

THE FIX DIFFERS FROM THE NAMED PATH, and the difference is deliberate. The named path REFUSES,
because an operator asked for a specific host and can be told no. A whole-segment build cannot
refuse on every segment that contains a nameserver or an API server, which is every real segment --
so those roles are EXCLUDED from the candidates and the exclusion is reported.

WHAT THESE TESTS PIN: that the roles are excluded from a whole-segment build, that they are never
even probed, that the named path still refuses, and that the exclusion does not silently shrink an
intercept without saying so.
"""

from __future__ import annotations

import pytest

from weirvern.admin import intercept as ic

# Reserved for documentation (RFC 5737), so nothing here can collide with a real network.
SEGMENT = "198.51.100.0/24"
API_SERVER = "198.51.100.55"
MGMT_ADDR = "198.51.100.44"
OUR_IP = "198.51.100.2"
GATEWAY = "198.51.100.1"


@pytest.fixture
def stubbed(monkeypatch):
    """Make `build_plan` work without a socket, and record who it probes.

    `arp_sweep` is replaced at the module level because `build_plan` calls it directly rather than
    taking it as a parameter -- so this is the real control flow, with only the network removed.
    """
    probed: list[str] = []

    def _sweep(iface, our_mac, our_ip, candidates, **kw):
        cands = [str(c) for c in candidates]
        probed.extend(cands)
        return {c: "aa:bb:cc:dd:ee:00" for c in cands}  # everyone answers

    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", API_SERVER)
    monkeypatch.setenv("MGMT_ADDR", MGMT_ADDR)
    monkeypatch.setattr(ic, "read_mac", lambda iface: "11:22:33:44:55:66")
    monkeypatch.setattr(ic, "arp_sweep", _sweep)
    monkeypatch.setattr(ic, "resolve_mac", lambda iface, ip: "99:99:99:99:99:99")
    return probed


# ── the whole-segment path ──────────────────────────────────────────────────────────────────

def test_a_whole_segment_intercept_EXCLUDES_the_api_server(stubbed):
    """THE DEFECT. The sensor reporting to a cluster it can no longer reach, while relaying."""
    plan = ic.build_plan("ens19", SEGMENT, our_ip=OUR_IP, gateway_ip=GATEWAY)
    assert plan is not None, "the plan could not be built, so this test proves nothing"
    assert API_SERVER not in plan.hosts, (
        f"a whole-segment intercept would forge the mapping for the Kubernetes API server "
        f"({API_SERVER}) that this sensor reports to"
    )


def test_a_whole_segment_intercept_EXCLUDES_the_management_address(stubbed):
    plan = ic.build_plan("ens19", SEGMENT, our_ip=OUR_IP, gateway_ip=GATEWAY)
    assert plan is not None
    assert MGMT_ADDR not in plan.hosts, (
        f"a whole-segment intercept would forge the mapping for the sensor's own management "
        f"address ({MGMT_ADDR})"
    )


def test_the_excluded_roles_are_never_even_PROBED(stubbed):
    """Excluding them from the plan is not enough: an ARP sweep at the API server is already
    traffic the sensor should not be generating toward its own control plane. The exclusion has to
    happen before the candidate list is built."""
    ic.build_plan("ens19", SEGMENT, our_ip=OUR_IP, gateway_ip=GATEWAY)
    assert API_SERVER not in stubbed, (
        f"the API server was swept as a candidate before being filtered: {sorted(stubbed)[:8]}"
    )
    assert MGMT_ADDR not in stubbed, "the management address was swept as a candidate"


def test_the_rest_of_the_segment_is_still_intercepted(stubbed):
    """The fix must not degrade the feature into doing nothing -- an intercept that excludes
    everything is not a safer intercept, it is a broken one."""
    plan = ic.build_plan("ens19", SEGMENT, our_ip=OUR_IP, gateway_ip=GATEWAY)
    assert plan is not None
    # A /24 minus the two roles, ourselves and the gateway: still a large intercept.
    assert len(plan.hosts) > 200, (
        f"only {len(plan.hosts)} host(s) planned, so the exclusion removed far more than the "
        f"never-intercept roles"
    )
    assert "198.51.100.99" in plan.hosts, "an ordinary host on the segment was excluded"


def test_our_own_address_and_the_gateway_stay_excluded(stubbed):
    """The pre-existing exclusions, so the new one did not replace them."""
    plan = ic.build_plan("ens19", SEGMENT, our_ip=OUR_IP, gateway_ip=GATEWAY)
    assert plan is not None
    assert OUR_IP not in plan.hosts
    assert GATEWAY not in plan.hosts, (
        "the gateway is the address being CLAIMED, never a target -- intercepting it would forge "
        "the gateway's view of its own peers"
    )


def test_a_segment_with_NO_roles_in_it_is_unaffected(stubbed, monkeypatch):
    """The common case for a lab segment: nothing derivable lives there, so the intercept must be
    exactly what it was before."""
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    monkeypatch.delenv("MGMT_ADDR", raising=False)
    plan = ic.build_plan("ens19", SEGMENT, our_ip=OUR_IP, gateway_ip=GATEWAY)
    assert plan is not None
    assert "198.51.100.99" in plan.hosts and len(plan.hosts) > 200


# ── the named path must keep REFUSING ───────────────────────────────────────────────────────

def test_the_NAMED_path_still_REFUSES_rather_than_excluding(stubbed):
    """The two paths differ on purpose. An operator who names a host can be told no; silently
    intercepting a different set than they asked for would look like success.

    `build_plan` LOGS the refusal and returns None rather than raising, which is easy to
    misread -- an earlier probe of mine reported this as "returned" because it caught exceptions
    and the function returns None instead.
    """
    plan = ic.build_plan("ens19", SEGMENT, our_ip=OUR_IP, gateway_ip=GATEWAY,
                         only={API_SERVER})
    assert plan is None, (
        "naming the API server produced a plan instead of a refusal, so an operator could "
        "intercept the control plane their sensor reports to"
    )


def test_force_unsafe_still_overrides_the_named_refusal(stubbed):
    """The documented escape hatch for a host that is genuinely the object of investigation must
    survive this change, or a legitimate use case becomes impossible."""
    plan = ic.build_plan("ens19", SEGMENT, our_ip=OUR_IP, gateway_ip=GATEWAY,
                         only={API_SERVER}, force_unsafe=True)
    assert plan is not None, "force_unsafe no longer overrides a non-structural never-intercept role"
    assert API_SERVER in plan.hosts


def test_force_unsafe_cannot_override_a_STRUCTURAL_role(stubbed):
    """Our own address and the gateway remain impossible regardless: forging those cannot relay
    anything at all, so there is no intent for which they would be correct."""
    plan = ic.build_plan("ens19", SEGMENT, our_ip=OUR_IP, gateway_ip=GATEWAY,
                         only={OUR_IP}, force_unsafe=True)
    assert plan is None, (
        "force_unsafe allowed intercepting the sensor's own address, which cannot relay anything"
    )
