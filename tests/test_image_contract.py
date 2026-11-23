"""What the IMAGE must contain for the features that ship in it to be able to work.

THE DEFECT CLASS. A feature can be fully implemented, fully tested, correctly wired into the
ConfigMap, correct in the GUI -- and still be INERT in every real deployment, because the thing it
shells out to is not in the image. Nothing fails: no build error, no probe failure, no test
failure. The feature reports DEGRADED with an honest reason and blocks nothing, forever.

That is not hypothetical. It is what the Sluice Gate did on its first deployment:

    $ command -v nft        ->  not found
    sluice gate: degraded -- ... the 'none' backend cannot install rules on this host
    (nft missing, or no NET_ADMIN).

The gate's own message was right, and the honest DEGRADED state is the CORRECT behaviour -- it
refuses to claim ARMED while enforcing nothing, which is this project's most-repeated failure. But
the result was a feature that a threat-hunt team could read about, find a tab for, and click a
block button in, on a system that could never enforce a single rule.

WHY THIS IS A TEST AND NOT A COMMENT. These lines are one word wide. Deleting `nftables` from the
apt line breaks no build, no probe, no lint, and no other test -- the image builds, the pod
starts, the gate reports DEGRADED as designed. The only signal is a log line nobody reads on a
clean deployment. A comment cannot fail; this can.

WHAT IS DELIBERATELY NOT ASSERTED: package versions, image base, layer order, or the presence of
anything the running code does not invoke. A test that pins more than the contract becomes a
maintenance cost that gets deleted, which would take the useful assertion with it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CONTAINERFILE = ROOT / "Containerfile"


@pytest.fixture(scope="module")
def containerfile_text() -> str:
    assert CONTAINERFILE.exists(), "Containerfile is missing from the repository root"
    return CONTAINERFILE.read_text()


def test_nftables_is_installed_because_the_sluice_gate_shells_out_to_it(containerfile_text: str) -> None:
    """The Sluice Gate compiles blocks into nftables sets.

    `choose_backend("nft")` returns a backend whose `available()` is False when the binary is
    absent, so the gate reports DEGRADED rather than claiming ARMED. Removing the package therefore
    produces no error anywhere -- only a gate that can never enforce. That is the silent-inert
    failure this test exists to prevent.
    """
    assert "nftables" in containerfile_text, (
        "the Containerfile no longer installs nftables; the Sluice Gate shells out to `nft` and "
        "will report DEGRADED and block nothing on every deployment"
    )

    # The assertion above would also pass on a comment MENTIONING nftables, including one
    # explaining why it was removed. Pin the install itself: an apt-get line that names it.
    install_lines = [
        line for line in containerfile_text.splitlines()
        if "apt-get install" in line and "nftables" in line
    ]
    assert install_lines, (
        "nftables appears in the Containerfile but not on an apt-get install line -- a comment is "
        "not a package"
    )


def test_softflowd_is_installed_because_the_tap_shells_out_to_it(
        containerfile_text: str) -> None:
    """`weirvern.tap` runs softflowd on the captured port, exporting to the deployment's own
    collector.

    Without the binary the operator's selection is silently inert: the tap warns once on a
    five-minute cooldown and collects nothing. That is the exact silent-inert class the
    nftables clause above exists for, so it gets the same treatment.
    """
    for pkg in ("softflowd", "tcpdump"):
        assert pkg in containerfile_text, (
            f"the Containerfile no longer installs {pkg}; the flow tap shells out to "
            f"it and the selection would collect nothing on every deployment"
        )
        install_lines = [
            line for line in containerfile_text.splitlines()
            if "apt-get install" in line and pkg in line
        ]
        assert install_lines, (
            f"{pkg} appears in the Containerfile but not on an apt-get install line -- a "
            f"comment is not a package"
        )


def test_the_tap_actually_shells_out_to_softflowd() -> None:
    """Same coupling note as the nftables pair: if the tap ever stops shelling out to
    softflowd, the image contract above becomes a stale requirement that blocks nothing."""
    source_text = (ROOT / "weirvern" / "tap.py").read_text()
    assert "softflowd" in source_text, "the tap no longer references softflowd at all"
    assert "tcpdump" in source_text, "the tap no longer references tcpdump at all"
    assert "TAP_COLLECTOR" in source_text


def test_the_sluice_backend_actually_shells_out_to_nft() -> None:
    """The test above is only meaningful while this is true.

    If the gate ever switches to a pure-Python or iptables backend, the image contract changes and
    the assertion above becomes a stale requirement that would block an unrelated refactor. This
    test makes that coupling EXPLICIT: break the link, and this fails first and says why.
    """
    from weirvern.sluice import NftBackend

    source_text = (ROOT / "weirvern" / "sluice.py").read_text()
    assert "nft" in source_text, "the sluice module no longer references nft at all"
    assert NftBackend().name == "nft"


# ── the SCAN image: the agent container's own filesystem is what it measures ─────────────────

SCANNER_CONTAINERFILE = ROOT / "Containerfile.scanner"
DEPLOY_WEIRLING = ROOT / "scripts" / "deploy-weirling.sh"


def test_the_scan_image_ships_nmap_and_the_capabilities_to_use_it():
    """A weirling measures the filesystem IT runs in.

    Installing nmap on the HOST cannot make a containerised agent capable: the container has
    its own rootfs. An agent image without nmap reports `nmap missing` forever, and the Install
    action cannot succeed either -- a container cannot install into its own image. This test
    pins both halves that make the container path work:

      * the binary (silent `nmap missing` otherwise), and
      * file capabilities on it (`getcap`/`setcap` come from libcap2-bin), which is how a
        non-root agent converts the container's NET_RAW/NET_ADMIN into an EFFECTIVE capability.
        Without them the unit is silently limited to TCP connect scans.
    """
    text = SCANNER_CONTAINERFILE.read_text()
    install_lines = [line for line in text.splitlines() if "apt-get install" in line]
    assert install_lines, "Containerfile.scanner has no apt-get install line"
    for pkg in ("nmap", "libcap2-bin"):
        assert any(pkg in line for line in install_lines), (
            f"Containerfile.scanner no longer installs {pkg} on its apt-get line; a comment is "
            f"not a package"
        )
    assert "setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap" in text, (
        "the scan image no longer grants nmap its file capabilities; a non-root agent gets no "
        "effective NET_RAW/NET_ADMIN and is silently connect-only"
    )
    assert "USER weirvern" in text, (
        "the scan image is expected to run as its non-root user by default; if this changes, "
        "the setcap rationale must be revisited rather than silently dropped"
    )


def test_the_weirling_installer_runs_the_agent_with_raw_socket_caps():
    """The other half: file capabilities outside the container's bounding set are ignored.

    The agent container must be granted NET_RAW and NET_ADMIN, and must NOT set
    no-new-privileges (that flag makes the kernel ignore the file capabilities too).
    """
    text = DEPLOY_WEIRLING.read_text()
    # Slice the AGENT's own block: from the docker run that precedes the sensor_agent entrypoint
    # to that entrypoint. A fixed-size window would bleed into the neighbouring netflow block.
    end = text.index("weirvern.admin.sensor_agent")
    start = text.rfind("docker run -d --name", 0, end)
    assert start != -1, "the agent container's docker run line is no longer recognisable"
    segment = text[start:end]
    assert "--cap-add NET_RAW" in segment and "--cap-add NET_ADMIN" in segment, (
        "deploy-weirling.sh no longer grants the agent container NET_RAW/NET_ADMIN; nmap -sS/-sU "
        "cannot open a raw socket"
    )
    assert "--security-opt no-new-privileges" not in segment, (
        "no-new-privileges on the agent container disables the image's file capabilities on nmap; "
        "it must stay off for the scan path"
    )
    assert "weirvern-scan:$WORKER_TAG" in text, (
        "deploy-weirling.sh no longer resolves the nmap-capable scan image for the agent"
    )


def test_both_agent_images_ship_the_inline_bridge_helper():
    """A channel plan with no helper in the image can only report a refusal forever.

    `sensor_agent.ChannelBridge` invokes `scripts/weirling-inline.sh` to create/tear down a
    channel bridge. Both images that can run the agent (the worker image, and the scan image that
    `deploy-weirling.sh` prefers) must carry it at the path the agent uses. The coupling is
    asserted in both directions: the copies and the Python path.
    """
    for name in ("Containerfile", "Containerfile.scanner"):
        text = (ROOT / name).read_text()
        assert "COPY scripts/weirling-inline.sh /app/scripts/weirling-inline.sh" in text, (
            f"{name} does not ship the inline bridge helper the agent invokes")
        assert "chmod 0755 /app/scripts/weirling-inline.sh" in text, (
            f"{name} copies the helper without making it executable")
    source = (ROOT / "weirvern" / "admin" / "sensor_agent.py").read_text()
    assert "weirling-inline.sh" in source, (
        "the agent no longer references the inline helper; the image copies have become stale")
