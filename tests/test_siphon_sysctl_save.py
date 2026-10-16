"""Issue #12: the siphon sysctl save records the node's originals ONCE.

The shipping init container wrote its save file UNCONDITIONALLY, so a second run -- any pod
restart, any node rejoin -- recorded the values the overlay had already changed as the "before"
state. The documented restore then restored the modified values: a silent no-op on the host that
was supposed to be handed back exactly as found, defeating the file's own promise that the
originals "outlive the deployment being undone".

These tests EXTRACT the shipping shell block from the overlay (parsed, not copied -- a copy would
keep passing after the ship file changed) and drive it twice against a stubbed /proc/sys root,
the pattern the installer harness uses for shipping shell.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "overlays" / "siphon" / "zeek-siphon-sysctl-init.yaml"

_SYSCTLS = {
    "net/ipv4/ip_forward": "0",
    "net/ipv4/conf/all/rp_filter": "1",
    "net/ipv4/conf/all/send_redirects": "1",
    "net/ipv4/conf/default/rp_filter": "1",
    "net/ipv4/conf/default/send_redirects": "0",
    "net/ipv4/conf/eth1/rp_filter": "1",
    "net/ipv4/conf/eth1/send_redirects": "0",
}


def _init_script() -> str:
    docs = [d for d in yaml.safe_load_all(OVERLAY.read_text()) if d]
    for d in docs:
        spec = ((d.get("spec") or {}).get("template") or {}).get("spec") or {}
        for c in spec.get("initContainers") or []:
            if c.get("name") == "siphon-sysctls":
                cmd = c.get("command") or []
                assert len(cmd) >= 3 and cmd[0] == "sh" and cmd[1] == "-c", (
                    f"unexpected command shape: {cmd[:2]!r}")
                return cmd[2]
    raise AssertionError("the siphon-sysctls init container is gone from the overlay")


def _stub(tmp_path: Path) -> tuple[str, Path, Path]:
    """The shipped script, aimed at a stubbed /proc/sys root and temp flows dir."""
    root = tmp_path / "proc-sys"
    flows = tmp_path / "flows"
    flows.mkdir(parents=True)
    for rel, val in _SYSCTLS.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(val)
    run = (_init_script()
           .replace("/proc/sys/", f"{root}/")
           .replace("/var/lib/weirvern/flows/", f"{flows}/"))
    assert f"{root}/" in run and f"{flows}/" in run, "the stub substitution did not take"
    return run, root, flows


def _sh(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=60,
                          env={"CAPTURE_IFACE": "eth1", "PATH": "/usr/bin:/bin"})


def test_the_second_run_keeps_the_first_run_originals(tmp_path):
    run, root, flows = _stub(tmp_path)
    save = flows / "siphon-sysctls.saved"

    first = _sh(run)
    assert first.returncode == 0, first.stderr
    before = save.read_text()
    assert "ip_forward=0" in before and "capture_rp_filter=1" in before, before

    # the overlay has since changed the node: the stub values now look post-change
    (root / "net/ipv4/ip_forward").write_text("1")
    (root / "net/ipv4/conf/eth1/rp_filter").write_text("0")

    second = _sh(run)
    assert second.returncode == 0, second.stderr
    assert save.read_text() == before, (
        "the second run overwrote the true originals with the already-changed values")
    assert "keeping them" in (second.stdout + second.stderr), (
        "the second run must SAY the originals were kept, not silently skip")


def test_restore_after_a_second_run_returns_the_TRUE_originals(tmp_path):
    run, root, flows = _stub(tmp_path)
    _sh(run)                                     # first run records 0/1
    (root / "net/ipv4/ip_forward").write_text("1")
    (root / "net/ipv4/conf/eth1/rp_filter").write_text("0")
    _sh(run)                                     # second run must not re-record 1/0

    restore = (flows / "siphon-sysctls.restore.sh").read_text()
    rrun = (restore.replace("/proc/sys/", f"{root}/")
            .replace("/var/lib/weirvern/flows/", f"{flows}/"))
    out = _sh(rrun)
    assert out.returncode == 0, out.stderr
    # echo > file lands a trailing newline; the VALUE is what must be the original.
    assert (root / "net/ipv4/ip_forward").read_text().strip() == "0", (
        "restore wrote the MODIFIED value back: the second run clobbered the save")
    assert (root / "net/ipv4/conf/eth1/rp_filter").read_text().strip() == "1"


def test_a_missing_save_still_refuses_to_guess(tmp_path):
    run, root, flows = _stub(tmp_path)
    _sh(run)
    (flows / "siphon-sysctls.saved").unlink()
    restore = (flows / "siphon-sysctls.restore.sh").read_text()
    rrun = (restore.replace("/proc/sys/", f"{root}/")
            .replace("/var/lib/weirvern/flows/", f"{flows}/"))
    out = _sh(rrun)
    assert out.returncode != 0, "restore ran without originals -- it must refuse to guess"
    assert "refusing to guess" in (out.stdout + out.stderr)
