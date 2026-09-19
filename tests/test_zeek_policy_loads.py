"""The Zeek site policy must LOAD, not merely look right.

WHY THIS FILE EXISTS. The sensor was in CrashLoopBackOff on the live node with:

    error in /zeek/site/weirvern-local.zeek, line 148: unknown identifier FILE_WRITE

...from a line that a reader -- and my own earlier review -- would call correct. `FILE_WRITE` IS a
member of `SMB::Action`, so the identifier exists. It is simply not IN SCOPE at that point.

THE MECHANISM, measured by reproducing the pod's exact invocation inside the zeek image:

    exec zeek -i "$IFACE" -C /zeek/site/weirvern-local.zeek Log::default_logdir=...

A script passed as a BARE PATH is parsed before Zeek's default closure is loaded, so `SMB`'s
identifiers do not exist yet. `SMB::FILE_WRITE` resolves against the module and parses; the bare name
does not. The neighbouring kerberos redefs survive the same context because they compare STRING
literals against a `set[string]` rather than naming enum members.

WHY A STATIC CHECK WOULD NOT DO. Every plausible grep passes: the identifier is spelled correctly, the
set name is right, the file has the `@load` lines it needs nearby. Only the loader knows. So this test
invokes the real `zeek` binary with the real invocation, and reports SKIP (never a silent pass) when
no zeek is available -- an unrun check must not read as a green one.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SITE_POLICY = ROOT / "k8s" / "zeek" / "weirvern-local.zeek"


def _zeek_available() -> bool:
    return shutil.which("zeek") is not None


def _run_zeek(policy: Path, *, bare_path: bool = True) -> subprocess.CompletedProcess:
    """Run zeek the way the DaemonSet does.

    `bare_path=True` is the deployed form and the one that broke. `-c` forces the default closure to
    be loaded FIRST, which masks the bug -- which is exactly why the earlier check passed while the
    pod crash-looped.
    """
    args = ["zeek", "-C"]
    if not bare_path:
        args.append("-c")
    args += [
        str(policy),
        "Log::default_rotation_interval=1hr",
        f"Log::default_logdir={policy.parent}",
    ]
    return subprocess.run(args, cwd=policy.parent, capture_output=True, text=True, timeout=120)


@pytest.mark.skipif(not _zeek_available(), reason="zeek is not installed in this environment")
def test_the_site_policy_loads_the_way_the_daemonset_loads_it():
    """The exact deployed invocation must parse. This is the test that would have caught the crash."""
    result = _run_zeek(SITE_POLICY, bare_path=True)
    assert result.returncode == 0, (
        "the site policy does not load under the DaemonSet's own invocation. The sensor will "
        "CrashLoopBackOff and the passive half of the product will be dead, silently:\n"
        + (result.stderr or result.stdout).strip()
    )


@pytest.mark.skipif(not _zeek_available(), reason="zeek is not installed in this environment")
def test_the_redefs_actually_take_effect():
    """Parsing is not applying: assert the values really are in the effective sets.

    A redef that parses but does not apply is the 'configured, never observed' failure this project
    has hit repeatedly -- a column that exists and is always zero.
    """
    probe = SITE_POLICY.parent / "_effective_check.zeek"
    probe.write_text(
        '@load base/protocols/smb\n'
        f'@load {SITE_POLICY}\n'
        'event zeek_init() {\n'
        '    print "SMB_SET", SMB::logged_file_actions;\n'
        '    print "KRB_SET", KRB::ignored_errors;\n'
        '}\n'
    )
    try:
        result = subprocess.run(
            ["zeek", "-C", str(probe), f"Log::default_logdir={probe.parent}"],
            cwd=probe.parent, capture_output=True, text=True, timeout=120,
        )
        out = result.stdout + result.stderr
        assert result.returncode == 0, f"the effective-set probe failed:\n{out.strip()}"
        assert "FILE_WRITE" in out, (
            "SMB::logged_file_actions does not contain FILE_WRITE, so every write-volume feature "
            f"is structurally always zero:\n{out.strip()}"
        )
        # The kerberos redefs REMOVE values; NEEDED_PREAUTH must be gone from the ignored set,
        # otherwise AS-REP roasting stays undetectable.
        assert "NEEDED_PREAUTH" not in out.split("KRB_SET", 1)[-1], (
            "KRB::ignored_errors still suppresses NEEDED_PREAUTH, so AS-REP roasting cannot be "
            f"detected:\n{out.strip()}"
        )
    finally:
        probe.unlink(missing_ok=True)


def test_no_bare_enum_members_are_referenced_from_another_module():
    """Guard the specific mistake, for identifiers this test cannot exercise with a real loader.

    The rule is narrow on purpose: an enum member belonging to another module must be namespaced,
    because a bare-path script is parsed before that module's scope exists. Only `SMB::` is checked
    as a live mechanism here; the general shape is asserted so a future `DCE_RPC::`-style addition is
    caught even when zeek is unavailable to run.
    """
    import re

    text = SITE_POLICY.read_text()
    # `redef SMB::x += { ... }` bodies are the risk surface.
    for match in re.finditer(r"redef\s+SMB::\w+\s*[-+]=\s*\{([^}]*)\}", text):
        body = match.group(1)
        # Strip the qualified forms FIRST: `SMB::FILE_WRITE` contains the token `SMB`, so a naive
        # scan flags the fix itself as the fault. (It did, on the first run of this test.)
        stripped = re.sub(r"\b[A-Za-z_]\w*::\w+", "", body)
        for token in re.findall(r"\b[A-Z][A-Z0-9_]*\b", stripped):
            raise AssertionError(
                f"`{token}` is an enum member of another module used unqualified inside a redef. "
                "A bare-path script is parsed before that module is in scope, so this fails to "
                f"load at run time even though it reads correctly here. Use `SMB::{token}`."
            )
