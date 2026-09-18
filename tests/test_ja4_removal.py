"""JA4+ must be ABSENT from the sensor image, not merely switched off.

WHY THIS FILE EXISTS, and why it runs the real script rather than reading it.

The failure being guarded against is shipping FoxIO-licensed code (JA4S/H/X/SSH/T/L/D,
FoxIO License 1.1 — internal/academic only, methods patent pending) inside a distributed
image. That failure is invisible at runtime: the sensor works, the logs fill, and nothing
anywhere indicates a licence is being breached. It surfaces later, from a lawyer.

It has already been wrong here once. The package gates its submodules with
`@if (JA4S_enabled) @load ./ja4s @endif`, and `@if` is evaluated **when the file is loaded**,
so disabling the options after loading was silently ignored — measured on a live sensor,
**28 of 28** ssl records carried a populated `ja4s` while the config claimed it was off. That
was fixed by load ordering, but it left licensed code in the image with only the sequence of
three lines standing between it and distribution.

So the mechanism is now deletion at build time, and these tests RUN `zeek/prune-ja4plus.sh`
against a fabricated package tree. A licensing guard that can only be exercised by a full
container build is a guard that will not be exercised; and a test that reads the script's
source instead of executing it cannot tell whether the awk filter actually removed the right
lines — which is the part most likely to be subtly wrong, since `JA4T_enabled` is a substring
of `JA4TS_enabled`.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "zeek" / "prune-ja4plus.sh"
CONTAINERFILE = ROOT / "zeek" / "Containerfile"
POLICY = ROOT / "k8s" / "zeek" / "weirvern-local.zeek"

FOXIO_MODULES = ["ja4s", "ja4h", "ja4ssh", "ja4x", "ja4l", "ja4t", "ja4d"]
FOXIO_OPTIONS = ["JA4S_enabled", "JA4S_raw", "JA4H_enabled", "JA4H_raw", "JA4L_enabled",
                 "JA4SSH_enabled", "JA4T_enabled", "JA4TS_enabled", "JA4X_enabled",
                 "JA4D_enabled"]

# The upstream config.zeek, reproduced EXACTLY as it appears on the live sensor (pulled from
# the running pod). Copied rather than paraphrased because the traps this filter has to
# survive -- the `JA4T`/`JA4TS` prefix overlap, and the `_raw` variants -- are properties of
# the real text, and a tidied-up version would not test them.
REAL_CONFIG = '''module FINGERPRINT;

export {
  option delimiter: string = "_";

  # BSD licensed
  option JA4_enabled:    bool = T;
  option JA4_raw:        bool = F;

  # FoxIO license required for JA4+
  option JA4S_enabled:   bool = T;
  option JA4S_raw:   bool = F;

  option JA4H_enabled:   bool = T;
  option JA4H_raw:   bool = F;

  option JA4L_enabled:   bool = T;

  option JA4SSH_enabled: bool = T;

  option JA4T_enabled:   bool = T;
  option JA4TS_enabled:  bool = T;

  option JA4X_enabled:   bool = F;

  option JA4D_enabled:  bool = T;
}
'''

REAL_LOADER = '''module FINGERPRINT;

export { type Info: record {}; }
redef record connection += { fp: FINGERPRINT::Info &optional; };

@load ./config

@if (JA4_enabled)
  @load ./ja4
@endif

@if (JA4S_enabled)
  @load ./ja4s
@endif

@if (JA4H_enabled)
  @load ./ja4h
@endif

@if (JA4SSH_enabled)
  @load ./ja4ssh
@endif

@if (JA4X_enabled)
  @load ./ja4x
@endif

@if (JA4L_enabled)
  @load ./ja4l
@endif

@if (JA4T_enabled)
  @load ./ja4t
@endif

@if (JA4D_enabled)
  @load ./ja4d
@endif
'''


def _fixture(tmp_path: Path) -> Path:
    """A package tree shaped like the real one."""
    d = tmp_path / "ja4-zeek-scripts"
    (d / "ja4").mkdir(parents=True)
    (d / "utils").mkdir()
    for m in FOXIO_MODULES:
        (d / m).mkdir()
        (d / m / "main.zeek").write_text(f"# {m}\n")
    (d / "tests" / "Traces" / "Scripts.ja4-ssh2").mkdir(parents=True)
    (d / "tests" / "Traces" / "Scripts.ja4-ssh2" / "ja4ssh.log").write_text(
        "# recorded JA4+ output\n")
    (d / "ja4" / "main.zeek").write_text("# ja4\n")
    (d / "utils" / "common.zeek").write_text("# common\n")
    (d / "config.zeek").write_text(REAL_CONFIG)
    (d / "__load__.zeek").write_text(REAL_LOADER)
    return d


def _run(dir_: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["sh", str(SCRIPT), str(dir_)],
                          capture_output=True, text=True, timeout=60)


# ── the removal itself ──────────────────────────────────────────────────────────

def test_the_script_is_present_and_executable_by_sh():
    assert SCRIPT.exists(), "the JA4+ prune script is missing"
    sh = subprocess.run(["sh", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert sh.returncode == 0, f"the prune script does not parse: {sh.stderr}"


def test_every_foxio_submodule_directory_is_deleted(tmp_path):
    d = _fixture(tmp_path)
    r = _run(d)
    assert r.returncode == 0, f"the prune failed: {r.stderr}"
    for m in FOXIO_MODULES:
        assert not (d / m).exists(), f"{m}/ survived the prune"


def test_the_packages_recorded_foxio_test_output_is_deleted(tmp_path):
    """The tests carry JA4+ FINGERPRINTS as recorded output, so leaving them would ship
    licensed material even with the code that produced it gone."""
    d = _fixture(tmp_path)
    _run(d)
    assert not (d / "tests").exists(), (
        "the package's tests/ directory survived, and it contains recorded JA4+ output"
    )


def test_the_bsd_module_and_its_dependencies_are_kept(tmp_path):
    d = _fixture(tmp_path)
    _run(d)
    assert (d / "ja4").is_dir(), "the BSD ja4 module was deleted"
    assert (d / "utils").is_dir(), "the shared utils/ the ja4 module needs was deleted"
    assert (d / "__load__.zeek").exists()


# ── the option filter, which is where a subtle mistake would hide ───────────────

def test_no_foxio_option_survives_in_config(tmp_path):
    d = _fixture(tmp_path)
    _run(d)
    text = (d / "config.zeek").read_text()
    for opt in FOXIO_OPTIONS:
        assert not re.search(rf"\b{opt}\b", text), f"the FoxIO option {opt} survived"


def test_the_bsd_options_survive_exactly_once(tmp_path):
    """An over-eager filter is its own failure: a sensor that parses cleanly and produces no
    fingerprint is silently useless, which is worse than a loud build failure."""
    d = _fixture(tmp_path)
    _run(d)
    text = (d / "config.zeek").read_text()
    for opt in ("JA4_enabled", "JA4_raw", "delimiter"):
        n = len(re.findall(rf"^\s*option\s+{opt}\s*:", text, re.M))
        assert n == 1, f"{opt} appears {n} time(s) as an option declaration, expected 1"


def test_the_ja4t_option_does_not_take_ja4ts_with_it(tmp_path):
    """THE SUBSTRING TRAP, as its own test.

    `JA4T_enabled` is a substring of `JA4TS_enabled`. Both are FoxIO and both must go, so a
    substring filter happens to look correct here -- but the same naive filter on the BSD
    side would match the wrong lines, and the fix is an exact `option <name>:` match rather
    than a substring one. This asserts the exact-match property directly: a BSD option whose
    name is a PREFIX of a FoxIO one must survive.
    """
    d = _fixture(tmp_path)
    # JA4_enabled is a prefix of JA4S_enabled etc. -- the BSD one must survive.
    _run(d)
    text = (d / "config.zeek").read_text()
    assert re.search(r"^\s*option\s+JA4_enabled\s*:", text, re.M), (
        "JA4_enabled was removed, most likely by a substring filter matching JA4S_enabled"
    )
    assert not re.search(r"^\s*option\s+JA4TS_enabled\s*:", text, re.M)


def test_the_loader_cannot_reference_a_foxio_module(tmp_path):
    """Rewritten rather than filtered, because the `@if` blocks would otherwise reference
    directories that no longer exist."""
    d = _fixture(tmp_path)
    _run(d)
    text = (d / "__load__.zeek").read_text()
    for m in FOXIO_MODULES:
        assert f"./{m}" not in text, f"the loader still @loads ./{m}"
    assert "@load ./ja4" in text, "the loader no longer loads the BSD ja4 module"
    assert "@load ./config" in text, "the loader no longer loads config"


def test_the_dangling_foxio_licence_label_is_removed(tmp_path):
    """A comment saying "FoxIO license required for JA4+" followed by nothing is worse than
    no comment: it reads as a licence notice for code that is not present, and invites
    someone to 'restore' it."""
    d = _fixture(tmp_path)
    _run(d)
    assert "FoxIO license required" not in (d / "config.zeek").read_text()


# ── the assertions must be able to FAIL ─────────────────────────────────────────

def test_the_script_refuses_a_tree_where_foxio_is_still_referenced(tmp_path):
    """A guard that cannot fail is decoration.

    NOTE WHICH CASE IS TESTED. Re-adding an option to `config.zeek` does NOT trip the
    assertion, because the filter removes it again on the next run -- which is correct
    idempotent behaviour, and a test asserting otherwise would be asserting a bug. The
    reachable case is a FoxIO reference in a file the script does not rewrite: a package
    update adding a new file, or an edit elsewhere in the tree. That is exactly the mistake
    the assertion exists to catch, since the prune only knows about the files it rewrites.
    """
    d = _fixture(tmp_path)
    _run(d)
    # A file the prune does not touch, still referencing licensed code.
    (d / "utils" / "leftover.zeek").write_text("@if (JA4S_enabled)\n  @load ../ja4s\n@endif\n")
    r = _run(d)
    assert r.returncode != 0, (
        "the script passed with a FoxIO reference still in the tree, so its assertions are "
        "not enforcing anything"
    )
    assert "ASSERT FAIL" in r.stderr


def test_the_script_refuses_a_tree_with_no_bsd_options(tmp_path):
    """The inverse failure: removing too much leaves a sensor that runs and fingerprints
    nothing."""
    d = _fixture(tmp_path)
    cfg = d / "config.zeek"
    cfg.write_text(cfg.read_text().replace("option JA4_enabled", "option XJA4_enabled"))
    r = _run(d)
    assert r.returncode != 0, "the script passed with JA4 itself removed"


def test_the_script_rejects_a_missing_directory():
    r = subprocess.run(["sh", str(SCRIPT), "/nonexistent/ja4-package"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode != 0
    assert "no such package directory" in r.stderr


# ── wiring: the image build must actually call it ───────────────────────────────

def test_the_image_build_runs_the_prune():
    text = CONTAINERFILE.read_text()
    assert "prune-ja4plus.sh" in text, "the Containerfile never prunes JA4+"
    assert "COPY prune-ja4plus.sh" in text, (
        "the script is not copied into the build context, so the RUN would fail"
    )
    # ORDER: the COPY must precede the RUN that executes it.
    assert text.index("COPY prune-ja4plus.sh") < text.index("RUN sh /tmp/prune-ja4plus.sh"), (
        "COPY comes after the RUN that uses it, so the build would fail with 'not found'"
    )
    # And the prune must come after the install, or there is nothing to prune.
    assert text.index("zkg install") < text.index("RUN sh /tmp/prune-ja4plus.sh")


def test_the_site_policy_no_longer_carries_a_disable_list():
    """The disable list is gone on purpose. Its absence IS the guarantee -- if it reappears,
    the licensed code is back in the image and someone is trying to switch it off again."""
    # Comments are stripped first: the policy deliberately QUOTES the removed
    # `redef FINGERPRINT::JA4S_enabled = F` line while explaining why it is gone, and a
    # naive substring search flags that explanation as the thing it warns about.
    text = "\n".join(ln.split("#")[0] for ln in POLICY.read_text().splitlines())
    for opt in FOXIO_OPTIONS:
        assert f"redef FINGERPRINT::{opt}" not in text, (
            f"the site policy redefines {opt}, which only makes sense if the licensed code "
            f"is present again"
        )
    assert "@load packages/ja4-zeek-scripts" in text, "the package is not loaded at all"


def test_the_policy_does_not_load_config_out_of_order_anymore():
    """The old policy loaded `packages/ja4-zeek-scripts/config` separately so it could
    disable options before the package loaded. With the option gone, that indirection is
    only a way to get the order wrong, so the package loads as a unit."""
    text = POLICY.read_text()
    assert "@load packages/ja4-zeek-scripts/config" not in text, (
        "the policy still loads the package config separately, an ordering requirement that "
        "no longer applies"
    )
