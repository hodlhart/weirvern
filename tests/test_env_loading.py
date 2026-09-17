"""`.env` must actually reach the settings it claims to configure.

THE BUG: `weirvern install` generates `.env` from `.env.example`, and `config` /
`tune` read and write it — but nothing loaded it into `os.environ`, and every
Settings field reads os.environ at construction. So `.env` had NO effect on any
runtime setting. Changing CLICKHOUSE_USER or PUSHOVER_ENABLED appeared to work and
silently did nothing.

It surfaced on a live box: `.env` said CLICKHOUSE_USER=default while the cluster
had been reconfigured to a named user, so `weirvern status` reported an
authentication failure that editing `.env` could not fix — the most confusing
possible shape, because the operator's obvious remedy was inert.
"""
from __future__ import annotations

import os

import pytest

from weirvern.config import _load_env_file


@pytest.fixture
def env_dir(tmp_path, monkeypatch):
    """Run in a temp dir with the relevant variables cleared."""
    for key in ("CLICKHOUSE_USER", "PUSHOVER_ENABLED", "QUOTED", "EXPORTED",
                "HASHED", "WEIRVERN_ENV_FILE", "WEIRVERN_HOME"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _write(env_dir, text):
    (env_dir / ".env").write_text(text)


def test_env_file_values_reach_the_environment(env_dir):
    _write(env_dir, "CLICKHOUSE_USER=weirvern\n")
    _load_env_file()
    assert os.environ["CLICKHOUSE_USER"] == "weirvern"


def test_env_file_reaches_settings(env_dir):
    """The end-to-end claim: .env, then a real Settings object."""
    from weirvern.config import Settings

    _write(env_dir, "CLICKHOUSE_USER=weirvern\nCLICKHOUSE_DB=weirvern\n")
    _load_env_file()
    assert Settings().clickhouse_user == "weirvern"


def test_real_environment_wins_over_the_env_file(env_dir, monkeypatch):
    """CRITICAL for Kubernetes: the ConfigMap and Secret are injected as real
    environment variables and must never be shadowed by a stale .env copied into
    an image."""
    monkeypatch.setenv("CLICKHOUSE_USER", "from-real-env")
    _write(env_dir, "CLICKHOUSE_USER=weirvern\n")
    _load_env_file()
    assert os.environ["CLICKHOUSE_USER"] == "from-real-env"


def test_inline_comment_is_stripped(env_dir):
    """`.env.example` ships `PUSHOVER_ENABLED=0   # 1 = real pushes`. Without
    stripping, the value becomes "0   # 1 = real pushes" and every truthiness
    check on it is wrong."""
    _write(env_dir, "PUSHOVER_ENABLED=0             # 1 = real pushes\n")
    _load_env_file()
    assert os.environ["PUSHOVER_ENABLED"] == "0"


def test_quoted_values_are_unquoted(env_dir):
    _write(env_dir, 'QUOTED="a b"\n')
    _load_env_file()
    assert os.environ["QUOTED"] == "a b"


def test_hash_inside_a_value_is_preserved(env_dir):
    """Only ` #` (space-hash) starts a comment. A password containing # must
    survive, or generated credentials break in a way that looks like a wrong
    password."""
    _write(env_dir, "HASHED=ab#cd\n")
    _load_env_file()
    assert os.environ["HASHED"] == "ab#cd"


def test_export_prefix_is_accepted(env_dir):
    _write(env_dir, "export EXPORTED=yes\n")
    _load_env_file()
    assert os.environ["EXPORTED"] == "yes"


def test_comments_and_blank_lines_are_ignored(env_dir):
    _write(env_dir, "# a comment\n\n   \nCLICKHOUSE_USER=weirvern\n")
    _load_env_file()
    assert os.environ["CLICKHOUSE_USER"] == "weirvern"


def test_a_missing_env_file_is_not_an_error(env_dir):
    """The worker runs in a container where .env does not exist and all values
    come from the environment. It must not raise."""
    assert not (env_dir / ".env").exists()
    _load_env_file()  # must not raise


def test_weirvern_env_file_overrides_the_search(env_dir, monkeypatch, tmp_path):
    """An explicit path is honoured, which is how a deployment points the tooling
    at a config outside the working directory."""
    other = tmp_path / "elsewhere"
    other.mkdir()
    (other / ".env").write_text("CLICKHOUSE_USER=explicit-path-user\n")
    _write(env_dir, "CLICKHOUSE_USER=from-cwd\n")
    monkeypatch.setenv("WEIRVERN_ENV_FILE", str(other / ".env"))
    _load_env_file()
    assert os.environ["CLICKHOUSE_USER"] == "explicit-path-user"


def test_every_env_example_key_is_parseable():
    """The shipped template must parse cleanly. It is the file every deployment
    starts from, so a key it cannot express is a key no deployment can set."""
    from pathlib import Path

    example = Path(__file__).resolve().parent.parent / ".env.example"
    if not example.exists():
        pytest.skip(".env.example not present")
    text = example.read_text()
    keys = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            # A commented-out KEY=value is still worth parsing, because the
            # install flow uncomments some of them.
            s = s.lstrip("#").strip()
        if not s or "=" not in s:
            continue
        key = s.split("=", 1)[0].strip()
        if key and key.replace("_", "").isalnum():
            keys.append(key)
    assert "CLICKHOUSE_USER" in keys, ".env.example must expose CLICKHOUSE_USER"
    assert len(keys) >= 15, f"only parsed {len(keys)} keys from .env.example: {keys}"
