"""Config-layer tests: .env parsing, comment stripping, secret masking, and
comment-preserving round-trips.

The parity tests matter because the SAME `.env.example` template is read by
three consumers: `weirvern.config.Settings` (the worker), the admin CLI, and
the schema/bootstrap path. If they disagree about what a value means, the system behaves
differently depending on which component you ask — verified failure:
DETECT_INTERVAL_S ships with a trailing comment in .env.example and the worker
raised on int() rather than stripping it.
"""
import pytest

from weirvern.admin.config_io import EnvFile, is_secret, mask
from weirvern.config import Settings, _clean_env


# --- inline comment handling -------------------------------------------------
def test_clean_env_strips_inline_comment():
    assert _clean_env("300          # sweep cadence (seconds)") == "300"
    assert _clean_env("0.35  # floor") == "0.35"
    assert _clean_env("clickhouse") == "clickhouse"
    assert _clean_env("") == ""
    assert _clean_env(None) is None


def test_clean_env_preserves_hash_inside_quotes():
    # A '#' inside quotes is part of the value, not a comment.
    assert _clean_env('"pass#word"') == "pass#word"
    assert _clean_env("'a#b'") == "a#b"


def test_clean_env_tab_before_comment():
    assert _clean_env("value\t# note") == "value"


def test_settings_parses_values_with_comments(monkeypatch):
    """The shipped .env.example has trailing comments; Settings must accept it."""
    monkeypatch.setenv("DETECT_INTERVAL_S", "300          # sweep cadence (seconds)")
    monkeypatch.setenv("BASE_THRESHOLD", "0.35   # ensemble score floor")
    monkeypatch.setenv("RETRAIN_EVERY_H", "6   # full retrain cadence")
    monkeypatch.setenv("PUSHOVER_ENABLED", "0   # log only")
    s = Settings()
    s.validate()
    assert s.detect_interval_s == 300
    assert s.base_threshold == 0.35
    assert s.retrain_every_h == 6
    assert s.pushover_enabled is False


def test_settings_rejects_genuinely_bad_ints(monkeypatch):
    monkeypatch.setenv("DETECT_INTERVAL_S", "not-a-number")
    with pytest.raises(ValueError, match="must be an integer"):
        Settings()


# --- EnvFile round-trip ------------------------------------------------------
def _write(tmp_path, text):
    p = tmp_path / ".env"
    p.write_text(text)
    return p


def test_roundtrip_preserves_comments_and_order(tmp_path):
    original = "# header comment\nA=1\n\n# section\nB=2\n"
    p = _write(tmp_path, original)
    env = EnvFile.load(p)
    env.save()
    assert p.read_text() == original, "save() must be a no-op when nothing changed"


def test_set_updates_in_place_keeping_comments(tmp_path):
    p = _write(tmp_path, "# keep me\nA=1\n# and me\nB=2\n")
    env = EnvFile.load(p)
    env.set("A", "99")
    text = env.render()
    assert "# keep me" in text and "# and me" in text
    assert "A=99" in text and "A=1" not in text
    assert text.index("A=99") < text.index("B=2"), "position preserved"


def test_set_does_not_create_duplicates(tmp_path):
    """A duplicated key is ambiguous (last wins in most parsers), so setting a
    key that already appears twice must collapse to a single entry."""
    p = _write(tmp_path, "A=1\nA=2\nB=3\n")
    env = EnvFile.load(p)
    assert env.duplicates() == ["A"]
    env.set("A", "7")
    assert env.duplicates() == []
    assert env.get("A") == "7"
    assert env.keys().count("A") == 1


def test_set_appends_when_absent(tmp_path):
    p = _write(tmp_path, "A=1\n")
    env = EnvFile.load(p)
    env.set("NEW_KEY", "x")
    assert env.get("NEW_KEY") == "x"


def test_unset_removes_key(tmp_path):
    p = _write(tmp_path, "A=1\nB=2\n")
    env = EnvFile.load(p)
    assert env.unset("A") is True
    assert env.get("A") is None
    assert env.unset("NOPE") is False


def test_commented_out_keys_are_not_values(tmp_path):
    p = _write(tmp_path, "# A=1\nB=2\n")
    env = EnvFile.load(p)
    assert "A" not in env.keys()  # noqa: SIM118 - EnvFile is not a dict
    assert env.get("A") is None


def test_save_sets_restrictive_permissions(tmp_path):
    """Secrets live here: 0600 or the values are readable by every local user."""
    p = _write(tmp_path, "SECRET=abc\n")
    env = EnvFile.load(p)
    env.save()
    assert (p.stat().st_mode & 0o777) == 0o600


def test_backup_created(tmp_path):
    p = _write(tmp_path, "A=1\n")
    env = EnvFile.load(p)
    backup = env.backup()
    assert backup is not None and backup.exists()
    assert backup.read_text() == "A=1\n"


def test_values_with_quotes_and_equals(tmp_path):
    p = _write(tmp_path, 'A="hello world"\nB=a=b\n')
    env = EnvFile.load(p)
    assert env.get("A") == "hello world"
    assert env.get("B") == "a=b"


# --- secret handling ---------------------------------------------------------
@pytest.mark.parametrize("key", [
    "PUSHOVER_USER_KEY", "PUSHOVER_API_TOKEN", "CLICKHOUSE_PASSWORD", "MY_SECRET",
])
def test_secret_keys_detected(key):
    assert is_secret(key)


@pytest.mark.parametrize("key", ["CLICKHOUSE_HOST", "BASE_THRESHOLD", "ZEEK_IFACE"])
def test_non_secret_keys(key):
    assert not is_secret(key)


def test_mask_hides_all_but_last_chars():
    assert mask("abcdefghijkl") == "********ijkl"
    assert mask("abc") == "***"
    assert mask("") == ""
    # Never leak the full value.
    assert "abcdefghijkl" not in mask("abcdefghijkl")


# --- shipped-template parity -------------------------------------------------
def test_env_example_parses_through_settings():
    """Regression: the SHIPPED .env.example must be loadable, or `install`
    produces a config the worker cannot start with."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    example = root / ".env.example"
    text = example.read_text()
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        values[k.strip()] = v

    # Every key that Settings reads as a number must survive comment stripping.
    for key in ("BASE_THRESHOLD", "MIN_AGREEMENT", "DETECT_INTERVAL_S",
                "RETRAIN_EVERY_H", "RETRAIN_WINDOW_H"):
        if key not in values:
            continue
        cleaned = _clean_env(values[key])
        float(cleaned)  # raises if the comment was not stripped

    # And the EnvFile reader must agree with the app's reader.
    env = EnvFile.load(example)
    for key in ("DETECT_INTERVAL_S", "BASE_THRESHOLD"):
        if key in env.keys():  # noqa: SIM118 - EnvFile is not a dict
            assert env.get(key) == _clean_env(values[key])
