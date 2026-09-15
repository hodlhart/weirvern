
import pytest

from weirvern.config import Settings


def test_defaults_are_sane():
    s = Settings()
    s.validate()
    assert s.base_threshold == 0.35
    assert not s.pushover_enabled


def test_invalid_threshold_rejected():
    with pytest.raises(ValueError):
        Settings(base_threshold=1.5).validate()


def test_invalid_agreement_rejected():
    with pytest.raises(ValueError):
        Settings(min_agreement=0.0).validate()


def test_pushover_requires_keys():
    with pytest.raises(ValueError):
        Settings(pushover_enabled=True, pushover_user_key="", pushover_api_token="").validate()


def test_interval_minimum():
    with pytest.raises(ValueError):
        Settings(detect_interval_s=5).validate()


def test_env_override(monkeypatch):
    # Settings reads env vars at construction; no reload() needed (reload()
    # would poison module identity for already-imported references).
    monkeypatch.setenv("BASE_THRESHOLD", "0.5")
    assert Settings().base_threshold == 0.5
