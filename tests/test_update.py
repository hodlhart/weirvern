from __future__ import annotations

from weirvern.admin import update


def test_version_compare_handles_v_prefix_and_short_forms():
    assert update.version_tuple("v0.23.7") == (0, 23, 7)
    assert update.version_tuple("0.23.7") == (0, 23, 7)
    assert update.version_tuple("0.23.7-rc1") == (0, 23, 7)
    assert update.version_tuple("release-latest") is None
    assert update.is_newer("0.23.7", "0.23.6")
    assert update.is_newer("0.24", "0.23.9")
    assert not update.is_newer("0.23.6", "0.23.6")
    assert not update.is_newer("0.23.6", "0.23.7")


def test_check_reports_a_newer_release(monkeypatch):
    update._cache.clear()
    monkeypatch.setattr(update, "_fetch_latest", lambda repo, token, timeout: {
        "latest": "0.23.7",
        "release_url": "https://github.com/hodlhart/weirvern/releases/tag/0.23.7",
        "published_at": "2026-10-27T00:00:00Z",
        "notes": "Release notes",
    })
    result = update.check("0.23.6", repo="hodlhart/weirvern", refresh=True)
    assert result["available"] is True
    assert result["latest"] == "0.23.7"
    assert result["update_available"] is True
    assert result["release_url"].endswith("/0.23.7")
    assert result["can_self_update"] is False


def test_check_reports_current(monkeypatch):
    update._cache.clear()
    monkeypatch.setattr(update, "_fetch_latest", lambda repo, token, timeout: {
        "latest": "0.23.7", "release_url": "", "published_at": "", "notes": "",
    })
    result = update.check("0.23.7", repo="hodlhart/weirvern", refresh=True)
    assert result["available"] is True
    assert result["update_available"] is False
    assert result["reason"] == "this deployment is current"


def test_private_feed_is_a_state_not_an_empty_answer(monkeypatch):
    update._cache.clear()
    def private(repo, token, timeout):
        raise update.ReleaseCheckError("no public release feed", private=True)
    monkeypatch.setattr(update, "_fetch_latest", private)
    result = update.check("0.23.7", repo="hodlhart/weirvern", refresh=True)
    assert result["available"] is False
    assert result["private"] is True
    assert "no public release feed" in result["reason"]
