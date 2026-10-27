"""Read-only release metadata for the Settings → Software update card.

WHY THIS DOES NOT APPLY UPDATES. The GUI runs on a LAN port and has no business holding
cluster-admin credentials or shell access to the sensor node. A release CHECK is a read: it
answers "is there a newer release", shows the notes, and links to the release. Applying an
update belongs to the deployment pipeline, where credentials, signatures and rollback can be
handled deliberately.

THE REPOSITORY IS CONFIGURABLE so the same code works while the repository is private and
after it becomes public. A private repository returns 404 from the public GitHub Releases API;
the card says that plainly instead of pretending the deployment is current. An optional
read-only token can be supplied by the deployment environment, never by the browser.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any

DEFAULT_REPO = "hodlhart/weirvern"
CACHE_SECONDS = 300.0
_API = "https://api.github.com/repos/{repo}/releases/latest"
_VERSION = re.compile(r"^v?(\d+(?:\.\d+)*)(?:[-+].*)?$")
_cache: dict[str, tuple[float, dict[str, Any]]] = {}


class ReleaseCheckError(RuntimeError):
    """A release feed could not be read, with an operator-safe reason."""

    def __init__(self, reason: str, *, private: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.private = private


def repo_name() -> str:
    return (os.environ.get("WEIRVERN_UPDATE_REPO") or DEFAULT_REPO).strip().strip("/")


def _token() -> str:
    return (os.environ.get("WEIRVERN_UPDATE_TOKEN") or "").strip()


def version_tuple(value: str) -> tuple[int, ...] | None:
    """Parse the numeric release part of a tag, or None for a non-version tag."""
    match = _VERSION.match(str(value or "").strip())
    if not match:
        return None
    parts = tuple(int(p) for p in match.group(1).split("."))
    # Compare 1.2 and 1.2.0 as the same version without a special case at every call site.
    while len(parts) > 1 and parts[-1] == 0:
        parts = parts[:-1]
    return parts


def is_newer(latest: str, current: str) -> bool:
    left, right = version_tuple(latest), version_tuple(current)
    if left is None or right is None:
        return False
    return left > right


def _fetch_latest(repo: str, token: str, timeout: float) -> dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "weirvern-update-check",
    }
    # A deployment may supply a read-only token while the repository is private. It is read
    # from the process environment only; it is never returned to the browser or logged.
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(_API.format(repo=repo), headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403, 404):
            raise ReleaseCheckError(
                f"GitHub has no public release feed for {repo} (HTTP {exc.code}); "
                "the repository may still be private", private=True,
            ) from exc
        raise ReleaseCheckError(f"GitHub returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ReleaseCheckError(f"could not reach GitHub: {exc}") from exc
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise ReleaseCheckError("GitHub returned a response that was not JSON") from exc
    if not isinstance(data, dict):
        raise ReleaseCheckError("GitHub returned an unexpected release payload")
    tag = str(data.get("tag_name") or "").strip()
    if version_tuple(tag) is None:
        raise ReleaseCheckError(f"the latest release has no usable version tag ({tag or 'empty'})")
    return {
        "latest": tag.lstrip("vV"),
        "release_url": str(data.get("html_url") or ""),
        "published_at": str(data.get("published_at") or ""),
        "notes": str(data.get("body") or "")[:4000],
    }


def check(current: str, *, repo: str | None = None, refresh: bool = False,
          timeout: float = 6.0) -> dict[str, Any]:
    """Return the release state for the Settings card. Never writes or mutates anything."""
    current = str(current or "").strip().lstrip("vV") or "(unknown)"
    repo = (repo or repo_name()).strip().strip("/")
    now = time.monotonic()
    key = f"{repo}|{current}"
    if not refresh:
        cached = _cache.get(key)
        if cached and now - cached[0] < CACHE_SECONDS:
            return dict(cached[1], cached=True)

    base = {
        "available": False,
        "current": current,
        "latest": None,
        "update_available": False,
        "release_url": "",
        "published_at": "",
        "notes": "",
        "repo": repo,
        "can_self_update": False,
    }
    if not repo:
        empty_result = dict(base, reason="no update repository is configured")
        _cache[key] = (now, empty_result)
        return empty_result
    try:
        latest = _fetch_latest(repo, _token(), timeout)
    except ReleaseCheckError as exc:
        failure = dict(base, reason=exc.reason, private=exc.private)
        _cache[key] = (now, failure)
        return failure
    result: dict[str, Any] = dict(base)
    result.update(latest)
    result["available"] = True
    result["update_available"] = is_newer(latest["latest"], current)
    result["reason"] = ("a newer release is available" if result["update_available"]
                        else "this deployment is current")
    _cache[key] = (now, result)
    return result
