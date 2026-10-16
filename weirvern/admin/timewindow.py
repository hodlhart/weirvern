"""The window every time-bound query runs against -- one answer, everywhere.

THE OPERATOR'S ASK (2026-10-16): "a better time search like kibana uses throughout the
project". Kibana's time filter is GLOBAL -- presets, free text, a custom absolute range --
and every panel answers to it. Weirvern had the opposite shape: eleven views, each with its
own little `hours` box, and a `hours=24` default hardcoded per call. Worse, the queries could
only ever ask "the last N hours", so an absolute range like 06:00-07:00 yesterday could not be
honoured at all.

This module replaces "the last %(h)s hours" with an explicit `%(since)s`/`%(until)s` pair.
The chosen range rides a ContextVar, so no query builder needs a new argument -- and the
request handler is the only place that decides what the window IS.

WHY A CONTEXTVAR AND NOT A PARAMETER. There are 35 windowed queries and ~20 builders. Threading
(from, to) through every signature would touch every call site and every test; a ContextVar is
per-request state by construction (one request = one context on this server), so the range is
set once at the edge and honoured at the depth, with nothing in between to get wrong.
"""

from __future__ import annotations

import contextvars
import logging
import re
from datetime import UTC, datetime, timedelta

logger = logging.getLogger(__name__)

# The console caps its own picker at 14 days; the server enforces the same ceiling so a
# hand-built URL cannot ask for a decade of history and call it a query.
MAX_HOURS = 24 * 14

# Set by the request handler for the duration of one request. None = "the last `hours` hours",
# which is what every pre-existing caller means.
_WINDOW: contextvars.ContextVar[tuple[datetime, datetime] | None] = contextvars.ContextVar(
    "weirvern_window", default=None
)


def set_window(since: datetime, until: datetime) -> None:
    _WINDOW.set((since, until))


def clear_window() -> None:
    """Called once per request BEFORE the handler runs. A thread is reused across requests, so
    a window left over from the last one would silently answer the next request against the
    wrong stretch of time -- the exact class of bug this module exists to end."""
    _WINDOW.set(None)


def w(hours: float) -> dict:
    """The SQL parameters a windowed query needs: `since` and `until`.

    Queries call this exactly where they used to pass `"h": hours`; nothing else changes.
    """
    held = _WINDOW.get()
    if held is not None:
        since, until = held
        return {"since": since, "until": until}
    now = datetime.now(UTC)
    try:
        span = max(1.0 / 60.0, float(hours))
    except (TypeError, ValueError):
        span = 24.0
    return {"since": now - timedelta(hours=span), "until": now}


_ISO = re.compile(
    r"^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?Z?$"
)


def parse_moment(text: str, *, now: datetime | None = None) -> datetime:
    """One endpoint of an absolute range, from text the console can produce.

    Accepts `2026-10-16`, `2026-10-16 05:00`, `2026-10-16T05:00:00` and a trailing `Z`.
    Raises ValueError with a sentence the operator can act on -- this value arrives from a
    query string, and a silent fallback to "now" would answer a different question than the
    one that was asked.
    """
    raw = (text or "").strip()
    if not raw:
        raise ValueError("empty time")
    if not _ISO.match(raw):
        raise ValueError(
            f"does not look like a time: {raw!r} (want 2026-10-16 or 2026-10-16 05:00)"
        )
    iso = raw.replace(" ", "T")
    if len(iso) == 10:
        iso += "T00:00:00"
    if iso.endswith("Z"):
        iso = iso[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError as exc:
        raise ValueError(f"does not look like a time: {raw!r} ({exc})") from exc
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def parse_range(frm: str | None, to: str | None, *,
                now: datetime | None = None) -> tuple[datetime, datetime]:
    """A complete absolute range. `to` defaults to now; `from` is required.

    The span is clamped to MAX_HOURS so the console cannot ask the database for more history
    than the product offers -- and the clamp is on the SPAN, not on the endpoints, so an old
    window (last week's incident) is still exactly that window.
    """
    now = now or datetime.now(UTC)
    since = parse_moment(frm, now=now) if frm else None
    until = parse_moment(to, now=now) if to else now
    if since is None:
        raise ValueError("a custom range needs a start ('from')")
    if since >= until:
        raise ValueError("the start must be before the end")
    if until - since > timedelta(hours=MAX_HOURS):
        raise ValueError(f"the range is longer than {MAX_HOURS} hours ({MAX_HOURS // 24} days)")
    return since, until
