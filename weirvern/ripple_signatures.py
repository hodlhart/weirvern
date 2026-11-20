"""Ripple signature normalization: one exact value, one host, one channel, until a review date.

WHY THIS EXISTS. A permanent change ripples every hour. A new appliance, a new TLS fingerprint, a
replaced SSH banner -- the per-host empirical baseline needs days of windows before the new value
is no longer surprising, and until then the same host produces the same evidence on every pass.
An operator who cannot say "this value is expected for this host" stops trusting the page.

WHAT THIS IS, AND WHAT IT IS NOT. It teaches the MEASUREMENT what is normal for that host. It is
not a suppression list and it never touches the alert path or the stored traffic: the rows stay in
`zeek_ssl`, `zeek_http` and the rest, every count still exists, and the only question that changes
is "is this value new for this host". `normal_traffic` is the same idea for the flow/DNS baseline;
this is the same idea for the ripple channels, whose novelty is a set difference rather than a
distribution.

SCOPE IS THE SAFETY PROPERTY. A row is exactly (host_addr, channel, value):
  * `host_addr` is ONE address literal -- a CIDR, a hostname or an empty string is refused;
  * `channel` is one of the deployment's real signature channels -- a family (`tls`), a table or
    a wildcard is refused, and `family` is DERIVED here rather than accepted from the caller;
  * `value` is one exact string compared with equality -- not a prefix, mask or regular
    expression. There is no shape in this module or its API that can express "this host forever"
    or "this whole channel": a signature always expires, and it always names a value.
The tests in `tests/test_ripple_signatures.py` prove each refusal.

THE REVIEW HORIZON. `review_after` defaults to 90 days and may not exceed 365. When the date
passes, the signature stops applying WITHOUT anyone acting: the evidence it was hiding returns on
the next pass. Yesterday's expected is this year's anomaly, and a normalization that outlived its
reason would be a blind spot nobody remembers creating.

THE STORE IS APPEND-ONLY IN EFFECT. Removal supersedes the row (ReplacingMergeTree on
`updated_at`); nothing is deleted, so the audit keeps who claimed it, why, and who removed it.
`created_at` is carried unchanged through a removal for exactly that reason.
"""
from __future__ import annotations

import contextlib
import ipaddress
import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)

TABLE = "weirvern.normal_ripple_signatures"

#: A signature is reviewed while it is still a fresh claim about a network. Ninety days is long
#: enough to cover a quarter of appliance lifecycle and short enough that it cannot silently
#: become part of the furniture.
REVIEW_DAYS = 90

#: The hard ceiling. A signature is never granted forever: past a year, the "expected" value has
#: to be looked at again by a person, or the operator has built a suppression list by accident.
MAX_REVIEW_DAYS = 365

#: Kinds whose channels ask "which VALUES did this bucket hold". `count`/`sum`/`ratio` channels
#: have no named value to normalize -- their statistic is a number, and a signature cannot name a
#: number without becoming "make this host quieter", which is not this feature.
SIGNATURE_KINDS = frozenset({"diversity", "novelty", "change"})

#: Every column the writer needs. A removal re-writes the row, so a partial read would blank
#: provenance; this list is shared by `entries()` and `write()` for that reason.
COLUMNS = ["id", "host_addr", "channel", "family", "value", "created_at", "created_by", "reason",
           "review_after", "removed_at", "removed_by", "removed_reason", "updated_at"]


def supports(spec: Any) -> bool:
    """Whether a channel spec can carry a signature at all.

    THE EXPRESSION MUST BE A RAW VALUE, NOT A PRE-AGGREGATED STATE. A channel over
    `flows_window` stores `uniq_state` combiner states, so the individual values no longer exist
    by the time the table is read: excluding one is not a filter, it is a missing history. Those
    channels (and the numeric ones) are refused here -- a channel is never special-cased in the
    query builder; it simply is not offered.
    """
    if str(getattr(spec, "kind", "")) not in SIGNATURE_KINDS:
        return False
    if not getattr(spec, "value_column", None):
        return False
    return not getattr(spec, "count_state", None)


def channels_for(specs: Iterable[Any]) -> dict[str, str]:
    """channel -> family for every spec that can carry a signature.

    The family is read from the SPEC, never from a request: a caller cannot label one channel as
    another family, and `tls` (a family) is not a key here.
    """
    return {spec.channel: str(getattr(spec, "family", "") or "") for spec in specs if supports(spec)}


def _today(day: date | datetime | None = None) -> date:
    if isinstance(day, datetime):
        return (day.replace(tzinfo=UTC) if day.tzinfo is None else day.astimezone(UTC)).date()
    if isinstance(day, date):
        return day
    return datetime.now(UTC).date()


def _host(value: str) -> str:
    """One address literal, canonicalised. A network or a name is a wider claim and is refused."""
    text = str(value or "").strip()
    if not text:
        raise ValueError("a signature must name one host address")
    if "/" in text:
        raise ValueError("a signature belongs to one host address, not a network; a CIDR would "
                         "normalize every host in it")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise ValueError("a signature must name one host address, not a hostname or a pattern: "
                         f"{text!r}") from exc


def _reason(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError("a signature needs a reason: it records why this value is expected, and "
                         "the next reader has only this row to go on")
    return text[:2000]


def _value(value: str) -> str:
    text = str(value or "")
    if not text.strip():
        raise ValueError("a signature must name one exact value; an empty value would match the "
                         "anonymous rows every channel already tries to exclude")
    if len(text) > 2048:
        raise ValueError("a signature value is one exact pattern, not a document (2048 chars max)")
    return text


def _review(value: Any, today: date) -> date:
    """The date this claim stops applying. Defaults to 90 days; never more than a year."""
    if value in (None, ""):
        return today + timedelta(days=REVIEW_DAYS)
    if isinstance(value, datetime):
        day = _today(value)
    elif isinstance(value, date):
        day = value
    else:
        try:
            day = date.fromisoformat(str(value).strip()[:10])
        except ValueError as exc:
            raise ValueError(f"review_after must be an ISO date (YYYY-MM-DD): {value!r}") from exc
    if day <= today:
        raise ValueError("review_after must be in the future; an already-expired signature would "
                         "be a row that never applied")
    if (day - today).days > MAX_REVIEW_DAYS:
        raise ValueError(f"review_after may be at most {MAX_REVIEW_DAYS} days out: a signature is "
                         "a reviewable claim, never a permanent exemption")
    return day


def new_signature(*, host: str, channel: str, value: str, reason: str,
                  channels: Mapping[str, str], actor: str = "operator",
                  review_after: Any = None, today: date | None = None) -> dict[str, Any]:
    """One row as it is written. Validation is here so a wider claim cannot reach the table.

    `channels` is the deployment's `channel -> family` map (see `channels_for`). A channel absent
    from it cannot be signed: there is no `family=` argument to widen the claim with, and the
    stored family is the spec's own, not the caller's.
    """
    name = str(channel or "").strip()
    if name not in channels:
        raise ValueError(
            f"{name!r} is not a channel this deployment can normalize a signature for. A signature "
            "names one channel's exact value; a family, a table or a pattern is not expressible.")
    now = datetime.now(UTC)
    day = _today(today)
    return {
        "id": uuid4().hex,
        "host_addr": _host(host),
        "channel": name,
        "family": str(channels[name] or ""),
        "value": _value(value),
        "created_at": now,
        "created_by": str(actor or "operator"),
        "reason": _reason(reason),
        "review_after": _review(review_after, day),
        "removed_at": None,
        "removed_by": "",
        "removed_reason": "",
        "updated_at": now,
    }


def removal(entry: Mapping[str, Any], *, actor: str = "operator", reason: str = "") -> dict[str, Any]:
    """The row that supersedes `entry`: same identity, removed, with who and why.

    `created_at` and `created_by` are deliberately carried through. A removal is a second
    decision about the same claim, not a new claim, and the audit must still be able to say when
    the original was made.
    """
    out = dict(entry)
    now = datetime.now(UTC)
    # `entries()` serialises timestamps for JSON; the writer needs them back as values or the
    # removal row would carry a string into a DateTime/Date column. Parse only what is present.
    created = out.get("created_at")
    if isinstance(created, str):
        try:
            out["created_at"] = datetime.fromisoformat(created)
        except ValueError:
            out["created_at"] = now
    review = out.get("review_after")
    if isinstance(review, str):
        with contextlib.suppress(ValueError):
            out["review_after"] = date.fromisoformat(review[:10])
    out.update({
        "removed_at": now,
        "removed_by": str(actor or "operator"),
        "removed_reason": str(reason or "")[:2000],
        "updated_at": now,
    })
    return out


def _literal(value: str) -> str:
    """A ClickHouse string literal. Signatures carry operator text, never SQL."""
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


@dataclass(frozen=True)
class SignatureFilter:
    """The live (host, channel) -> exact values map the channel queries receive.

    ONE OBJECT, EVERY CHANNEL. `ChannelSpec.sql_anchored`/`sql_values` call `predicate()` with
    their own host and value expressions, so a new channel gets the behaviour by existing rather
    than by being added to a list here. The predicate is a conjunction per signature and a
    disjunction across signatures, negated as a whole: a value is excluded only for the host and
    channel it was written for.

    `available=False` means the store could not be read. That FAILS OPEN -- the measurement runs
    unfiltered, exactly as it did before this feature -- because refusing to measure would turn a
    table problem into a silent network. The pass receipt names the state so it is not invisible.
    """

    by_host_channel: Mapping[tuple[str, str], frozenset[str]] = field(default_factory=dict)
    available: bool = True
    reason: str = ""

    @property
    def count(self) -> int:
        """How many exact values are currently excluded (not how many rows: a row is one value)."""
        return sum(len(values) for values in self.by_host_channel.values())

    def values_for(self, host: str, channel: str) -> frozenset[str]:
        return self.by_host_channel.get((str(host or ""), str(channel or "")), frozenset())

    def predicate(self, channel: str, host_expr: str, value_expr: str) -> str:
        """The SQL predicate excluding this channel's live signatures, or '' when there are none.

        It is written against the EXPRESSIONS the channel already uses (the attributed subject
        and the channel's own value expression), so it composes with pre-aggregation, direction
        and scope instead of assuming a column name.
        """
        parts: list[str] = []
        for (host, name), values in sorted(self.by_host_channel.items()):
            if name != str(channel or "") or not values:
                continue
            listed = ", ".join(_literal(value) for value in sorted(values))
            parts.append(f"({host_expr} = {_literal(host)} AND {value_expr} IN ({listed}))")
        if not parts:
            return ""
        return "NOT (" + " OR ".join(parts) + ")"


EMPTY = SignatureFilter()


def as_filter(rows: Sequence[Mapping[str, Any]], *, today: date | None = None) -> SignatureFilter:
    """Build the filter from entry dicts, applying the review horizon exactly as the read does.

    Kept separate from the ClickHouse read so the horizon can be tested without a database, and
    so a caller that already holds the rows (the console list) never re-queries to ask what.
    """
    day = _today(today)
    grouped: dict[tuple[str, str], set[str]] = {}
    for row in rows:
        if row.get("removed_at"):
            continue
        review = row.get("review_after")
        if isinstance(review, datetime):
            review = review.date()
        elif isinstance(review, str):
            try:
                review = date.fromisoformat(review[:10])
            except ValueError:
                continue
        if not isinstance(review, date) or review < day:
            continue
        host = str(row.get("host_addr") or "")
        channel = str(row.get("channel") or "")
        value = row.get("value")
        if host and channel and value is not None and str(value) != "":
            grouped.setdefault((host, channel), set()).add(str(value))
    return SignatureFilter({key: frozenset(values) for key, values in grouped.items()})


def load_filter(client: Any, *, today: date | None = None,
                hosts: Iterable[str] | None = None,
                channels: Iterable[str] | None = None) -> SignatureFilter:
    """The live signatures, as the filter the ripple pass hands to every channel query.

    ONE READ PER PASS. `hosts`/`channels` bound the scan when a caller is measuring a subset; the
    console's list does not use this path (it needs the provenance columns too).
    """
    day = _today(today)
    where = ["removed_at IS NULL", f"review_after >= toDate('{day.isoformat()}')"]
    wanted_hosts = sorted({str(h) for h in (hosts or ()) if str(h)})
    wanted_channels = sorted({str(c) for c in (channels or ()) if str(c)})
    if wanted_hosts:
        where.append("host_addr IN (" + ", ".join(_literal(h) for h in wanted_hosts) + ")")
    if wanted_channels:
        where.append("channel IN (" + ", ".join(_literal(c) for c in wanted_channels) + ")")
    sql = ("SELECT host_addr, channel, value FROM " + TABLE + " FINAL WHERE "
           + " AND ".join(where) + " ORDER BY host_addr, channel, value")
    try:
        rows = list(client.query(sql).result_rows)
    except Exception as exc:  # noqa: BLE001 - an unreadable store is a named state, not a crash
        logger.warning("ripple signatures could not be read: %s", exc)
        return SignatureFilter(available=False,
                               reason=f"the signature store could not be read: "
                                      f"{type(exc).__name__}: {str(exc)[:160]}")
    grouped: dict[tuple[str, str], set[str]] = {}
    for host, channel, value in rows:
        if host and channel and value not in (None, ""):
            grouped.setdefault((str(host), str(channel)), set()).add(str(value))
    return SignatureFilter({key: frozenset(values) for key, values in grouped.items()})


def entries(client: Any, *, include_removed: bool = False) -> list[dict[str, Any]]:
    """Current state per signature, newest first. FINAL because removal supersedes a row."""
    where = "" if include_removed else "WHERE removed_at IS NULL "
    try:
        result = client.query(
            "SELECT " + ", ".join(COLUMNS) + " FROM " + TABLE + " FINAL "
            + where + "ORDER BY created_at DESC LIMIT 2000"
        )
        rows = [dict(zip(result.column_names, row, strict=False)) for row in result.result_rows]
    except Exception as exc:  # noqa: BLE001
        logger.warning("ripple signature list failed: %s", exc)
        return []
    for row in rows:
        for key in ("created_at", "removed_at", "updated_at"):
            if isinstance(row.get(key), datetime):
                row[key] = row[key].isoformat()
        review = row.get("review_after")
        if isinstance(review, (date, datetime)):
            row["review_after"] = review.isoformat()[:10]
    return rows


def write(client: Any, rows: Sequence[Mapping[str, Any]]) -> int:
    """Insert rows (new claims or removals). Returns how many were sent."""
    if not rows:
        return 0
    client.insert(TABLE, [[row.get(column) for column in COLUMNS] for row in rows],
                  column_names=COLUMNS)
    return len(rows)


def summary(rows: Sequence[Mapping[str, Any]], *, today: date | None = None) -> dict[str, Any]:
    """What the tab says above the list: how many apply, how many have expired, who claimed them."""
    day = _today(today)
    live = [row for row in rows if not row.get("removed_at")]
    expired: list[Mapping[str, Any]] = []
    active: list[Mapping[str, Any]] = []
    for row in live:
        review = row.get("review_after")
        if isinstance(review, datetime):
            review = review.date()
        elif isinstance(review, str):
            try:
                review = date.fromisoformat(review[:10])
            except ValueError:
                review = None
        (expired if isinstance(review, date) and review < day else active).append(row)
    return {
        "total": len(rows),
        "active": len(active),
        "expired": len(expired),
        "hosts": len({row.get("host_addr") for row in active if row.get("host_addr")}),
        "channels": len({row.get("channel") for row in active if row.get("channel")}),
    }


def candidates(client: Any, spec: Any, *, host: str, start: datetime, end: datetime,
               scope_cidrs: tuple[str, ...] | None = None,
               limit: int = 25) -> list[dict[str, Any]]:
    """The exact values this channel saw for this host in one window, with their counts.

    THE PREVIEW IS A READING, NOT A GUESS. The evidence row carries a statistic (a diversity
    count, a novelty count), not the values behind it, so the sheet asks the source table the
    same question the measurement asked and shows the operator exactly what a signature would
    make expected. A value that is not in this list is not offered by the sheet; the API would
    still accept it (an operator may know it appears next hour), but the console never invents it.
    """
    if not supports(spec):
        return []
    if not str(getattr(spec, "value_column", "") or ""):
        return []
    sql = spec.sql_patterns(host=str(host), since=start, until=end,
                            scope_cidrs=scope_cidrs, limit=limit)
    rows = list(client.query(sql).result_rows)
    out: list[dict[str, Any]] = []
    for value, count in rows:
        if value in (None, ""):
            continue
        out.append({"value": str(value), "count": int(count or 0)})
    return out


def find_spec(specs: Iterable[Any], channel: str) -> Any:
    """The spec for one channel name, or None. A family name is not a channel and finds nothing."""
    wanted = str(channel or "")
    for spec in specs:
        if spec.channel == wanted:
            return spec
    return None


__all__ = ["COLUMNS", "EMPTY", "MAX_REVIEW_DAYS", "REVIEW_DAYS", "SIGNATURE_KINDS", "TABLE",
           "SignatureFilter", "as_filter", "candidates", "channels_for", "entries", "find_spec",
           "load_filter", "new_signature", "removal", "summary", "supports", "write"]
