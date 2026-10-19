"""One clock for the whole package.

THE CONVENTION: a time that is computed, stored, compared or sent to ClickHouse is AWARE UTC.
Only presentation may convert to the viewer's zone. A naive datetime is not a time; it is a
wall clock reading whose zone the reader has to guess, and guessing wrong is how this project
produced a five-hour sweep window and a negative sensor age (see docs/design/audit history).

`as_aware` is the ONE exception, and it exists for values written before this convention:
a legacy naive value means LOCAL time (that is what the old code wrote), so it is attached to
the system zone rather than relabelled UTC. New code never needs it for its own values.
"""
from datetime import UTC, datetime


def utcnow() -> datetime:
    """Now, aware, in UTC. The only 'now' the data path may use."""
    return datetime.now(UTC)


def from_epoch(epoch_seconds: float) -> datetime:
    """An epoch converted to aware UTC. Never naive, whatever the host TZ is."""
    return datetime.fromtimestamp(float(epoch_seconds), UTC)


def as_aware(value: datetime) -> datetime:
    """Attach the system zone to a LEGACY naive value; leave aware values alone.

    Legacy rows were written as naive local wall-clock, so that is their meaning. This is not
    a licence to create naive values in new code -- `tests/test_clock.py` forbids it.
    """
    return value.astimezone() if value.tzinfo is None else value


def age_seconds(value: datetime) -> float:
    """Seconds since `value`, correct for aware values and for legacy naive ones."""
    return (utcnow() - as_aware(value)).total_seconds()
