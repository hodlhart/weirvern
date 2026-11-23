"""Read and write the deployment's demo-mode marker.

ONE ROW, ONE MEANING. The seeder writes it, the console reads it, and both agree that the data in
this ClickHouse is seeded. The Health panel consults it before judging a feed stale, because a
demo has no capture and a "stalled ingest" verdict about a box that never had one is a false
alarm an operator would chase.

WHY NOT A SETTING. A setting is editable and revocable by anyone with the Settings tab; demo mode
is a property of the DATA, and it stays true until the data is replaced. It is also what the
banner reads, so the console cannot show seeded data without saying so.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

TABLE = "weirvern.demo_state"


def read(client: Any) -> dict[str, Any] | None:
    """The current demo marker, or None when the deployment is not a demo."""
    try:
        rows = client.query(
            f"SELECT enabled, seeded_at, seed, hosts, note FROM {TABLE} FINAL WHERE id = 1 LIMIT 1"
        ).result_rows
    except Exception:  # noqa: BLE001 - an older schema simply has no demo mode
        return None
    if not rows:
        return None
    enabled, seeded_at, seed, hosts, note = rows[0]
    return {
        "enabled": bool(enabled),
        "seeded_at": seeded_at.isoformat() if seeded_at else None,
        "seed": int(seed or 0),
        "hosts": int(hosts or 0),
        "note": note or "",
    }


def is_enabled(client: Any) -> bool:
    state = read(client)
    return bool(state and state["enabled"])


def enable(client: Any, *, seed: int, hosts: int, note: str = "") -> None:
    """Mark this deployment as a demo. Called by the seeder, after the data is written."""
    client.insert(
        TABLE,
        [[1, 1, datetime.now(UTC), int(seed), int(hosts), note]],
        column_names=["id", "enabled", "seeded_at", "seed", "hosts", "note"],
    )


def disable(client: Any, *, note: str = "demo mode retired") -> None:
    """Retire demo mode while keeping the record that a demo ran here."""
    client.insert(
        TABLE,
        [[1, 0, datetime.now(UTC), 0, 0, note]],
        column_names=["id", "enabled", "seeded_at", "seed", "hosts", "note"],
    )
