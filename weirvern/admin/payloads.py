"""Fetchers that return a finished payload, for any surface to call.

WHY THIS MODULE EXISTS. `web_api` formats and knows nothing about HTTP; the handler in `web.py` both
fetches AND routes, so a second surface had no way to reach the data without copying the fetch. That
copy is what I had already started doing in the Flask route for episodes, and a copy is exactly what
this codebase spends its time removing: two readers, two ideas of what the payload means, drifting
apart with each copy looking correct alone.

SO THE SEAM MOVES ONE LAYER DOWN. A function here takes a ClickHouse client and the request's
arguments and returns the SAME payload the console returns. A surface then does only two things:
parse arguments, and turn the result into a response. Neither surface knows how the data is read.

THE ERROR SHAPE IS PART OF THE CONTRACT. Every fetcher raises on a failed read and leaves the wording
to the caller through `read_failure`, which is the one place a failure is described by what was
OBSERVED rather than by the layer assumed to have broken (WV1-20). A fetcher that swallowed the
exception and returned an empty payload would be the "absence reads as healthy" defect at the source.

MIGRATION IS INCREMENTAL, DELIBERATELY. Only routes that have been moved here appear, and each one is
deleted from the handler as it lands so there is never a second implementation lying around. The
console keeps serving everything not yet moved.
"""

from __future__ import annotations

from typing import Any

from clickhouse_connect.driver.client import Client

from weirvern.admin import status as status_mod
from weirvern.admin import web_api


def episodes(client: Client, *, hours: int, limit: int) -> dict[str, Any]:
    """One row per incident, with the hostname resolved the same way everywhere.

    The queue's Host column is the fact (the address); the hostname is the convenience, resolved
    through the same cached reverse-DNS path the anomaly route uses, so the two tables cannot
    disagree about a name. A missing name is an empty cell, never an invented label.
    """
    payload = status_mod.episodes_recent(client, hours=hours, limit=limit)
    for row in payload.get("episodes", []):
        row["hostname"] = web_api._hostname(row.get("src_addr"))
    return payload


def baselines(client: Client) -> dict[str, Any]:
    """The per-host baseline snapshot: latest row per host, when it refreshed, what fired lately.

    `available`/`reason` pass through intact, because "the store could not be read" and "no host has a
    baseline yet" need different words on screen and only the server knows which is true.
    """
    return web_api.baselines_payload(status_mod.baselines_overview(client))
