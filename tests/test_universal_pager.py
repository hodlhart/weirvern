"""The one pager, and the registry that keeps every table honest.

Operator (2026-11-20): "any table that is long needs the same, make previous and next buttons
universal in the whole project." A shared control only stays universal if a NEW table cannot
quietly skip it, so this test enumerates every ``<table id>`` in the shipped markup and requires
each one to be either PAGED (wired through ``wireTablePager``) or BOUNDED (a fixed top-N panel
whose renderer cannot emit a screenful). A table in neither list fails here.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "weirvern" / "admin" / "web"
INDEX = (WEB / "index.html").read_text()
APP_JS = (WEB / "app.js").read_text()
ASSETS_JS = (WEB / "assets.js").read_text()

#: Tables wired to the shared pager in `app.js`'s DOMContentLoaded block.
PAGED = {
    "nw-table": "Network edges",
    "nw-detail-table": "connection detail",
    "nw-hosts-table": "Network hosts",
    "anomalies-table": "model alerts",
    "nf-detail-table": "flow drill-down",
    "zk-hosts-table": "Zeek hosts",
    "sl2-rules": "Sluice rules",
    "audit-table": "write trail",
    "nz-feed": "Normalize feed",
}

#: Tables whose renderer is a fixed top-N panel (charts, summaries, one-object lists) and
#: therefore cannot exceed one screen. Every entry states WHY, so a new long table cannot be
#: added here by habit.
BOUNDED = {
    "ripples-table": "Alerts ripples: already paged through renderPager at the shared 25-row size",
    "hp-alerts-reasons": "host page: top outcome reasons (bounded list)",
    "hp-alerts-recent": "host page: recent alerts, already carries its own pager",
    "episodes-table": "incident queue: one row per episode under the queue's own limit",
    "nz-entries": "normalize entries: operator-created, listed in full",
    "nz-sigs": "ripple signatures: operator-created, listed in full",
    "md-table": "models: one row per model in the registry",
    "m-stale": "models: stale-model report (top-N)",
    "mb-hosts": "models: baseline hosts (top-N)",
    "m-cov": "models: coverage summary (one row per source)",
    "m-slo": "models: SLO table (fixed metric set)",
    "m-shadow": "models: shadow comparison (top-N)",
    "m-ripple": "models: ripple summary (fixed family set)",
    "m-cal": "models: calibration (fixed scale set)",
    "m-near": "models: near-miss list (top-N)",
    "ev-flows": "evidence: one alert's flows (bounded by the evidence payload)",
    "ev-zeek": "evidence: one alert's Zeek logs (bounded by the evidence payload)",
    "ev-tls": "evidence: one alert's TLS rows (bounded by the evidence payload)",
    "ev-dns": "evidence: one alert's DNS rows (bounded by the evidence payload)",
    "ev-notice": "evidence: one alert's notices (bounded by the evidence payload)",
    "hp-dns": "host page: top DNS names (top-N)",
    "hp-zeek": "host page: top Zeek services (top-N)",
    "hp-dests": "host page: top destinations (top-N)",
    "hp-anoms": "host page: recent anomalies (top-N)",
    "fd-table": "findings: one host's findings (bounded server read)",
    "as-table": "Assets: server-paged at the console page size (its own offset pager)",
    "ac-table": "asset changes: capped change ledger",
    "h-zeek": "identity: host Zeek summary (top-N)",
    "h-dests": "identity: top destinations (top-N)",
    "h-ports": "identity: top ports (top-N)",
    "h-anoms": "identity: recent anomalies (top-N)",
    "id-table": "identity: fingerprint table (one row per fingerprint, capped)",
    "hp-checks": "host page: check results (fixed check set)",
    "hp-tables": "host page: table inventory (fixed schema set)",
    "bl-hit-table": "blocked: recent hits (capped server read)",
    "wl-table": "weirlings: one row per sensor",
    "st-users": "settings: one row per account",
    "st-tokens": "settings: one row per token",
    "st-networks-table": "settings: one row per declared network scope",
}


def _table_ids() -> set[str]:
    return set(re.findall(r'<table id="([\w-]+)"', INDEX))


def test_every_table_is_registered_as_paged_or_bounded():
    ids = _table_ids()
    assert ids, "no tables parsed from index.html -- the regex or the markup changed"
    unknown = sorted(ids - set(PAGED) - set(BOUNDED))
    assert not unknown, (
        f"these tables are neither paged nor declared bounded: {unknown}. A long table that is "
        f"not wired to wireTablePager renders as one endless scroll; add it to PAGED (and the "
        f"wireTablePager list) or state why its renderer cannot exceed one screen."
    )


def test_every_paged_table_is_wired_in_the_console():
    for table_id in PAGED:
        assert f'["{table_id}", ' in APP_JS, (
            f"{table_id} is listed as paged but is not wired through wireTablePager")
    # ...and the shared helper is the only pager implementation for these tables.
    assert "function paginateTable(" in ASSETS_JS
    assert "function wireTablePager(" in ASSETS_JS
    assert "const PAGER_PAGE_SIZE = 25;" in ASSETS_JS


def test_paged_and_bounded_do_not_overlap():
    overlap = sorted(set(PAGED) & set(BOUNDED))
    assert not overlap, f"a table is declared both paged and bounded: {overlap}"
