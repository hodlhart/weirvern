"""Scanner coverage is a percentage of the MONITORED network, not of every address seen.

Operator directive, 2026-11-12: "for assets and the coverage table we need to know the percentage
covered of our monitored network hosts, not every ip."

The defect this guards: `_asset_change_coverage` counted `count()` over the whole
`weirvern.asset_registry`, so the denominator included internet peers, scanners and one-off
lookups. The percentage therefore fell as the box saw more of the world, and answered a question
nobody asked. "Have we scanned the network we said we were watching" needs that network as the
denominator, and it must be the SAME population decision scoring and training use, or the three
drift apart and a host can be alertable but outside scanner coverage, or the reverse.
"""

from __future__ import annotations

import pytest

from weirvern import networks
from weirvern.admin import assets


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    """Answers the three reads the coverage function makes, and records the registry SQL."""

    def __init__(self, registry):
        self.registry = registry
        self.registry_sql = ""

    def query(self, sql, parameters=None, **_kw):
        if "asset_service_history" in sql:
            return _Result([(120, 8, "2026-11-12 10:00:00")])
        if "asset_registry" in sql:
            self.registry_sql = sql
            return _Result([self.registry])
        raise AssertionError(f"unexpected query: {sql}")


def _scope(cidr: str, monitored: bool = True, policy: str = "full") -> networks.Scope:
    return networks.normalize_scope(cidr, monitored=monitored, policy=policy)


# assets / scanned / last_scan / in_scope / in_scope_scanned
REGISTRY = (500, 100, "2026-11-12 09:00:00", 20, 15)


def test_the_PERCENTAGE_IS_OVER_MONITORED_HOSTS(monkeypatch):
    """The headline case. With a declared monitored scope the payload must report the in-scope
    pair, so the UI can say "15/20 monitored hosts" rather than "100/500 addresses"."""
    monkeypatch.setattr(networks, "load_scopes", lambda _c: [_scope("192.0.2.0/24")])
    client = _Client(REGISTRY)
    out = assets._asset_change_coverage(client, 24)

    assert out["basis"] == "monitored"
    assert out["in_scope"] == 20 and out["in_scope_scanned"] == 15
    # The registry-wide pair stays, so a reader can see the dilution it was hiding.
    assert out["assets"] == 500 and out["scanned"] == 100
    assert "isIPAddressInRange(ip, '192.0.2.0/24')" in client.registry_sql, (
        f"the registry read does not filter on the declared scope: {client.registry_sql}"
    )


def test_the_predicate_uses_the_ip_column_not_src_addr(monkeypatch):
    """`asset_registry` stores the address as `ip`. The shared helper defaults to `src_addr`, so a
    caller that forgets to pass the column gets a ClickHouse error rather than a wrong number."""
    monkeypatch.setattr(networks, "load_scopes", lambda _c: [_scope("198.51.100.0/24")])
    client = _Client(REGISTRY)
    assets._asset_change_coverage(client, 24)

    assert ".ip," in client.registry_sql or "InRange(ip," in client.registry_sql
    assert "src_addr" not in client.registry_sql, (
        "the asset coverage read used the flow-table column name on the asset registry"
    )


def test_NO_declared_scopes_keeps_the_legacy_denominator_and_says_so(monkeypatch):
    """An upgrade with nothing declared must not suddenly report 0%: before anyone has declared a
    network there is no monitored population, so everything counts and the basis says `all`."""
    monkeypatch.setattr(networks, "load_scopes", lambda _c: [])
    client = _Client(REGISTRY)
    out = assets._asset_change_coverage(client, 24)

    assert out["basis"] == "all"
    # ASSERTED ON THE PREDICATE, NOT ON THE NUMBERS. This stub returns fixed counts whatever the
    # SQL says, so it cannot model `countIf(1) == count()`; the real server would return the
    # registry pair for both. The condition being "1" is the fact that carries the legacy
    # behaviour, and it is what a reader can check.
    assert "countIf(1) AS in_scope" in client.registry_sql, (
        "with no declarations the in-scope condition must be true for every row: "
        f"{client.registry_sql}"
    )


def test_declared_but_NONE_MONITORED_is_its_own_state(monkeypatch):
    """A declaration set with every scope unmonitored is an explicit no-monitoring configuration.
    Reporting it as 0% coverage would blame the scanner for a policy choice."""
    monkeypatch.setattr(networks, "load_scopes", lambda _c: [_scope("203.0.113.0/24", monitored=False)])
    out = assets._asset_change_coverage(_Client(REGISTRY), 24)

    assert out["basis"] == "none", (
        "scopes exist but none is monitored, which is a different fact from having no declarations"
    )


def test_an_OBSERVE_ONLY_scope_is_not_monitored(monkeypatch):
    """The same rule scoring uses: `is_monitored` requires a monitoring policy as well as the
    flag, so an observe-only scope must not become scanner coverage."""
    monkeypatch.setattr(networks, "load_scopes",
                        lambda _c: [_scope("192.0.2.0/24", monitored=True, policy="observe")])
    out = assets._asset_change_coverage(_Client(REGISTRY), 24)

    assert out["basis"] == "none", "an observe-only scope must not count as monitored coverage"


def test_a_failed_read_carries_the_same_keys(monkeypatch):
    """The failure payload must stay shape-compatible, or the UI reads `undefined` and renders
    NaN% on exactly the screen that is already telling the operator something went wrong."""
    monkeypatch.setattr(networks, "load_scopes", lambda _c: [])

    class _Broken(_Client):
        def query(self, sql, parameters=None, **_kw):
            if "asset_registry" in sql:
                raise RuntimeError("clickhouse is unreachable")
            return super().query(sql, parameters, **_kw)

    out = assets._asset_change_coverage(_Broken(REGISTRY), 24)
    assert out["available"] is False
    for key in ("basis", "in_scope", "in_scope_scanned", "assets", "scanned"):
        assert key in out, f"the failed payload is missing {key!r}"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
