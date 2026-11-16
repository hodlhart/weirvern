"""The fetch layer exists once, and both surfaces call it.

This is the anti-drift test for the extraction. Before it, the Flask route re-implemented the
episodes fetch and its hostname enrichment inline, which is the same defect as two auth
implementations: two readers of one dataset, drifting, each looking right alone.

A source-level guard is used for the "the route calls it" half because the alternative -- asserting
nothing -- is how a duplicated fetch survives. It is cheap and it names the one function the route
must call, not the shape around it; the fetchers themselves are driven below over a stub client.
"""

from __future__ import annotations

import pathlib

from weirvern.admin import payloads

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_episodes_resolves_the_hostname_the_same_way_for_any_surface(monkeypatch):
    """The row keeps the address as the fact and gains the hostname as the convenience. A surface
    that resolved it differently would render a different table from the same data."""
    from weirvern.admin import status as status_mod

    monkeypatch.setattr(status_mod, "episodes_recent",
                        lambda c, *, hours, limit: {"episodes": [{"src_addr": "192.0.2.10"}]},
                        raising=True)
    monkeypatch.setattr(payloads.web_api, "_hostname", lambda addr: "box.example", raising=True)

    out = payloads.episodes(object(), hours=6, limit=25)

    assert out["episodes"][0]["src_addr"] == "192.0.2.10", "the address must survive"
    assert out["episodes"][0]["hostname"] == "box.example"


def test_episodes_keeps_an_unresolvable_hostname_empty_rather_than_inventing_one(monkeypatch):
    from weirvern.admin import status as status_mod

    monkeypatch.setattr(status_mod, "episodes_recent",
                        lambda c, *, hours, limit: {"episodes": [{"src_addr": "203.0.113.9"}]},
                        raising=True)
    monkeypatch.setattr(payloads.web_api, "_hostname", lambda addr: None, raising=True)

    out = payloads.episodes(object(), hours=1, limit=1)

    assert out["episodes"][0]["hostname"] is None, "a missing name became a label"


def test_baselines_passes_availability_through(monkeypatch):
    """'the store could not be read' and 'no host has a baseline yet' need different words on screen,
    and only the server knows which is true. A fetcher that flattened both to an empty list would be
    the absence-reads-as-healthy defect at the source."""
    from weirvern.admin import status as status_mod

    monkeypatch.setattr(status_mod, "baselines_overview",
                        lambda c: {"available": False, "reason": "cannot reach ClickHouse: x"},
                        raising=True)

    out = payloads.baselines(object())

    assert out.get("available") is False
    assert "reason" in out


def test_the_routes_call_the_shared_fetcher():
    """A route that fetched inline again would be the second implementation this module removes.

    THE CONSOLE'S HANDLER IS GONE. The remaining surface is Flask, and the property is that its
    views delegate to `payloads.*` rather than reading ClickHouse themselves.
    """
    src = (ROOT / "weirvern" / "admin" / "flask_app.py").read_text()

    episodes = src.split("def episodes(", 1)[1].split("    @app.", 1)[0]
    assert "_windowed(payloads.episodes)" in episodes, (
        "the episodes route does not use the shared fetcher, so it can drift from the payload "
        "layer again"
    )

    baselines = src.split("def baselines(", 1)[1].split("    @app.", 1)[0]
    assert "_soft_route(payloads.baselines" in baselines, (
        "the baselines route does not use the shared fetcher"
    )


def test_the_flask_routes_call_the_shared_fetcher():
    src = (ROOT / "weirvern" / "admin" / "flask_app.py").read_text()

    assert "payloads.episodes" in src, "the Flask episodes route re-implemented the fetch"
    assert "payloads.baselines" in src, "the Flask baselines route re-implemented the fetch"
    # The enrichment loop must exist in exactly one place. If this string is back in the Flask
    # module, the duplication has returned.
    assert 'row["hostname"] = ' not in src, (
        "the Flask surface enriches episodes itself again instead of using the shared fetcher"
    )
