"""The HaGeZi five-tier preload and the add-a-list format contract."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from weirvern import blocklists


class _Stub:
    def __init__(self):
        self.rows = []
        self.inserted = []

    def query(self, _sql, parameters=None):
        return SimpleNamespace(result_rows=self.rows)

    def insert(self, table, rows, column_names=None):
        self.inserted.append((table, rows, column_names))


def test_the_five_tiers_are_loaded_once_each_in_the_portable_format():
    assert [s["source_id"] for s in blocklists.DEFAULT_SOURCES] == [
        "hagezi-light", "hagezi-normal", "hagezi-pro", "hagezi-proplus", "hagezi-ultimate"]
    assert [s["tier"] for s in blocklists.DEFAULT_SOURCES] == [
        "light", "normal", "pro", "proplus", "ultimate"]
    assert all(s["format"] == "domains" for s in blocklists.DEFAULT_SOURCES)
    assert all("onlydomains.txt" in s["url"] for s in blocklists.DEFAULT_SOURCES)
    assert [s["enabled"] for s in blocklists.DEFAULT_SOURCES].count(1) == 1
    assert blocklists.DEFAULT_SOURCES[0]["enabled"] == 1
    assert blocklists.DEFAULT_SOURCES[2]["recommended"] is True


def test_adding_a_list_states_the_format_and_refuses_adblock_by_name():
    with pytest.raises(ValueError, match="Adblock and RPZ"):
        blocklists.add_source(_Stub(), "https://example.com/list.txt", fmt="adblock")
    with pytest.raises(ValueError, match="http"):
        blocklists.add_source(_Stub(), "not-a-url", fmt="domains")

    client = _Stub()
    src = blocklists.add_source(client, "https://example.com/list.txt",
                                name="example list", fmt="domains")
    assert src["format"] == "domains" and src["enabled"] is True
    assert client.inserted and client.inserted[0][0] == "weirvern.blocklist_sources"
