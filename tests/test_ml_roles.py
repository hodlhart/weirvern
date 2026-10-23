"""Role proposals are context, not a silent default."""
from pathlib import Path

from weirvern.models.roles import classify


def test_media_and_gateway_names_are_recognised_from_dhcp():
    assert classify("10.0.0.10", "Sonarr", private=True)[0] == "media"
    assert classify("10.0.0.1", "gateway", private=True)[0] == "gateway"
    assert classify("10.0.0.20", "umbrel", private=True)[0] == "server"


def test_an_external_peer_is_not_a_local_role():
    role, _, why = classify("203.0.113.9", "", private=False)
    assert role == "external" and "private" in why


def test_a_name_without_a_pattern_is_workstation_but_no_name_is_unknown():
    assert classify("10.0.0.30", "Samuels-iPad", private=True)[0] == "workstation"
    role, confidence, why = classify("10.0.0.40", "", private=True)
    assert role == "unknown" and confidence == 0.0 and "no name" in why


def test_the_role_table_is_replacing_and_correctable():
    sql = (Path(__file__).resolve().parents[1] / "weirvern" / "schema" / "031_host_roles.sql").read_text()
    assert "host_roles" in sql and "ReplacingMergeTree" in sql
    assert "source" in sql
