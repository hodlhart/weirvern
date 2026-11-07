"""Pure tests for the Nmap-to-ML change ledger."""
from weirvern.asset_changes import detect_service_changes


def test_new_and_closed_ports_have_different_confidence():
    previous = [(22, "tcp", "ssh", "OpenSSH", "9.6", "")]
    current = [
        (22, "tcp", "ssh", "OpenSSH", "9.6", ""),
        (8080, "tcp", "http", "nginx", "1.24", ""),
    ]
    changes = {c.kind: c for c in detect_service_changes(previous, current)}
    assert changes["port_opened"].port == 8080
    assert changes["port_opened"].confidence == "high"
    assert changes["port_opened"].new_value == "http nginx 1.24"


def test_closed_port_is_low_confidence():
    changes = detect_service_changes(
        [(443, "tcp", "https", "nginx", "1.24", "")], []
    )
    assert len(changes) == 1
    assert changes[0].kind == "port_closed"
    assert changes[0].confidence == "low"


def test_service_and_version_changes_are_distinct():
    previous = [(22, "tcp", "ssh", "OpenSSH", "9.6", "")]
    current = [(22, "tcp", "ssh", "OpenSSH", "10.0", "")]
    change = detect_service_changes(previous, current)[0]
    assert change.kind == "version_changed"
    assert change.old_value == "ssh OpenSSH 9.6"
    assert change.new_value == "ssh OpenSSH 10.0"

    previous = [(80, "tcp", "http", "nginx", "1.24", "")]
    current = [(80, "tcp", "http", "Apache httpd", "2.4", "")]
    change = detect_service_changes(previous, current)[0]
    assert change.kind == "service_changed"


def test_scan_with_no_changes_returns_none():
    same = [(22, "tcp", "ssh", "OpenSSH", "9.6", "")]
    assert detect_service_changes(same, same) == []
