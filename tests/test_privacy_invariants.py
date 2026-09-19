"""Privacy assertions: prove the deployment does not capture payloads or credentials.

WHY THIS IS A TEST AND NOT A COMMENT: the standing decision is that Weirvern must not
capture credentials or payload bytes -- "capturing credentials on your network creates a
liability you don't need." That decision is enforced by Zeek DEFAULTS and by which policy
files we load. A single `@load` added later, or a Zeek upgrade that changes a default,
silently turns capture back on with no visible symptom: the logs simply start containing
passwords.

Research into the wider Zeek log set found three more sources of raw payload bytes that
this deployment does not currently produce but could be switched on by one line:

  * `unknown_protocols.log:first_bytes`   -- hex-encoded leading bytes of unknown flows,
                                             from `policy/misc/unknown-protocols.zeek`
  * `analyzer.log:failure_data`           -- up to `failure_data_max_size` (40) bytes
                                             from `base/frameworks/analyzer/logging.zeek`
  * `mqtt_publish.payload`                -- MQTT message bodies

These are functionally the same exposure as flipping `capture_password` on. So the
invariants below are asserted rather than assumed.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "k8s" / "zeek" / "weirvern-local.zeek"
CONFIG = ROOT / "weirvern" / "config.py"


def _code(text: str) -> list[str]:
    """Executable lines only -- this repo explains traps in comments, and a comment
    naming a policy file is not a `@load` of it."""
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


# ── payload capture must stay off ───────────────────────────────────────────────


def test_the_policy_does_not_load_unknown_protocols():
    """`policy/misc/unknown-protocols.zeek` logs raw leading bytes of unknown traffic.

    Verified in Zeek 9.0.0 source: `first_bytes: string &log;` and the handler does
    `info$first_bytes = bytestring_to_hexstr(first_bytes);`. It lives in policy/, so it is
    OPT-IN -- nothing loads it unless we say so. Asserted so nobody adds it for
    "visibility" and starts logging payload bytes.
    """
    for line in _code(POLICY.read_text()):
        assert "unknown-protocols" not in line, (
            "the site policy loads policy/misc/unknown-protocols, which logs the first "
            "bytes of unknown traffic in hex. That is payload capture."
        )


def test_mqtt_payload_is_not_logged():
    """`mqtt_publish.payload` carries MQTT message bodies verbatim."""
    text = POLICY.read_text()
    for line in _code(text):
        assert not re.search(r"mqtt", line, re.I), (
            "the site policy enables MQTT logging, whose `payload` field carries "
            "message bodies"
        )


def test_analyzer_failure_data_is_not_enabled():
    """analyzer.log's `failure_data` keeps up to 40 bytes of the failing packet.

    Small, but it is raw packet content from flows Zeek could not parse -- precisely the
    traffic most likely to be non-standard or malicious, and therefore most likely to
    contain credentials for an unknown protocol.
    """
    text = POLICY.read_text()
    for line in _code(text):
        assert "failure_data" not in line, (
            "the site policy references analyzer failure_data, which is raw packet content"
        )
        assert not re.search(r"frameworks/analyzer/logging", line), (
            "the site policy loads the analyzer logging framework, whose failure_data "
            "field retains raw bytes from unparseable flows"
        )


def test_http_credentials_are_not_captured():
    """The `capture_password` decision, asserted rather than remembered.

    Zeek's HTTP analyzer only fills http.log's username/password when
    `HTTP::default_capture_password = T`. The standing decision is that it stays F, so
    this is a guard against a future "more visibility" change.
    """
    text = POLICY.read_text()
    assert not re.search(r"default_capture_password\s*=\s*T", text), (
        "the site policy turns on HTTP::default_capture_password. Capturing credentials "
        "creates a liability with no analytic payoff, and it is a deliberate standing "
        "decision that this stays off."
    )


def test_the_ingester_never_stores_http_credentials():
    """Even if Zeek logged them, the mapper must not persist them.

    Defence in depth: the policy assertion above is the primary control, but a log file
    copied from another sensor, or a config drift, would otherwise flow straight into
    ClickHouse where it is harder to delete and backed up.
    """
    from weirvern.ingester import map_zeek_http

    row = map_zeek_http({
        "ts": "1789689741.76", "uid": "H1", "id.orig_h": "198.51.100.5",
        "id.resp_h": "93.184.216.34", "id.resp_p": "80", "method": "POST",
        "host": "example.com", "uri": "/login", "status_code": "200",
        "resp_mime_types": "text/html", "resp_bytes": "1234",
        "username": "alice", "password": "hunter2",
        "user_agent": "Mozilla/5.0", "referrer": "http://example.com/",
    })
    assert row is not None
    for field, value in row.items():
        assert "hunter2" not in str(value), f"the password reached column {field!r}"
        assert value != "alice", f"the username reached column {field!r}"


# ── the policy must keep the detections we DO want ──────────────────────────────


def test_the_policy_still_loads_certificate_validation():
    """validate-certs is a real detection and should not be lost in a privacy sweep."""
    assert re.search(r"@load\s+policy/protocols/ssl/validate-certs",
                     POLICY.read_text()), (
        "certificate validation is no longer loaded, so plaintext or mismatched certs "
        "stop producing notices"
    )


def test_scoped_scan_detection_is_not_reintroduced():
    """`policy/misc/scan` was removed in Zeek 6.1+; loading it aborts startup.

    Recorded because it is the single most tempting `@load` to add back, and the failure
    it causes is a total sensor outage rather than a degraded feature.
    """
    for line in _code(POLICY.read_text()):
        assert not re.search(r"@load\s+policy/misc/scan\b", line), (
            "policy/misc/scan does not exist in Zeek 6.1+ and is not in this image; "
            "loading it makes Zeek abort at startup with 'failed to locate script'"
        )


# ── retention: the config must expose the caps ─────────────────────────────────


def test_disk_caps_are_exposed_in_the_environment_contract():
    """The three caps the rotation CronJob reads must be documented in the config layer.

    A cap that the code reads but the config never mentions is invisible to an operator,
    so it stays unset and the pruning silently does nothing.
    """
    text = CONFIG.read_text()
    for var in ("ZEEK_MAX_MB", "NETFLOW_MAX_MB", "ML_MAX_MB"):
        assert var in text, (
            f"{var} is read by the prune path but never declared in weirvern/config.py, "
            f"so nothing tells an operator it exists"
        )


def test_the_env_example_documents_every_cap():
    """`.env.example` is the operator-facing contract; a missing cap reads as not needed."""
    env = (ROOT / ".env.example").read_text()
    for var in ("ZEEK_MAX_MB", "NETFLOW_MAX_MB", "ML_MAX_MB"):
        assert var in env, f"{var} is missing from .env.example"
