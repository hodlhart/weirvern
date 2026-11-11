"""The live smoke test stays read-only, token-safe and fail-closed.

These are source assertions because the smoke needs a running deployment; the script itself was
run against the box and printed `E2E SMOKE PASS` on 2026-11-11.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMOKE = ROOT / "scripts" / "e2e_smoke.sh"


def test_the_smoke_has_no_private_network_address():
    src = SMOKE.read_text()
    for private in ("192.168.", "10.0.", "172.16.", "172.17."):
        assert private not in src


def test_the_token_comes_from_a_file_never_argv():
    src = SMOKE.read_text()
    assert "TOKEN_FILE" in src
    assert 'TOKEN=$(cat "$TOKEN_FILE")' in src


def test_the_smoke_is_read_only():
    src = SMOKE.read_text()
    assert "curl -fsS" in src
    assert "-X POST" not in src and "-X PUT" not in src and "-X DELETE" not in src


def test_a_failed_request_fails_the_smoke():
    src = SMOKE.read_text()
    assert "|| fail" in src
    assert "E2E SMOKE PASS" in src
