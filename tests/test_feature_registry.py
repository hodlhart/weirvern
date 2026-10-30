"""The source-to-feature registry must stay aligned with the schema."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "audit_feature_registry.py"
REGISTRY = ROOT / "docs" / "design" / "source-feature-registry.md"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )


def test_registry_covers_every_schema_table():
    result = _run("--check")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "FEATURE REGISTRY OK" in result.stdout


def test_registry_has_the_dns_and_ja4_contracts():
    text = REGISTRY.read_text()
    for phrase in ("zeek_dns", "zeek_ssl", "ja4", "query_entropy", "server_name"):
        assert phrase in text


def test_the_guard_fires_when_a_table_is_removed(tmp_path: Path):
    text = REGISTRY.read_text().replace("zeek_dns | feature-now\n", "")
    broken = tmp_path / "registry.md"
    broken.write_text(text)
    result = _run("--check", "--registry", str(broken))
    assert result.returncode != 0
    assert "missing from the registry" in result.stdout
    assert "zeek_dns" in result.stdout
