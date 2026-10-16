"""The four documentation drifts corrected for issue #14 must not come back.

Each check couples a DOCUMENT to the CODE it describes, so a re-drift fails here
rather than in a reader's head. They are narrow on purpose: each asserts the
specific claim that was found wrong, not a broad reading of prose.

The four drifts, as filed:
  1. docs/security.md said the Zeek sensor was "non-root" while k8s/32-zeek.yaml
     runs it at uid 0 (Kubernetes drops added capabilities for non-root
     containers; verified on a real cluster: CapEff 0x2000 at uid 0, 0x0 otherwise).
  2. docs/operations.md listed SLUICE_CRITICALITY as off/high/critical while
     weirvern/sluice.py.CRITICALITY_POLICIES ships off/high/medium/strict.
  3. k8s/README.md documented `weirvern install --dry-run` (the parser rejects it)
     and its file table omitted three files that exist in k8s/.
  4. .env.example set CLICKHOUSE_USER=default while the ConfigMap creates
     `weirvern` and the official entrypoint locks `default` to localhost.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_every_k8s_manifest_is_named_in_the_k8s_readme_table():
    """The table claims to list the directory's files; it must actually list them."""
    readme = (ROOT / "k8s" / "README.md").read_text()
    manifests = sorted(
        p.name for p in (ROOT / "k8s").glob("*.yaml") if p.name != "kustomization.yaml"
    )
    missing = [name for name in manifests if name not in readme]
    assert not missing, f"k8s/README.md does not mention: {missing}"


def test_the_operations_page_lists_exactly_the_real_sluice_policies():
    from weirvern.sluice import CRITICALITY_POLICIES

    ops = (ROOT / "docs" / "operations.md").read_text()
    rows = [line for line in ops.splitlines() if "`SLUICE_CRITICALITY`" in line]
    assert rows, "docs/operations.md no longer documents SLUICE_CRITICALITY"
    row = rows[0]
    for policy in CRITICALITY_POLICIES:
        assert f"`{policy}`" in row, (
            f"policy {policy!r} is missing from the documented list ({row!r})"
        )
    # "critical" is a SEVERITY, not a policy; it was documented as one and an
    # unknown policy refuses every block, so the confusion had teeth.
    assert "`critical`" not in row


def test_env_example_user_matches_the_cluster_user():
    example = (ROOT / ".env.example").read_text()
    m = re.search(r"^CLICKHOUSE_USER=(.*)$", example, flags=re.M)
    assert m, ".env.example must set CLICKHOUSE_USER"
    value = m.group(1).split("#", 1)[0].strip()
    assert value == "weirvern", (
        "the ConfigMap creates user `weirvern`; the official ClickHouse entrypoint "
        "locks `default` to localhost, so .env.example must not say `default` "
        f"(found {value!r})"
    )


def test_the_security_page_states_the_zeek_sensor_runs_as_root():
    """Couples the sentence to the manifest: if the sensor runs at uid 0, the
    security page must say so — it used to claim the opposite, on the page a
    reader goes to specifically to learn what runs privileged."""
    doc = (ROOT / "docs" / "security.md").read_text()
    manifest = (ROOT / "k8s" / "32-zeek.yaml").read_text()
    if re.search(r"^\s*runAsUser:\s*0\b", manifest, flags=re.M):
        assert "runs as root" in doc, (
            "32-zeek.yaml runs the sensor at uid 0; docs/security.md must state "
            "that (and why: Kubernetes drops added capabilities for non-root "
            "containers)"
        )
        assert "non-root, all other capabilities dropped" not in doc, (
            "the stale phrasing that described a non-root sensor is back"
        )
