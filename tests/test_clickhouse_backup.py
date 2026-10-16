"""Issue #16: the backup must be runnable on the SHIPPED stack, and the restore verified.

The operations page used to prescribe "snapshot them with your storage provisioner" -- advice
that cannot be followed anywhere this stack runs (the shipped `local-path` storage class has
no snapshots), with no restore procedure anywhere in the repository. These pins keep the
replacement honest:

  * the manifest must TEACH ClickHouse the backup is allowed (its engine refuses a disk the
    server has not been told about: "backups.allowed_disk ... is not set"), and must MOUNT
    that drop-in where config.d is read -- a ConfigMap that is never mounted changes nothing;
  * the script must parse under the interpreter its shebang names (the gate's rule for every
    script) and must carry the exact commands the docs promise;
  * the docs must name the script and the verification (count parity for the three tables a
    reader would actually check).
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "backup_clickhouse.sh"


def test_the_manifest_teaches_clickhouse_to_allow_the_backup():
    docs = [d for d in yaml.safe_load_all((ROOT / "k8s" / "30-clickhouse.yaml").read_text())
            if d]
    cm = next((d for d in docs if d.get("kind") == "ConfigMap"
               and d["metadata"]["name"] == "weirvern-clickhouse-config"), None)
    assert cm, ("the backup allow-list ConfigMap is gone; without it ClickHouse refuses "
                "BACKUP ... TO Disk with INVALID_CONFIG_PARAMETER")
    body = cm["data"]["zz-weirvern-backups.xml"]
    assert "<allowed_disk>default</allowed_disk>" in body
    assert "<allowed_path>/var/lib/clickhouse/backups</allowed_path>" in body

    sts = next(d for d in docs if d.get("kind") == "StatefulSet")
    spec = sts["spec"]["template"]["spec"]
    mounts = [m for c in spec["containers"] for m in c.get("volumeMounts", [])
              if m.get("name") == "clickhouse-config"]
    assert mounts and mounts[0]["mountPath"] == (
        "/etc/clickhouse-server/config.d/zz-weirvern-backups.xml"), (
        "the drop-in is not mounted where ClickHouse reads config.d")
    vols = [v for v in spec.get("volumes", []) if v.get("name") == "clickhouse-config"]
    assert vols and vols[0]["configMap"]["name"] == "weirvern-clickhouse-config"


def test_the_backup_script_parses_and_carries_the_real_commands():
    sha = SCRIPT.read_text().splitlines()[0]
    assert sha == "#!/bin/sh"
    r = subprocess.run(["sh", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    src = SCRIPT.read_text()
    assert "BACKUP DATABASE weirvern TO Disk(" in src
    assert "RESTORE DATABASE weirvern AS weirvern_restore FROM Disk(" in src
    # A backup script that can only back up cannot be verified; the restore path and the
    # count parity are the part that proves the artifact is real.
    for table in ("flows", "netflow_anomalies", "flows_aggregated"):
        assert table in src


def test_the_docs_replace_the_snapshot_advice_with_the_runnable_procedure():
    ops = (ROOT / "docs" / "operations.md").read_text()
    section = ops[ops.index("### Backups"):]
    section = section[:section.index("## Configuration")]
    assert "scripts/backup_clickhouse.sh" in section
    assert "snapshot them with your storage provisioner" not in section, (
        "the snapshot advice is back -- it cannot be followed on the shipped local-path class"
    )
    assert "RESTORE DATABASE weirvern AS weirvern_restore" in section
    assert "DROP DATABASE weirvern_restore" in section
    for table in ("flows", "netflow_anomalies", "flows_aggregated"):
        assert table in section
