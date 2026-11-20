"""The drift check must fail when a workload lags — otherwise it is decoration.

The script exists because two workloads were found days behind on 2026-11-18, and nothing in the
console compares them: `_running_version` reports only the image of the pod serving the page.
These tests run the SHIPPING script against a stub `kubectl` on PATH, so they exercise the real
argument parsing and the real exit codes without a cluster.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "image_drift.sh"
PIN = "sha-2c3bee529"


def _run(tmp_path: Path, deploys: str, tap: str, *args: str, crons: str = "") -> subprocess.CompletedProcess:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "kubectl"
    stub.write_text(
        "#!/bin/sh\n"
        "case \"$*\" in\n"
        f"  *'get deploy'*) cat {tmp_path / 'deploys.txt'} ;;\n"
        f"  *'get ds zeek'*) cat {tmp_path / 'tap.txt'} ;;\n"
        f"  *'get cronjob'*) cat {tmp_path / 'crons.txt'} ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n"
    )
    stub.chmod(0o755)
    (tmp_path / "deploys.txt").write_text(deploys)
    (tmp_path / "tap.txt").write_text(tap)
    (tmp_path / "crons.txt").write_text(crons)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ.get('PATH', '')}")
    return subprocess.run(["sh", str(SCRIPT), *args], capture_output=True, text=True,
                          timeout=30, env=env, check=False)


def test_a_stale_workload_fails_the_check_and_is_named(tmp_path):
    out = _run(tmp_path,
               f"weirvern-worker weirvern-worker:{PIN}\n"
               "weirvern-ingest weirvern-worker:sha-cd0f002\n",
               f"weirvern-worker:{PIN}\n", "--pin", PIN)

    assert out.returncode == 1, out.stdout
    assert "DRIFT" in out.stdout
    assert "weirvern-ingest" in out.stdout
    assert "sha-cd0f002" in out.stdout, "the check must say WHAT it found, not only that it failed"


def test_the_tap_is_checked_too_because_it_lags_separately(tmp_path):
    out = _run(tmp_path, f"weirvern-worker weirvern-worker:{PIN}\n",
               "weirvern-worker:sha-fb40221\n", "--pin", PIN)

    assert out.returncode == 1
    assert "zeek-tap" in out.stdout


def test_everything_on_the_pin_passes(tmp_path):
    out = _run(tmp_path,
               f"weirvern-worker weirvern-worker:{PIN}\nweirvern-gui weirvern-worker:{PIN}\n",
               f"weirvern-worker:{PIN}\n", "--pin", PIN)

    assert out.returncode == 0, out.stdout
    assert "DRIFT" not in out.stdout


def test_an_upstream_image_is_not_reported_as_drift(tmp_path):
    out = _run(tmp_path,
               "goflow2 netsampler/goflow2:v2.2.6@sha256:abc\n"
               f"weirvern-worker weirvern-worker:{PIN}\n",
               f"weirvern-worker:{PIN}\n", "--pin", PIN)

    assert out.returncode == 0, out.stdout
    assert "external" in out.stdout


def test_without_a_pin_it_refuses_rather_than_guessing(tmp_path):
    out = _run(tmp_path, "", "", )

    assert out.returncode == 2
    assert "--pin" in out.stderr


def test_a_stale_cronjob_fails_the_check_and_is_named(tmp_path):
    # MEASURED: cronjob/weirvern-prune sat on a pruned tag in ImagePullBackOff for days while this
    # check reported green, because it only read Deployments and the zeek DaemonSet. A CronJob's
    # image lives at .spec.jobTemplate.spec.template.spec.containers[*].image, one level deeper,
    # and `kubectl set image` on a Deployment never touches it.
    out = _run(tmp_path,
               f"weirvern-worker weirvern-worker:{PIN}\n",
               f"weirvern-worker:{PIN}\n",
               "--pin", PIN,
               crons="weirvern-prune weirvern-worker:sha-cd0f002\n")

    assert out.returncode == 1, out.stdout
    assert "DRIFT" in out.stdout
    assert "prune" in out.stdout, "the check must NAME the CronJob that lags"
    assert "sha-cd0f002" in out.stdout


def test_a_current_cronjob_is_in_the_table_and_passes(tmp_path):
    out = _run(tmp_path,
               f"weirvern-worker weirvern-worker:{PIN}\n",
               f"weirvern-worker:{PIN}\n",
               "--pin", PIN,
               crons=f"weirvern-prune weirvern-worker:{PIN}\n")

    assert out.returncode == 0, out.stdout
    assert "cronjob.weirvern-prune" in out.stdout
    assert "DRIFT" not in out.stdout


def test_a_cronjob_with_no_images_is_not_reported_as_drift(tmp_path):
    # A suspended or malformed CronJob must not be turned into a phantom row with an empty image.
    out = _run(tmp_path,
               f"weirvern-worker weirvern-worker:{PIN}\n",
               f"weirvern-worker:{PIN}\n",
               "--pin", PIN,
               crons="weirvern-prune\n")

    assert out.returncode == 0, out.stdout
    assert "cronjob." not in out.stdout
