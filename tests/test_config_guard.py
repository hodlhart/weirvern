"""The apply guard: a manifest must never blank a capture setting that is live.

THE INCIDENT THESE TESTS ENCODE (2026-11-20 23:33:43). `kubectl apply -k k8s/` restored the
manifest's placeholders over the live ConfigMap: CAPTURE_IFACE and NETFLOW_IFACE emptied,
ZEEK_IFACES emptied, SENSOR_MODE siphon -> loch, INTERCEPT_PLANS emptied. The DaemonSet rolled,
the tap selected zero targets, and flow AND Zeek capture stopped for ~18 hours.

The two halves of the fix are tested separately:
  * `decide()` is the PRE-ROLL guard -- it runs before kubectl is invoked at all.
  * `apply()` renders, merges GUI-recorded values back, applies, and reads the ConfigMap back.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from weirvern.admin import config_guard as cg  # noqa: E402

LIVE = {
    "ZEEK_IFACE": "eth1",
    "ZEEK_IFACES": "eth1,eth2",
    "CAPTURE_IFACE": "eth1",
    "MGMT_IFACE": "eth0",
    "SENSOR_MODE": "siphon",
    "NETFLOW_MODE": "auto",
    "NETFLOW_IFACE": "eth1,eth2",
    "INTERCEPT_TARGETS": "*",
    "INTERCEPT_PLANS": '{"eth1":{"mode":"siphon"}}',
    "DETECT_INTERVAL_S": "300",
}

# What k8s/20-configmap-env.yaml ships: the placeholders that caused the outage.
MANIFEST = {
    "ZEEK_IFACE": "eth1",
    "ZEEK_IFACES": "",
    "CAPTURE_IFACE": "",
    "MGMT_IFACE": "eth0",
    "SENSOR_MODE": "loch",
    "NETFLOW_MODE": "auto",
    "NETFLOW_IFACE": "",
    "INTERCEPT_TARGETS": "",
    "INTERCEPT_PLANS": "",
    "DETECT_INTERVAL_S": "300",
}


def _records() -> dict[str, str]:
    return {
        "CAPTURE_IFACE": "eth1",
        "ZEEK_IFACES": "eth1,eth2",
        "NETFLOW_IFACE": "eth1,eth2",
        "SENSOR_MODE": "siphon",
        "INTERCEPT_TARGETS": "*",
        "INTERCEPT_PLANS": '{"eth1":{"mode":"siphon"}}',
    }


# ── the refusal: blanking a key that is set, with nothing to restore it ───────────────────────
def test_blanks_with_no_gui_record_are_refused_and_named():
    decision = cg.decide(LIVE, MANIFEST, {})
    assert decision.ok is False
    message = decision.message()
    assert "REFUSING TO APPLY" in message
    # Every key that would be emptied is named with its live value.
    for key in ("ZEEK_IFACES", "CAPTURE_IFACE", "NETFLOW_IFACE", "INTERCEPT_TARGETS", "INTERCEPT_PLANS"):
        assert f"{key} (live " in message, message
    assert "--allow-blank" in message
    # The remedy names exactly the keys that need an explicit decision.
    assert "ZEEK_IFACES,CAPTURE_IFACE,NETFLOW_IFACE,INTERCEPT_TARGETS,INTERCEPT_PLANS" in message


def test_the_blank_refusal_names_the_interface_values_that_would_be_lost():
    """The message an operator reads at 3am must say what the value WAS."""
    decision = cg.decide(LIVE, MANIFEST, {})
    assert 'NETFLOW_IFACE (live "eth1,eth2")' in decision.message()
    assert 'CAPTURE_IFACE (live "eth1")' in decision.message()


def test_a_capture_change_with_no_gui_record_is_refused():
    """NETFLOW_MODE active -> auto was the other half of the same outage."""
    manifest = dict(MANIFEST)
    manifest.update({"ZEEK_IFACES": "eth1,eth2", "CAPTURE_IFACE": "eth1",
                     "NETFLOW_IFACE": "eth1,eth2", "INTERCEPT_TARGETS": "*",
                     "INTERCEPT_PLANS": '{"eth1":{"mode":"siphon"}}', "SENSOR_MODE": "siphon"})
    live = dict(LIVE, NETFLOW_MODE="active")
    decision = cg.decide(live, manifest, {})
    assert decision.ok is False
    assert "NETFLOW_MODE" in decision.message()
    assert '"active" -> "auto"' in decision.message()
    assert "--allow-capture-change" in decision.message()


# ── the repair: GUI-recorded values are merged back, so the deploy converges to the choice ────
def test_gui_recorded_values_are_restored_instead_of_blanked():
    decision = cg.decide(LIVE, MANIFEST, _records())
    assert decision.ok is True, decision.message()
    assert decision.effective["CAPTURE_IFACE"] == "eth1"
    assert decision.effective["ZEEK_IFACES"] == "eth1,eth2"
    assert decision.effective["NETFLOW_IFACE"] == "eth1,eth2"
    assert decision.effective["SENSOR_MODE"] == "siphon"
    assert decision.effective["INTERCEPT_PLANS"] == '{"eth1":{"mode":"siphon"}}'
    restored = {p.key for p in decision.preserved if p.why == "gui-record"}
    assert restored >= {"CAPTURE_IFACE", "ZEEK_IFACES", "NETFLOW_IFACE", "SENSOR_MODE",
                        "INTERCEPT_PLANS"}


def test_a_previous_clobber_is_repaired_even_when_live_already_agrees_with_the_manifest():
    """After the bad apply, live says "" too. The annotation is the only surviving copy."""
    live = dict(LIVE)
    live["CAPTURE_IFACE"] = ""
    live["NETFLOW_IFACE"] = ""
    manifest = dict(MANIFEST)
    decision = cg.decide(live, manifest, _records())
    assert decision.ok is True
    assert decision.effective["CAPTURE_IFACE"] == "eth1"
    assert decision.effective["NETFLOW_IFACE"] == "eth1,eth2"
    assert {p.key for p in decision.preserved if p.why == "clobber-repair"} >= {
        "CAPTURE_IFACE", "NETFLOW_IFACE"}


def test_an_explicit_allow_blank_still_works_and_is_reported():
    decision = cg.decide(
        LIVE, MANIFEST, _records(),
        allow_blank={"CAPTURE_IFACE"}, allow_capture_change=True,
    )
    assert decision.ok is True
    assert decision.effective["CAPTURE_IFACE"] == ""
    assert ("CAPTURE_IFACE", "eth1", "") in decision.changed


# ── ordinary changes must still apply ────────────────────────────────────────────────────────
def test_a_legitimate_setting_change_applies():
    manifest = dict(MANIFEST)
    manifest["DETECT_INTERVAL_S"] = "240"
    decision = cg.decide(LIVE, manifest, _records())
    assert decision.ok is True
    assert decision.effective["DETECT_INTERVAL_S"] == "240"
    assert ("DETECT_INTERVAL_S", "300", "240") in decision.changed


def test_a_gui_owned_setting_the_manifest_would_revert_keeps_the_live_value():
    live = dict(LIVE, DETECT_INTERVAL_S="240")
    manifest = dict(MANIFEST, DETECT_INTERVAL_S="300")
    decision = cg.decide(live, manifest, dict(_records(), DETECT_INTERVAL_S="240"))
    assert decision.ok is True
    assert decision.effective["DETECT_INTERVAL_S"] == "240"


def test_a_key_only_on_the_live_configmap_is_never_dropped():
    live = dict(LIVE, ONLY_LIVE="keep-me")
    decision = cg.decide(live, MANIFEST, _records())
    assert decision.effective["ONLY_LIVE"] == "keep-me"
    assert "ONLY_LIVE" in decision.dropped_live_keys


def test_a_fresh_install_with_no_live_configmap_applies_the_manifest():
    decision = cg.decide({}, MANIFEST, {})
    assert decision.ok is True
    assert decision.effective["CAPTURE_IFACE"] == ""


def test_a_malformed_annotation_is_not_permission_to_blank():
    decision = cg.decide(LIVE, MANIFEST, cg.gui_records({"weirvern.io/gui-written-keys": "{"}))
    assert decision.ok is False


# ── the apply path: render, merge, apply, read back ───────────────────────────────────────────
class FakeKubectl:
    """Records argv and serves a live ConfigMap that apply() can mutate."""

    def __init__(self, live: dict[str, str], annotations: dict[str, str] | None = None):
        self.live = dict(live)
        self.annotations = dict(annotations or {})
        self.calls: list[list[str]] = []

    def __call__(self, argv, cwd):
        self.calls.append(list(argv))
        if argv[:2] == ["kubectl", "kustomize"]:
            doc = {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "weirvern-env", "namespace": "weirvern"},
                "data": dict(MANIFEST),
            }
            ds = {"apiVersion": "apps/v1", "kind": "DaemonSet",
                  "metadata": {"name": "zeek", "namespace": "weirvern"},
                  "spec": {"template": {"spec": {"containers": []}}}}
            return SimpleNamespace(returncode=0, stdout=json.dumps(doc) + "\n---\n"
                                   + json.dumps(ds), stderr="")
        if argv[:3] == ["kubectl", "-n", "weirvern"] and argv[3] == "get":
            obj = {"metadata": {"name": "weirvern-env",
                                "annotations": self.annotations}, "data": self.live}
            return SimpleNamespace(returncode=0, stdout=json.dumps(obj), stderr="")
        if argv[:3] == ["kubectl", "apply", "-f"]:
            # Simulate the apply by reading the temp file and adopting the env ConfigMap data.
            import yaml
            with open(argv[3]) as fh:
                docs = [d for d in yaml.safe_load_all(fh) if d]
            for doc in docs:
                if doc.get("kind") == "ConfigMap":
                    self.live = dict(doc.get("data") or {})
            return SimpleNamespace(returncode=0, stdout="applied", stderr="")
        raise AssertionError(f"unexpected argv: {argv}")


def _annotation(records: dict[str, str]) -> dict[str, str]:
    return {cg.GUI_ANNOTATION: json.dumps({k: {"value": v, "at": "2026-11-20T00:00:00Z"}
                                           for k, v in records.items()})}


def test_apply_refuses_before_kubectl_apply_is_called(tmp_path):
    fake = FakeKubectl(LIVE)  # no annotation: nothing can restore the blanks
    result = cg.apply(tmp_path, runner=fake)
    assert result.ok is False
    assert result.code == 3
    assert "REFUSING TO APPLY" in result.message
    assert not any(call[:2] == ["kubectl", "apply"] for call in fake.calls), (
        "the guard must refuse BEFORE kubectl apply, i.e. before the DaemonSet can roll")


def test_apply_merges_the_recorded_values_and_reads_them_back(tmp_path):
    fake = FakeKubectl(LIVE, _annotation(_records()))
    result = cg.apply(tmp_path, runner=fake)
    assert result.ok is True, result.message
    assert fake.live["CAPTURE_IFACE"] == "eth1"
    assert fake.live["NETFLOW_IFACE"] == "eth1,eth2"
    assert fake.live["SENSOR_MODE"] == "siphon"
    # And it says what it preserved rather than doing it silently.
    assert "preserved the operator's settings" in result.message


def test_apply_fails_loudly_if_capture_was_blanked_after_the_apply(tmp_path):
    class LyingKubectl(FakeKubectl):
        def __call__(self, argv, cwd):
            out = super().__call__(argv, cwd)
            if argv[:3] == ["kubectl", "apply", "-f"]:
                self.live["CAPTURE_IFACE"] = ""  # the apply "succeeded" but capture is gone
            return out

    fake = LyingKubectl(LIVE, _annotation(_records()))
    result = cg.apply(tmp_path, runner=fake)
    assert result.ok is False
    assert result.code == 4
    assert "APPLY DID NOT TAKE" in result.message
    assert "CAPTURE_IFACE" in result.message


def test_dry_run_applies_nothing(tmp_path):
    fake = FakeKubectl(LIVE, _annotation(_records()))
    result = cg.apply(tmp_path, dry_run=True, runner=fake)
    assert result.ok is True
    assert "DRY RUN" in result.message
    assert not any(call[:2] == ["kubectl", "apply"] for call in fake.calls)


def test_a_missing_live_configmap_is_a_fresh_install_not_an_error(tmp_path):
    def fake(argv, cwd):
        if argv[:2] == ["kubectl", "kustomize"]:
            return SimpleNamespace(returncode=0, stdout=json.dumps({
                "kind": "ConfigMap", "metadata": {"name": "weirvern-env"},
                "data": {"CAPTURE_IFACE": ""}}), stderr="")
        if argv[:3] == ["kubectl", "-n", "weirvern"]:
            return SimpleNamespace(returncode=1, stdout="",
                                   stderr='Error from server (NotFound): configmaps "weirvern-env" not found')
        return SimpleNamespace(returncode=0, stdout="applied", stderr="")

    result = cg.apply(tmp_path, runner=fake)
    assert result.ok is True, result.message


# ── the real manifests are in scope ───────────────────────────────────────────────────────────
def test_the_shipped_manifest_is_the_dangerous_shape_this_guard_exists_for():
    """If someone "fixes" the manifest by filling in site values, this test tells them the guard
    is still doing its job -- and if they empty a key that was never dangerous, nothing breaks."""
    import subprocess
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    r = None
    try:
        for argv in (["kubectl", "kustomize", str(root / "k8s")],
                     ["kustomize", "build", str(root / "k8s")]):
            try:
                r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
            except FileNotFoundError:
                continue
            if r.returncode == 0:
                break
    except subprocess.TimeoutExpired:
        pytest.skip("kustomize render timed out")
    if r is None or r.returncode != 0:
        pytest.skip("kustomize is not installed")
    import yaml
    docs = [d for d in yaml.safe_load_all(r.stdout) if d]
    doc = next(d for d in docs if d.get("kind") == "ConfigMap"
               and d["metadata"]["name"] == "weirvern-env")
    # The manifest still HAS the keys (so a fresh install works) but their dangerous values are
    # placeholders -- which is exactly why the guard, not the file, is the safety boundary.
    assert "CAPTURE_IFACE" in doc["data"]
    assert doc["data"]["CAPTURE_IFACE"] == ""
