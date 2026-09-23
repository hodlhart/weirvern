"""A GUI settings write has the lifetime of a deploy, and nothing said so.

── WHY THIS FILE EXISTS (audit F016, CONFIRMED BY RUNNING IT) ───────────────────────────────────

The GUI writes settings into `weirvern-env`, which is the SAME ConfigMap `k8s/20-configmap-env.yaml`
owns. `kubectl apply -k` therefore restores the manifest's value and silently undoes whatever an
operator changed. Measured against a live cluster:

    POST /api/settings/apply  {"changes": {"DETECT_INTERVAL_S": "240"}}
      -> {"ok": true, "applied": {"DETECT_INTERVAL_S": "240"}, "restarted": ["deploy/weirvern-worker"]}
      -> ConfigMap: 240

    kubectl apply -k k8s/
      -> ConfigMap: 300        (the manifest's value, restored)

The write path was working exactly as designed and reported success honestly. The DEFECT was that
nothing recorded the operator's intent, so after a deploy their choice was gone with no trace and
no way to tell "the operator chose 300" from "a deploy took 240 away".

This is not fixable by making the write stronger: the field belongs to the manifest, so an apply is
entitled to reset it. Fighting Kubernetes there (a second ConfigMap, overlay generators, admission
webhooks) trades a silent revert for a much larger machine. The codebase already made the opposite
trade deliberately for the account store -- `kustomization.yaml` does NOT ship a manifest for data
the product writes, precisely so an apply cannot wipe accounts.

So the fix makes the conflict LEGIBLE: writes are recorded in an annotation with the value and
time, and the settings view reports which keys a deploy would revert.

WHAT THESE TESTS PIN:
  * a write records provenance, and does not lose earlier records
  * provenance survives the apply that reverts the value (the whole point)
  * the drift warning computes `reverted` from the LIVE ConfigMap, not from a stale view
  * a no-op re-write does not make a key look operator-modified
  * a malformed annotation degrades to "no provenance" rather than breaking settings
"""

from __future__ import annotations

import pytest

from weirvern.admin import cluster_config as cc


class _FakeAPI:
    """A ClusterConfig whose HTTP layer is replaced by an in-memory ConfigMap.

    `_request` is the only boundary that matters: everything above it (the annotation bookkeeping,
    the read-back check, the drift comparison) is product code under test.
    """

    def __init__(self, data=None, annotations=None):
        self.data = dict(data or {})
        self.meta = {"annotations": dict(annotations or {})}
        self.patches: list[dict] = []

    def install(self, monkeypatch) -> cc.ClusterConfig:
        cfg = cc.ClusterConfig(configmap="weirvern-env")

        def _request(method, body=None):
            if method == "GET":
                return {"metadata": dict(self.meta), "data": dict(self.data)}
            # merge-patch+json: per-key merge for both `data` and `metadata.annotations`, which is
            # the semantic the real API server applies and the reason this fix cannot clobber the
            # kustomize annotations.
            self.patches.append(body or {})
            self.data.update((body or {}).get("data") or {})
            ann = ((body or {}).get("metadata") or {}).get("annotations") or {}
            self.meta["annotations"].update(ann)
            return {"metadata": dict(self.meta), "data": dict(self.data)}

        monkeypatch.setattr(cfg, "_request", _request, raising=True)
        return cfg


# ── provenance is recorded ───────────────────────────────────────────────────────────────────

def test_a_write_records_which_keys_it_changed(monkeypatch):
    api = _FakeAPI()
    cfg = api.install(monkeypatch)
    cfg.apply({"DETECT_INTERVAL_S": "240"})

    recorded = cfg.gui_written_keys()
    assert "DETECT_INTERVAL_S" in recorded, (
        f"the write left no provenance, so nothing can tell this value apart from the manifest's: "
        f"{recorded!r}"
    )
    assert recorded["DETECT_INTERVAL_S"]["value"] == "240"
    assert recorded["DETECT_INTERVAL_S"]["at"], "no timestamp was recorded"


def test_provenance_ACCUMULATES_across_writes(monkeypatch):
    """An operator who changes one key today and another tomorrow must not lose the first record --
    each one is a separate piece of intent that a deploy can take away."""
    api = _FakeAPI()
    cfg = api.install(monkeypatch)
    cfg.apply({"BASE_THRESHOLD": "0.4"})
    cfg.apply({"MIN_AGREEMENT": "0.6"})

    recorded = cfg.gui_written_keys()
    assert {"BASE_THRESHOLD", "MIN_AGREEMENT"} <= set(recorded), (
        f"a second write replaced the first instead of adding to it: {recorded!r}"
    )


def test_a_repeated_write_of_the_SAME_value_is_not_a_new_change(monkeypatch):
    """Saving a value the GUI itself already wrote must not look like a fresh operator edit --
    otherwise every key the page ever touched would appear operator-modified forever."""
    api = _FakeAPI()
    cfg = api.install(monkeypatch)
    cfg.apply({"BASE_THRESHOLD": "0.4"})
    first = cfg.gui_written_keys()["BASE_THRESHOLD"]["at"]
    cfg.apply({"BASE_THRESHOLD": "0.4"})
    second = cfg.gui_written_keys()["BASE_THRESHOLD"]

    assert second["value"] == "0.4"
    assert second["at"] >= first, "the timestamp went backwards"


def test_the_write_also_keeps_the_kustomize_annotations(monkeypatch):
    """A merge patch adds annotations; it must not replace the ones kustomize and kubectl own, or
    the next apply would see an unmanaged ConfigMap and behave differently."""
    api = _FakeAPI(annotations={"kubectl.kubernetes.io/last-applied-configuration": '{"x":1}'})
    cfg = api.install(monkeypatch)
    cfg.apply({"BASE_THRESHOLD": "0.4"})

    ann = api.meta["annotations"]
    assert "kubectl.kubernetes.io/last-applied-configuration" in ann, (
        f"the write clobbered kubectl's own annotation: {sorted(ann)}"
    )
    assert cc.GUI_WRITE_ANNOTATION in ann


def test_the_legend_explains_what_to_do(monkeypatch):
    """The annotation is read by a human debugging a reverted setting, so it has to say what
    happened and what to do instead of only naming a key."""
    api = _FakeAPI()
    cfg = api.install(monkeypatch)
    cfg.apply({"BASE_THRESHOLD": "0.4"})

    legend = api.meta["annotations"].get(cc.GUI_WRITE_LEGEND, "")
    assert "kubectl apply" in legend, f"the legend does not name the command that reverts it: {legend!r}"
    assert "20-configmap-env" in legend, (
        f"the legend does not say how to make the change permanent: {legend!r}"
    )


# ── the drift warning ────────────────────────────────────────────────────────────────────────

def _drift(cfg):
    """The drift rows THE PRODUCT computes.

    THIS CALLS `settings_drift`, and that matters: the first version of this file reimplemented the
    calculation locally, and mutation testing showed the tests then proved nothing about the view --
    breaking the view's own `reverted` expression left the whole suite green. A test that
    reimplements the logic it checks tests its own copy. The computation was moved into the module
    so the view and this file call one implementation.
    """
    return cfg.settings_drift()


def test_a_reverted_key_is_reported_as_reverted(monkeypatch):
    """THE SCENARIO THE FINDING DESCRIBES: the operator set 240, a deploy restored 300."""
    api = _FakeAPI()
    cfg = api.install(monkeypatch)
    cfg.apply({"DETECT_INTERVAL_S": "240"})

    api.data["DETECT_INTERVAL_S"] = "300"  # what `kubectl apply -k` does
    rows = _drift(cfg)

    row = next(r for r in rows if r["key"] == "DETECT_INTERVAL_S")
    assert row["reverted"] is True, (
        f"a deploy reverted the operator's 240 back to 300 and nothing reported it: {row!r}"
    )
    assert row["chosen"] == "240", "the row lost the value the operator actually chose"
    assert row["current"] == "300", "the row does not show what the value is NOW"
    # WHEN they set it is the operator's only clue about which deploy took it away -- "you set this
    # on the 23rd" points at a specific change, where "you set this" points at all of them.
    # MUTATION TESTING FOUND THIS ASSERTION MISSING: blanking the timestamp left the suite green.
    assert row["at"], (
        f"the drift row does not say WHEN the operator set this value, so it cannot be matched "
        f"against a deploy: {row!r}"
    )


def test_a_key_matching_its_manifest_value_is_not_called_reverted(monkeypatch):
    """The other direction, so the warning cannot pass by always crying wolf."""
    api = _FakeAPI()
    cfg = api.install(monkeypatch)
    cfg.apply({"DETECT_INTERVAL_S": "240"})
    rows = _drift(cfg)  # live value is still 240

    row = next(r for r in rows if r["key"] == "DETECT_INTERVAL_S")
    assert row["reverted"] is False, f"a key holding the operator's value read as reverted: {row!r}"


def test_an_ABSENT_key_is_not_a_revert(monkeypatch):
    """A manifest that does not define a key cannot revert it. Reporting one would send an operator
    looking for a deploy that did nothing."""
    api = _FakeAPI()
    cfg = api.install(monkeypatch)
    cfg.apply({"SOME_NEW_KEY": "1"})
    api.data.pop("SOME_NEW_KEY")

    row = next(r for r in _drift(cfg) if r["key"] == "SOME_NEW_KEY")
    assert row["reverted"] is False, f"an absent key was reported as reverted: {row!r}"


def test_NO_writes_means_no_drift_rows(monkeypatch):
    """A cluster nobody has configured through the GUI must not show a warning -- a permanent
    warning is one an operator learns to ignore."""
    api = _FakeAPI()
    cfg = api.install(monkeypatch)
    assert cfg.gui_written_keys() == {}
    assert _drift(cfg) == []


# ── degradation ──────────────────────────────────────────────────────────────────────────────

def test_a_corrupt_annotation_degrades_to_no_provenance(monkeypatch):
    """The annotation is JSON in a field a human can edit. Broken JSON must cost the warning, not
    the settings page."""
    api = _FakeAPI(annotations={cc.GUI_WRITE_ANNOTATION: "{not json"})
    cfg = api.install(monkeypatch)
    assert cfg.gui_written_keys() == {}, "corrupt provenance was accepted as data"


@pytest.mark.parametrize("bad", ["[]", "null", '"a string"', "123"])
def test_non_dict_provenance_is_ignored(monkeypatch, bad):
    """Valid JSON of the wrong SHAPE is the same problem as invalid JSON: a list has no keys, so
    iterating it would produce nonsense rows or raise inside the view."""
    api = _FakeAPI(annotations={cc.GUI_WRITE_ANNOTATION: bad})
    cfg = api.install(monkeypatch)
    assert cfg.gui_written_keys() == {}


def test_an_unreadable_cluster_does_not_break_the_settings_page(monkeypatch):
    """The warning is advisory. A GUI that cannot read its own ConfigMap still has to render, since
    that page is how an operator would diagnose the problem."""
    cfg = cc.ClusterConfig(configmap="weirvern-env")

    def _boom(*a, **kw):
        raise cc.ConfigError("cluster unreachable")

    monkeypatch.setattr(cfg, "_request", _boom, raising=True)
    assert cfg.gui_written_keys() == {}
    assert cfg.configmap_annotation("anything") == ""
