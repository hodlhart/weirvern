"""Every ConfigMap key a workload READS must be injected into its pod.

THE BUG THIS GUARDS: `MGMT_IFACE` was added to the ConfigMap and read by the Zeek
startup script, but the container's `env:` list only declared `ZEEK_IFACE`. A ConfigMap
having a key does not put it in a container -- a pod receives the keys it names (or all
of them via `envFrom`). So the variable was empty at runtime, the two-interface check
silently fell through to default-route detection, and an operator who explicitly set
MGMT_IFACE would never be told that the capture port and the management port were the
same NIC.

The failure is invisible from every angle: valid YAML, valid schema, healthy pod, and
a feature that simply never runs.

These tests PARSE the render rather than pattern-matching it. An earlier version used
regexes, and a false negative came from `namespace:` sitting between the ConfigMap's
`name:` and `data:` -- the regex silently failed to match and reported the ConfigMap as
empty. Structured data deserves a structured parser.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
K8S = REPO / "k8s"


@pytest.fixture(scope="module")
def docs() -> list[dict]:
    """The kustomize render, as parsed YAML documents."""
    import yaml

    exe = Path.home() / ".local" / "bin" / "kustomize"
    if not exe.exists():
        pytest.skip("kustomize not installed")
    r = subprocess.run([str(exe), "build", str(K8S)],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        pytest.fail(f"kustomize build failed: {r.stderr[:400]}")
    return [d for d in yaml.safe_load_all(r.stdout) if d]


def _find(docs: list[dict], kind: str, name: str) -> dict:
    for d in docs:
        if d.get("kind") == kind and d.get("metadata", {}).get("name") == name:
            return d
    pytest.fail(f"{kind}/{name} not found in the render")


def _pod_spec(docs: list[dict], kind: str, name: str) -> dict:
    obj = _find(docs, kind, name)
    return obj["spec"]["template"]["spec"]


def _containers(spec: dict) -> list[dict]:
    return list(spec.get("initContainers") or []) + list(spec.get("containers") or [])


# --- the operator Role's scope (issue #10) ----------------------------------------------------
def _operator_rules(docs: list[dict]) -> list[dict]:
    return list(_find(docs, "Role", "weirvern-operator")["rules"])


def test_every_configmap_write_is_name_scoped(docs):
    """A patch/update on configmaps must name its objects. `create` is exempt, and the reason is
    measured, not stylistic: the API server denies a create scoped by resourceNames even when the
    name matches exactly (probe Role, live cluster, 2026-10-16) -- so a name-scoped create would
    silently break the users store's first startup."""
    for rule in _operator_rules(docs):
        if "configmaps" not in rule.get("resources", []):
            continue
        writes = set(rule.get("verbs", [])) & {"patch", "update"}
        if writes:
            assert rule.get("resourceNames"), (
                f"unscoped configmap write {sorted(writes)}: name the objects this may touch")


def test_every_scale_grant_is_name_scoped_to_what_the_cli_drives(docs):
    """`weirvern stop/start` scales exactly runtime.WORKLOADS. An unscoped scale grant can
    rescale anything in the namespace; the scope is the list itself, not a copy of it."""
    from weirvern.admin.runtime import WORKLOADS

    by_kind: dict[str, set] = {}
    for name, kind in WORKLOADS:
        by_kind.setdefault(kind, set()).add(name)

    seen = set()
    for rule in _operator_rules(docs):
        for res in rule.get("resources", []):
            if not res.endswith("/scale"):
                continue
            names = rule.get("resourceNames")
            assert names, f"unscoped {res} grant: the stop/start path must name its workloads"
            kind = res.split("/")[0][:-1]  # deployments/scale -> deployment
            assert kind in by_kind, f"scale granted on {res}, which the CLI does not drive"
            assert set(names) <= by_kind[kind], (
                f"{res} names {sorted(set(names) - by_kind[kind])}, beyond the CLI's workloads")
            seen.add(kind)
    assert seen, "no scale rule found at all -- did the stop/start path lose its grant?"


def test_update_is_granted_on_no_workload_object(docs):
    """A PUT replaces the whole object. `update` may appear only on a /scale subresource, where
    it carries spec.replicas alone."""
    for rule in _operator_rules(docs):
        if "update" not in rule.get("verbs", []):
            continue
        for res in rule.get("resources", []):
            assert res.endswith("/scale"), (
                f"update on {res}: one malformed PUT could strip a securityContext")


# --- the specific regression ---------------------------------------------------
def test_mgmt_iface_is_in_the_configmap(docs):
    cm = _find(docs, "ConfigMap", "weirvern-env")
    data = cm.get("data") or {}
    assert "MGMT_IFACE" in data, (
        "MGMT_IFACE is missing from the ConfigMap; the two-port model cannot be "
        "detected at runtime without it"
    )
    assert data["MGMT_IFACE"], "MGMT_IFACE is present but empty"


def test_zeek_receives_every_interface_variable_it_reads(docs):
    """Zeek's startup script reads ZEEK_IFACE and MGMT_IFACE. Both must be declared.

    THE REGRESSION: MGMT_IFACE was in the ConfigMap and referenced by the script, but
    absent from the container's env list, so it was empty inside the pod.
    """
    spec = _pod_spec(docs, "DaemonSet", "zeek")
    pods_envfrom = spec.get("envFrom")
    assert not pods_envfrom, "pod-level envFrom would change how this is wired"

    names: set[str] = set()
    envfrom_used = False
    for c in _containers(spec):
        if c.get("envFrom"):
            envfrom_used = True
        for e in c.get("env") or []:
            names.add(e.get("name", ""))
    if envfrom_used:
        pytest.skip("a container uses envFrom; all ConfigMap keys are imported")

    for var in ("ZEEK_IFACE", "MGMT_IFACE"):
        assert var in names, (
            f"the zeek container reads ${var} but does not declare it in env:, so it "
            f"is empty at runtime and every check that uses it is dead code"
        )


def test_the_startup_script_and_the_env_list_agree(docs):
    """Any ${VAR} the startup script references must be declared in env: or set by the
    script itself. Catches the whole class, not just MGMT_IFACE."""
    spec = _pod_spec(docs, "DaemonSet", "zeek")
    declared: set[str] = set()
    script = ""
    for c in _containers(spec):
        for e in c.get("env") or []:
            declared.add(e.get("name", ""))
        for arg in c.get("args") or []:
            script += arg

    referenced = set(re.findall(r"\$\{?([A-Z][A-Z0-9_]{2,})\}?", script))
    # Set by the script itself, or by the kernel/container runtime. MODE and MGMT are
    # the script's own derived locals (MODE="${SENSOR_MODE:-loch}"), so requiring them
    # in env: would be wrong -- and an earlier version of this test did exactly that,
    # flagging a correct script.
    internal = {
        "IFACE", "IFARGS", "MGMT", "MODE", "DEFROUTE", "CAPS", "IFLAGS", "HOME", "PATH", "PWD",
        "SHELL", "HOSTNAME", "KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT",
        # BPF is the script's OWN local: it is built from WEIRVERN_CAPTURE_EXCLUDE_CIDRS and
        # assigned before use (`BPF=""` then appended to). Requiring it in env: would be wrong for
        # the same reason MODE and MGMT are wrong -- it is derived, not configured.
        "BPF",
        # Locals of the per-NIC startup loop and the siphon init's plan-derived list.
        "IFACES", "COUNT", "LOGDIR", "PIDS", "PLAN_IFACES",
        # The runtime merge of the trunk probe's state file with configured NICs.
        "CONFIG_IFACES", "STATE_IFACES",
        # The trunk init's own local: it is assigned from CAPTURE_IFACE/ZEEK_IFACE.
        "PARENT",
    }
    missing = {v for v in referenced if v not in declared and v not in internal}
    assert not missing, (
        f"the zeek startup script references {sorted(missing)} but the container does "
        f"not declare them, so they are empty at runtime"
    )


def test_no_workload_reads_a_missing_configmap_key(docs):
    """A configMapKeyRef to a key that does not exist makes the pod fail to start."""
    cm = _find(docs, "ConfigMap", "weirvern-env")
    keys = set((cm.get("data") or {}).keys())

    referenced: set[str] = set()
    for kind in ("Deployment", "DaemonSet", "Job", "StatefulSet"):
        for d in docs:
            if d.get("kind") != kind:
                continue
            spec = d["spec"]["template"]["spec"]
            for c in _containers(spec):
                for e in c.get("env") or []:
                    ref = (e.get("valueFrom") or {}).get("configMapKeyRef")
                    # An `optional: true` reference to a missing key is intentional
                    # and safe; a required one that is absent stops the pod starting.
                    if ref and ref.get("name") == "weirvern-env" and not ref.get("optional"):
                        referenced.add(ref.get("key", ""))

    missing = referenced - keys
    assert not missing, (
        f"these keys are referenced by a required configMapKeyRef but absent from the "
        f"ConfigMap, so those pods will not start: {sorted(missing)}"
    )


def test_the_two_interfaces_are_not_the_same_by_default(docs):
    """The shipped default must not point both roles at one NIC -- that is the
    configuration that produces a broadcast-only capture."""
    data = _find(docs, "ConfigMap", "weirvern-env").get("data") or {}
    zeek, mgmt = data.get("ZEEK_IFACE", ""), data.get("MGMT_IFACE", "")
    assert zeek and mgmt, "both interface vars must have defaults"
    assert zeek != mgmt, (
        f"ZEEK_IFACE and MGMT_IFACE both default to '{zeek}'; the capture port must be "
        f"a separate interface from the management port"
    )


def test_root_containers_are_only_ones_with_a_documented_reason(docs):
    """Root is required in exactly two places, both verified on a real cluster and
    both documented in their manifests:

      zeek              -- Kubernetes DROPS added capabilities for non-root containers,
                           so CAP_NET_RAW only survives at uid 0. Without it the sensor
                           crashes with "pcap_error: socket: Operation not permitted",
                           which reads like a bad interface.
      fix-permissions   -- an init container that chowns the ClickHouse data volume to
                           the clickhouse uid. It runs before the server and exits; the
                           kubelet refuses it under runAsNonRoot.

    Anything else at uid 0 is a new privilege grant and should be a deliberate decision,
    not something that slips in unnoticed. This test is the tripwire for that.

    ── AN UNSET UID WAS INVISIBLE TO THIS TRIPWIRE (audit F041, CONFIRMED) ──────────────────────

    It resolved `uid = sc.get("runAsUser", pod_sc.get("runAsUser"))` and flagged `uid == 0`. A
    container that sets runAsUser NOWHERE resolves to None, not 0, so it was skipped -- and a
    container with no runAsUser and no runAsNonRoot runs as whatever its IMAGE says, which is
    usually root, because root is the container default.

    Measured on the live cluster: `goflow2` was exactly that shape at both levels, and it happened
    to run as uid 100 only because the goflow2 image declares `USER flow`. Nothing in the manifest
    said so, the tripwire could not see it, and one image update would have collected flow data as
    root with no guard noticing. It is now pinned with runAsNonRoot and an explicit uid, and this
    test treats an UNSPECIFIED uid as needing the same deliberate decision as root -- with
    `zeek`'s own manifest showing why an unspecified uid is not safe merely because it is not 0.
    """
    # siphon-forwarding-init is deliberately root: it writes the host's /proc/sys and netfilter
    # through a privileged hostPath, the one job the capture container must not do. It is inert
    # outside siphon mode. trunk-init is root because creating VLAN devices needs NET_ADMIN,
    # which Kubernetes only grants to a root container.
    expected_root = {"zeek", "fix-permissions", "siphon-forwarding-init", "trunk-init"}
    # Containers whose uid is unspecified at BOTH levels. They inherit the image's USER, which for
    # most images is root, so each one needs an explicit decision like root does.
    expected_unspecified: set[str] = set()

    root: set[str] = set()
    unspecified: set[str] = set()
    for kind in ("Deployment", "DaemonSet", "Job", "StatefulSet"):
        for d in docs:
            if d.get("kind") != kind:
                continue
            spec = d["spec"]["template"]["spec"]
            pod_sc = spec.get("securityContext") or {}
            for c in _containers(spec):
                sc = c.get("securityContext") or {}
                uid = sc.get("runAsUser", pod_sc.get("runAsUser"))
                name = c.get("name", "?")
                if uid == 0:
                    root.add(name)
                elif uid is None:
                    unspecified.add(name)

    unexpected = root - expected_root
    assert not unexpected, (
        f"these containers run as root without a documented reason: {sorted(unexpected)}. "
        f"If deliberate, add the name to `expected` in this test and explain why in the "
        f"manifest — a silently-root workload widens the blast radius."
    )
    assert unspecified == expected_unspecified, (
        f"containers whose uid is UNSPECIFIED at every level: {sorted(unspecified)}. An unset "
        f"runAsUser is not a neutral default -- it means 'take whatever the image says', and the "
        f"container default is root. Set runAsNonRoot and an explicit uid, or add the name to "
        f"`expected_unspecified` here and explain in the manifest why the image's own USER is "
        f"trusted. `goflow2` was the case that proved this: it ran as uid 100 purely because its "
        f"image declared `USER flow`, with nothing in the deployment pinning it."
    )
    # And the documented ones must actually still be there: if a capability fix makes
    # zeek able to run unprivileged, this test should be updated rather than quietly
    # passing with an empty set.
    assert "zeek" in root, (
        "the zeek container no longer runs as root; if capture still works, the note in "
        "32-zeek.yaml about dropping capabilities for non-root containers is stale"
    )


def test_every_intercept_variable_the_cli_reads_is_settable_in_the_configmap():
    """THE GAP FOUND BY RUNNING A 1-HOUR INTERCEPT.

    `weirvern intercept` falls back to INTERCEPT_SEGMENT / INTERCEPT_ADDR / INTERCEPT_GATEWAY
    when the flags are absent, and all three were in `.env.example` — but NOT in the ConfigMap.
    So a cluster deployment had no way to configure them except by hand-passing flags to a
    command inside a pod, every time. Measured in the deployed pod: all three empty, and the
    command reporting "missing: segment, our address, gateway".

    An operator following the README would have hit a siphon mode that could not be configured.
    This asserts the CLI's fallbacks and the ConfigMap agree, so a new variable cannot be added
    to one and forgotten in the other.
    """
    import re
    from pathlib import Path as _P
    root = _P(__file__).resolve().parents[1]
    cli = (root / "weirvern" / "admin" / "cli.py").read_text()
    cm = (root / "k8s" / "20-configmap-env.yaml").read_text()
    env_example = (root / ".env.example").read_text()

    # Every INTERCEPT_* name the CLI asks for by name.
    read = set(re.findall(r'_get\(\s*"(INTERCEPT_[A-Z_]+)"', cli))
    assert read, "the CLI no longer reads any INTERCEPT_* variable -- has intercept changed?"

    for name in sorted(read):
        assert name in cm, f"{name} is read by the CLI but is not in the ConfigMap"
        assert name in env_example, f"{name} is read by the CLI but not in .env.example"


def test_the_intercept_defaults_are_empty_not_plausible():
    """An empty segment means preflight CANNOT pass, so siphon refuses to start. A default that
    looked plausible (a guessed CIDR, or an address) would instead poison hosts the operator
    never chose."""
    import re
    from pathlib import Path as _P
    cm = (_P(__file__).resolve().parents[1] / "k8s" / "20-configmap-env.yaml").read_text()
    for name in ("INTERCEPT_SEGMENT", "INTERCEPT_ADDR", "INTERCEPT_GATEWAY"):
        m = re.search(rf'^\s*{name}:\s*"?([^"\n]*)"?\s*$', cm, re.M)
        assert m, f"{name} is not present in the ConfigMap"
        assert m.group(1).strip() == "", (
            f"{name} ships a non-empty default ({m.group(1)!r}). A default here is a range "
            f"nobody chose, and siphon mode would act on it."
        )
