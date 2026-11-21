"""Make a manifest apply safe for the settings the GUI owns.

WHY THIS EXISTS (measured outage, 2026-11-20 23:33:43)
------------------------------------------------------
`kubectl apply -k k8s/` restored the manifest's PLACEHOLDERS over the live ConfigMap:
`CAPTURE_IFACE` and `NETFLOW_IFACE` became empty (they were `eth1` and `eth1,eth2`),
`ZEEK_IFACES` emptied, `SENSOR_MODE` went siphon -> loch and `INTERCEPT_PLANS` emptied. The
DaemonSet rolled two seconds later, the tap selected zero targets, and BOTH flow and Zeek capture
stopped for ~18 hours while every surface still looked configured.

The values were not lost from the record -- `weirvern.io/gui-written-keys` still named them -- but
nothing ENFORCED that record. This module enforces it at the only place that can: before the
manifests are applied.

WHAT IT DOES
------------
1. Renders the manifests (`kubectl kustomize`), so it reads exactly what would be applied.
2. Compares the pending `weirvern-env` data with the LIVE ConfigMap.
3. Refuses -- before anything is applied, therefore before the DaemonSet or tap can roll -- when
   a setting that is non-empty live would be BLANKED and has no recorded value to restore, or
   when a capture setting would CHANGE with no GUI record to justify it.
4. Restores GUI-recorded values into the rendered ConfigMap (including a value a PREVIOUS bad
   apply already blanked). A deploy therefore converges the cluster back to the operator's choice
   instead of reverting it.
5. Applies the merged render, then READS THE CONFIGMAP BACK and fails if a capture setting that
   was non-empty before is empty after.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It never drops a key that exists on the live ConfigMap but not in the manifest. The effective data
starts from the live values and overlays the manifest's changes, so an apply can add or change a
setting but can never make one disappear. A setting removed from a manifest is retired by an
operator explicitly, not as a side effect of a deploy.

This is the sanctioned deploy path (`weirvern apply`, `scripts/apply_safe.sh`). A raw
`kubectl apply -k` bypasses it; k8s/README.md and docs/deployment.md say so.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

NAMESPACE = "weirvern"
ENV_CONFIGMAP = "weirvern-env"
GUI_ANNOTATION = "weirvern.io/gui-written-keys"

# Settings whose value decides whether packets are captured and where. A blank or an unexplained
# change in any of these is the outage class this module exists to stop. Broader than the GUI's
# editable-key list on purpose: SENSOR_MODE and the intercept plan were clobbered in the measured
# incident yet are not GUI-editable keys.
CAPTURE_KEYS = frozenset({
    "ZEEK_IFACE",
    "ZEEK_IFACES",
    "CAPTURE_IFACE",
    "MGMT_IFACE",
    "NETFLOW_IFACE",
    "NETFLOW_MODE",
    "SENSOR_MODE",
    "INTERCEPT_TARGETS",
    "INTERCEPT_SEGMENT",
    "INTERCEPT_ADDR",
    "INTERCEPT_GATEWAY",
    "INTERCEPT_PLANS",
    "CHANNEL_NETFLOW",
    "SIPHON_NETFLOW",
    "SLUICE_IFACE",
    "WEIRVERN_CAPTURE_EXCLUDE_CIDRS",
})

BLANK_REFUSAL = (
    "REFUSING TO APPLY: the manifests would BLANK {n} setting(s) that are set on the live "
    "ConfigMap: {items}. A blank capture interface stops all capture. Fix k8s/20-configmap-env.yaml, "
    "or pass --allow-blank {keys} if the blank is intended."
)

CAPTURE_CHANGE_REFUSAL = (
    "REFUSING TO APPLY: the manifests would CHANGE {n} capture setting(s) with no GUI record to "
    "justify it: {items}. A deploy must not silently change how the sensor captures. Re-apply the "
    "setting in the GUI, or pass --allow-capture-change."
)

POST_APPLY_REFUSAL = (
    "APPLY DID NOT TAKE: after applying, the live ConfigMap still has a BLANK/CHANGED capture "
    "setting: {items}. Capture is not safe. Restore it before trusting the deployment."
)


class GuardError(RuntimeError):
    """The guard could not do its job (kubectl missing, render failed, API unreadable)."""


@dataclass(frozen=True)
class Refusal:
    kind: str  # "blank" | "capture-change"
    key: str
    live: str
    pending: str


@dataclass(frozen=True)
class Preserved:
    key: str
    live: str
    value: str
    why: str  # "gui-record" | "clobber-repair"


@dataclass
class Decision:
    effective: dict[str, str]
    preserved: list[Preserved] = field(default_factory=list)
    changed: list[tuple[str, str, str]] = field(default_factory=list)
    refusals: list[Refusal] = field(default_factory=list)
    dropped_live_keys: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.refusals

    def message(self) -> str:
        """The exact refusal, blanking first because that is the outage shape."""
        blanks = [r for r in self.refusals if r.kind == "blank"]
        changes = [r for r in self.refusals if r.kind == "capture-change"]
        parts: list[str] = []
        if blanks:
            parts.append(BLANK_REFUSAL.format(
                n=len(blanks),
                items=", ".join(f'{r.key} (live "{r.live}")' for r in blanks),
                keys=",".join(r.key for r in blanks),
            ))
        if changes:
            parts.append(CAPTURE_CHANGE_REFUSAL.format(
                n=len(changes),
                items=", ".join(f'{r.key} ("{r.live}" -> "{r.pending}")' for r in changes),
            ))
        return "\n".join(parts)


def gui_records(annotations: dict[str, Any] | None) -> dict[str, str]:
    """The GUI's recorded key -> value map, from the ConfigMap annotation.

    A malformed annotation is treated as EMPTY rather than as permission: the annotation is the
    only evidence of an operator's choice, and a parse failure must not turn a blanking apply into
    an allowed one.
    """
    raw = (annotations or {}).get(GUI_ANNOTATION)
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    out: dict[str, str] = {}
    for key, rec in parsed.items():
        if isinstance(rec, dict) and isinstance(rec.get("value"), str):
            out[str(key)] = rec["value"]
    return out


def decide(
    live: dict[str, str],
    pending: dict[str, str],
    records: dict[str, str],
    *,
    allow_blank: frozenset[str] | set[str] = frozenset(),
    allow_capture_change: bool = False,
) -> Decision:
    """Merge the pending manifest over the live ConfigMap, refusing the unsafe shapes.

    THE ORDER OF THE RULES IS THE INCIDENT, in order:

    * a non-empty live value that would become empty is the outage. If the GUI recorded a value,
      restore it (the deploy then does not blank anything); if not, REFUSE and name the keys.
    * a capture setting that would CHANGE with no GUI record is the other half of the same
      incident (`NETFLOW_MODE` active -> auto). REFUSE; a deploy must not silently re-point the
      sensor.
    * everything else is a normal settings change and is applied.
    """
    effective = dict(live)  # never drop a live key
    decision = Decision(effective=effective)

    for key, want in pending.items():
        want = "" if want is None else str(want)
        if key not in live:
            effective[key] = want
            continue
        have = str(live.get(key) or "")
        recorded = records.get(key)

        if want == have:
            # EVEN AN UNCHANGED PAIR CAN BE A PREVIOUS CLOBBER: if the recorded GUI value differs
            # from what both the manifest and the cluster now say, the pair agrees on the WRONG
            # value. Restore it, but only for the blank/capture shapes -- never resurrect a stale
            # value for an ordinary setting an operator may have changed deliberately.
            if recorded and recorded != want and (want == "" or key in CAPTURE_KEYS):
                effective[key] = recorded
                decision.preserved.append(Preserved(key, have, recorded, "clobber-repair"))
            continue

        if want == "":
            if key in allow_blank:
                effective[key] = ""
                decision.changed.append((key, have, ""))
            elif recorded:
                effective[key] = recorded
                decision.preserved.append(Preserved(key, have, recorded, "gui-record"))
            else:
                decision.refusals.append(Refusal("blank", key, have, want))
            continue

        if key in CAPTURE_KEYS and not allow_capture_change:
            if recorded is not None and recorded == have:
                # The manifest would revert an operator's live choice.
                effective[key] = have
                decision.preserved.append(Preserved(key, have, have, "gui-record"))
            elif recorded is not None and recorded == want:
                effective[key] = want
                decision.changed.append((key, have, want))
            elif recorded is not None:
                # A third value: the live one is newer than the record. Keep it and say so.
                effective[key] = have
                decision.preserved.append(Preserved(key, have, have, "gui-record"))
            else:
                decision.refusals.append(Refusal("capture-change", key, have, want))
            continue

        if recorded is not None and recorded == have and recorded != want:
            # A GUI-owned value the manifest would revert. Same rationale as above, for keys that
            # are not capture-critical: the GUI owns them.
            effective[key] = have
            decision.preserved.append(Preserved(key, have, have, "gui-record"))
            continue

        effective[key] = want
        decision.changed.append((key, have, want))

    decision.dropped_live_keys = sorted(k for k in live if k not in pending)
    return decision


# ── rendering and applying ───────────────────────────────────────────────────────────────────
Runner = Callable[[list[str], Path], Any]


def _default_runner(args: list[str], cwd: Path) -> Any:
    return subprocess.run(args, cwd=str(cwd), capture_output=True, text=True, timeout=180)


def render(project_dir: str | Path, runner: Runner | None = None) -> list[dict]:
    """The manifests exactly as kustomize would apply them."""
    run = runner or _default_runner
    root = Path(project_dir)
    k8s = root / "k8s"
    attempts = (
        ["kubectl", "kustomize", str(k8s)],
        ["kustomize", "build", str(k8s)],
    )
    last = ""
    for argv in attempts:
        try:
            r = run(argv, root)
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired as exc:
            raise GuardError(f"rendering the manifests timed out: {exc}") from exc
        if getattr(r, "returncode", 1) == 0:
            docs = [d for d in yaml.safe_load_all(getattr(r, "stdout", "") or "") if d]
            if docs:
                return docs
            last = "the render produced no documents"
            continue
        last = (getattr(r, "stderr", "") or getattr(r, "stdout", "") or "").strip()[:400]
    raise GuardError(f"could not render k8s/ ({last or 'kubectl/kustomize not found'})")


def _env_doc(docs: list[dict]) -> dict:
    for doc in docs:
        if doc.get("kind") == "ConfigMap" and (doc.get("metadata") or {}).get("name") == ENV_CONFIGMAP:
            return doc
    raise GuardError(f"the render does not contain ConfigMap/{ENV_CONFIGMAP}")


def read_live(project_dir: str | Path, runner: Runner | None = None) -> dict:
    """The live ConfigMap as {"data": ..., "annotations": ...}; empty when it does not exist.

    A MISSING ConfigMap is a fresh install, not an error. Any OTHER failure is an error: guessing
    "no live values" would disable every guard exactly when the API is unwell.
    """
    run = runner or _default_runner
    root = Path(project_dir)
    r = run(["kubectl", "-n", NAMESPACE, "get", "configmap", ENV_CONFIGMAP, "-o", "json"], root)
    if getattr(r, "returncode", 1) != 0:
        detail = (getattr(r, "stderr", "") or getattr(r, "stdout", "") or "")
        if "NotFound" in detail or "not found" in detail.lower():
            return {"data": {}, "annotations": {}}
        raise GuardError(f"could not read ConfigMap/{ENV_CONFIGMAP}: {detail.strip()[:300]}")
    try:
        obj = json.loads(getattr(r, "stdout", "") or "{}")
    except ValueError as exc:
        raise GuardError(f"ConfigMap/{ENV_CONFIGMAP} was not valid JSON: {exc}") from exc
    return {
        "data": {str(k): str(v) for k, v in (obj.get("data") or {}).items()},
        "annotations": dict((obj.get("metadata") or {}).get("annotations") or {}),
    }


@dataclass
class ApplyResult:
    ok: bool
    code: int
    message: str = ""
    stdout: str = ""
    decision: Decision | None = None

    @property
    def text(self) -> str:
        return "\n".join(part for part in (self.message, self.stdout) if part).strip()


def _summary(decision: Decision) -> str:
    lines: list[str] = []
    if decision.preserved:
        lines.append("preserved the operator's settings (a manifest would have reverted them):")
        for p in sorted(decision.preserved, key=lambda item: item.key):
            note = " (restored a value an earlier apply blanked)" if p.why == "clobber-repair" else ""
            lines.append(f"  {p.key}: kept {p.value!r}{note}")
    if decision.changed:
        lines.append("changed by this apply:")
        for key, old, new in sorted(decision.changed):
            lines.append(f"  {key}: {old!r} -> {new!r}")
    return "\n".join(lines)


def apply(
    project_dir: str | Path,
    *,
    dry_run: bool = False,
    allow_blank: frozenset[str] | set[str] = frozenset(),
    allow_capture_change: bool = False,
    runner: Runner | None = None,
) -> ApplyResult:
    """Guard, merge, apply, and verify. The pre-roll check runs BEFORE kubectl touches anything."""
    run = runner or _default_runner
    root = Path(project_dir)
    try:
        docs = render(root, run)
        live = read_live(root, run)
        doc = _env_doc(docs)
        pending = {str(k): ("" if v is None else str(v)) for k, v in (doc.get("data") or {}).items()}
        decision = decide(
            live["data"], pending, gui_records(live["annotations"]),
            allow_blank=allow_blank, allow_capture_change=allow_capture_change,
        )
    except GuardError as exc:
        return ApplyResult(ok=False, code=2, message=f"APPLY REFUSED: {exc}")

    if not decision.ok:
        return ApplyResult(ok=False, code=3, message=decision.message(), decision=decision)

    summary = _summary(decision)
    doc["data"] = decision.effective
    if dry_run:
        return ApplyResult(ok=True, code=0, decision=decision,
                           message="DRY RUN -- nothing applied.\n" + summary)

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        yaml.safe_dump_all(docs, fh, sort_keys=False)
        rendered = fh.name
    try:
        r = run(["kubectl", "apply", "-f", rendered], root)
    finally:
        Path(rendered).unlink(missing_ok=True)
    if getattr(r, "returncode", 1) != 0:
        return ApplyResult(ok=False, code=getattr(r, "returncode", 1) or 1,
                           message="APPLY FAILED: " + (
                               getattr(r, "stderr", "") or getattr(r, "stdout", "") or ""
                           ).strip()[:1200],
                           decision=decision)

    # ── READ BACK. A green kubectl says the request was accepted, not that capture survived. ──
    after = read_live(root, run)
    broken: list[str] = []
    for key in sorted(CAPTURE_KEYS):
        if key not in decision.effective:
            continue
        want = decision.effective[key]
        got = after["data"].get(key, "")
        # Only settings that were non-empty before are promises this apply makes.
        if str(live["data"].get(key, "")) and got != want:
            broken.append(f"{key} (expected {want!r}, live {got!r})")
    if broken:
        return ApplyResult(ok=False, code=4, decision=decision,
                           message=POST_APPLY_REFUSAL.format(items=", ".join(broken)),
                           stdout=getattr(r, "stdout", "") or "")

    return ApplyResult(ok=True, code=0, decision=decision,
                       message="apply ok" + (f"\n{summary}" if summary else ""),
                       stdout=getattr(r, "stdout", "") or "")


def _split_keys(raw: str) -> frozenset[str]:
    return frozenset(part.strip().upper() for part in (raw or "").split(",") if part.strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="apply_safe",
        description="Apply the manifests without letting them blank GUI-owned capture settings.",
    )
    parser.add_argument("--project-dir", default=".", help="checkout root (default: .)")
    parser.add_argument("--dry-run", "--check", dest="dry_run", action="store_true",
                        help="print the decision; apply nothing")
    parser.add_argument("--allow-blank", default="",
                        help="comma-separated keys this apply may blank (explicit, audited)")
    parser.add_argument("--allow-capture-change", action="store_true",
                        help="allow a capture setting to change without a GUI record")
    args = parser.parse_args(argv)

    result = apply(
        args.project_dir,
        dry_run=args.dry_run,
        allow_blank=_split_keys(args.allow_blank),
        allow_capture_change=args.allow_capture_change,
    )
    stream = sys.stdout if result.ok else sys.stderr
    print(result.text, file=stream)
    return result.code


if __name__ == "__main__":
    raise SystemExit(main())
