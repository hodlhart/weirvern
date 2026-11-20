"""Nuclei is REMOVED: no table, no route, no UI, no settings, no binary.

This file used to pin the Findings drill's read contract. That surface had exactly one producer
(Nuclei) and the operator removed the scanner, so the honest pin is now the ABSENCE: a dormant
table with no writer would let an old match read as a current finding forever. These assertions
are the inverse of the old tests on purpose -- they fail if any of it grows back.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_the_nuclei_table_is_dropped_by_a_migration():
    migration = ROOT / "weirvern" / "schema" / "049_drop_nuclei.sql"
    assert migration.exists(), "the Nuclei removal has no schema migration"
    body = migration.read_text(encoding="utf-8")
    assert re.search(r"DROP\s+TABLE\s+IF\s+EXISTS\s+weirvern\.asset_findings", body, re.I), (
        "the migration must drop asset_findings -- a dormant table is not a removal")


def test_no_code_path_reads_or_writes_asset_findings():
    hits = []
    for path in sorted((ROOT / "weirvern").rglob("*.py")):
        if "asset_findings" in path.read_text(encoding="utf-8"):
            hits.append(path.relative_to(ROOT))
    assert not hits, f"these modules still touch asset_findings: {hits}"


def test_the_findings_route_and_view_are_gone():
    app = _text(ROOT / "weirvern" / "admin" / "flask_app.py")
    assert "/api/findings" not in app, "the Findings route survived the removal"
    html = _text(WEB / "index.html")
    assert 'id="view-findings"' not in html, "the Findings view survived the removal"
    assert 'id="fd-table"' not in html
    js = "".join(_text(p) for p in (WEB / "app.js", WEB / "assets.js", WEB / "scan.js"))
    assert "openFindings" not in js, "a control still opens the removed Findings view"
    assert "/api/findings" not in js


def test_old_findings_bookmarks_land_on_the_inventory():
    app = _text(WEB / "app.js")
    assert re.search(r'if\s*\(v\s*===\s*"findings"\)\s*v\s*=\s*"assets"', app), (
        "a #v=findings bookmark must land on Assets, not fall through to Health")


def test_no_nuclei_setting_or_binary_remains():
    """ZERO OCCURRENCES IN CODE AND DEPLOYMENT, not "disabled".

    Docs are excluded on purpose: `docs/scanner.md` explains what was removed and why, and a
    doc that cannot name the thing it removed is less useful, not more honest. The migration's
    FILE NAME is the record of the drop; its contents are pinned above.
    """
    offenders = []
    for pattern in ("weirvern/**/*.py", "k8s/**/*.yaml", "Containerfile*", "scripts/*.sh"):
        for path in sorted(ROOT.glob(pattern)):
            if "nuclei" in path.read_text(encoding="utf-8").lower():
                offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, f"Nuclei still appears in code/config: {offenders}"


def test_docs_name_nuclei_only_where_they_record_its_removal():
    """ZERO OPERATIONAL MENTIONS. A docs line that says "run nuclei" re-installs it by habit.

    The removal itself must stay documented -- a doc that cannot name what it removed is less
    useful -- so the allow-list is narrow on purpose: the one section that records the removal,
    plus a sentence asserting absence ("no Nuclei", "Nuclei is removed"). A command, a setting,
    a template path or a URL fails, because each of those is an instruction someone can follow.
    """
    allowed = re.compile(
        r"no\s+nuclei|nuclei\s+is\s+removed|nuclei\s+cannot|nuclei\s+match"
        r"|removing\s+nuclei|nuclei\s+is\s+gone", re.I)
    offenders = []
    docs = sorted(ROOT.glob("docs/**/*.md"))
    readme = ROOT / "README.md"
    if readme.exists():
        docs.append(readme)
    for path in docs:
        text = _text(path)
        if "nuclei" not in text.lower():
            continue
        # Strip the section that records the removal (heading to the next heading or EOF).
        body = re.sub(r"^##\s+Removing Nuclei\b.*?(?=^##\s|\Z)", "", text,
                      flags=re.S | re.M | re.I)
        for number, line in enumerate(body.splitlines(), 1):
            if "nuclei" in line.lower() and not allowed.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()[:100]}")
    assert not offenders, (
        "a doc still describes Nuclei as something to use: " + "; ".join(offenders))


def test_the_central_scanner_deployment_is_gone():
    assert not (ROOT / "k8s" / "36-scanner.yaml").exists(), (
        "the central scanner Deployment must be removed: scanning is a weirling capability")
    kustomization = _text(ROOT / "k8s" / "kustomization.yaml")
    assert "36-scanner.yaml" not in kustomization
    assert "weirvern-scanner" not in kustomization, (
        "the scanner image transformer entry outlived the Deployment it pinned")
