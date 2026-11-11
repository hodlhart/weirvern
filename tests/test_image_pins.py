"""Every shipped image is pinned; a floating tag fails the suite.

The release problem this guards: a build that silently follows `latest` is not the artifact that
was tested, and a CVE scan against a moving target has no stable answer. The derived zeek image is
the deliberate exception because it is built from this tree and has its own version line
(`zeek/Containerfile` explains why).
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _from_lines(path: Path) -> list[str]:
    return [ln.strip() for ln in path.read_text().splitlines()
            if ln.strip().upper().startswith("FROM ")]


def test_application_and_scanner_bases_are_digest_pinned():
    for name in ("Containerfile", "Containerfile.scanner", "zeek/Containerfile"):
        lines = _from_lines(ROOT / name)
        assert lines, f"{name} has no FROM line"
        for line in lines:
            assert "@sha256:" in line, f"{name} has a floating base image: {line}"


def test_manifest_third_party_images_are_digest_pinned():
    floating = []
    for path in sorted((ROOT / "k8s").glob("*.yaml")):
        for line in path.read_text().splitlines():
            m = re.search(r"^\s*image:\s*(\S+)", line)
            if not m:
                continue
            image = m.group(1)
            # Bare names are rewritten by kustomization.yaml's images: block; derived zeek has
            # its own version line. Everything else must name a digest.
            if image in {"weirvern-worker", "weirvern-scanner", "weirvern-zeek:0.5.0"}:
                continue
            if "@sha256:" not in image:
                floating.append(f"{path.name}: {image}")
    assert not floating, "unpinned images in manifests: " + ", ".join(floating)


def test_the_kustomization_tags_are_not_latest():
    text = (ROOT / "k8s" / "kustomization.yaml").read_text()
    tags = re.findall(r"^\s*newTag:\s*\"?([^\"\n]+)\"?", text, re.M)
    assert tags, "no newTag found in kustomization.yaml"
    assert all(tag != "latest" for tag in tags), tags
