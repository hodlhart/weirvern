"""Who this host is, and which package family its installer belongs to.

TWO QUESTIONS, TWO SOURCES -- and never one inferred from the other. `/etc/os-release` carries
both, and conflating them produced a measured defect: an Ubuntu 26.04 LTS host was reported as
"debian 13", because the package FAMILY (`ID_LIKE`) was used as the distribution name and a
version was paired with it. The display name is what a person recognises (`PRETTY_NAME`); the
family is what picks a package manager (`ID`, then `ID_LIKE`). This module keeps them apart.
"""
from __future__ import annotations

import os

DEFAULT_PATH = "/etc/os-release"

# The distro identifiers `nmap_install_command` knows how to choose a manager for. Membership
# here decides the FAMILY; it never decides the displayed name.
KNOWN_FAMILIES = (
    "debian", "ubuntu", "linuxmint", "pop", "raspbian", "kali", "devuan", "elementary",
    "fedora", "rocky", "almalinux", "ol", "rhel", "centos",
    "alpine", "arch", "manjaro", "endeavouros", "garuda",
    "opensuse-leap", "opensuse-tumbleweed", "opensuse", "sles", "suse",
)


def parse(text: str) -> dict[str, str]:
    """Parse os-release content. Quoted values lose their quotes; comments are ignored."""
    values: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"')
    return values


def read(path: str | None = None) -> dict[str, str]:
    """Read the host's os-release. An unreadable file is an EMPTY mapping, never a guess."""
    target = path or os.environ.get("WEIRVERN_OS_RELEASE") or DEFAULT_PATH
    try:
        with open(target, encoding="utf-8") as handle:
            return parse(handle.read())
    except OSError:
        return {}


def identity(values: dict[str, str]) -> dict[str, str]:
    """The distro a person recognises, the version from the SAME record, and the family.

    `os_display` prefers PRETTY_NAME (it carries "LTS"), then NAME + VERSION_ID, then ID.
    `os_family` prefers ID when it is a family we know, then the first known ID_LIKE entry.
    An empty mapping answers "unknown" with no family, so the caller shows the generic command.
    """
    ident = str(values.get("ID") or "").strip().lower()
    like = [part.strip().lower() for part in str(values.get("ID_LIKE") or "").split() if part.strip()]
    version = str(values.get("VERSION_ID") or "").strip()
    name = str(values.get("NAME") or "").strip()
    pretty = str(values.get("PRETTY_NAME") or "").strip()
    display = pretty or " ".join(part for part in (name, version) if part) or (
        ident.title() if ident else "unknown")
    family = like[0] if like else ident
    return {
        "os_id": ident,
        "os_version": version,
        "os_family": family,
        "os_display": display or "unknown",
    }
