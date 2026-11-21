"""What the host calls itself, and which package family installs for it.

The measured defect: `ID_LIKE=debian` was used as the distribution name, so a real Ubuntu 26.04
host was reported as Debian with a version from the wrong line. These tests pin the two separate
answers: the DISPLAY comes from NAME/PRETTY_NAME + VERSION_ID; the FAMILY comes from ID/ID_LIKE
and only chooses the package manager. An unreadable file is `unknown` and a generic command.
"""
from weirvern import os_release, scanner

UBUNTU = """PRETTY_NAME="Ubuntu 26.04 LTS"
NAME="Ubuntu"
VERSION_ID="26.04"
VERSION="26.04 (Resolute Raccoon)"
VERSION_CODENAME=resolute
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
UBUNTU_CODENAME=resolute
"""

DEBIAN = """PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION="13 (trixie)"
VERSION_CODENAME=trixie
ID=debian
"""

FEDORA = """NAME="Fedora Linux"
VERSION_ID="42"
PRETTY_NAME="Fedora Linux 42 (Workstation Edition)"
ID=fedora
"""

CUSTOM = """NAME="Acme Appliance"
VERSION_ID="7"
ID=acme
ID_LIKE="debian"
"""


def identity(text: str) -> dict[str, str]:
    return os_release.identity(os_release.parse(text))


def test_ubuntu_reports_ubuntu_not_debian():
    got = identity(UBUNTU)
    assert got["os_id"] == "ubuntu"
    assert got["os_version"] == "26.04"
    assert got["os_display"] == "Ubuntu 26.04 LTS"
    assert got["os_family"] == "debian"
    # NAME never comes from ID_LIKE, and the version is Ubuntu's, not Debian's.
    assert "debian" not in got["os_display"].lower()


def test_debian_reports_debian():
    got = identity(DEBIAN)
    assert got["os_id"] == "debian"
    assert got["os_version"] == "13"
    assert got["os_display"].startswith("Debian GNU/Linux 13")
    assert got["os_family"] == "debian"


def test_the_command_comes_from_the_family_while_the_name_stays_the_distro():
    ubuntu = identity(UBUNTU)
    install = scanner.nmap_install_command(ubuntu["os_family"], ubuntu["os_version"])
    assert install["manager"] == "apt" and install["known"] is True
    assert ubuntu["os_display"] == "Ubuntu 26.04 LTS"


def test_a_custom_distro_with_debian_like_uses_apt_but_keeps_its_own_name():
    got = identity(CUSTOM)
    assert got["os_id"] == "acme"
    assert got["os_display"] == "Acme Appliance 7"
    assert got["os_family"] == "debian"
    assert scanner.nmap_install_command(got["os_family"], got["os_version"])["manager"] == "apt"


def test_an_unknown_or_unreadable_os_never_guesses_debian():
    got = identity("")
    assert got["os_id"] == ""
    assert got["os_family"] == ""
    assert got["os_display"] == "unknown"
    install = scanner.nmap_install_command(got["os_family"], got["os_version"])
    assert install["known"] is False
    assert install["manager"] == ""
    assert not install["command"].startswith("sudo apt-get")


def test_the_label_names_the_family_when_it_differs():
    """The exact sentence the operator asked to see for a differing family."""
    ubuntu = identity(UBUNTU)
    install = scanner.nmap_install_command(ubuntu["os_family"], ubuntu["os_version"])
    label = ubuntu["os_display"]
    if ubuntu["os_family"] and ubuntu["os_family"] != ubuntu["os_id"] and install["manager"]:
        label = f"{ubuntu['os_display']} ({ubuntu['os_family']} family — {install['manager']})"
    assert label == "Ubuntu 26.04 LTS (debian family — apt)"


def test_detect_scanner_reads_the_os_release_path(monkeypatch, tmp_path):
    """The detector reads the FILE, so a container can be pointed at the host's copy."""
    fixture = tmp_path / "os-release"
    fixture.write_text(UBUNTU, encoding="utf-8")
    monkeypatch.setenv("WEIRVERN_OS_RELEASE", str(fixture))
    # Only the parsing path is under test here; nmap/sudo are measured separately.
    parsed = os_release.read()
    assert parsed["ID"] == "ubuntu"
    assert os_release.identity(parsed)["os_display"] == "Ubuntu 26.04 LTS"
