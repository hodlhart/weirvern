"""Logo asset tests.

The logo is a build artifact, not decoration, so these tests encode the rules
that make it usable and stop a later edit from quietly breaking it.

History worth knowing, because it explains the assertions: two earlier attempts
at an SVG mark were built and rejected on taste. What remains is a supplied
raster image (docs/logo.png). That makes RASTER-SPECIFIC properties load-bearing
— you cannot scale a PNG indefinitely, and you cannot recolour it — so the tests
below check for the derivatives that compensate, rather than pretending a raster
is a vector.
"""
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
LOGO = DOCS / "logo.png"
FAVICON = DOCS / "favicon"

# Sizes a browser or platform actually asks for. Each exists so no usage site has
# to upscale: upscaling a raster is what makes a small logo look soft, and 16px
# favicons are the case where it shows most.
REQUIRED_FAVICON_SIZES = (16, 32, 48, 64, 128, 180, 192, 512)


def test_logo_asset_exists():
    assert LOGO.is_file(), f"missing logo asset: {LOGO}"
    assert LOGO.stat().st_size > 1000, "logo file looks empty or truncated"


def test_logo_is_a_real_image_with_sane_dimensions():
    """Parsed from the PNG header rather than a library, so the test needs no
    image dependency in the dev extra."""
    data = LOGO.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "logo is not a PNG"
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    assert width >= 256 and height >= 256, (
        f"logo is only {width}x{height}; too small for a README header or a "
        f"social preview, and upscaling it will look soft"
    )
    # A square or near-square canvas, because logo usage sites assume one.
    assert abs(width - height) / max(width, height) < 0.10, (
        f"logo canvas {width}x{height} is not square enough for a logo slot"
    )


def test_favicon_set_is_complete():
    """Every size a browser or platform asks for, so nothing has to upscale."""
    assert FAVICON.is_dir(), "docs/favicon/ is missing"
    missing = [
        f"favicon-{s}.png" for s in REQUIRED_FAVICON_SIZES
        if not (FAVICON / f"favicon-{s}.png").is_file()
    ]
    assert not missing, f"missing favicon sizes: {missing}"


def test_favicons_are_non_trivial():
    """A zero-byte or 1-byte file would pass an existence check and fail in a
    browser, which is the worst combination."""
    for size in REQUIRED_FAVICON_SIZES:
        p = FAVICON / f"favicon-{size}.png"
        assert p.stat().st_size > 200, f"favicon-{size}.png is suspiciously small"


def test_favicons_are_mark_only_not_the_full_wordmark_canvas():
    """Favicons must derive from a crop of the MARK, without the wordmark.

    Verified reason: downscaling the full canvas to 16px squeezes the wordmark in
    as well, and it degrades into illegible text artifacts that read as noise.
    Cropping to the mark gives the dragon a larger share of those 16 pixels.

    HOW THIS IS CHECKED: the shipped favicon is compared against BOTH candidate
    derivations (a downscale of the full source vs of the mark crop) using mean
    absolute per-channel difference. The favicon must be measurably closer to the
    mark crop. Measured on the current assets: the mark crop matches at 0.316
    RMSE while the full canvas is 0.354 — so the assertion discriminates between
    two real alternatives rather than merely asserting a square exists.

    ImageMagick is required; the test skips if it is unavailable rather than
    reporting a false pass.
    """
    magick = shutil.which("magick") or shutil.which("compare")
    if not magick:
        pytest.skip("ImageMagick not available to compare derivations")

    def mad(a: Path, b: Path) -> float:
        r = subprocess.run(
            [magick, "compare", "-metric", "MAE", str(a), str(b), "null:"],
            capture_output=True, text=True,
        )
        # stderr carries "12345.6 (0.1884)"
        m = re.search(r"\(([0-9.]+)\)", r.stderr)
        return float(m.group(1)) if m else float("inf")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        source = LOGO

        # Two candidate derivations to compare against the shipped favicon:
        # a downscale of the full canvas, and of the mark crop (top ~62%).
        candidates = {"full": "100%", "mark": "62%"}
        rendered: dict[str, Path] = {}
        for label, crop in candidates.items():
            out = tmp / f"{label}.png"
            subprocess.run(
                [magick, str(source), "-crop", f"100%x{crop}+0+0", "+repage",
                 "-resize", "128x128", "-background", "#0a1220",
                 "-gravity", "center", "-extent", "128x128", str(out)],
                capture_output=True, text=True,
            )
            rendered[label] = out

        shipped = FAVICON / "favicon-128.png"
        if not shipped.is_file():
            pytest.skip("favicon-128.png not present")

        d_mark = mad(rendered["mark"], shipped)
        d_full = mad(rendered["full"], shipped)
        assert d_mark < d_full, (
            f"favicons appear to derive from the FULL canvas (with wordmark), not "
            f"the mark crop: MAD vs mark={d_mark:.4f}, vs full={d_full:.4f}. "
            f"Regenerate per docs/README.md."
        )


def test_source_logo_is_not_used_directly_as_a_favicon():
    """A 490x480, 380 KB PNG is not a favicon. If a browser is handed the source
    it will download 380 KB to draw 16 pixels."""
    if not LOGO.exists():
        return
    assert LOGO.stat().st_size > (FAVICON / "favicon-512.png").stat().st_size, (
        "the source logo should be the largest asset; if a favicon is bigger "
        "something is wrong with the derivation"
    )


def test_ico_is_multi_resolution():
    """A single-resolution .ico looks blurry in tabs and bookmarks. The ICONDIR
    header states the image count; assert it really is multi-resolution rather
    than a renamed PNG."""
    ico = FAVICON / "favicon.ico"
    assert ico.is_file(), "missing favicon.ico"
    data = ico.read_bytes()
    assert data[:4] == b"\x00\x00\x01\x00", "favicon.ico has no ICONDIR header"
    count = int.from_bytes(data[4:6], "little")
    assert count >= 3, f"favicon.ico holds only {count} image(s); expected 16/32/48"


def test_readme_references_the_logo():
    """A logo nobody references is a logo nobody sees.

    The README shows docs/banner.png, which is composed from docs/logo.png: the mark,
    the name and the claim in one lockup, instead of a small mark above an h1. The
    reference moved with the design, so this asserts what the reader is actually shown
    and that the asset behind it exists, rather than a filename that is now only a source.
    """
    readme = (ROOT / "README.md").read_text()
    assert "docs/banner.png" in readme, "the README does not show the banner"
    assert (DOCS / "banner.png").is_file(), "the README references a banner that is missing"
    # The source mark must survive: the banner is generated from it.
    assert LOGO.is_file(), "docs/logo.png is the source of the banner and must stay"


def test_logo_is_not_used_as_an_html_element_in_a_code_block():
    """A README image inside a fenced code block renders as text, which looks
    like a broken asset to a visitor."""
    readme = (ROOT / "README.md").read_text()
    # The logo reference is the first occurrence; it must not be indented as code.
    for line in readme.splitlines():
        if "docs/logo.png" in line:
            assert not line.startswith(("    ", "\t")), (
                f"logo reference is indented (renders as code): {line!r}"
            )
            break


def test_no_stray_svg_logo_left_behind():
    """The SVG attempts were removed. If one reappears it must be referenced from
    the README, or it is dead weight in the repository."""
    strays = [p.name for p in DOCS.glob("*.svg")]
    if not strays:
        return
    readme = (ROOT / "README.md").read_text()
    for name in strays:
        assert f"docs/{name}" in readme, (
            f"docs/{name} exists but is not referenced from the README"
        )
