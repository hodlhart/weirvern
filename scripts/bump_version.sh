#!/bin/sh
# Bump the release version in every place it is written down.
#
# There are four: the package, pyproject, the kustomize newTag, and the README. The README had
# drifted for FIVE releases (it said 0.9.0 while the code reached 0.10.4), so every image tag in
# its copy-paste build commands was wrong. Bumping by hand is how that happens; this does all
# four at once, and scripts/verify_versions.sh (in the gate) makes a miss a build failure rather
# than a slow surprise.
set -eu
[ $# -eq 1 ] || { echo "usage: scripts/bump_version.sh <X.Y.Z>"; exit 2; }
NEW="$1"
case "$NEW" in [0-9]*.[0-9]*.[0-9]*) ;; *) echo "not a version: $NEW"; exit 2 ;; esac

OLD=$(grep -m1 '^__version__' weirvern/__init__.py | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
[ "$OLD" != "$NEW" ] || { echo "already at $NEW"; exit 0; }
echo "  $OLD -> $NEW"

sed -i "s/^__version__ = \"$OLD\"/__version__ = \"$NEW\"/" weirvern/__init__.py
sed -i "s/^version = \"$OLD\"/version = \"$NEW\"/" pyproject.toml
# The kustomize newTag is NOT bumped here any more: since issue #69 it names the BUILT sha tag,
# and rewriting it with a version number would point the overlay at an image nobody built. The
# release version still moves in the three places above; the deployment pin moves at build time.
sed -i "s/Current release: \*\*$OLD\*\*/Current release: **$NEW**/" README.md
sed -i "s/Current release: <strong>$OLD<\/strong>/Current release: <strong>$NEW<\/strong>/" README.md
sed -i "s/weirvern-worker:$OLD/weirvern-worker:$NEW/g" README.md

sh scripts/verify_versions.sh
