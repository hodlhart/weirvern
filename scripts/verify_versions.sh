#!/bin/sh
# Every place the release version is written down must agree.
#
# WHY THIS EXISTS. The version lives in four places (the package, pyproject, the kustomize
# newTag, and the README), and the README had already drifted: it said 0.9.0 while the code
# reached 0.10.4 -- FIVE releases in which every image tag in the README's copy-paste build and
# deploy commands was wrong. An operator following those instructions builds and deploys a stale
# version and has no way to notice, because the wrong number is perfectly plausible.
#
# The project already has the rule ("declare the image tag in ONE place; never let it drift");
# this is the check that makes it true rather than aspirational. `newTag` in kustomization.yaml
# IS the one place for the deployed tag, so the others must follow it.
set -u

CODE_V=$(grep -m1 '^__version__' weirvern/__init__.py | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
PYPROJ_V=$(grep -m1 '^version = ' pyproject.toml | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
KUST_V=$(grep -m1 'newTag:' k8s/kustomization.yaml | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
README_V=$(grep -m1 'Current release:' README.md | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')

echo "    code=$CODE_V  pyproject=$PYPROJ_V  kustomize=$KUST_V  README=$README_V"

if [ -z "$CODE_V" ]; then
    echo "    FAIL -- no __version__ found in weirvern/__init__.py"
    exit 1
fi

FAIL=0
for pair in "pyproject:$PYPROJ_V" "kustomize:$KUST_V" "README:$README_V"; do
    name=${pair%%:*}
    got=${pair#*:}
    if [ "$got" != "$CODE_V" ]; then
        echo "    FAIL -- $name says '$got' but the code says '$CODE_V'"
        FAIL=1
    fi
done

# And no OTHER image tag in the README may be pinned to a different version either: those appear
# in commands an operator copies, so a stale one silently deploys the wrong build.
STALE=$(grep -cE 'weirvern-worker:[0-9]+\.[0-9]+\.[0-9]+' README.md 2>/dev/null || echo 0)
MATCH=$(grep -cE "weirvern-worker:$CODE_V" README.md 2>/dev/null || echo 0)
if [ "$STALE" != "$MATCH" ]; then
    echo "    FAIL -- README pins $((STALE - MATCH)) image tag(s) to a version other than $CODE_V"
    FAIL=1
fi

if [ "$FAIL" = "0" ]; then
    echo "    PASS"
else
    exit 1
fi
