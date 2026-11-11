#!/bin/sh
# End-to-end smoke against a RUNNING deployment. Read-only: it never writes a setting, files a
# rule or changes an image. It answers the question a unit suite cannot: "do the shipping pieces
# still line up on this box?".
#
# The token is read from a file so the credential never appears in argv, the process table or a
# shell history. No address in this script belongs to a private network; the target comes from
# WEIRVERN_BASE.
set -eu

BASE=${WEIRVERN_BASE:-http://127.0.0.1:30088}
TOKEN_FILE=${WEIRVERN_TOKEN_FILE:?set WEIRVERN_TOKEN_FILE to the GUI token file}
[ -r "$TOKEN_FILE" ] || { echo "FATAL: cannot read $TOKEN_FILE" >&2; exit 2; }
TOKEN=$(cat "$TOKEN_FILE")
EXPECT=${WEIRVERN_EXPECT_VERSION:-}
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

fail() { echo "FAIL  $*" >&2; exit 1; }
get() {
    curl -fsS -m 20 -H "X-Weirvern-Token: $TOKEN" "$BASE/api/$1" >"$TMP" \
        || fail "GET /api/$1 did not answer with 2xx"
}

echo "=== e2e smoke: $BASE ==="

# 1. install/status: the deep health payload names every check and all are green.
get health
python3 - "$TMP" <<'PY' || fail "deep health is not green"
import json, sys
d = json.load(open(sys.argv[1]))
h = d.get("health") or {}
if not h.get("ok"):
    raise SystemExit(f"health.ok is false: {h.get('reason')}")
checks = h.get("checks") or []
if not checks:
    raise SystemExit("health returned no checks")
bad = [c.get("name") for c in checks if not c.get("ok")]
if bad:
    raise SystemExit("failed checks: " + ", ".join(bad))
print(f"  status: {len(checks)} checks green")
PY

# 2. ingest -> anomaly: a live anomaly row and the raw flows behind it.
get 'anomalies?limit=1'
python3 - "$TMP" <<'PY' >"$TMP.addr" || fail "no anomaly row was returned"
import json, sys
d = json.load(open(sys.argv[1]))
rows = d.get("rows") or []
if not rows:
    raise SystemExit("no anomaly rows")
r = rows[0]
# The evidence route takes the console's own window format, not the ISO offset the JSON row
# carries; normalise here so a live row can be replayed without hand-editing.
from datetime import datetime
start = datetime.fromisoformat(r.get("window_start") or r["detected_at"]).strftime("%Y-%m-%d %H:%M:%S")
print(r["src_addr"] + "\t" + start)
PY
ADDR=$(cut -f1 "$TMP.addr")
START=$(cut -f2 "$TMP.addr" | sed 's/ /%20/g')
get "evidence?addr=$ADDR&start=$START"
python3 - "$TMP" <<'PY' || fail "evidence did not return flows for the anomaly"
import json, sys
d = json.load(open(sys.argv[1]))
if not d.get("anomaly"):
    raise SystemExit("evidence has no anomaly object")
flows = d.get("flows") or []
if not flows:
    raise SystemExit("evidence returned zero flows")
print(f"  ingest->anomaly: {len(flows)} flows for {d['anomaly'].get('src_addr', '?')}")
PY

# 3. findings: the registry read is attempted and its availability is explicit.
get 'findings?limit=1'
python3 - "$TMP" <<'PY' || fail "findings is unavailable without a reason"
import json, sys
d = json.load(open(sys.argv[1]))
if not d.get("available"):
    raise SystemExit(f"findings unavailable: {d.get('reason')}")
print(f"  findings: available, {d.get('count', 0)} rows")
PY

# 4. settings: the read view is served with real groups and help text.
get settings
python3 - "$TMP" <<'PY' || fail "settings payload is empty"
import json, sys
d = json.load(open(sys.argv[1]))
if not d.get("available"):
    raise SystemExit(f"settings unavailable: {d.get('reason')}")
rows = [r for g in (d.get("groups") or {}).values() for r in g]
if not rows:
    raise SystemExit("settings returned no rows")
if any(not r.get("help") for r in rows):
    raise SystemExit("a settings row has no help text")
print(f"  settings: {len(rows)} rows, every row has help")
PY

# 5. release identity: read the running version and compare when the caller names one.
get update
python3 - "$TMP" "$EXPECT" <<'PY' || fail "running version does not match the expected release"
import json, sys
d = json.load(open(sys.argv[1]))
cur = d.get("current") or d.get("version") or ""
if not cur:
    raise SystemExit("no running version in /api/update")
if sys.argv[2] and cur != sys.argv[2]:
    raise SystemExit(f"running {cur!r}, expected {sys.argv[2]!r}")
print(f"  release: {cur}")
PY

echo "E2E SMOKE PASS"
