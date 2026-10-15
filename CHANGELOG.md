# Changelog

## Unreleased — the review round: every finding fixed with the test that proves it

A four-area audit (siphon/sluice, SOC/GUI, ML, core) ran against this tree; every
CRITICAL/HIGH claim was re-derived from the code before it was trusted, and each fix
below carries a test condition that fails on the defect it answers. The findings ledger
(`docs/audit-findings.json`) stays the index of record.

**Sluice: a rule it cannot compile is refused, not widened.** A rule naming both a
source AND a destination used to compile as source-only — blocking more than its own
description said, while `describe`/dry-run claimed the narrower shape. Refusal now
happens at three layers (authoring, store validation, base-ruleset compile), so a
hand-written row cannot bypass it either; destination-only INBOUND rows are refused
for the same reason.

**The NetFlow cap no longer re-ingests the world.** Trimming `flows.jsonl` at the size
cap changed the inode and reset the reader's offset, re-reading (and re-inserting,
non-dedup) the whole file every 5 minutes — ~1 GB per cycle at the cap. The trim now
never cuts past the reader's checkpointed offset, records every rewrite in a sidecar
chain the reader subtracts through, and a lagging reader makes the trim WAIT: the cap
is a ceiling, not a deadline. `prune --dry-run` also stopped lying ("would free
0.0 MB" unconditionally — it read attributes that existed on no version), and `.gz`
rotations are pruned like plain ones.

**The agreement gate binds at every tier.** With four detectors the smallest non-zero
agreement (1/4) equalled the top-tier bar, so a lone strong detector could reach
critical — a leak the unit tests had pinned as correct. A solo share never passes now,
with one deliberate exemption: a lone strong specialist plus a direct structural
signature (the zero-byte port scan case). The three drifted copies of the 0.20
"detected by" bar are one constant.

**Model artifacts carry the feature schema in name AND metadata.** The `_v1` in the
filename was a literal under a comment claiming versioning: every retrain overwrote the
only artifact, and a feature-schema change scored 0.0 under `is_ready() == True` until
the next scheduled retrain. Save stamps the schema; load refuses a schema or column
mismatch before adopting; a version bump moves to a new file and keeps the old.
DBSCAN now WARNS when it finds no cluster centres — the state that silently disables
the scan-family escalation (measured: 2 centres at 146 sampled rows, 0 at 124).

**The seeded-attack eval no longer trains on the attacks it scores.** Attacks are
seeded in the last third and training holds out the first two-thirds; every `train()`
return is read (which caught DBSCAN's 100-row minimum vs a 90-minute seed — the seed
is 300 minutes now); the benign-host set is derived from the seed and the precision
check bounds both mass alerting and chronic per-host false positives; the determinism
check resets the sweep's own state (cursor + recorded pairs) and compares two scoring
passes with the same models; the scanner's verdict must sit where the scan was seeded;
a storm ceiling bounds verdict volume. Severity bars recalibrated to measured truth.

**The GUI stops claiming a quiet network when its own filter hid the data.** The
network panel's flows filter collapsed "filtered to empty" into "no traffic was
recorded"; the filtered case now names the filter and its count.

**Sensor identity resolved through ONE door.** `worker._sensor_name` read
`settings.sensor_name` — a field `Settings` never defined — so the documented way to
name a sensor was unreachable and SENSOR_ID never reached the gate's rows. The field
exists now (it reads SENSOR_ID), so the gate, the heartbeat and the fleet view agree.

**Dead knobs removed.** `NETFLOW_PORT`/`SFLOW_PORT` sat in the ConfigMap and
`.env.example` reading like switches while nothing consumed them; they are gone, with a
pointer to the files that actually own the ports.

**CI and the gate grew the checks this round needed.** CI now lints `scripts/`, runs
the installer harness against simulated machines, syntax-checks every shell script
under its own shebang, and runs the jsdom DOM harness (294 checks; it executes the
shipping JavaScript and needs no server). The gate's shell check went from ONE file to
every script, and its node check now covers all five view scripts plus the harness.

**The console's `kubectl` resolves on its own.** The installer's own calls worked -- its
PATH has `/usr/local/bin`, where k3s drops the binary -- but the operator's login shell
did not: `Command 'kubectl' is available in '/usr/local/bin/kubectl' ... not included in
the PATH`, measured at the first end-to-end deployment, while every documented next step
is a console command. Install now links `/usr/bin/kubectl` (on every PATH, for every
user) and adds one idempotent PATH line to root's rc -- never clobbering anything already
at the link path, and saying so when the entry is a dangling symlink. Pinned in the
installer harness against a sandbox: fresh, rerun, existing file, dangling link, and no
kubectl at all.

## Unreleased — the Network view becomes a map: deterministic forces, TTL hop rings

**The connection graph was a fixed circle; it is now a settled force map.** The three
objections that made the circle the right call are answered in code, not waived:

- **Comparable, still.** No randomness and a fixed tick count: the start is the old
  degree-ordered circle and every step is deterministic arithmetic, so one window of data
  settles to the same map on every load — what animates is the path to it. The settled map
  is applied by a watchdog even when animation frames stall (a backgrounded tab costs the
  animation, never the map), and **Re-settle** returns a hand-dragged map to the arranged
  one — verified end-to-end: drag a host, re-settle, get the identical map back.
- **Bounded, still.** The solve runs once per render (measured: ~12ms for the demo
  segment's 20 nodes / 63 edges) and then the picture is frozen; a drag re-runs a bounded
  warm start. Nothing iterates per frame once the map has settled.
- **Now with real structure to uncover.** `ip_ttl` has been ingested since the first
  release and read by nothing — the layout consumes it. A host's observed TTL gives its
  hop distance from the sensor (`64 -> 0`, `63 -> 1`, ...), and measured hosts settle into
  hop-distance rings, each circle drawn where its class actually settled (measured on the
  demo dataset: r~75 and r~147, no overlap). Hosts whose records carry no TTL keep `hops`
  ABSENT — 0 means NOT MEASURED, never "distance zero" — and float on links alone.

Also in this pass: drag any host and the map re-settles around it; the dragged host HOLDS
its dropped position (the pin lives in the solver — freed, the springs pull it straight
back and the gesture reads as broken). A plain click during the settle is a selection,
not an interruption — the settle completes behind it (cancelling it at press froze the
map mid-flight, measured at 185 px short); a cancelled pointer ends the drag rather than
leaving the host following the cursor; and a capped hop ring prints "3+" so a capped
class can never read as a measured three. Node and edge hover cards and the detail panels
show the TTL evidence behind a ring (`2 hops from the sensor (ttl 62)`), the tracked-host
path carries the same fields so a filtered graph keeps its rings, ring labels ride on top
of the nodes with a halo (drawn underneath, "0 hops" sat behind a node and read as
"hops"), and the settled cloud is recentred so an asymmetric link structure cannot leave
the map visibly off to one side.

## Unreleased — export the observed topology as an Obsidian vault

`scripts/obsidian_export.py` writes one note per host — named by address, reverse-DNS name
alongside — with observed peers as `[[wikilinks]]` carrying measured bytes, flows and ports;
flagged hosts get an `anomaly` tag and an Anomalies section. Verified against the sandbox
vault: 20 hosts, 63 connections, 27 anomalies, every link resolves.

Re-runs are strictly self-replacing: a `.weirvern-manifest.json` records what the run
created, so only its own notes are refreshed or removed — a note the operator adds to
`Hosts/`, a `README.md`/`Topology.md` the operator wrote, are left alone exactly as the
vault README promises (before the manifest, the cleanup deleted anything it did not
recognise). And a note's frontmatter omits `anomalies` when the anomaly source could not be
read, instead of claiming a measured zero.

## Unreleased — 0.9.0: the TUI is gone, and the fingerprinting story is one sentence

**Two surfaces were telling a story the software no longer had.**

**The TUI is removed.** The web console replaced it, and a second interactive surface
was both a maintenance cost and a source of copy that had to be kept in sync with a
product it no longer was. `weirvern tui` is gone as a command, `admin/tui.py` is gone
as a module, and the `textual`/`rich` dependencies (and the `[admin]` extra that
carried them) are gone from `pyproject.toml`. Everything it did, the CLI and the GUI
still do — nothing in the deployment read it.

- The scrub went deeper than the file itself: every comment, docstring and message
  that referenced the TUI as a live surface was rewritten (`CLI and TUI` -> `CLI`,
  `the TUI uses` -> `weirvern status` uses, the Settings copy that suggested editing
  values "or the TUI", the RBAC and GUI-manifest comments). The token survives only in
  `CHANGELOG.md`, where it is a record of what existed, which is what a changelog is.
- The two tests that exercised TUI-only code (`test_tui_mode.py`, and the three
  `_condense` tests in `test_admin_runtime.py`) were re-expressed against surviving
  code rather than deleted: `_condense` lives in `runtime.py` (it always did — the
  TUI imported it), so its tests now target their real module, and the mode-panel
  tests are gone with the panel.

**Fingerprinting is now one method, vendored, and nothing else is mentioned.** The
previous arrangement installed the upstream package at build time and then pruned the
parts this project does not use — correct, but it left the repository and the docs
explaining a licensing split for code the software never runs. Now:

- The **JA4 module is vendored at `zeek/vendor/ja4-zeek-scripts/`** (BSD 3-Clause,
  license text included) and `COPY`ed into the sensor image at build time. No package
  manager, no network fetch; the image contains exactly what the repository shows.
- **Every reference to the other methods is gone** — code, comments, docs, the NOTICE
  table, the research notes — and a token scan in `tests/test_ja4_licensing.py` fails
  CI if one returns anywhere in the tracked tree. The scan has a must-fire test, so it
  cannot quietly stop looking.
- The old build-time pruning script and its notice file are deleted with the machinery they
  described. `zeek/verify-ja4.sh` survives in simplified form: it still proves at build
  time that Zeek can actually load the module (a module that parses but emits nothing
  is a sensor that records no fingerprints while looking healthy).
- The site policy's licensing essay (fourteen lines about a package that no longer
  ships) is three lines about the vendored module. The README's "TLS fingerprinting
  and licensing" section is now "TLS fingerprinting" — one method, one license, no
  tables of what is excluded.
- The **Zeek image tag moves to 0.5.0** (the image contents changed materially). The
  worker release is **0.9.0**.

## Unreleased — 0.8.2: the Settings tab tells the truth, and a Test run button

**The Settings tab rendered `loch` through a demonstrably running intercept.** Measured on the
first live siphon test: the operator pressed Sonar, applied the plan (mode + segment + address
+ gateway + targets), and the tab came back showing `loch` — so the apply looked like it had
failed. It had not: the ConfigMap held `siphon`, and the worker was redirecting ten hosts
through the supervised intercept at that moment. The cause is the display: settings rows were
built from this process's environment, read once when the GUI pod started, and a mode change
restarts the WORKER — not the GUI — so the tab kept its frozen startup copy.

- `/api/settings` now reads the `weirvern-env` ConfigMap per request and renders every
  non-derived row from the CLUSTER's value (`source: "cluster"` reports that provenance).
  When the cluster is unreachable the pod env remains the honest fallback, and the row
  provenance says which one you are reading.
- Secrets never ride this path (a ConfigMap row for one does not exist, and the test feeds a
  hostile map to prove none can be smuggled through), and derived rows (namespace, version,
  reverse_dns) keep their own sources.
- This is the same class as the earlier "restart the workload that READS the key" fix: the
  data was right and the display was wrong, and the display is what the operator acts on.

**A Test run button next to Apply: siphon for 30 seconds, then back to loch.** Asked for by
name after the first live test. It runs the REAL intercept through the REAL supervision — not
a stub: the worker restarts with the mode temporarily set to siphon, spawns the intercept the
same way a production run does, and the revert's restart stops it through the orderly SIGTERM
path that restores every forged ARP mapping.

- The revert runs in a `finally` AND under a daemon-timer backstop, because the browser
  cannot be trusted to send a second request: a closed tab, a lost network, or a dead machine
  must not leave the sensor in the traffic path.
- A refusal (incomplete plan, empty targets, an IPv6 target list) writes NOTHING — a test
  that cannot intercept is not started at all.
- A failed revert is reported loudly and never folded into success; the result states the
  observation and the revert as separate facts, because "the mode went back" and "an
  intercept was seen" are different claims.
- The button is admin-gated like every other write, and its "?" explains exactly what runs
  and what it costs before anyone clicks it.
- Tests: `tests/test_siphon_probe.py` (12 — the sequencing driven with an injectable clock),
  settings-tab tests pinning live-vs-frozen rendering and the secret fence, harness at 232.

## Unreleased — 0.8.1: Sonar, and the names come back

**Settings gains Sonar: one button that surveys the segment the capture interface is ON and
stages the siphon plan for review.** Asked for after the first live test ("auto discover the
segment of the listening nic and offer recommended settings... call this button like sonar").
The survey reads the interface's own address and netmask (the segment is a fact the kernel
holds, not a guess), sends ONE ARP sweep — the same frames every host on a LAN sends — for
live hosts and free addresses, resolves the gateway and its MAC, and returns recommendations
in the exact Settings row vocabulary: mode, segment, address, gateway, targets. Everything
lands in the existing PENDING CHANGES list: editable, discardable, inert until Apply.

- **The survey runs as a one-shot Job in the SENSOR's shape** (hostNetwork, pinned to the
  sensor node, NET_RAW only — NET_ADMIN is deliberately absent: the probe assigns nothing and
  must not be able to reroute). A survey inside the GUI process would have measured the GUI
  pod's own namespace and recommended interfaces the sensor node does not have.
- **Result transport is one `SONAR_RESULT {json}` log line**, read back by the GUI with the
  jobs/pod-log RBAC the operator Role already grants. No volume, no sidecar, no callback path.
- **The Job's image is the RUNNING deployment's tagged image** — a tagless name resolves to
  `:latest`, which k3s containerd never imported, and the failure would look like a cluster
  problem.
- **Recommendations stage through `stageChange()`** and are compared against each row's
  running value: a recommendation equal to the current value stages nothing. There is no
  direct-apply path for recommendations, deliberately — the review step is the feature.

**Reverse-DNS names: the setting now actually reaches the process that does the lookups.**
Measured live after `WEIRVERN_REVERSE_DNS='all'` was set: the ConfigMap held `all` and the
GUI pod still resolved `private`, so the setting was inert exactly where the tabs need it.

- `WEIRVERN_REVERSE_DNS` restarts `deploy/weirvern-gui` — the GUI process resolves the names
  (`web_api._hostname`); the worker never reads the key, so the old worker-only restart
  mapped to a workload the change never touched.
- `k8s/34-gui.yaml` no longer pins `WEIRVERN_REVERSE_DNS: "private"` in its own `env:` — a
  pod's env entry SHADOWS envFrom, so the ConfigMap value could never reach the GUI. The
  default now lives only in the ConfigMap, which is the one place a Settings write updates.

**The apply receipt told the truth about a write it had just proved.** `/api/settings/apply`
built its `applied` echo from ROW keys (`reverse_dns`) against ConfigMap-keyed data
(`WEIRVERN_REVERSE_DNS`), so every key rendered `saved: x=(empty)` — after a write that
landed, verified by the same request's read-back. Fixed at the boundary with
`to_configmap_key`.

**The costly-change confirmation was being skipped, for the same class of reason.** The plan
route returned proposals keyed by ConfigMap name while the client matches warnings against
the staged ROW keys — so the confirmation dialog never matched, silently, for exactly the
changes that need it (the in-path mode among them). Both routes now echo the caller's key
vocabulary.

**Names in the tabs that were missing them — the payload builders, not the resolver.** The
Assets table declared `"name": ""` per host and nothing ever filled it; the Netflow fan-out
rows carried no name; the Zeek drill-down showed bare IPs. Each now resolves through the
shared `revdns` helper (same policy everywhere: private by default, public only when set to
`all`, never instead of the address).

- Tests: `tests/test_sonar.py` (16 — the arithmetic on injected readers, the Job shape field
  by field, the result transport, the runner's create→poll→read→delete cycle), the DOM
  harness grew to 226 checks (button presence, its `?` help, staging-not-applying, the
  no-op-recommendation dedupe), and the sanitizer learned the netmask forms.

## Unreleased — 0.8.0: the intercept runs itself, and a one-command install

**WEIR-1 closed: siphon mode now actually intercepts in-cluster.** The remaining gap from
the 0.7.0 audit: `SENSOR_MODE=siphon` configured an INTENT, and nothing in the cluster
ever ran the intercept — the mode could read "in-path" on every surface while redirecting
zero hosts. The WORKER now supervises the intercept (`admin/siphon_supervisor.py`): with
the mode set and a complete plan (segment, address, gateway, at least one target), it
runs `weirvern intercept` as a supervised child, restarts it when bounded runs end, backs
off on crashes, and reports every refusal on the sensor heartbeat.

- **A child process, not an in-process intercept.** The intercept's fail-open watchdog
  installs SIGTERM/SIGINT handlers that restore the ARP mappings AND end the process;
  in the worker's main process they would replace the worker's own graceful shutdown, so
  a pod termination would tear down ingest and detection as a side effect of a restore.
  As a child, the intercept owns its signals and the restore contract is the one the CLI
  already proves in the field.
- **Each run is bounded (`--seconds`, default 1h).** The child restores on its way out
  and a new run starts seconds later, so every seam is a working proof of the restore
  path. The CLI's non-TTY rule (a non-interactive run must carry `--seconds`) is
  respected, not bypassed.
- **Readiness is rechecked before every spawn attempt** (NET_RAW+NET_ADMIN from CapEff,
  the three sysctls from /proc) — a pod that starts before the overlay's init container
  finishes self-heals on the next attempt instead of refusing forever.
- **One owner per heartbeat row.** `sensor_status` is keyed `(sensor_id, mode)`; the
  worker and the child share both. The supervisor decides who publishes
  (`worker_should_publish`): the child while it runs, the worker on loch, on a refused
  plan, after a crash, and after a clean seam once the row would go stale. Two writers
  would have made the liveness check flap.
- **Settings changes restart the workers that read them.** `SENSOR_MODE` now restarts
  `ds/zeek` AND `deploy/weirvern-worker` (the daemonset states the mode and runs the
  sysctl init container; the worker supervises the intercept). The intercept-plan keys
  restart the WORKER — they were mapped to `ds/zeek` before, a restart that applied
  nothing because the sensor does not read them.
- `siphon_liveness`'s "no intercept running" message updated: this is no longer the
  expected steady state — it is a fault with a stated cause (the supervisor's note rides
  the heartbeat's `failures`).

**`install.sh` — one command from a bare Ubuntu box to a running deployment.** Installs
docker (image builder ONLY), k3s (the runtime) and kustomize; gets the repo; prepares the
node (host directories, sensor-node label, interface detection with management/capture
roles); builds both images and imports them into k3s's containerd (the step local
deployments fail on); applies the manifests; creates the Secret once and never rotates
it; replaces the schema Job (immutable after creation — a changed Job fails while the
rest of the apply silently succeeds) and restarts the readers; waits for the schema
Job's completion and every pod Ready, naming any that is not; prints the sign-in URL and
the one-time admin password from the GUI log. `--siphon` also applies the overlay so the
in-path mode's capabilities exist BEFORE anyone flips the switch in Settings. Idempotent
throughout: re-running converges, and it never overwrites credentials or models.

**It was then dogfooded on a genuinely blank Ubuntu VM, and the run paid for itself:**
node prep died on `install -g 10001` because no fresh machine has the worker's gid (and
the group cannot be NAMED `weirvern` — Ubuntu's per-user private groups mean a host
whose admin login is `weirvern` already owns that name at gid 1000), and the pinned
ClickHouse image turned out to be an x86-64-v3 (AVX2) build that crash-loops on a VM
whose CPU model masks AVX2 (Proxmox's default `kvm64`) with nothing in-cluster saying
why. The script now creates its own group (the numeric gid is the contract every
container sees; the name is cosmetic) and refuses up front on an AVX2-less CPU, naming
the remedy.

## Unreleased — siphon mode, a dropdown that lied, and a capability probe that refused forever

**The in-path mode is renamed: `weir` -> `siphon`.** The name was asked for and never
applied — the string "siphon" appeared nowhere in the tree while the mode was called
`weir` (its former name) in 315 places, including the overlay directory, the dataplane
module (`weirnet.py` -> `siphonnet.py`), the stress-test script, two test files, and
every doc. Renamed throughout. The metaphor holds: a wyvern keeps its water in a
**loch** (passive observer, still water) and draws it through a **siphon** (in-path, the
flow passes through).

The old spelling survives in exactly two places, both deliberate, both guarded by a
test that scans every tracked file for regressions:

- `mode.normalise` accepts `weir` on input and stores `siphon`, so a CLI invocation or
  script written before the rename keeps working;
- the sensor's startup `case` accepts `weir` and announces `siphon`, **with a note**, so
  a ConfigMap that has not been updated since the rename cannot crash-loop the sensor.
  (Without this, every pre-rename deployment's Zeek daemonset would have hit the
  `unknown SENSOR_MODE` fatal branch.)

**Reported from the box: "I can't change admin to admin. It's stuck on viewer."** Two
distinct defects stacked:

1. **The dropdown lied.** `el()` dropped the `selected` property (the same silent-drop
   trap as the earlier `type:` bug), so every role dropdown rendered its FIRST option —
   "viewer" — while the store held "admin". The server log shows the role was set
   successfully ten times; the panel re-rendered the wrong value each time, which reads
   exactly as "stuck". `el()` now applies `selected`, and the DOM harness asserts the
   SELECTED VALUE rather than the control's existence — it fails on the old code
   (`selected=viewer`) and passes on the fix.
2. **A no-op role write signed you out.** `_users_role` revoked the account's sessions
   on every call, including setting the role an account already had. In the operator's
   own tab that drops the session mid-action, so the next click 401s — indistinguishable
   from a refusal. A role change now revokes only when the role actually CHANGES.

**Reported from the box: "I can't apply [in-path] mode."** The GUI's mode gate asked
`_sensor_caps()`, which was a stub returning `(False, False)` unconditionally — so the
gate refused the in-path mode forever, on every deployment, overlay or not. It now reads
the zeek DaemonSet from the cluster API (new `ClusterConfig.get_json`, same
ServiceAccount/token/CA path the config write uses), and still defaults to ABSENT when
the read fails: the refusal direction is the safe one, and the tests pin both halves.

**Also fixed while in the area:** the README documented `weirvern mode --set loch`, which
the CLI has never accepted (it takes a positional: `weirvern mode loch`) — a doc that
404s for the reader who follows it exactly.

Guards added: `tests/test_mode_naming.py` (whole-word scan for the old spelling, with the
two acceptance points as the only exemptions, plus end-to-end checks that the acceptance
actually WORKS), six route-level tests for the capability probe and the no-op/real role
writes, and five new DOM-harness checks for the dropdown's rendered value. Full suite
green; harness 217 checks; gate green.

## Unreleased — the break-glass door moves to the sign-in screen

**The gap this closes.** The operator token is the documented recovery for a lost admin
password, but its input lived ONLY on the Settings tab — which sits behind the sign-in
gate it exists to open. An operator whose only remaining credential was the token could
not reach the control that saves them; the recovery story was circular.

**The fix.** The sign-in gate now carries a "Lost the admin password? Use the operator
token instead" door: one click opens the token form on the locked-out screen itself. The
token is verified the same way as everywhere else — the client submits it, re-reads
`/api/session`, and boots from the SERVER's answer, so a wrong token leaves the gate up
with a plain refusal and never a local claim of success. After signing in as the
break-glass admin, the recovery path completes in the UI: Settings → Users → **Reset
password** on the admin row, then sign in with the temporary password and change it.

**A deploy lesson this release records** (also added to the README's setup notes): the
bootstrap admin password is printed ONCE, by the pod that created the account. Rolling the
GUI to a new image tag replaces that pod and the log with it — capture the password before
deploying a newer tag, or recover via the operator token door. (Encountered live: the
0.6.8 deploy rolled the pod and retired the only copy of the bootstrap line.)

Guarded by: 7 new DOM-harness checks (door hidden by default, opens on click, wrong token
refused with the gate up, right token accepted on the server's answer, gate closes) and a
Python pin that the token form lives INSIDE the sign-in gate and its handler verifies via
`loadSession` — a future refactor cannot quietly move the door back behind the wall.

## Unreleased — the gates actually hide: a CSS cascade collision that covered the sign-in form

**Symptom, reported from the box:** "it says log in first. i cant change the password."
The forced-password gate was painted over the sign-in gate; the sign-in form could not be
reached at all, and submitting the password form without a session correctly answered
"sign in first".

**Root cause, one line of CSS.** `.hidden { display: none }` and `.gate { display: flex }`
have equal specificity, so the cascade decides by source order — and `.gate` came LATER in
`style.css`. Both gates carry `.gate` and start with `.hidden`; the "hidden" class was on
the element the whole time and lost to the later rule. The forced-change gate (later in the
DOM, same z-index) sat on top of the sign-in gate, and the dashboard was unreachable for
every caller, signed in or not. The fix is `.hidden { display: none !important; }`: hidden
means hidden, whatever else the element carries.

**Why every existing guard was green through this.** All of them asserted class NAMES —
`classList.contains("hidden")` was true the entire time. What an operator sees is decided
by the COMPUTED style, and nothing computed it. Class-name checks cannot see a cascade
collision by construction.

**What now guards it, each proven to fail on the old CSS (`flex/flex`) and pass on the fix:**
- Four DOM-harness checks read `getComputedStyle` at every gate state: the harness now
  injects the real `style.css` so it measures the shipping cascade, not just the markup.
- A Python test scans the stylesheet for every class that shares an element with `hidden`
  and requires `hidden` to win — via `!important` or source order (guard proof: reverting
  the fix turns it red with the exact colliding rule).

**Two more defects the same report surfaced, fixed in the same release:**

- **The password form dead-ended on an expired session.** With the cascade fixed, a change
  submitted after the session had ended (revoked by another tab, expired, GUI restarted)
  still answered only "sign in first" while leaving the operator on a form that could not
  work. The client now clears the dead session and returns to the sign-in gate with a note
  saying what happened and what to do. The harness pins the path (`stale-session-value` →
  refused → session cleared → sign-in gate painted with the pointer).
- **The GUI logged nothing at INFO.** Python's last-resort handler prints WARNING and above,
  so a deployment's log carried the bootstrap password and rejected sign-ins but not ONE
  successful sign-in, password change, role change or account creation — which is exactly
  what diagnosing "I can't sign in" needs. `weirvern gui` now configures INFO logging, the
  same level the worker and ingester already use.

### Fixed

- The sign-in and forced-password gates actually hide when they should, so the sign-in
  form is reachable and the forced-change flow completes as designed.
- A password change on an expired session returns to the sign-in gate instead of dead-ending.
- The GUI service logs its account events at INFO, so the pod log is readable as an audit
  trail rather than a list of failures.

## Unreleased — accounts: a default admin at setup, roles, and a sign-in gate

The GUI has one credential until this release (the shared operator token), which is not an
account: it cannot be given to a second person without giving them everything, it records
nobody, and there is nothing to disable when someone leaves. This lands accounts and roles.

### Added — accounts with two roles

- **A default admin is created at first startup**, and its generated password is printed
  **once** to the pod log (`kubectl -n weirvern logs deploy/weirvern-gui | grep "initial
  admin"`). It is forced to change that password at first sign-in — enforced server-side, so
  the dashboard genuinely stays locked until it does.
- **admin / viewer, deliberately only two.** Admins read everything, change settings, and
  manage accounts; viewers read everything and change nothing. A viewer's Settings page
  renders every value **with no controls at all** rather than controls that fail on Apply.
- **Account management in the GUI** (Settings → Users): create accounts (choose role, set the
  initial password, forced change at first sign-in), change roles, delete, and **reset a
  lost password** — the only recovery path that works without email on a deployment like
  this. The last admin cannot be demoted or deleted; the server refuses and says why.
- **Change your own password** from Settings → Account. The current password is required
  (a stolen session cannot lock the owner out), and every session for the account is revoked
  afterwards.

### How it works — and the trade-offs, stated

- **The account store is a `weirvern-users` ConfigMap**, created by the GUI on first startup
  rather than shipped as a manifest (a placeholder manifest would be re-applied with empty
  values on every `kubectl apply -k` and wipe live accounts — the same failure mode the
  Secret carries a note about). Not a Secret: the GUI's ServiceAccount grant deliberately has
  no access to Secrets, and that absence is what stops a compromised GUI pod from reading the
  Pushover credentials; widening it to store password hashes would trade a proven guard for a
  smaller one. Hashes are scrypt (stdlib `hashlib`, per-user salt, n=2^14), so the store's
  exposure is bounded and stated in the module header.
- **Not ClickHouse**, which already holds alert reviews: a login gate must work when the
  database does not, and the first thing an operator wants during a database incident is the
  health page.
- **Sessions are in memory** with a 12-hour absolute TTL; a GUI restart signs everyone out.
  The alternative — sessions in the ConfigMap — would write on every request.
- **Reads now require a signed-in account** (either role) when accounts are provisioned.
  Before accounts, reads were open so nobody had to log in during an incident; "a viewer may
  read" only means something if reading is attributable, so the gate arrived with the roles.
  A deployment whose store cannot be read falls back to the pre-accounts posture (open reads,
  token-gated writes) rather than locking the operator out of their own dashboard.
- **The operator token survives as the break-glass credential**: it works everywhere an admin
  does and cannot be disabled by account state, so a lost admin password can never lock a
  deployment out of its own configuration. It is not an account — no username, nothing to
  sign out of — and the UI says so instead of offering a form that cannot work.

### Security properties, pinned by tests

- A wrong password and an unknown username are one message ("the username or password is not
  correct"), and an unknown username burns the same scrypt cost as a wrong password
  (`users.dummy_verify`), so neither the response nor the timing enumerates accounts.
- Failed sign-ins get a bounded, escalating per-address delay — never a lockout, which on a
  LAN tool would let anyone deny the operator access to their own sensor.
- Sessions ride a **header, never a cookie**: a cookie would accompany cross-site requests,
  a custom header cannot be set by a cross-site form.
- `must_change` gates every route except the password change itself, server-side.
- Role changes and deletions revoke the account's sessions immediately, so an open tab
  cannot keep acting under the old role.
- A transient store read failure is **never** read as "no accounts exist" — the tri-state
  (`exists` True/False/None) keeps bootstrap from overwriting live accounts it merely could
  not see, and the DOM harness drives all of it (44 Python tests + 26 harness checks).

## Unreleased — the Settings tab becomes a real setup surface

Every editable setting renders as the control that changes it, and every setting — editable or
not — carries a "?" with a plain-language explanation. The request was literal ("toggles or
buttons or drop downs… question mark icon with an explanation… setup should be easy"), and the
implementation takes the parts of it that are testable properties rather than styling.

### Changed — controls, chosen per key, bounded by the write path's own rules

The Settings tab rendered every editable value as a free-text box: the operator typed a value,
and the first honest answer about whether it was legal came back from the server on Apply. The
fix is a single registry (`cluster_config.SETTING_CONTROLS`) that says which control each key
renders as:

- **Toggles** for booleans, with the state stated in words beside the box — for the Pushover
  switch the difference between "checked means enabled, right?" and a wrong guess is alerts
  that never send. The toggle normalises across every spelling the configuration actually
  carries (`enabled`/`disabled` from the settings payload, `1`/`on`/`yes` from a hand-edited
  ConfigMap), including for the changed-or-not comparison, so flipping a switch back to its
  running state un-stages it instead of leaving a phantom change.
- **Dropdowns** for closed sets (sensor mode, reverse-DNS mode) carrying exactly the values
  the write path accepts; if the running value is none of them — a hand-edited ConfigMap — it
  is spliced into the list so the control shows reality rather than a different value.
- **Number inputs** with the validator's own bounds and step, and the range printed beside
  them. The bounds are not a second copy: `NUMERIC_RANGES` feeds both the control and
  `validate()`, and a test drives the real validator at both endpoints and just outside them.
- **Text** remains a per-key decision for the genuinely free-text keys (interface names,
  addresses, CIDR lists) — not a fallback for a forgotten spec, which a test enforces: every
  editable key must have an explicit control, so nothing can silently regress to a text box.

### Added — an explanation on every row

A "?" on every setting that opens a paragraph under it: what the value does, its default, and
what changing it costs. Written for someone who has just deployed Weirvern and is reading the
panel top to bottom, because a settings page that shows a value without explaining it forces
the reader into the source — which is the opposite of "setup should be easy". Read-only rows
carry the help too: an unexplained value gets misconfigured whether or not it is editable.

### Fixed — two defects the DOM harness caught, not review

- `el()` applies attributes via `attrs` → `setAttribute`, and a bare `type:` option is silently
  ignored. The first version of the number and toggle controls passed `type` at the top level
  and rendered as text inputs; the harness's check for `type === "number"` failed and found it.
  (The old text input passed `type: "text"` the same wrong way and looked correct only because
  text is the default.)
- The harness's stub payload had no `controls`, and every new control fell back to text while
  every server-side test stayed green — the same shape of gap the harness exists to close, this
  time caught by it.

### Fixed — four latent gate failures, found by running the gate

`scripts/gate.sh` had not been run on this branch; it would have caught these and the same
failures would have surfaced in CI:

- `scripts/eval_detection.py`: an unused import and a `try/except/pass` (ruff).
- `weirvern/admin/soc.py`: `alert_audit` summed a value the type checker saw as `object`; the
  accumulation now happens where the int is actually typed (mypy).
- `scripts/audit_schema.py`: `review_state` was reported as a phantom reference because the
  audit only knew SQL aliases — it now also counts row keys **produced in Python**
  (`row["x"] = ...`), symmetric with how it finds readers.
- `scripts/verify_liveness.sh`: defaulted to an absolute path from the original author's
  machine; it resolves beside itself now, so the liveness proof runs anywhere.

## Unreleased — the audit fixes: the review loop, the near-miss surface, and the siphon safety gaps

A fresh audit of the running system, fixed finding by finding. The theme running through all of
it: the system was good at showing what it found and bad at showing what it decided. The headline
fixes were verified against the live deployment, not just the test suite.

### Added — an alert review lifecycle (SOC-1)

The GUI could show an anomaly and explain it, and then the workflow ended: no acknowledge, no
resolve, no false-positive marking, and no way to clear a recurring benign alert, so the anomalies
list only ever grew. Each anomaly now carries a review state — `ack`, `resolved`, `false_positive`
— persisted per `(window_start, src_addr)` in a new `alert_reviews` table, rendered as a chip with
disposition buttons on the row, and filterable to unreviewed-only. Those dispositions are the
labels a feedback loop needs later, which is why they are recorded now.

Found by running it, not by testing it: the first version wrote review keys with timezone-aware
datetimes and looked them up with tz-stripped ones, so every review merged as a silent miss. The
unit fakes used naive datetimes throughout and could not have caught it; the live box did, on the
first end-to-end POST. Both sides now normalise through the same function, and the regression test
feeds tz-aware rows on purpose.

### Added — the near-miss surface (SOC-2)

The Anomalies view lists what was flagged. Nothing showed what almost was: a window at 0.66 against
a 0.70 bar, or one that cleared the bar and died at the agreement gate. Without that surface a
threshold can only be tuned by guessing, because the only feedback is "an alert fired" or "nothing
happened" — and the second collapses "traffic was normal" with "we nearly alerted and did not".

The audit said this data "exists, it just is not queried". It did not exist. Measured against
`detect_flows`: both drop paths `continue`d before anything was recorded, so the scores were
computed and thrown away — following the audit literally would have produced a panel over an empty
table forever. The fix therefore records as well as reads: both drop paths append to an optional
near-miss list (score, the adaptive threshold that host faced, which of the two gates dropped it,
per-detector scores), the worker stores it best-effort, and a table with a 7-day TTL —
deliberately shorter than the anomalies' 30 days, because a near miss is a tuning observation, not
an incident record — holds it. The Models view grows the panel, which measured live caught windows
at 0.3465 against a 0.35 bar within minutes of deployment. Its unavailable state renders as its
own message, never an empty table: "the table does not exist yet" and "nothing nearly alerted" are
different facts, and the second is a much stronger claim.

### Added — the alert audit, not just a count of it (SOC-8)

The worker writes every alert decision to `alert_events` — sent, suppressed by cooldown, dropped at
the rate cap, or log-only when Pushover is unconfigured. The GUI surfaced it as one number in the
Health checks table: on the live deployment, five decisions sat in the table and the only visible
fact was "0 alerts", which reads as "nothing happened" when the truth was "five anomalies fired and
the layer acted on each". The Health tab now shows the outcome breakdown and the recent decisions,
and counts SUPPRESSED (cooldown, cap) separately from LOG-ONLY — the second is a configuration
state, not a withheld alert, and conflating them overstates what the system did.

### Added — a detection-quality harness, gated in CI (ML-1)

Nothing measured whether the pipeline actually detected the attacks it exists for. `f1_score`
appeared in the training report and never in a gate, so a detector that stopped detecting would
have shipped green. `scripts/eval_detection.py` seeds demo attacks into a scratch ClickHouse, runs
the real detection sweep against the real materialised views, and asserts the FINAL verdicts: the
port scan must reach critical, the beacon medium, the exfil spike critical, and a seeded-benign
host must stay quiet. A negative control — the same run with no attacks seeded — proves the
harness can fail, because a guard that cannot fail is decoration. It runs as a gating CI job on
every push.

### Fixed — the siphon safety batch: six gaps between what the code claimed and what it enforced

- `NEVER_INTERCEPT` was advisory text in a comment. It is enforced now, and the refusal is
  reported rather than silent.
- An IPv6 segment failed late and confusingly. It is refused up front, by name.
- `quiet_samples` was accounted and never read. `status` surfaces it.
- The watchdog's `failures` list was unbounded and partial. Capped.
- The batch-drain window divided by a near-zero denominator. The formula is defined at the
  boundary rather than being approximately right.
- The node-restore command was computed and never shown. `weirvern status` shows it.

### Fixed — the ARP-expiry backstop, measured at last, and a self-destruct deadline (SIPHON-2/2b)

The watchdog's comments described recovery behaviour nobody had measured. Measured on a real
segment: a graceful stop restores traffic immediately; after a hard kill an idle host's entry
sits reachable until gc, goes stale at ~65 s, and nothing recovers it until the host next sends —
at which point the first packet re-resolves within seconds. A busy host recovers in ~55 s. The
module docstring now carries the measurement instead of the claim.

And the case no signal can reach: a SIGKILLed `kubectl exec` client or a vanished SSH session
delivers nothing, ever. Non-TTY runs now require `--seconds` — someone must be there to stop it —
and every bounded run carries a self-destruct deadline: default `--seconds` + 120, an explicit
`--max-runtime` wins, and an unbounded interactive run has none, because nobody asked. When the
deadline fires it restores, loudly, and says that nothing requested the stop.

### Fixed — a siphon-configured sensor with no live intercept now says so (SIPHON-1)

`SENSOR_MODE=siphon` is a fact about a ConfigMap. An intercept is a RUNNING process. The two were
treated as the same thing, so a sensor whose intercept had ended reported as healthy. `weirvern status`
now distinguishes three honest states — intercept live / intercept RAN and stopped, node may still
be in-path / cannot tell — by scanning every `sensor_status` row for intercept evidence rather
than trusting the ranked best row, because in a siphon deployment the worker itself publishes a
zero-mapping row that would otherwise masquerade as evidence. The loud state exits 1; verified
against the box's real rows, including the real intercept from September 19.

### Fixed — the GUI batch (SOC-3/5/6/7)

- `jsdom_render.js` was hardcoded to the author's machine, with a require path that could not
  work anywhere else. It is machine-independent now, so the DOM harness runs anywhere.
- Two `getJSON` definitions existed and the last-loaded won, with different error semantics.
  One definition remains, with shared helpers.
- Three CSS variables were referenced and never defined (`--card`, `--danger`,
  `--muted-foreground`). Defined, and pinned by a stylesheet test.
- The Settings page copy contradicted itself in two places. Corrected.

### Fixed — the ML batch: a config key that did nothing, and three measured corrections (ML-2/3/4)

- `STRONG_SIGNAL` was editable through the GUI, validated, and read by no code — a config key
  that changed nothing, of exactly the class this changelog keeps finding. Wired end-to-end and
  verified on the live deployment.
- Training data included the attacks it was scoring. Flagged host-windows are now excluded from
  retraining, verified against ClickHouse with a tuple match on both columns.
- DBSCAN's score divided by a hardcoded 5.0. It is calibrated against the measured score
  distribution now.
- The Adaptive Baseline's flat stddev floor distorted z-scores for low-count hosts. Dispersions
  are measured per field now rather than assumed.

## Unreleased — Tier 3 Zeek logs, chosen from research rather than guesswork

### Added — five logs, and a recorded reason for the eleven that were not

Two independent research passes ranked **every log Zeek 9.0.0 ships**, extracting field lists from
the v9.0.0 release source tree rather than from documentation. Both independently placed the same
five at the top. Reports: `docs/research/zeek-log-research-{threat-hunting,ml}.md`; decision and
reasoning: `docs/research/zeek-log-expansion-decision.md`.

| Log | What it adds that no ingested log can |
|---|---|
| `dhcp` | **The only log with L2 identity.** Converts an IP into a MAC and hostname — the pivot that makes every other log attributable after a lease expires, and what lets a per-host baseline key on something stable. A `server_addr` that is not yours is a rogue DHCP server. |
| `x509` | **Already written and previously unread.** `ssl.log` stores fingerprints only, so it structurally cannot say whether a certificate is self-signed, a CA, expired, short-key, or carries a SAN contradicting the SNI. |
| `tunnel` | **The existence of a row is the finding** — Zeek's own documentation says so. `conn.log` carries `tunnel_parents` (UIDs) but never the encapsulation type. |
| `quic` | **Closes a TLS blind spot.** QUIC is encrypted at the transport layer and never reaches `ssl.log`, so a host moving its C2 to QUIC had no TLS record at all. Recovers the SNI and ALPN. |
| `ldap_search` | **AD enumeration is defined by filter content**, and nothing else exposes directory queries. `result_count` is the numeric signal. |

**Not added, each with a reason recorded:** `signatures` (duplicates the scan signal already
derived in `flows_aggregated_diversity`), `pe` (no PE traffic on this deployment — a table that
stays empty is a defect), `unknown_protocols` (gated, and `first_bytes` is **raw payload**, which
would break the no-payload invariant), `smb_cmd` (Zeek's own header calls it debugging-only), and
the ten protocols not present on this segment.

Feature set: **33 → 49**.

### Fixed — three bugs in the first draft of this work

- **`x509` cannot be a per-host feature.** The feature join is `(window, src_addr)` and x509 has no
  `src_addr` — it is keyed on the certificate fingerprint, because one certificate is presented by
  many hosts and Zeek deduplicates per certificate. A first draft joined it by a constant, which
  would have given every host a column reading the default *forever*: a feature that is always 0.0
  and indistinguishable from a quiet network. Caught by `tests/test_ml_table_coverage.py`.
- **Three of the five were already being written.** `ls /zeek/logs/` on the running sensor is the
  ground truth: `dhcp` was already producing rows, and `x509`/`quic` are in the default load
  closure producing none only because no matching traffic had arrived. Adding `@load` lines would
  have looked like configuration while changing nothing. Only `tunnel` needs an explicit load.
- **An audit exemption was unsubstantiated, and the audit was made to check it.** The exemption
  claimed x509 was readable "via the protocol query" so it could be skipped by the unread-table
  check. It was not. The audit now *verifies* every exemption against the query rather than
  trusting it — which is the entire point of that check.

### Fixed — the stress test's counters and teardown

Four faults in the harness rather than the product, each of which produced a confident wrong answer:

- `read_forwarding` was imported from `siphonnet`, which does not have it — so the teardown raised
  `ImportError` **during cleanup**, after the intercept ran and before the policy route was
  removed.
- `remove_forwarding_path()` takes one argument; the script passed two. `remove_address()` takes
  three; the script passed two.
- `ForwardingState` has no `rp_filter` attribute — it carries `rp_filter_off`.
- **The forwarding counter was read by fixed column position**, and printed EMPTY for a
  demonstrably working intercept (`ForwDatagrams` was 272,959). The field is now resolved **by
  name** from `/proc/net/snmp`'s own header line, because the column order is kernel-version
  dependent.
- The poison-hold sampler read `ip neigh show` **on the sensor**, which is this host's cache for
  the target and says nothing about whether the *target* is poisoned. Replaced with the evidence
  the dataplane proof used: whether the forwarding counter advances between samples, since the
  kernel only forwards datagrams that arrived because a remote host sent them to our MAC.

## Unreleased — ATT&CK mapping, a full schema audit, and the tables that fed nothing

### Added — MITRE ATT&CK technique mapping

Every anomaly is mapped to the techniques its measurements support: 18 techniques with a
confidence, the evidence that produced each one, and an explicit statement of what a network
sensor can see for it. Wired into the alert, the scoring path, the API and the GUI evidence
view, and **stored on the anomaly row** rather than recomputed for display — a later threshold
change must not rewrite what the system said at the time.

Presented as a hypothesis throughout. The no-match string is "no ATT&CK technique matched these
measurements", never "benign", and the technique block is not rendered when nothing matched,
because an empty frame reads as a clearance. `attack.coverage()` reports the techniques
deliberately NOT mapped (process injection, credential dumping, registry edits) with the reason,
so "not mapped" is never confused with "not observable".

The rules are weighted against overstatement, which is the damaging direction: a busy server
with many ports and real volume is not a scan; a 900-port probe of ONE host is T1046 and not
range reconnaissance; an ordinary DCE/RPC call is not service execution; a large two-way
transfer is not exfiltration; high DNS volume without entropy and failures is not tunnelling.

### Fixed — three tables were ingested and read by nothing

A full schema audit (`scripts/audit_schema.py`) checks the whole project in three directions:
columns nothing writes, tables nothing reads, names the code reads that nothing produces. It
found more than the feature it was written for.

- **`zeek_http` (327 rows), `zeek_files` (321) and `zeek_ssh` (155) were collected, stored, and
  read by no query, no feature and no view.** Data gathered for the life of the deployment and
  discarded, while every individual file looked complete. The feature set went from 18 to 33.
- **Four ATT&CK rules read column names no query produces** — `dns_query_count`,
  `kerberos_distinct_services`, `orig_bytes`, `ssh_auth_attempts` — so each read 0.0 and the
  rule could never fire. They looked like working coverage. Same defect as the dead
  `ja3`/`ja3s` columns and the six Tier-2 tables that had no mapper: a name that exists in one
  place and is produced nowhere.
- **The `or` fallbacks that hid it.** `_f(row.get("zeek_dns_count")) or _f(row.get("dns_query_count"))`
  is worse than a wrong name: 0 is falsy, so a host with a legitimate zero fell through to a
  name that does not exist, and the code *appeared* to handle two sources.

### Added — schema migrations that reach an existing database

`005_attack_techniques.sql`. Adding a column to a `CREATE TABLE IF NOT EXISTS` does nothing on a
database that already has the table — measured: the deployed cluster returned
`Unknown expression identifier attack_techniques` with the column plainly listed in the schema
file. Works on a fresh install, fails on an upgrade: the worst combination. Schema changes to an
existing table now go in a numbered `ALTER` migration, and `tests/test_schema_migrations.py`
requires it.

### Fixed — bugs in the instruments, not the system

Recorded because each produced a confident wrong answer about the code:

- The audit reported nine working columns as dead; they are written by materialized views in the
  same `.sql` file and the check only searched Python.
- It reported the whole GoFlow2 flow mapper as phantom; those names are the collector's JSON
  schema, not our DDL.
- It reported removed `or` fallbacks as live, because the mapper's docstrings *quote* the wrong
  names they replaced while explaining why. The sixth place in this project an assertion had to
  distinguish code from prose about code.
- `tests/test_attack_wiring.py` asserted that the *invented* names exist — written against the
  same wrong names the mapper used, so it could not fail for the reason it existed.
- A `str.index("keys AS (")` matched that phrase inside an explanatory comment, producing a
  four-character slice that made every assertion against it fail.

### Added — in-cluster `siphon` mode

`kubectl apply -k overlays/siphon/` is now the entire procedure:

- a **privileged init container** sets the three sysctls, because the API server rejects
  pod-level sysctls when `hostNetwork` is true *and* holding `NET_ADMIN` is insufficient —
  Kubernetes mounts `/proc/sys` read-only for a normal container
- the worker gains `NET_RAW` + `NET_ADMIN`, `hostNetwork` (measured: without it the pod sees
  `['lo','eth0']` and cannot reach the capture NIC), and `dnsPolicy: ClusterFirstWithHostNet`
  (the default for a hostNetwork pod cannot resolve cluster Services)
- **`iproute2` added to the worker image** — `ip` was missing, so `siphon` could never have worked
  in-cluster with every capability granted; it would have failed at the first `ip` call, after
  the preflight had passed
- `runAsUser: 0` at **both** pod and container level, because Kubernetes drops added
  capabilities for non-root containers: measured `CapBnd 0x3000` with `CapEff 0x0` until the
  user was changed

## Unreleased — in-path intercept, Zeek in the models

### Added — in-path intercept (`siphon` mode)

`weirvern intercept` puts Weirvern **in** the path: it ARP-forges the gateway mapping for
chosen hosts so their off-link traffic arrives at Weirvern, which relays it in the kernel.
This is an L2/L3 redirect, not a TLS intercept — nothing is decrypted and no certificate is
substituted.

**Verified end to end against a real host on a live segment.** A real device's off-link
traffic arrived at our MAC while its ARP cache named us as the gateway, *and* the kernel
forwarded it (`ForwDatagrams` rose in the same window). Both halves matter: traffic arriving
with the counter flat means the host was cut off, not relayed.

- `--hosts` targets named hosts rather than a whole segment, because poisoning everything
  makes a crash an outage for every device until ARP caches expire. A requested host that did
  not answer the sweep is **reported**, not silently dropped.
- `--dry-run` prints the plan, the blast radius, and free addresses before changing anything.
- The command assigns its own address on the capture interface and **withdraws it on every
  exit path**, including failure and Ctrl-C.

Three bugs found by running it rather than by testing it:

- **The poison frame was silently ignored.** Linux does not update a neighbour entry in
  `REACHABLE` state from an unsolicited ARP *reply*, and a host's gateway entry is always
  reachable — so the frame was byte-perfect and discarded every time. Measured: reply
  ignored, forged *request* took effect, gratuitous broadcast ignored. Interception had been
  a no-op that logged success. Now sends an announcement.
- **Relayed traffic left by the wrong interface.** `ip_forward=1` makes the kernel willing to
  forward; it does not decide *where*. A relayed packet matched the default route and would
  have left via the **management** interface carrying the victim's source address onto the
  wrong segment. Fixed with a one-armed-router policy route, installed before any poison
  frame exists.
- **The watchdog fired on a healthy network.** `ForwardingMonitor` was built with its
  default sample of zero, so the first health check compared the real kernel counter against
  zero and always reported progress — setting "forwarding has been observed working" without
  a packet being forwarded. The one case the quiet-network protection exists for (an idle
  segment) was the case it could never protect. Now primed from the kernel.

### Added — Zeek features in every model

All four detectors train and score on **both** sensors. The NetFlow half describes volume and
breadth; the Zeek half describes what the traffic *is*: connection-state mix, DNS entropy and
failure rates, service variety and novelty, JA4 diversity, TLS version mix, and Zeek's own
notices and weirds. One measured host-window showed 89 connections of which **88 were
unanswered SYNs with zero response bytes** — a scan that NetFlow reports as modest traffic.

- `zeek_present` is a feature in its own right, because the two sensors may observe different
  hosts (measured: 91 NetFlow hosts, 35 Zeek hosts, **2 overlapping**). Without it the models
  would learn that most host-windows are defined by empty features, which is a fact about the
  deployment rather than the network.
- The join is a LEFT JOIN on `(5-minute window, host)`. An inner join would drop every host
  Zeek did not see; joining on host alone would compare one window against all its history.
- The Adaptive Baseline gained a **behavioural** norm alongside the volumetric one, and
  `weirvern status` reports the actual NetFlow/Zeek coverage.

Three bugs found by running the queries against a live database:

- A five-way `FULL OUTER JOIN` with `coalesce` over the join keys returned **epoch zero** and
  an empty host — every feature row keyed on nothing. Rebuilt as UNION-of-keys then LEFT JOIN,
  which also removed a row cross-multiplication that inflated every count.
- `zeek_present` was a feature but not a SQL column, so the training query named a column
  that did not exist.
- Feature names and SQL column names differed, so *every* training query failed.

### Changed — the sensor image carries only the fingerprinting method it uses

The TLS client fingerprint (BSD 3-Clause) is kept. The other methods in the upstream package
carry different license terms and are **deleted at build time** rather than switched off.

The previous design redefined ten `FINGERPRINT::JA4*_enabled = F` options, and it worked — but
the package gates its submodules with `@if`, which is evaluated when the file is **loaded**, so
a disable placed after the package loaded was silently ignored. That was measured: the server
fingerprint field populated in **28 of 28** records while the configuration claimed it was off. It was fixed by
load ordering, which left licensed code in the image with a three-line sequence as the only
thing preventing its distribution.

The build-time pruning script deleted the submodule directories, the package's recorded test
output, the loader lines and the options — and **failed the build** if any of that did not
take, or if it removed too much and the fingerprint itself would no longer work.

> **Upgrading:** the sensor image and the site policy must ship together. The policy must not
> carry redefinitions of options the image no longer provides; Zeek aborts at startup with
> `"redef" used but not previously defined`.

### Added — Models view in the web GUI

Training history (log-scaled, one line per retrain), score distribution including
sub-threshold scores, model agreement, and per-feature deviations against each host's own
baseline. Hand-rolled SVG — the GUI stays dependency-free because it has to work on an
isolated sensor network.

Built from data that is deep at any volume rather than from the anomalies themselves: a young
deployment has very few, and a chart of three points is indistinguishable from a rendering
bug. Every panel either draws real data or says in words what is absent and why.

### Fixed

- **`arp_sweep` reported 0 hosts on a live segment with 11.** It read `/proc/net/arp`, which
  the kernel only populates for addresses the interface *owns*, and it sent a whole /24 before
  reading any replies — ARP replies are unicast, so a full socket buffer dropped most of them.
- **`forwarding_path_problems` aborted every intercept.** It used `ip route get <dst> iif
  <iface>`, which errors without a source address, and read that error as "misrouted" — so it
  refused to run against a correctly configured host while telling the operator to fix it.
- **Preflight demanded the policy route that `start()` installs**, a prerequisite nothing
  could satisfy, so the command could never reach the code that fixed the problem.
- **`INTERCEPT_SEGMENT` / `INTERCEPT_ADDR` / `INTERCEPT_GATEWAY`** were read by the CLI and
  appeared in neither `config.py` nor `.env.example`.
- **The prune tests read the wall clock** at all 11 call sites despite `plan_prune` accepting
  `now`, making the grace-period assertions depend on how long the suite took.

## v0.4.0 — Kubernetes-native deployment, control plane, and a
## packaging bug that would have deployed an empty database

The project's deployment target is Kubernetes. This release removes the
single-host container path entirely and replaces it with manifests plus a
control plane, and fixes two bugs that only a non-editable install or a real
cluster would have revealed.

### Added — Kubernetes manifests (`k8s/`)

Applied with `kubectl apply -k k8s/` (kustomize). 20 resources:

| File | Contents |
|---|---|
| `00-namespace.yaml` | Namespace with Pod Security Admission labels (`baseline` enforce, `restricted` audit/warn) |
| `10-storage.yaml` | `clickhouse-data` and `models` PVCs; storage class configurable in one place |
| `20-configmap-env.yaml` | Non-secret settings, mirroring `.env.example` |
| the `weirvern-secrets` Secret | Created imperatively by the operator; deliberately not a manifest |
| `30-clickhouse.yaml` | StatefulSet, headless Service, optional external Service |
| `31-goflow2.yaml` | Collector Deployment + UDP NodePort Service, node-pinned |
| `32-zeek.yaml` | **DaemonSet** with `hostNetwork` and `NET_RAW` |
| `33-worker.yaml` | Detection worker Deployment, node-pinned, single replica |
| `50-schema-job.yaml` | Applies the schema via the application's own `init-db` |
| `60-rbac.yaml` | Least-privilege `viewer` and `operator` roles (neither reads Secrets) |
| `70-networkpolicy.yaml` | Optional hardening; not enabled by default |
| `kustomization.yaml` | Assembles the above; generates the Zeek ConfigMap from source |

Design decisions encoded, not incidental:

- **Zeek is a DaemonSet with `hostNetwork`** — a packet sniffer sees only its own
  node's interface, so per-node is the only correct abstraction. A single-host
  "run the sniffer on the host" idiom has no cluster equivalent and no answer for
  "which node?".
- **Collector and worker are node-pinned and single-replica** — the collector
  writes a file the worker tails by byte offset, so they must share a node. The
  pin is a `nodeSelector` on a labelled sensor node rather than scheduling luck,
  because the failure mode (healthy stack, reading an empty file) is silent.
- **`externalTrafficPolicy: Local`** on the collector Service — with the default
  policy, kube-proxy on another node can accept and misroute the UDP packets.
- **`Recreate` strategy** on both writer and reader — two collectors appending to
  one file interleaves records and corrupts offset tracking.
- **Schema applied by a Job, not an initdb directory** — the initdb directory
  only runs against an empty data directory, which is precisely why schema
  changes never reached a running database in the legacy lineage.

### Added — control plane

- **CLI** (`weirvern`): `install`, `apply [--dry-run]`, `wait`, `init-db`,
  `start`/`stop`/`restart`, `status`, `logs`, `down [--volumes]`, `pull`,
  `config`, `tune`, `tui`, `version`.
- **TUI** (Textual): workload state, health probes, live anomalies, top talkers,
  editable config with secrets masked, logs by label, help.
- **`K8sBackend`** behind the existing `Backend` protocol, driving `kubectl -o
  json` rather than human-readable tables (which change shape between client
  versions and would break the TUI on an unrelated upgrade).
- Project discovery: `$WEIRVERN_HOME`, then the nearest ancestor containing
  `k8s/kustomization.yaml`, then the package location.

Lifecycle vocabulary does not map cleanly onto Kubernetes, so the tool reports the
operation it actually performed:

| Command | Operation |
|---|---|
| `start` / `stop` | Scale Deployments/StatefulSets 1 ↔ 0 |
| `stop zeek` | **Suspend** — Kubernetes rejects `replicas: 0` on a DaemonSet. A JSON-patch `remove` on resume restores the manifest's own selector exactly |
| `restart` | `kubectl rollout restart` (there is no pod-restart verb) |
| `pull` | No-op that explains itself: each node's kubelet pulls images |

### Fixed — a non-editable install deployed an empty database

The schema lived in a repo-level `clickhouse/init/`, resolved as
`Path(__file__).parent.parent / "clickhouse" / "init"`. That is correct in a
checkout and **wrong in an installed wheel**, where it resolved to a
non-existent `site-packages/clickhouse/init`. Verified against a real
non-editable install: `apply_schema()` globbed zero files, applied nothing, and
returned success — so the schema Job in a container image would have reported
completion while creating not a single table.

Two fixes, because either alone is insufficient:

1. The schema moved inside the package (`weirvern/schema/`) and is declared in
   `pyproject.toml`'s package-data, so it ships in the wheel. Verified present
   after a non-editable install.
2. `apply_schema()` now raises when the schema directory is missing or empty. A
   silent no-op that reports success is worse than a crash: it produces a
   running system with no tables.

### Fixed — `copytruncate` log rotation silently skipped records

A file replaced by a **larger** one is indistinguishable from an append by every
`stat()` field — inode (the filesystem may reuse it), size (it grew), and mtime
(a write happened either way). Verified: 5 records written, 4 inserted, one
fragment logged as malformed JSON. This is the standard `copytruncate` rotation
mode.

Detection now uses the content: for a line-oriented log, a valid continuation
offset is preceded by a newline. If the byte before the saved offset is not a
newline, the file is not the one being read and the tailer re-reads from the
start. The Zeek tailer shares the logic. Verified against a case matrix:
initial read, replacement-by-larger, append, unchanged, truncation,
partial-line-hold-back, partial-line-completion, and legacy call signature.

### Fixed — CI red on every push

`test_rotation_detection_re_reads` asserted that delete-and-recreate changes the
inode. That is a filesystem allocator property, not the behaviour under test: it
held on ext4 (0/20 reuses) and failed on GitHub's overlayfs (inode reused), which
turned every push red. Chasing it is what surfaced the `copytruncate` bug above.
Replaced with behaviour-based tests.

### Changed

- **Removed** the single-host orchestration file, the class that wrapped it, and
  all single-host container references from documentation. The `Containerfile` is
  retained: it is the image specification the cluster needs, not orchestration.
- `.gitignore` pattern corrected from `*.env` to `.env*`. The old pattern only
  matched names *ending* in `.env`, so `.env.bak` — written by the config
  editor, containing Pushover tokens and database passwords — would have been
  committed. `.env.local`, `.env.prod` and similar were also unignored.
- `.env` parsing now strips inline trailing comments, matching the `.env.example`
  template that ships them. Previously the worker crashed on `int()` for
  `DETECT_INTERVAL_S=300          # sweep cadence` while the container runtime
  accepted the same line — a divergence between two readers of one file.

### Fixed — the documented secret step was silently undone by `apply -k`

`k8s/21-secrets.yaml` shipped placeholder values and was included in the
kustomization, so the sequence the README documented —

```
kubectl -n weirvern create secret generic weirvern-secrets --from-literal=...
kubectl apply -k k8s/
```

— ended with `apply` OVERWRITING the real credentials with empty strings
(verified: `PUSHOVER_USER_KEY` went from a real key to `""`). Alerting then never
fired, with no error anywhere: the worst possible failure shape for an alerting
system.

The Secret manifest is removed and the Secret is now created out of band only.
A `secretGenerator` reading a gitignored file was tried and rejected: it fixes
the overwrite but makes `kustomize build` fail on a fresh clone and in CI, which
breaks the `--dry-run` inspection an operator uses to decide whether to deploy.

### Fixed — version skew across four places

`pyproject.toml`, `weirvern.__version__`, the image tag in the manifests, and
the CHANGELOG heading disagreed (0.1.0 / 0.1.0 / 0.1.0 / "Unreleased (v0.4.0)").
All now report 0.4.0.

### Changed

- `weirvern install` returns exit code 3 (not ready) when kubectl or a cluster
  is unavailable, distinct from 1 (error). It previously returned 0 in both
  cases, so a wrapper could not distinguish "prerequisites missing" from
  "something broke".
- Every container, including init containers, now declares resource requests and
  limits. A namespace with a ResourceQuota requiring requests would otherwise
  reject the Pod outright, and the short-lived `wait-for-clickhouse` pollers
  could be scheduled onto a full node.
- Added commented `imagePullSecrets` placeholders to the worker Deployment and
  the schema Job: a private registry is the likely case for a personal project,
  and the pods otherwise ImagePullBackOff with no in-repo hint.
- Added a commented control-plane toleration to the Zeek DaemonSet. On a
  single-node cluster that node is tainted `NoSchedule`, so without it the sensor
  stays Pending forever while everything else looks healthy. Commented rather
  than enabled, because tolerating the taint lets a privileged packet sniffer run
  on control-plane nodes in a multi-node cluster — a placement decision, not a
  default.

### Verified

- 155 tests, `ruff` clean, `mypy` clean.
- `kubeconform -strict`: 20/20 resources valid.
- `kustomize build k8s/`: succeeds; every ConfigMap/Secret reference, volume
  mount, PVC reference and probe port resolved programmatically (which caught a
  `clickhouse-logs` mount with no declared volume — the pod would have been
  rejected).
- Schema present after a non-editable install; `apply_schema` raises loudly on an
  empty or missing schema directory.

## Unreleased (v0.3.0) — Zeek packet sensor (second view of the network)

Adds Zeek as an independent sensor alongside NetFlow. Decision rationale and
measured evidence are in the README ("Why both sensors?") — the short version:
each sensor is blind to a different class of attack, and a DNS-tunnelling host
was measured with 0 connections but 40 high-entropy queries (4.82 vs 2.52
benign), which is unreachable from flow records.

### Added

- `zeek` sensor (`zeek/zeek:lts`, BSD-3-Clause) sniffing a chosen NIC / span
  port: `ZEEK_IFACE`, host networking with `NET_RAW` scoped to that workload
  only. Omit `32-zeek.yaml` to run NetFlow-only.
- Four Zeek tables: `zeek_conn`, `zeek_dns` (with computed `query_entropy` and
  `query_len` — the tunnelling signal), `zeek_ssl` (JA3/JA3S), `zeek_notice`
  (Zeek's own curated detections, ingested as corroboration, not as alerts).
- `zeek_host_activity` view joining all four per host per 5-minute window.
- Zeek TSV parser (`parse_zeek_header`, `map_zeek_*`) driven by the `#fields`
  header rather than a hardcoded column order — Zeek's field set varies by build
  and version, and a positional assumption silently shifts every value.
- `k8s/zeek/weirvern-local.zeek` site policy (hourly rotation, no mail, noisy
  notices suppressed). Two corrections since: the `policy/misc/scan` load was
  removed (deleted upstream in Zeek 6.1+), and `k8s/zeek/zeekctl.cfg` was deleted
  because nothing read it — the container runs the `zeek` binary, and that file's
  INI syntax is not Zeek script.

### Bugs found while building this (both caught only by running real inputs)

1. **Resumed Zeek reads dropped records.** Zeek data lines are positional and
   meaningless without their `#fields` header, but a resumed tail starts
   part-way through the file (the tailer deliberately holds back a partial
   trailing line). The header was no longer in front of the data, so the record
   completing that partial line was silently discarded. Fixed by caching and
   threading the parsed header through the tailer's state.
2. **`arrayStringConcat(uniqExact(x))` is illegal in ClickHouse** (needs
   `groupUniqArray`), so the `zeek_host_activity` view failed to create —
   reported only by a real server, not by the unit suite.
3. **`FULL OUTER JOIN` + `coalesce()` lost hosts present in only one source**:
   the DNS-only tunnelling host surfaced with a blank `src_addr` and zeroed
   counters. Replaced with a `UNION DISTINCT` key set LEFT JOINed to each
   source.

## Unreleased (v0.2.0) — full audit + validation

Audited the v0.1.0 baseline end-to-end against a **real ClickHouse server**
(24.8, local instance), which surfaced bugs the unit suite could not. Every fix
below was reproduced first, then fixed, then covered by a regression test.

### Critical bugs found by the audit (all would have broken a first deployment)

| # | Bug | Root cause | Fix / evidence |
|---|---|---|---|
| 1 | Worker **died on first boot** | `worker.py` read `if_model.X_train_unscaled`, an attribute the v20 detector rewrite had removed → AttributeError, retry loop, no training | Attribute restored and set at train time; guarded with `is not None` |
| 2 | **Every query raised TypeError** | `db.py` passed `database=` to `Client.query()`; clickhouse-connect accepts that only on `command()` | Removed; client is bound to the database at connect |
| 3 | **Fresh volume was unbootable** | `connect()` bound straight to the `weirvern` DB, which does not exist yet → `UNKNOWN_DATABASE` on all 30 retries, so `apply_schema()` never ran | Two-phase connect: bootstrap on `default`, `CREATE DATABASE IF NOT EXISTS`, then bind. Verified against a dropped database |
| 4 | **Three tables failed to create** | ClickHouse rejects `TTL <DateTime64 column>` (code 450, BAD_TTL_EXPRESSION) | `TTL toDateTime(col) + INTERVAL …`; all 12 objects now create on a fresh DB |
| 5 | **Duplicate ingestion** | The tailer re-read the file from offset 0 every 5s → every row re-inserted ~12×/min, corrupting aggregates and baselines | Offset + inode tracking with rotation/truncation handling |
| 6 | **Silent flow-record loss** | A half-written trailing JSON line was consumed; once the write finished the remainder was read as a fragment and lost forever | Only newline-terminated lines are consumed; offset points at the start of the partial line |
| 7 | **One collapsed aggregation window** | Materialized views windowed on `timestamp` (ingestion time), so backfilled/historical flows piled into the current 5-min bucket — 79,349 flows and 12.2 GB in one window | Views window on `time_flow_start` (the flow's own time). 102 windows → **10,372**; max window 12.2 GB → 2.6 MB |
| 8 | **Port scanner went unalerted** | Mean fusion averaged DBSCAN's correct 0.99 down to 0.405 — *below* benign hosts (0.543) — because volume-based models score ~0 on a zero-byte scan | `fuse_scores(..., mode="max")`: a confident specialist is no longer averaged away. Legacy mean retained for A/B |
| 9 | **Benign hosts alerted as "critical"** | Raw `predict_proba` is distorted by 15× class-imbalance weights → ordinary windows scored 0.97 | Percentile calibration for GB (and IF) against each model's own training distribution |
| 10 | **Alert storms by design** | Alerts were re-queried from a sliding window, so the same anomaly rows re-alerted every sweep | Sweep returns its own verdicts; alerting consumes them once |
| 11 | **Models went stale forever** | `load_or_train` early-returned after a warm start; the 6h retrain / 5-min baseline refresh had been dropped | Explicit `train_if_due` cadence (full retrain every `RETRAIN_EVERY_H`, baseline refresh each cycle) |
| 12 | **Phase 2 features silently dead** | The worker attached `_diversity`/`_temporal`, but the ensemble never passed them into `extract_features` | Enrichment now reaches the feature vector |

### Detection-quality work (driven by measured results, not preference)

- **Fusion changed from mean to max.** Measured on live data: scanner 0.405 vs
  benign 0.543 under mean fusion; the scanner was never alerted. Under max,
  scanner 0.990 vs benign ceiling well below it.
- **Thin-window damping.** 3–4 flow windows let one heavy-tailed flow (backup,
  streaming) dominate the window's statistics — measured false positives
  (benign 3-flow window, GB 0.96). Scores are damped proportionally below
  `min_flows_for_full_confidence` (10). Genuine attacks were unaffected
  (the scan had 305 flows; the exfil 3.6 GB vs a 65 MB host baseline).
- **Corroborated severity escalation.** `high`/`critical` now require two-or-more
  detectors at ≥0.85, **or** one such detector backed by a direct structural
  signature (≥50 distinct ports at ≥4.0 entropy). This fixes the case where a
  zero-byte SYN scan is invisible to volume models — they are not disagreeing,
  they have no opinion — without re-opening the single-strong-model false-positive
  shape. A lone uncorroborated signal still alerts at `medium`: not escalated,
  not silenced.
- **Realistic demo traffic.** The generator drew byte sizes from a flat uniform
  range, which made every host look statistically novel and masked tuning bugs.
  Now heavy-tailed (80% small / 17% medium / 3% large), matching LAN reality.

### Validation result (live ClickHouse, fresh database, seeded attacks)

```
port scanner .10 : 0.990  critical   (DBSCAN + 300-port structural signature)
exfil .11        : 0.990  critical   (all four detectors >= 0.99)
benign hosts     : 0 at high/critical
ACCEPTANCE: PASS
```

### Hardening / tooling

- `bandit`: 8 medium → 0 high; remaining 11 items individually reviewed and
  documented (B104 is `ipaddress` parsing, not socket binding; B608 f-strings
  interpolate only formatted datetimes and int config, never flow data;
  B301/B403 pickle of the trusted local `MODEL_DIR`; B311 demo RNG).
- `ruff` + `mypy` clean; **68 tests** (was 30) covering ingester offsets/rotation/
  partial-line handling, detector persistence roundtrip, fusion, severity gates,
  signature corroboration, thin-window damping, calibration, and worker cadence.

### Known gaps (next iteration)

- Feedback loop for reducing false positives (needs a review UI).
- Model drift alerting (e.g. F1 decay from `ml_models` history).
- TLS for ClickHouse / auth beyond `default`.
- Real NetFlow validation on hardware (pfSense/switch) — so far exercised with
  the synthetic generator against a real ClickHouse.

## v0.1.0 — the v20 rebuild

Rebuilt from scratch against every lesson of the v14 → v19 legacy lineage.
This is the testing/refinement baseline; nothing is production yet.

### Lessons applied (legacy → v20)

| # | Legacy pain point (v14–v19) | Fix in v20 |
|---|---|---|
| 1 | **Version skew**: v14.11 stayed deployed while v15/v17/v19 sat as drafts in `src/`; nobody could tell what was running | Single source of truth: the deployed artifacts (image tag + persisted models). ML code lives only in `weirvern/models/`; `MODEL_DIR` artifacts are versioned (`_v1.pkl`) and the running version is visible |
| 2 | **State loss**: models trained in-memory each boot; every restart meant cold-start retraining | Detectors persist to disk (pickle) + metadata to `ml_models`; warm start on boot (`BaseDetector.load()`) |
| 3 | **Schema in configmap**: giant YAML-escaped SQL drift; "0 baselines" bugs from schema mismatches | Real `.sql` files packaged with the application, applied idempotently, version-stamped in `schema_versions` |
| 4 | **pip install at pod boot** (`python:3.11-slim` + pip in `command:`) | Build-time install in the `Containerfile`; pinned deps in `pyproject.toml` |
| 5 | **Inline-heredoc tailer** in the goflow2 Deployment | `weirvern/ingester.py` — tested module |
| 6 | **No tests at all** | `tests/` (scoring, features, ensemble, alerts, config, demo) + CI (lint, mypy, pytest) |
| 7 | **Magic numbers across versions** (thresholds, weights, agreement levels changed every release) | All knobs in `weirvern/config.py` (env-driven) with validation |
| 8 | **Explainability bugs**: fake 9.9 z-scores, empty `feature_contributions` | Scored, bounded explainability fields; percentiles/z-score driven |
| 9 | **No alerting**: anomalies sat in a table | Pushover transport + per-source cooldown + hourly cap + full `alert_events` audit |
| 10 | **Runaway pod / no graceful shutdown** | Resource limits, probes, non-root user, SIGTERM handling |
| 11 | **No security posture** | Network exposure minimal (collector UDP only), SECURITY.md, RBAC, Pod Security Admission labels |
| 12 | **Grafana failure → custom TUI** | Control-panel TUI (`weirvern tui`): status, health, anomalies, config, logs |

### Architecture changes vs legacy

- **Kubernetes-native**: manifests under `k8s/`, applied with `kubectl apply -k
  k8s/`. The legacy k0s layout is reflected there (namespace → storage →
  configmaps → workloads → services → jobs).
- ClickHouse database renamed `default` → `weirvern`.
- New `alert_events` table (audit trail), `schema_versions` (schema stamps).
- Worker is one long-running process: ingest thread + detection loop.
- Synthetic traffic generator (`weirvern.tools.demo_flows`) writes goflow2-
  shaped JSONL so the whole pipeline is exercisable without a NetFlow source.

### v19 feature set retained (Phase 2 multi-granularity)

- Diversity metrics: unique dst ports, port entropy (Shannon), bytes stddev,
  connection density.
- Temporal metrics: activity regularity (CV — C2 beaconing), burstiness,
  minute activity.
- Isolation Forest: 14 features, contamination 0.06, extremes sampling.
- DBSCAN: 8 features.
- Adaptive baseline: per-host p95/p99/p999 + σ baselines.
- Adaptive thresholds: pattern-aware sensitivity reduction (floor 0.20).

### Known gaps (next iteration)

- Feedback loop for reducing false positives (needs a review UI).
- Model drift alerting (e.g., F1 decay from `ml_models` history).
- TLS for ClickHouse / auth beyond `default`.
- Real NetFlow validation on hardware (pfsense/switch) — demo generator only so far.
