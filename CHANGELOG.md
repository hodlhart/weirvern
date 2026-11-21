# Changelog

## 0.23.124 — 2026-11-21

TWO OUTAGE-CLASS DEFECTS FIXED AT THE CAUSE. A MANIFEST APPLY CAN NO LONGER BLANK THE SETTINGS THE
GUI OWNS, AND A CAP-TRIM RACE CAN NO LONGER RE-INSERT THE FLOW FILE. THE DAMAGE FROM THE SECOND IS
CLEANED UP AND COUNTED.

- **THE 18-HOUR DUAL CAPTURE OUTAGE WAS AN APPLY, AND AN APPLY IS NOW GUARDED.** The 2026-11-20
  23:33:43 deploy restored `k8s/20-configmap-env.yaml`'s placeholders over the live ConfigMap:
  `CAPTURE_IFACE` and `NETFLOW_IFACE` emptied, `ZEEK_IFACES` and `INTERCEPT_PLANS` emptied,
  `SENSOR_MODE` siphon -> loch; the DaemonSet rolled two seconds later and the tap selected zero
  targets. Nothing enforced the `weirvern.io/gui-written-keys` annotation that still held the lost
  values. `weirvern/admin/config_guard.py` now does, at the only point that can: BEFORE kubectl is
  invoked. It renders the manifests, merges the recorded GUI values back into the env ConfigMap,
  and refuses when a key that is non-empty live would become empty (or when a capture setting would
  change with no GUI record). The refusal names every key and its live value, e.g. `CAPTURE_IFACE
  (live "eth1")`, and the override is explicit (`--allow-blank KEY[,KEY]`). `weirvern apply` and
  `scripts/apply_safe.sh` both call it; the wrapper then applies the merged render and reads the
  ConfigMap back, failing if a capture setting did not survive. The effective data starts from the
  LIVE values, so a deploy can add or change a setting but can never make one disappear. Raw
  `kubectl apply -k k8s/` is documented as unsafe in `k8s/README.md` and `docs/deployment.md`.
- **1,070,782 DUPLICATE `flows` ROWS WERE A TRIM RACE, AND THE RACE IS CLOSED.** A cap trim rewrites
  the sink in place and THEN atomically replaces `<sink>.trimhint`. A tailer that landed between the
  two saw a valid file whose cursor the old hint could not explain, fell back to a full re-read, and
  re-inserted the whole surviving file. Two prunes (12:20/12:25) meant two re-reads. `tail_and_insert`
  now retries `_apply_trim_chain` three times with a growing delay before concluding the hint cannot
  explain the cursor -- the window is milliseconds, and the retry removes it. As defence in depth, a
  fallback re-read now checks each batch's NATURAL KEY (flow start/end, addresses, ports, protocol,
  bytes, packets, sampler, interface -- never `timestamp`, which is ingest time) against `flows` in
  bounded queries and does not insert a row the database already has. The check runs only on the
  re-read path; a normal append still pays nothing. A failed existence query logs an error and
  admits the batch (data over exactness) rather than stopping ingest.
- **THE DAMAGE IS CLEANED UP, NOT MERELY STOPPED.** Targeted `ALTER TABLE ... DELETE` removed the
  re-read population (`timestamp >= 2026-11-21 00:00 AND time_flow_start < 2026-11-21 00:00`):
  1,070,782 rows from `flows`. 84,189 rows whose natural key had NO older copy (records the re-read
  ingested for the first time) were preserved and re-inserted with `timestamp = time_flow_start`.
  The affected window range (`2026-11-16 13:05` .. `2026-11-21 00:00`) was then rebuilt from raw
  `flows` for `flows_window`, `flows_window_endpoint`, `flows_aggregated`,
  `flows_aggregated_diversity` and `flows_aggregated_temporal`. Measured before/after in the
  repaired range: `flows` 1,070,782 duplicates -> 0; `flows_window` 354,148 rows /
  78,309,038 states -> 168,155 / 1,077,984; `flows_window_endpoint` 507,536 / 4,129,154 ->
  352,045 / 2,155,968; `flows_aggregated` 4,291,257 rows / 78,309,038 flows -> 168,155 / 1,077,984;
  and the two side tables 168,155 and 166,517 rows. The rebuilt totals now equal the raw flow count
  exactly (1,077,984), and `flows_window_endpoint` is exactly twice it (2,155,968).
- **Tests, not just fixes.** `tests/test_config_guard.py` proves a blanking apply refuses and names
  the interfaces, that a recorded value is restored (including a value a PREVIOUS apply blanked),
  that a capture change with no record is refused, that a legitimate change still applies, and that
  no live key is ever dropped. `tests/test_ingester.py` proves a hint that appears one retry late
  causes no re-read, that a forced re-read inserts only genuinely new rows, and that a normal append
  never queries the table.

## 0.23.123 — 2026-11-21

THE NETFLOW OUTAGE IS DIAGNOSED FROM THE EVIDENCE, THE CAPTURE PATH IS RESTORED, AND A STALLED
INGEST NOW ANNOUNCES ITSELF. THE ENSEMBLE'S COVERAGE IS MEASURED IN BOTH MODES.

- **THE OUTAGE WAS A CONFIG APPLY, NOT A COLLECTOR FAULT.** At 2026-11-20 23:33:43 the deploy
  applied `k8s/20-configmap-env.yaml` over the live ConfigMap, restoring the manifest's
  placeholders: `NETFLOW_MODE` auto (was active), `NETFLOW_IFACE` and `CAPTURE_IFACE` empty
  (were `eth1,eth2` and `eth1`), `SENSOR_MODE` loch (was siphon) and `INTERCEPT_PLANS` empty. The
  zeek DaemonSet rolled two seconds later; the new tap sidecar selected ZERO targets and
  published `running: false, targets: []` every fifteen seconds without a word. The old tap's
  last export, the last goflow2 log line and the last byte of both JSONL files are all
  23:33:14.94 — the in-flight 30s segment was lost with the pod, and nothing was metered after.
  `kubectl get cm -o jsonpath='{.metadata.managedFields[*].time}'` (23:33:43) and the
  `weirvern.io/gui-written-keys` annotation (the values a GUI write recorded, still naming
  `eth1,eth2` / `eth1` / siphon) are the two records that make the clobber visible.
- **The `template error` lines were a symptom, not the cause.** goflow2's counters at the last
  scrape read 565,420 DataFlowSet records and 29,296 `template_not_found` errors (5.2%) — real,
  from the one-shot softflowd runs' ephemeral source ports filling the template cache, but the
  writer advanced through them for the whole 25 minutes they were logged. Decoding resumed on
  the first packet after the tap was restored, with no collector restart and no error. NetFlow
  template expiry does not explain a file that stopped growing; a tap with no targets does.
- **goflow2 IS ONLY THE EXPORTED-NETFLOW COLLECTOR, and the console must not conflate it with
  soft flow.** On this deployment every row in `flows` carries `sampler_address = 127.0.0.1` —
  the local tap's softflowd IPFIX, i.e. SOFT FLOW summarised off the NIC, not a router export
  (714,350 of 714,350 rows in the six hours to 18:22Z; `flows-external.jsonl` has never received
  a packet). The `zeek_conn` view is the same capture pod's own conn.log, a second product of
  the same tap. So the freeze was a CAPTURE stop: the tap wrote nothing, and both `flows` and
  `zeek_conn` stopped with it. The guard now measures both sinks separately.
- **ClickHouse's DateTime columns here are naive LOCAL time.** `max(timestamp)` reading
  `12:19:31` at 18:19Z is FRESH (America/Chicago is UTC-6 in November), not six hours stale; the
  freshness module computes the age with `dateDiff(..., now())` inside ClickHouse so a local-time
  read cannot be mistaken for a stall.
- **The capture path is restored and the flow records prove it.** `NETFLOW_MODE=active` with the
  two NICs re-tapped produced rows within 90 seconds (17:52Z), but a passive tap on these ports
  sees only broadcast (the gateway's mDNS): the volume before the outage came from the siphon
  intercept, so the recorded `INTERCEPT_PLANS` were restored and the siphon overlay re-applied.
  Flows then climbed to 219 rows / 73 hosts in the 11:59 local minute against a 287-rows/minute
  pre-outage baseline.
- **A stalled ingest is now loud in two places, from one measurement.** `weirvern/ingest_freshness.py`
  reads the age of the newest row in `flows` (one aggregate; the table is ordered by timestamp)
  and classifies it FRESH / STALLED / NO_DATA / UNREADABLE. The worker runs it every cycle and
  logs `FLOW INGEST STALLED: ...` at ERROR while stalled, WARNING on the recovery edge, INFO while
  fresh; the `ingest_freshness` Health probe reports the same verdict at a 300s (one detection
  bucket) limit instead of the old 900s, and its detail names the age, the fault and the checks
  to run. The tap itself now warns `NOT METERING ANY INTERFACE` (rate-limited to 5 minutes) with
  the settings that produced the empty selection, instead of idling silently.
- **Coverage is measured whether or not missing-data handling is on.** The ensemble computed
  coverage counts only when `ML_MISSING_FEATURES` was on; on this deployment it is off, so every
  `ml_window_scores` row carried NULL and every calibration row did too — and the eligibility
  gate refused all five detectors with `coverage not recorded`. The measurement now runs on the
  missing-preserving view of the same inputs in both modes (the flag governs imputation, not
  measurement), so a NetFlow-only host reads 10 of 79 measured rather than 79 of 79, and
  `excluded` still only marks windows the scoring path actually dropped.
- **Eligibility reads each detector's OWN newest pooled row.** The query selected rows written at
  the single newest `computed_at`; a pass that could not build a reference for KNN/LOF (no
  population under the running version) therefore made them read `no calibration row` instead of
  `stale`, which is a different fault with a different remedy. `LIMIT 1 BY model_name` makes the
  freshness check do the refusing, and the calibration row states WHY coverage is unmeasurable
  when the reference is the stored anomaly tail (no feature vector exists to measure).

## 0.23.122 — 2026-11-21

THE ZEEK ROW STOPS BEING BLIND TO ZEEK'S OWN EVIDENCE, THE COARSE SCALES ARE RE-MEASURED, AND THE
ENSEMBLE IS RE-CHECKED AGAINST ITS LIVE NUMBERS.

- **A Normalize row's Alert column is now joined by PIPELINE, not by a hard-coded family list.**
  The rule was `{"dns"}` for a DNS row and `{"conn", "flow"}` for everything else, so a Zeek
  session row could only ever claim conn/flow evidence: tls, http, ssh, identity, notice and dns
  ripples for the same host in the same hour were visible on the Ripples page and invisible on the
  row. `ripple_evidence.feed_lane_channels()` now answers the question from the ChannelSpecs
  themselves -- a channel is offered when its own source table belongs to the lane's collector and
  its `required_columns` are present in the live `availability()` reply -- so a new channel on a
  Zeek table is evaluable from a Zeek row with no second list to maintain. A channel whose table
  lacks a required column is not offered at all; it reports insufficient, never zero.
- **Measured on the live 45-hour feed: a Zeek row goes from 10 evaluable channels / 2 families to
  26 / 8** (all but `service_set_change`, which is the scanner's pipeline, not a feed lane). 429
  (host, family, hour) evidence keys that were unreachable are now reachable; 304 of 336 Zeek rows
  gain evidence from a family beyond conn/flow (dns 144, tls 108, notice 105, http 56, ssh 16) and
  0 rows change from "—" to "Ripple", because those hosts already had conn/flow evidence. The
  blind spot was real even where the headline did not move; a host observed only through Zeek can
  now show what Zeek measured. One key per (host, family, hour): no row multiplication.
- **The tail validator now reports the DETECTOR, not the data's potential.** `_verdict` refuses a
  scale whose fitted tail is disabled even when the window count looks sufficient, and refuses one
  with no usable held-out fit; it gained a `p_floor` per scale and a `tail_only` block that
  measures the fit on its own at the full sample instead of hiding behind the 100-window
  preference for the rank test.
- **6h re-validated as history grew.** 97 six-hour windows at most (so production still uses the
  fit), 40 held-out tests: raw FAR 2/40 = 5.0% (95% CI 1.4-16.5%), and 0/35 on windows the
  empirical test calls ordinary (0%, 95% CI 0-9.9%). The 2026-11-20 reading was 1/9 (11.1%); the
  rate fell as the sample grew. Still enabled.
- **24h and 7d stay disabled, with the measurement named.** 24h holds 30 windows on ONE
  host/channel, an empirical p floor of 0.032, and one held-out fit (95% CI 0-79%): not
  measurable, and `ml_ripple_evidence` has produced no 24h rows. 7d holds 4 windows (30 are
  needed; about 210 days of history). Enabling either would be a claim with no measurement behind
  it.
- **The ensemble is re-checked live and the gate is left alone.** At 11:24 the pool held
  Isolation Forest FAR 0.0103 (0.0087-0.0122, n=13171), Gradient Boosting 0.0130
  (0.0110-0.0154, n=10507) and Adaptive Baseline 0.0433 (0.0392-0.0479, n=8425) -- all three
  `not-eligible` because their pooled row records NO coverage (`ML_MISSING_FEATURES` is off, so
  the reference fell back to stored anomaly scores with no feature vector), and Adaptive Baseline
  is also above the 3% tolerance. KNN and LOF have no pooled row at all; their newest is 17.7h old
  with n=12. Contributing detectors: none. Fused rate on the freshest 24h of window time: 178/3104
  = 5.73% (95% CI 4.97-6.61%) at the 0.35 decision bar, and 31.4% at the fused calibration's own
  0.1611 threshold -- against a 1% target. Not hand-tuned: the eligibility machinery holds them.
- **Measured, not inferred: the NetFlow feed stopped at 2026-11-20 23:33 UTC.** goflow2 logs
  `template error` for the NetFlow v9 templates and `/data/flows.jsonl` stops growing, so there is
  no detection population after that window; the next sweeps have nothing new to score. This is a
  collector fault, reported here rather than papered over by the ripple numbers above.

## 0.23.121 — 2026-11-21

THE INVENTORY'S "CURRENT" SERVICES ARE TRUE, AND A SERVICE CHANGE NOW FEEDS DETECTION — the
scanner stops accumulating ports a host no longer exposes, and the change becomes a ripple
channel instead of a table nobody compares.

- **`asset_services` is a snapshot of the newest COMPLETE scan.** Measured defect: one host listed
  twelve services while its latest scan found one, and another listed six while its latest scan
  found four. `ReplacingMergeTree` only replaces a row with the same `(asset_key, port, protocol)`,
  so a port that disappeared was never removed. A complete scan now inserts its set and deletes
  that host's rows which the scan did not produce; `asset_service_history` keeps every scan, so
  nothing measured is lost. `last_seen_scan_id` names the scan behind each current row.
- **A partial scan cannot erase a snapshot, and `asset_scans.scan_complete` says why.** Nmap's own
  XML decides (`runstats/finished/@exit`, `<host timedout>`); a run that timed out keeps the
  previous snapshot and records `scan_complete = 0`. An observation-only result (no completeness
  marker) changes nothing. A genuinely empty complete scan produces an empty snapshot — which is
  a measurement, not a hole.
- **`service_set_change` is a ripple channel over the per-scan history.** It compares the newest
  complete scan with the previous one and fires on a port opened, a port closed, or a product or
  version changed on the same port. The p-value is the host's own history of scan-to-scan changes
  under the same empirical/100-window rule (a `change` is not a count, so a short baseline reports
  `insufficient`, never a fitted number); the evidence row lands in `ml_ripple_evidence` and the
  ripple takes its severity from the one `severity_bands()` table. A host's first scan is
  `insufficient`, never "no change".
- **The sentence names the change in plain words.** `192.0.2.10 opened 8080/tcp (Golang net/http)
  since the previous scan`; a version change names both versions. It rides in the evidence row so
  the operator reads it on the Ripples surface, not a numeric delta.
- **`service` is a new family, deliberately.** No passive pipeline can see a listener that never
  sent a packet: flow/conn measure traffic, dns measures names, tls/http/ssh measure protocols the
  host speaks, and notice is Zeek's own conclusion. The scanner is an independent measurement and
  can corroborate them.

## 0.23.120 — 2026-11-21

A CONTAINERISED WEIRLING CAN SCAN — the agent image ships Nmap with raw-socket capabilities, and
the readiness line names the scan mode it really has.

- **The scan image is where Nmap belongs, and it now carries both halves.** `Containerfile.scanner`
  installs `nmap` and `libcap2-bin` and runs
  `setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap`, so the non-root agent converts the
  container's `NET_RAW`/`NET_ADMIN` into an effective capability. Installing Nmap on the HOST could
  never fix a containerised unit: the agent measures its own container filesystem, and a container
  cannot install into its own image. The worker image stays Nmap-free — every hub workload runs
  it — and the scan image's `nmap`/`libcap2-bin` layer measures 29.1 MB, paid per sensor.
- **The installer resolves and verifies the agent image instead of assuming it.** It reads the
  scan image from the same Docker store `docker save` uses (copying it out of containerd when that
  is the only copy), accepts `--agent-image`, and after start runs `nmap --version`, `getcap` and
  the container's `CapAdd` inside `weirvern-agent-<id>`, printing the readiness line the hub will
  show. A unit left on the worker image says so at install time rather than surfacing later as
  `nmap missing`.
- **The mode is `connect` or `syn/udp`, not the internal word `raw`.** `detect_scanner` and the
  fleet sentence now read `1 of 1 weirling can scan (nmap 7.95, syn/udp)`; a row written by an
  older build still parses (`raw` is normalised), and the scan command omits `--unprivileged` for
  either spelling. The Weirlings card hides **Install nmap** when the unit is already capable, and
  the Details sheet offers neither Install nor Copy for it: on a containerised weirling there is
  nothing to install, and the answer line says so instead of describing a privilege path.
- **A measured scan result is JSON before it leaves the weirling.** The first live containerised
  scan ran Nmap, then failed at the mTLS send with `Object of type Service is not JSON
  serializable`: `run_service_scan` returned its `Service`/`Observation` dataclasses and the
  gateway client calls `json.dumps` on the payload. The job stayed `claimed` until its lease
  expired. The result is converted to plain dicts at that one process boundary, with a test that
  serialises a parsed scan.
- **The two install paths are documented separately and no longer contradict.** `docs/scanner.md`
  and `docs/deployment.md` describe the containerised path (image + capabilities, no Install
  action) apart from the host-installed path (package + `setcap`, scoped sudoers or one-click
  prompt). The old "no NET_RAW / NET_ADMIN, connect scans only" boundary described neither.

## 0.23.119 — 2026-11-21

A SILENT WEIRLING IS REPORTED AS SILENT — a stale capability row stops reading as a verdict, and
the installer documentation matches the containers it actually starts.

- **An aged capability row is `stale`, never `reported`.** `/api/scanner` stamped every row it read
  as a current measurement, so a row past the freshness window was shown as this weirling's verdict
  and the card offered an install from it. A row older than `CAPABILITY_MAX_AGE_S` (900 s) now comes
  back as `state: "stale"` with its `age_s` and `age`; the card says
  `No report from this weirling in 1h — no agent is reporting.` and offers no install. Both
  endpoints call one `scanner.freshness()`, so `/api/scan-readiness` and `/api/scanner` cannot
  disagree about freshness.
- **The docs describe the containers the installer starts.** `docs/scanner.md` documented a systemd
  unit `weirvern-weirling` that no release shipped. It now names the real containers
  (`weirvern-capture-<id>`, `weirvern-agent-<id>`, plus `--netflow` / `--gate`), their
  `unless-stopped` restart policy, the env file, every mount, and the commands to check and read
  their logs. The systemd instructions are deleted, not left beside the real path.
- **The agent reports the HOST's distro.** The agent container mounts `/etc/os-release` read-only,
  so a weirling reports `Ubuntu 26.04 LTS (debian family — apt)` instead of the base image's
  Debian. Without the mount every containerised unit misnamed its own host on the scan card.
- **The shipped installer actually starts a unit.** Three defects stopped `deploy-weirling.sh`
  before its own verification: the generated helper expanded `$ID` and `$AGENT_USER` in the
  deployer instead of in the helper, and a non-netflow `start` branch ended with status 1 and
  aborted the script before the heartbeat check. A fresh unit now starts, and the installer's last
  step prints `heartbeat OK`.
- **The scanner table fits a phone.** At 390 px the four columns plus the row action overflowed
  the card and clipped its Details button; the table now scrolls inside its own wrapper and drops
  the Nmap-version column below 640 px, so the action is whole at every width.
- **The fleet note is one line, and the reasoning is behind Details.** The 30-word paragraph above
  the scanner card is now the count and the network (`1 declared network has no sensor:
  203.0.113.0/24.`); why declared and seen differ moved into the card's Details disclosure. This
  copy fix was committed after the 0.23.118 image was built and ships here.

## 0.23.118 — 2026-11-20

ONE-CLICK NMAP INSTALL ON A WEIRLING — the memory-only sudo path, and a cancel button that
actually uses the route it was promised.

- **A weirling can install Nmap without a shell channel.** The console asks the ingest gateway
  (`POST /v1/scan/install`) for one registered host; the gateway holds the request in MEMORY for
  five minutes and the target unit picks it up on its own authenticated mTLS poll
  (`GET /v1/scan/install/next`), runs it, and reports the outcome. There is no inbound connection
  to a sensor and no durable row: the request table is a process-local dict, so the sudo password
  cannot be read out of ClickHouse, a ConfigMap, an environment variable or a backup.
- **The password is used once and never recorded.** It arrives in the POST body, is forwarded
  over the cluster network, delivered once to the unit, piped to `sudo -S` and the buffer is
  overwritten. Three attempts per host per ten minutes; the prompt expires after five. The audit
  row names the actor, host, command, exit code, timestamp and the FACT that a password was used
  — never the secret. Tests search every serialised payload, log line and audit row for it.
- **Only the shipped Nmap command can run.** The request carries a distro id and version; the
  hub and the weirling each recompute the command from `scanner.nmap_install_command` and refuse
  a mismatch. A crafted family string is a refusal, not an argument.
- **One path, no dead ends.** `sudo_state=root|passwordless` gets one click and NO password
  field; only `password` shows the field, labelled with the host. An unknown package manager or
  a user outside sudoers replaces the button with the copy-command line rather than a prompt that
  cannot work. The install sheet is one command line (`Runs: …`), a `Details` disclosure and one
  action; success reads `Installed. This weirling can scan <networks>.`
- **The console says less, and says it plainly.** One status line and one action per state: the
  readiness card is `0 of 1 can scan` plus `Not scanning — nmap missing on this weirling.` and an
  `Install nmap` button; the disabled Scan control says `No weirling can scan.`; the install
  sheet asks only for `sudo password` / `Needed to install on this host.` when that host needs
  one. Every explanation — the queue-is-not-a-percentage note, the sudoers paragraph, the
  measured capability sentence — moved behind `Details`. The DOM harness enforces a 25-word
  budget on the rendered card/sheet copy, and the operator's exact strings are asserted.
- **The reported OS is the HOST'S distro, not the package family.** `ID_LIKE=debian` had been
  used as the distribution name, so an Ubuntu 26.04 LTS host was reported as “debian 13”. The
  detector now takes the display name from `PRETTY_NAME`/`NAME` and the version from
  `VERSION_ID` (the same record), and uses `ID`/`ID_LIKE` only to choose the package manager.
  A differing family is stated plainly: `Ubuntu 26.04 LTS (debian family — apt)`. An unreadable
  `/etc/os-release` answers `unknown` and the generic command — never a guessed Debian. Remote
  units mount the host's `/etc/os-release` read-only so the agent does not report its own image.
- **The console's Cancel button now calls the DELETE route.** It was still POSTing to a
  `/cancel` path the server no longer serves. It now asks `Cancel scan?` · `This removes the job
  from the record.` with `Cancel scan` / `Keep`, sends `DELETE /api/scan-jobs/<id>` with the
  console's audit reason, and prints the server's own receipt; a running job's 202 says the
  weirling has not confirmed and the row stays. The DOM harness pins the DELETE route, the
  reason in the body and the receipt.
- **The service credential is single-scope.** `WEIRVERN_SCAN_INSTALL_TOKEN` is a separate Secret
  key mounted only into the console and the ingest gateway; it opens the two install routes and
  nothing else, and an unset credential refuses (503) rather than accepting every caller. A
  request for an unregistered, revoked or disabled host is refused before a request exists, and
  a viewer cannot create one (403 before the body is read).
- **A 390px fix on the same sheet.** The scanner table (415px inside a 336px card) had no
  scroller and widened the page, so a phone opened every view scrolled sideways. The card keeps
  its width and the table scrolls inside it.

## 0.23.117 — 2026-11-20

NUCLEI IS REMOVED, AND SCANNING BECOMES A MEASURED FLEET CAPABILITY. A scan is now queued only
when a registered weirling both reports Nmap and declares the target's network, and cancelling
means something different for a queued job than for a running one.

- **Nuclei is removed everywhere.** The identity layer is Nmap `-sV` plus safe NSE scripts; a
  template vulnerability scan was never part of it. `Containerfile.scanner` builds Nmap and NSE
  only, the `SCAN_NUCLEI_*` settings are gone, the `k8s/36-scanner.yaml` Deployment and its
  kustomize image entry are deleted, and migration `049_drop_nuclei.sql` drops
  `weirvern.asset_findings` — its only producer. A Nuclei match cannot be re-derived without the
  binary and template set, so this is a real deletion rather than an archive.
- **The Findings view is gone with it.** `/api/findings` and its view are removed, and an old
  `#v=findings` bookmark lands on Assets instead of falling through to Health. The migration is
  the record; the docs' only remaining mentions of Nuclei are the paragraph explaining what was
  removed and why.
- **Capability is measured on each weirling, not configured on the hub.** Every agent runs
  `detect_scanner` (`nmap --version`, `getcap`, sudo state, `/etc/os-release`) and reports it;
  migration `050_scan_mode.sql` adds `privileged`, `scan_mode`, `can_install` and `sudo_state` to
  `scanner_status`. The hub counts only a row that is fresh (15-minute window), registered,
  enabled and not revoked — a removed scanner's last row can no longer make the fleet look
  capable.
- **Scope limits the CLAIM, not just the button.** `claim_next_job(networks=...)` skips a queued
  row whose address is outside the networks the weirling declared in its own registration, and
  an empty declaration proves nothing, so it refuses. The readiness count, the POST refusal and
  the claim all read the same definition, so the console cannot promise a scan the claim refuses.
- **A queued scan is refused when nothing can run it.** `GET /api/scan-readiness` returns the
  fleet's own answer (who can scan, at what mode, and which declared networks each weirling
  covers). `POST /api/scan-jobs` answers 409 with the measured sentence — naming `nmap missing`
  and the exact install command for the host's `os-release` ID (`apt-get`, `dnf`/`yum`, `apk`,
  `pacman`, `zypper`, or a generic instruction that refuses to guess) — instead of filing a job
  that would never be claimed. The Weirlings sheet shows the same sentence and disables Scan.
- **Install commands are per host OS, on the sheet.** Unknown distributions get the generic
  instruction and `known: false`; no package manager is ever guessed.
- **Cancel has two honest answers.** A QUEUED job is deleted and one `fleet_audit` row
  (`scan_cancel`) records that it was asked for and why. A RUNNING job is not deleted: it becomes
  `cancel_requested` (202) and stays visible while the weirling polls the hub once a second, kills
  the Nmap child, records `scan_cancelled_confirmed` and then removes the row. Bulk cancel keeps
  one audit row per job and per-job outcomes; a reason is required on every path; a viewer is
  refused 403 before a table is read.

## 0.23.116 — 2026-11-20

THREE STANDING DEFECTS, each one a check that could not see what it claimed to look at. No
detection, capture or enforcement semantics changed.

- **`image_drift.sh` now checks CronJobs.** `cronjob/weirvern-prune` sat on a pruned tag in
  `ImagePullBackOff` for days while drift reported every workload green, because the check read
  Deployments and the zeek DaemonSet only — and `kubectl set image` on a Deployment never touches
  a CronJob. The script now reads
  `.spec.jobTemplate.spec.template.spec.containers[*].image`, lists each as `cronjob.<name>` in the
  same table, applies `--pin` to the verdicts, and includes CronJob images in the local-containerd
  presence check. `tests/test_image_drift.py` pins a stale CronJob failing the run and naming
  `prune`, a current one passing in the table, and an image-less CronJob not becoming a phantom
  drift row.
- **`sanitize_identifiers --write` no longer rewrites test assertions.** A `--write` run replaced
  a private /8 literal with a TEST-NET value inside a test, which changed what the test asserted
  while leaving the suite green. `--write` now refuses anything under `tests/`/`test/`, any
  `test_*.py`, `*_test.py` or `conftest.py`, and `scripts/jsdom_render.js`; inside other files it
  leaves quoted literals on an assertion line and raw/regex literals alone; every skip is reported
  by path and every rewrite prints a unified diff. A second run is a no-op. `--check` still reports
  identifiers in tests — a leak there is still a leak, but a human replaces it.
- **The ML host-hour shadow's datetime subtraction is fixed.** The worker logged `ML host-hour
  shadow failed: can't subtract offset-naive and offset-aware datetimes` on every tick: ClickHouse
  returns `DateTime` values aware (the deployment's tz) while the tick's clock is naive UTC. A new
  `hour_key()` normalises both sides to one offset-free UTC value, and `count_episodes` sorts on
  the same key so mixed inputs cannot raise either. Regression tests run the real tick against an
  aware reference, a naive reference and an aware `now`, plus a mixed naive/aware episode window.

## 0.23.115 — 2026-11-20

TWO READING DEFECTS the audit caught on a 390px sheet. No detection, capture or enforcement
semantics changed.

- **A finding row no longer wraps its timestamp.** The scan sheet's finding row was one flex line:
  the severity chip, the name and the time all competed for 390px, and the timestamp broke across
  two or three lines while rows stopped lining up with each other. The row is a two-column grid
  now — the chip spans both rows at the start, the name and the timestamp stack in the text column
  — and the timestamp is `white-space: nowrap`, so a long finding name wraps instead of the time.
- **A failed graph read says "Could not read", not "Nothing matches".** Blocking `/api/graph` left
  the Network host table showing the amber *filtered* empty state — "Nothing matches", with the
  operator's filters named — while the edges table beside it correctly said "Could not read". A
  read failure is not a filter result. The host table now carries the failed state and the
  server's reason ("The connection graph could not be read: … The host list is part of that
  read."), and the same fix covers the host-status-unavailable branch. A genuine empty filter
  result still says "Nothing matches" with its filters; `scripts/jsdom_render.js` pins both facts
  against a real failed payload and fails if either surface borrows the other's word.

## 0.23.114 — 2026-11-20

TWO JOBS: the scan sheet the operator asked to watch, and the three console unifications the audit
measured. No detection, capture or enforcement semantics changed.

- **A manual scan now has a pop-out you can watch.** Pressing "Scan now" (Assets row or host page)
  opens the right-side sheet on the job the POST created. It reads the queue row every 2.5s while
  it is open: target, state (Queued / Running / Done / Failed, with the raw queue word beside it),
  queued/started/finished times, a live-ticking elapsed clock, and the scanner's own recorded
  result or error. Findings recorded for the host since the job was queued appear as they land,
  with a count and one control into the findings drill; Retry re-queues the same host after a
  failure or a timeout. The sheet stops polling on a terminal state and says so.
  **No percentage**: `weirvern.scan_jobs` carries state, not phase or progress, and the sheet
  states that rather than drawing a bar. A URL may address a job (`#…&scan=<job id>`) and the
  sheet restores from it; closing drops the key. `GET /api/scan-jobs?job=<id>` reads one row so a
  bookmarked job survives falling out of the 20-row recent list, and "Recent manual scans" on the
  Scanner readiness card is where a still-running job is found again.
- **One empty state, three facts.** Seven classes (`.empty`, `.chart-empty`,
  `.net-peers-empty`, `.palette-empty`, `.review-none`, `.wl-spark-empty`, `.empty-act`) gave
  "nothing exists", "nothing matches the active filters" and "the read failed" one muted look.
  They are one `emptyState()` component with `data-state=none|filtered|failed`, the state word in
  the DOM, the **named filters** for a filtered empty, and a failure that says it is a failure.
  Every occurrence migrated; `.review-none` was a review disposition and is now
  `.review-unreviewed`, and the sparkline's measured value is `.spark-value`, not an empty state.
  The `#nw-table` "No edges" case now reads as a failed read when the graph read failed.
- **Sheets are the only detail surface.** The Blocked hit detail was the last object detail
  opened through `openModal()`; it is the house right-side sheet now (one scrim, one Escape, focus
  returns to the row). Centre modals remain only for destructive confirmations with target, blast
  radius and reason: the shared `confirmDestructive()` and the gate-change form.
- **One card anatomy.** `.card`, `.ext-card`, `.gate-card`, `.net-card`, `.nz-card` and
  `.rp-card` now share one box (surface, radius 8, shadow) and one spacing scale
  (`--card-pad` 20 / `--card-pad-tight` 10 / `--card-gap` 16 / `--card-tight` 8), with
  header/body/footer/action-row classes. Only layout and status edges vary; no variant declares
  its own padding or radius. `docs/design/cards.md` and `docs/design/empty-states.md` state the
  rules, and `tests/test_console_unification.py` pins them.

## 0.23.113 — 2026-11-20

THE OPERATOR PASS: the console answers the reports against 0.23.112. No detection, capture or
enforcement semantics changed — this is the reading surface.

- **Weirlings: declared and observed networks are two counts, and both are shown.** The tile
  counted only the segments a sensor happened to report, so a declared scope with no NIC behind
  it vanished while Settings still listed it ("the Weirlings tab says we only have 1 network,
  but we have 2"). `/api/weirlings` now carries `summary.networks_declared` (monitored
  declarations), `networks_declared_all`, `networks_observed` and a `network_coverage` block with
  every scope, its observed flag and the declared-but-unseen list; the fleet summary states
  "Declared but not seen by any sensor: …" instead of letting the two facts contradict. A scope
  table that cannot be read is `available: false` with the reason, never a confident zero, and
  observation is decided by CIDR OVERLAP (a sensor reporting a narrower /25 still observes its
  declared /24).
- **One pill for the whole console: `.bubble`.** Four vocabularies (`.chip`, `.dc-chip`,
  `.rp-sev-chip`, `.pill`) drew status and filter pills at different radii, padding and heights —
  the header's `<button>` pills inherited the 28px button box while table pills were 21px, and
  the filter pill's `×` was a larger font than its own text. Every pill is now
  `.bubble.state` (still: no pointer, no hover, no handler) or `.bubble.filter` (pressable:
  `aria-pressed` required, dashed at rest, solid + checkmark when holding) or `.bubble.control`
  (opens something). One rule owns radius (999px), padding (4×8), type (11px/1) and height
  (auto); no variant may re-declare them, and the phone block's 44px touch floor is the only
  sanctioned exception. Sluice's gate chips, the fleet rows, the severity chips and the header
  controls all wear it.
- **The filter bar: one surface, two verbs, never both.** `#filter-bar` sits between the header
  and `<main>` and `filters.js` mirrors every view's existing filter state into removable
  `.bubble.filter` pills. Clicking a VALUE in a table adds a pill and narrows (the handler is
  capture-phase and swallows the event, so the row cannot also act); clicking the ROW keeps its
  established verb (open the host sheet, open the rule, drill). Removing a pill restores the
  view; `clear all` empties the bar; every pill's state rides the URL (`nw.q`, `nw.subnet`,
  `nw.status`, `nz.band`, `nz.kind`, `dc.f.…`, …) and a cold load rebuilds the pill. Adapters
  exist for every tab, including the three that have no value filters and keep the bar hidden.
- **Alerts: counters and actions behave the same in both lists.** One `renderBandCounters`
  component draws the model and ripple criticality rows from identical markup, band order,
  geometry and colours; a ripple band tile is a real pressed button (click again to clear, click
  another to switch) and the count sentence names the active filter. A ripple and a model
  anomaly now open the SAME side sheet (`#rp-detail-card`) with the same action menu — Block goes
  through the identical confirmation and read-back, and "Open host" works for either kind. The
  two differ in the sheet's body (ripple evidence vs model scores) and nowhere else.
  `al.band` and `al.model_band` ride the URL (`an.sev` still reads for old links).
- **Normalize: the Alert column.** Feed rows are joined server-side to the same
  `ml_ripple_evidence` and `netflow_anomalies` the Alerts tab reads, under the global window,
  and carry `alert_kind` / `alert_band` / `alert_ref`. A ripple alert opens its house sheet; a
  model detection lands on Alerts filtered to the host; a measured em dash says no alert
  matched; an unreadable join says "unavailable", never "no alert". The band counters and a
  kind axis (All / Ripple / Anomaly / None) compose, and both ride the URL. Normalize no longer
  owns `#nz-hours`: it reads the header's window through `trHours()`.
- **Network: solid rings, reserved ring colours, one pager, and a host sheet.** The ripple ring
  is SOLID (`stroke-dasharray: none`) — a dashed ring read as the legend's "unclassified" cue —
  and unclassified scope is a word in the tables, not a third outline. Ring hues are a reserved
  cool set so a high ring is not the alerted fill's orange; a host with no ripples draws no
  ring. All long tables share one pager (25 rows, `Previous / page N of M / Next`, 44px targets,
  "rows 1–25 of 102", server truncation stated). Clicking a host opens a right-side sheet with
  identity, traffic, peers, services, DNS/TLS, ripples, model detections and normalization, each
  stating the coverage it actually holds.
- **One time control.** No view declares its own hours selector (a `data-hours` preset, a
  `*hours` id or a JS lookup of one outside `#tr-panel` fails the suite); every loader answers
  the header's range, and the phone layout stacks the same controls.

Tests: pytest 3,635 passed / 6 skipped; jsdom 1,121 checks passed, 0 failed — including the new
bubble-geometry sweep across every view and the filter bar's five rendered behaviours.

## 0.23.109 — 2026-11-20

THE SLUICE TAB NOW LEADS WITH WHAT THE GATES HAVE MEASURABLY DONE, NOT WITH THE CONTROLS THAT
CHANGE THEM. Enforcement semantics are unchanged: the same DNS answer path, the same nft rules,
the same routes and the same confirmations.

- **State before action, and state from measurement.** Each gate card reads state chip → what it
  enforces → what it has actually done → the one control. The packet gate's state comes from the
  supervisor's own row (`armed + rules_active > 0` = enforcing, `armed + 0` = monitoring,
  `disarmed` = off, `stale/degraded` = degraded); a disagreement between the setting and the
  measurement is shown as degraded with both facts named, instead of trusting the flag. An armed
  gate with no matches says "nothing has matched in the last 24h" rather than wearing a green
  badge that implies activity.
- **Per-rule firing evidence, from the event table.** `/api/sluice` now carries a grouped
  `evidence` map for the selected window — events, DNS matches, flow matches, packets, bytes and
  `last_age_s` — and each rule row states it ("12 DNS matches in the last 24h · last 6m ago",
  "4 flow matches · 1,204 packets dropped", or "no packet matches in the last 24h"). An
  unreadable event table is its own state: the rows say the evidence is unavailable rather than
  rendering a confident zero.
- **Rules are sentences with a door.** The six-column raw-field table is gone: each row is the
  rule sentence, its evidence, and a link into the surface that owns the evidence (domain →
  Blocks filtered to the name; address → Flows filtered to the address). Gate, state, expiry,
  origin and reason live in the rule sheet, whose fact tiles became a definition list with the
  firing record beside them.
- **The fleet is per-sensor cards, honest when empty.** Each card names the sensor, its
  interfaces and verified path, its installed/stored rules, the packets it has dropped and when
  it last reported; a sensor that has caught nothing says so. No fleet state renders the old
  empty table: the card says "No sensor has reported a packet gate yet" or names the read failure.
  Reach still names only sensors with a verified in-path channel.
- **Decoration deleted.** The six stat tiles that repeated numbers already in the sentence, the
  green "on"/"armed" badge, the duplicated degraded paragraph (the server's detail was printed
  verbatim twice) and the raw-field columns are gone. Gate state uses the Alerts `sev-*` chip
  vocabulary (`enforcing` = low, `monitoring` = medium, `degraded` = critical, `off` = low) —
  colour, glyph and word, never a new palette.
- **Arming is one blocking question with a recorded reason, then a read-back.** Arm, disarm and
  pause-auto-block open the shared modal, require a non-empty reason, POST it to
  `/api/settings/apply` and then print the server's `applied` value beside the re-read value:
  a write is reported as landed only when the read-back matches. A viewer sees a disabled control
  and the stated reason; the server remains the enforcement point.
- **390 verified in a real browser, not inferred.** At 390×844 the document is 390px wide, no
  element in the view exceeds the viewport (max right = 378), every rule is a stacked card
  (`display: block`, 346px), the rules wrapper has no horizontal scroll (`scrollWidth` 346 =
  client width) and every gate control is 44px tall. At 1440 the same page is 1440/1440.
- **Tests.** jsdom **1045 → 1055** checks (0 failed): the confirm-with-reason flow, the receipt,
  the per-rule evidence sentences, the rule links, the severity chips and the per-sensor cards.
  pytest adds seven source/contract pins for the same surface; the Sluice review pins that named
  the deleted tiles were re-authored, not deleted.

## 0.23.108 — 2026-11-20

THE COARSE SCALES CAN NOW SPEAK WITHOUT INVENTING A RESULT, AND THE TAB IS CALLED ALERTS.

- **A fitted negative-binomial tail, used only where the rank test cannot resolve the bar.** The
  empirical two-sided p has a floor of 1/(n+1): 94 baseline windows (the live 6h count) can
  express no p below 0.0105, and 30 windows no p below 0.032, so those rows were measured and then
  refused against the 0.01 family bar. A **count** channel (`count`, `diversity`, `novelty`) below
  100 windows is now measured against a negative binomial fitted to its own baseline (mean and
  size by method of moments), with Poisson only when the chi-square dispersion test cannot
  distinguish the variance from the mean. A byte `sum`, a `ratio` and a boolean `change` are not
  counts and keep the empirical test; below 100 windows they report `insufficient baseline`.
- **The selection rule is explicit and one-way.** n >= 100 → `empirical` (unchanged); 30 <= n <
  100 and the scale is validated and the statistic is a count → `negbin` or `poisson`; otherwise
  `insufficient` (no p at all, never p=0 and never p=1). Every evidence row now carries
  `p_method` and `p_detail` (the fitted mean/variance/dispersion/size, or the reason for the
  refusal), stored in `ml_ripple_evidence` by schema **063** and returned by `/api/ripples`,
  `/api/anomalies`' ripple payload and the evidence sheet. The sheet prints `0.00600 (negbin
  tail)` and shows the fit on hover.
- **THE BAR IS UNCHANGED.** Two independent families at p <= 0.01, or one at p <= 0.001, score
  >= 3.0. The tail changes how a p is produced, not what a ripple requires; the family-collapse
  and criticality code was not touched, and a parametric row cannot corroborate a second view of
  its own family.
- **Validation, measured rather than asserted** (`scripts/ripple_tail_far.py`, live ClickHouse
  2026-11-20, retention 234d, fit-on-baseline/score-the-next-window):
  - **1h** — 160 observed windows, empirical (n >= 100). 86 held-out tests, FAR 2/86 = **2.3%**
    (95% Wilson 0.6–8.1%); 0/70 on windows the empirical test called ordinary (p > 0.05).
  - **6h** — 94 windows, the tail's actual use. 9 held-out tests, **1/9 = 11.1%** raw FAR (95% CI
    2.0–43.5%); the single fire was a window the empirical test ranked at its own floor
    (p=0.024), i.e. a resolution gain, not an ordinary window. On the 8 ordinary windows the tail
    fired **0/8 (0%, 95% CI 0–32.4%)**. 4 fits chose negbin, 5 Poisson. **Enabled, provisional**:
    the sample is small and the interval is wide; it must be re-measured as history accumulates.
  - **24h** — 29 observed windows, one short of the 30-window fit minimum. **Disabled**, reason
    named; it becomes method-usable when the tables hold 30+ days.
  - **7d** — 4 observed windows (the deployment holds eight days). **Disabled**, reason named.
    Its expected 32-window lookback is method-capable, and a negative-binomial replay at 32
    windows puts the estimator's FAR at **2.6%** (95% CI 2.0–3.4%) — reported as SYNTHETIC, not as
    live evidence. The 7d scale does **not** become live-usable at this deployment.
- **The 6h report is honest about which number is which.** `scale_report` now returns `method`
  (`empirical` | `parametric` | `insufficient`), `fallback_method`, `tail_p_floor` (1e-6 trust
  floor) beside the empirical `p_floor`, the validation record (`held_out_windows`, FAR and
  interval, ordinary-window FAR), and `observed_windows` is exposed per scale so a 102-window
  capability with 29 windows of history cannot read as a working baseline. `overview` now passes
  the observed count into `scale_report`, so the page says "no evidence rows at this scale in
  this reading" instead of "0 of 30 windows" when a scale simply was not measured.
- **The Ripples tab is now Alerts** (operator: "Because we have ripples and anomalies in the
  ripples tab. Rename it to Alerts"). The view id `anomalies`, the API routes, the ripple data
  model and the severity bands are unchanged. The page heading is `Alerts` with the subtitle
  "ripples first, model detections as corroboration — read-only"; the Models card, the Network
  tab's "open Alerts" link, breadcrumbs and Normalize's empty state follow. The old copy
  "Read-only: this page does not alert" became a contradiction under the new name and is replaced
  by "Alerts collects ripples and model detections. This page is a record: it does not send
  notifications."
- **Dependencies.** `scipy` is declared (it was already present transitively via scikit-learn) for
  the regularized incomplete beta/gamma tails and the dispersion test. `MODEL_VERSION` is
  `ripple-evidence-6`; a deployment mid-migration falls back to the pre-063 column list and labels
  those rows `empirical`, which is what they are.
- **Tests.** New coverage for: n >= 100 keeps the empirical p unchanged; n < 100 uses the fitted
  tail and records `p_method`; an over-dispersed baseline stays quiet where a Poisson tail fires;
  a degenerate baseline reports `insufficient` rather than p=0; a non-count statistic refuses the
  tail; the family rule and score bar are unchanged for parametric rows; the stored row and the
  read path carry the method; the 7d scale reports usable-or-not with a reason. jsdom
  `1049 passed, 0 failed` adds the Alerts tab/heading, the read-only sentence and a
  `(negbin tail)` provenance label on the evidence sheet.

## 0.23.107 — 2026-11-20

HISTORY SHOULD NOT SILENTLY CONTRACT BECAUSE THE DISK GOT FULLER.

- **Retention is a ratchet now.** The window is derived from free space, so it shrank whenever the
  disk filled — measured live: 284 → 258 → 239 days with nobody touching a setting, and every
  shrink expired rows on the next merge. The highest window ever derived is persisted beside the
  other model state in `$MODEL_DIR/retention_ratchet.json` (day count plus the date it was set),
  and the effective window is `max(derived_from_disk, floor)`. A dip in free space no longer
  lowers it.
- **The floor only falls by explicit operator action.** An apply that lowers the effective window
  — an explicit day count below the floor, or a lower `DATA_RETENTION_RATIO` whose derived window
  is below it — is refused unless the request carries `reset_ratchet: true` and a reason. The
  receipt names the old floor, the new floor, the actor and the reason; the record lives in the
  `RETENTION_RATCHET` ConfigMap key and is consumed by the worker on its next start. The console's
  existing destructive-retention confirmation is that explicit action. A lower number can never
  quietly become the new floor.
- **A hard capacity guard, because a ratchet that fills the disk is an outage.** If honouring the
  floor would need more than `ML_RETENTION_MAX_DISK_FRACTION` (default **0.85**) of the volume,
  the floor is NOT honoured: the control holds the longest window that fits and says so in one
  sentence on the Settings row, at WARNING in the worker log, and as a red `retention_floor` row
  in Health — `retention floor 284d needs 96% of the volume; holding 212d, the most the disk
  supports`. The stored floor is not rewritten downward.
- **The Settings sentence states the floor and its date**, e.g. `Auto — 239 days (ratchet floor
  239d since 2026-11-20; disk supports 239d)`. The guard's refusal is in the same sentence as the
  number, not a tooltip.
- **Fresh installs are unchanged.** No ratchet file means the old arithmetic exactly; the first
  pass seeds the floor from what the tables already keep, so adopting the ratchet cannot shorten
  the window on the pass that introduces it. `derive` never writes — `ensure` owns persistence.
- **Measured.** 139 retention/health tests (18 new) cover a free-space dip holding the floor, the
  floor rising on a larger derivation, a lower value refused with both numbers named, a reset
  applying with actor+reason, the 85% guard holding the max affordable window AND warning in the
  worker log without rewriting the stored floor, the guard sentence in the Settings payload, and
  the fresh-install path. jsdom `1047 passed, 0 failed` adds the reset flag on a destructive apply
  and its absence on ordinary applies.

## 0.23.106 — 2026-11-20

A PERMANENT CHANGE SHOULD NOT RIPPLE EVERY DAY UNTIL THE BASELINE CATCHES UP.

- **A signature is one host, one channel, one exact value.** A new appliance, a new TLS
  fingerprint or a replaced SSH banner is a real change the per-host empirical baseline needs days
  to absorb, so the same host fires the same ripple every hour in the meantime. The Normalize tab
  taught this to the FLOW/DNS baseline (`normal_traffic`); the ripple channels never read it,
  because their question is "is this VALUE new for this host", not "how much traffic". Schema
  `062` adds `normal_ripple_signatures` for that question.
- **The channel queries consult it, generically.** `ChannelSpec.sql_anchored` and `sql_values`
  take a `SignatureFilter`; a diversity channel composes the exclusion into `uniqExactIf`, and a
  novelty/change channel adds it to the `WHERE` before the bucket set is built. A new
  value-bearing channel gets the behaviour by declaring its value column — there is no per-channel
  special case. The raw traffic is not read differently, written or deleted: a live test asserts
  the event population and the row counts are identical with and without a signature.
- **Scope is the safety property, and it is enforced where the claim is made.** `host_addr` must
  parse as ONE address (a CIDR or hostname is refused); `channel` must be a deployed channel (a
  family such as `tls` is refused); `value` must be one non-empty exact string; the family is
  derived from the spec, never supplied; `review_after` defaults to 90 days and may not exceed
  365. There is no shape in the store or the API that can say "this whole channel" or "this host
  forever". Tests drive each refusal through the API.
- **The claim expires on its own.** A signature stops applying when `review_after` passes, with
  no operator action: last year's expected is this year's anomaly. Removal is a superseding row
  (`ReplacingMergeTree(updated_at)`) so `created_at`/`created_by` survive it — the record is the
  audit, not a cache.
- **The sheet can normalize one evidence line, with a preview and a reason.** Every evidence row
  in the ripple sheet carries **Normalize this pattern**; a channel that measures a rate says why
  it has no single value to name. The preview reads the same table the measurement read, for the
  same hour, and shows the exact values that occurred — the evidence row only carried a count.
  The write requires a reason, names host/channel/value/until, and offers **Undo — remove this
  normalization** in one click. The Normalize tab lists every signature with its reason, review
  date and one-click Remove. Admin-only write, viewer read-only, same gate and CSRF posture as
  `/api/normalize`.
- **Measured.** `tests/test_ripple_signatures.py` (23 tests) proves: the normalized value stops
  contributing significant evidence for that host; the same value on ANOTHER host still ripples;
  a DIFFERENT value on the same host/channel still ripples; removal and expiry bring the evidence
  back; the raw population is unchanged; a family/CIDR/empty value is refused through the API;
  a viewer cannot write; the actor and reason are recorded. jsdom `1045 passed, 0 failed` adds the
  preview, the required reason and the one-click undo.

## 0.23.105 — 2026-11-20

THE OTHER HALF OF THE NETWORK WAS INVISIBLE: A HOST THAT ONLY RECEIVES TRAFFIC HAD NO FLOW EVIDENCE.

- **`flows_window` describes sources only, and that is half a LAN.** Measured live before this
  change: `flows` over 3.4 days held **4,800 distinct sources against 5,666 distinct
  destinations**, so at least 866 addresses — servers, NAS, printers, cameras — never appeared as
  a source and produced no flow channel at all. The ripple layer dropped their inbound rows
  because the only host column was `src_addr`.
- **A parallel table, not a `dst_addr` column.** `flows_window` is one row per
  `(window_start, src_addr)` with AggregateFunction states; adding `dst_addr` would change the
  grain to host PAIRS and silently redefine every aggregate that reads it. Schema `061` adds
  `flows_window_endpoint` keyed on `(window_start, host_addr, direction)`, with the same state
  columns, `AggregatingMergeTree`, partitioned by month and bootstrapped on the 7-day TTL floor
  (the retention pass converges it like every other managed table).
- **The view is a `UNION ALL` of the two endpoints** (`flows_window_endpoint_mv`, dropped and
  recreated the way `050` does): `src_addr` as `'out'` with `uniqState(dst_addr)`, and `dst_addr`
  as `'in'` with `uniqState(src_addr)`. Each flow reaches the aggregate exactly once per
  direction, so the outbound side is the same population as `flows_window` — the property the
  live parity check uses — and inbound is new information, not a recount.
- **Six flow channels, two directions — and the old three do not move.** `flow_volume`,
  `flow_bytes` and `flow_dst_diversity` stay on `flows_window` with their names, population and
  retained history unchanged; `flow_in_volume`, `flow_in_bytes` and `flow_in_peer_diversity` read
  the endpoint table's `'in'` rows and attribute them to the receiving host. All six are one
  FAMILY, so inbound volume cannot corroborate outbound volume — they are one measurement seen
  from opposite ends. The outbound channels were deliberately NOT moved to the new table: measured
  on the box, the window table held 7 days while raw flows held 3.4, so moving them would have cut
  their baseline and stopped their evidence.
- **The Network tab attributes both endpoints.** No second mapping was added: `/api/graph` already
  carries the `/api/ripples` rows, and the edge chip already takes the higher band of its two
  ends. What was missing was a ripple ROW on the receiving endpoint; the jsdom harness now pins
  an edge whose only rippling end is its target.
- **A bounded, idempotent backfill** (`scripts/backfill_flows_window_endpoint.py`, dry-run by
  default). The view only sees inserts after it exists, so the retained history was re-derived:
  it deletes and rewrites a bounded range (`--days`, default 7) ending at the previous five-minute
  boundary, clamped to the first complete window raw `flows` still holds (deleting a range whose
  raw rows have expired would erase what cannot be rebuilt). It reports rows before/after per
  direction, the inbound-only host count measured both from the table and from raw flows, a
  measured time estimate, and outbound parity against raw flows over the whole range plus against
  `flows_window` over the last 24 hours, where the old table is itself a faithful roll-up.
- **Deliberately still on `flows_window`:** the detection sweep (`worker.py`), the candidate
  matrix, the specialist detectors, scope profiling and the host-hour detector. Their unit is the
  per-host outbound window the models were fitted on; changing that population mid-flight would
  reshape every baseline and score. The endpoint table is a ripple and Network-view source.

## 0.23.103 — 2026-11-20

A FAR ESTIMATE MUST BE ABLE TO ANSWER BEFORE IT BENCHES A DETECTOR, AND 0.35 MUST MEAN THE SAME
THING WITH ONE DETECTOR AS WITH FIVE.

- **The eligibility rule now judges the Wilson 95% upper bound, on a minimum sample.** Measured
  live: three detectors read FAR 0.045–0.091 over ~110 validation windows and were benched, after
  the SAME detector had read 0.000 seven minutes earlier. 5/110 is 0.045 but its interval is
  0.020–0.102 — it cannot separate the 1% target from the 3% tolerance. Below
  `ML_ELIGIBILITY_MIN_WINDOWS` (default **300**: the smallest n at which a detector realising the
  1% target has an upper bound of 2.9%, inside 3%) the state is
  `calibrating (n=X, need Y)` and the detector keeps the state it held; above it, a detector fails
  only when the interval's upper bound exceeds the tolerance. `ML_ELIGIBILITY_MULTIPLE` is
  unchanged at 3.0.
- **Every calibration row records its denominator and both bounds.** Schema `060` adds
  `far_lower` / `far_upper` to `ml_calibration` and its history; `calibration.run` writes them from
  (`observed_far`, `validation_count`) and the eligibility read recomputes them for older rows. The
  Detectors table cannot print a FAR without `95% CI … n=…` again, and the fused summary line
  carries the same.
- **The fused alert bar is now a calibrated scale.** Raw `max` fusion meant 0.35 was whatever the
  current member emitted: with KNN alone (own threshold 0.962) it fired on **79.2%** of windows.
  Each detector's score is mapped by `score × BASE_THRESHOLD / threshold_i`, putting its own
  conformal threshold on 0.35. Measured on the live 6-hour population (154 windows with all five
  detectors scored): fused rate at 0.35 before → after was **80.5% → 13.0%** with KNN alone,
  **83.8% → 14.9%** with KNN+LOF, **89.6% → 17.5%** with all five. The promotion budget is
  measured on the same calibrated scale (its SQL scales each compared model), so a candidate is
  judged by the bar the decision uses. The raw fused score still drives severity, confidence and
  the stored anomaly score; only the alert comparison is rescaled.
- **The promotion state no longer writes an evidence failure as a promotion state.** A stale or
  under-sampled reading is recomputed every sweep; overwriting the recorded state with
  `not-eligible` made a transient measurement sticky and lost incumbency. `save_state` preserves
  the prior state for `calibrating` / `not-eligible` decisions instead.

## 0.23.102 — 2026-11-20

ELIGIBILITY IS MEASURED EVIDENCE, A PROMOTION MUST FIT THE ALERT BUDGET, AND DBSCAN IS GONE.

- **The model card is no longer a gate.** `ml_model_cards` is hand-curated: it is written only when
  somebody edits a card, so it was 8 days stale on 2026-11-20 and had **no row at all** for the two
  cross-sectional detectors — which barred KNN distance and LOF from the fused score by ABSENCE,
  not by any measurement. A card is documentation of intent (owner, approved version, rollback) and
  is now readable by anything that wants it, but it cannot veto a detector.
- **Eligibility is three measured facts**, each from the engine: (a) a calibration row no older
  than `RETRAIN_EVERY_H` plus `ML_CALIBRATION_GRACE_H` (the calibration pass runs after the retrain
  it measures), (b) recorded coverage on that row (`coverage_observed`/`coverage_expected`, never
  NULL — an unmeasured vector is not evidence), and (c) a realised FAR inside
  `ML_TARGET_FAR × ML_ELIGIBILITY_MULTIPLE` (0.01 × 3 = 0.03 by default). A missing fact is named
  in the Detectors table (`not contributing: no calibration row`, `coverage not recorded`,
  `calibration stale (9.0h old, 6h retrain interval)`, `FAR 0.083 above the 0.030 tolerance`).
- **A promotion must fit the fused alert budget.** Measured on the live 24-hour population,
  admitting both cross-sectional detectors moved the share of host-windows at or above
  `BASE_THRESHOLD` from **25.6% to 42.8%** — a doubling of the page load from an automatic decision
  nobody made. A calibrated detector is now promoted only when the fused rate WITH it stays inside
  `ML_FUSED_ALERT_BUDGET` (default **0.30**: the measured 25.6% baseline plus headroom, below the
  measured 42.8%). Otherwise it reads `calibrated, held for budget (fused 42.8% with it vs 25.6%
  without; budget 30.0%)` and is promoted **automatically** on a later sweep once the rate fits.
  The rate is paired — only windows where every compared detector scored — over
  `ML_FUSED_BUDGET_HOURS` (24 h), and a promotion under budget also needs
  `ML_FUSED_BUDGET_MIN_WINDOWS` (200) behind it. The guard never demotes an incumbent: dropping a
  working detector is not a budget decision.
- **DBSCAN IS COMPLETELY REMOVED, not retired (operator, 2026-11-20: "Completely remove dbscan").**
  The measurement that decided it: **97.89% of 27,454 stored scores sat at 0.99 or above**
  (p50 = p99 = max = 0.99), over 2026-11-12 → 2026-11-19 — a score at its ceiling on 98% of
  windows cannot be given a threshold, and any cut below the ceiling fires on essentially
  everything. Removed: the `DBSCANDetector` class and its train/predict/query paths, its
  `calibrate_distance` scorer, the `dbscan_*` hyper-parameters and `weight_dbscan`, its
  `MODEL_FAMILIES`/`NAME_TO_KEY`/weight entries, the `dbscan_score` keys in verdicts and near
  misses, and its row in the Detectors payload — it has **no row**, because removal is not a
  status. `DBSCAN_FEATURES`/`ZEEK_DBSCAN_FEATURES` are renamed
  `CROSS_SECTIONAL_FEATURES`/`ZEEK_CROSS_SECTIONAL_FEATURES` with the same 19 columns in the same
  order, because KNN distance and LOF still share that vector — and nothing else.
  `DBSCAN_v3/v4/v5.pkl` were deleted from the models PVC, and schema `059_remove_dbscan.sql`
  removes its card, training, calibration and score rows from an upgraded deployment. The
  dormant `dbscan_score` columns in `netflow_anomalies`/`near_misses` are no longer written or
  read; the columns themselves are left for a separate decision, because dropping them while an
  older pod still inserts would fail that pod's writes during the rollout.
- **KNN distance and LOF remain independent detectors**, unchanged in behaviour: separate classes,
  reference sets, artifacts, calibrations and eligibility rows, and separate corroboration
  families. LOF's partial-coverage blindness (0.00% alert rate on partial rows against 0.90% on
  full ones) is a documented limitation, not a merge.
- **The Detectors table reads `eligible` / `not contributing: <reason>` / `calibrated, held for
  budget (…)`**, states the budget, the bar and the window count it was measured over, and derives
  its rows from the engine roster — so a detector that is no longer built cannot appear as a row.

## 0.23.101 — 2026-11-20

DBSCAN IS RETIRED; TWO CROSS-SECTIONAL DETECTORS TAKE ITS PLACE, AND THE THRESHOLD NOW KNOWS HOW
MUCH OF THE VECTOR WAS MEASURED.

- **kNN distance (k = 10) replaces DBSCAN in the ensemble.** Score = distance to the k-th nearest
  neighbour in the standardised 19-column vector, with the reference set persisted in the artifact
  (at most 5,000 × 19, 760 KB). The bake-off measured 1.18% held-out FAR at a 0.01 target with
  per-stratum calibration, 2,590 distinct scores and 4.8 µs per window.
  `docs/research/cross-sectional-detector-2026-11-20.md`.
- **LOF (k = 20, `novelty=True`) ships as a separate, independent detector** — its own reference
  set, artifact, calibration and eligibility row. It is bounded on purpose: the statistic is
  `log1p(LOF)`, so the bake-off's 8.5e8 threshold becomes ~20.6, and a fit whose reference cannot
  produce a distinguishable score is REFUSED instead of persisted.
- **DBSCAN is gone from `build_detectors`, `MODEL_FAMILIES` and the fusion.** Its stored score was
  degenerate: 97.89% of 27,454 rows at 0.99 or above, p50 = p99 = max. The class is kept for one
  release with the measurement in its docstring, and the Detectors table says
  `retired -- removed from the ensemble on 2026-11-20, scores were degenerate` rather than
  inferring retirement from a missing artifact (it has one).
- **The `sipHash64(src_addr) % 5 == 1` host sampling is removed from the cross-sectional training
  path.** It kept 5 of 24 monitored hosts; a cross-sectional reference of five hosts is not a
  population. The reference is capped by ROWS (5,000) with the same deterministic hash order, so
  every monitored host can contribute, and the live sample now covers 24 of 24.
- **Calibration is stratified by coverage, generically.** `calibration.fit_stratified` takes
  `(score, stratum)` and knows nothing about which model produced the score; a model registers how
  its rows map to a key. Each stratum carries its own threshold and a stratum with too few
  reference windows explicitly falls back to the pooled one. This is the fix for the measured
  0.00% alert rate on partial-coverage windows against 2.3–2.5% on full ones; the scorer grades
  each window against its own stratum, so a partial window at its stratum's 99th percentile is as
  alertable as a full one at its own.
- **Fusion excludes an ineligible model instead of zeroing it**, and a model absent from a
  non-empty eligibility mapping is ineligible. A freshly trained kNN/LOF therefore contributes
  nothing until it has a calibration row **and** a `production` model card — the honest first
  state, visible in the Detectors table, not a silent zero.
- **No fused weight, alert bar or ripple channel changed.** Both new detectors carry the explicit
  neutral weight 1.0 (inert under `max` fusion). Measured on the live 24 h day: with both eligible
  the fused `max` shifts p50 0.145 → 0.302 and the share at or above `BASE_THRESHOLD` 25.6% →
  42.8%, which is stated here because it is a real rebalancing and not a free addition; nothing
  downstream changes until the two are promoted.
- **Ripples still consume raw telemetry only.** The single place a detector score and a ripple meet
  is the anomaly page's corroboration block, which is display, not input.

## 0.23.85 — 2026-11-19

THE ML TAB NAMES ITS WHOLE INPUT.

- **The Models overview says how much normalized traffic the baseline has learned from**, by lane
  (Netflow / Zeek / DNS), and says what that means: pooled into the baseline's distribution, never
  used to silence an alert. The tab explained four detectors and never mentioned that the operator
  can now teach the baseline directly, which made a shipped feature invisible from the page that
  exists to explain the engine.
- **"Nothing has been normalized yet" is a state, not a blank.** When the count is zero the line
  says so, so an empty input reads as empty rather than as a panel that failed.

## 0.23.84 — 2026-11-19

THE MODELS TAB REPORTS THE ENGINE, NOT ITS OWN PAPERWORK.

- **The engine's training record rides with both panels.** `ml_models` holds one row per training;
  the tab read only the curated card registry (frozen at its approval date) and the last
  operator-requested retrain. That is how "DBSCAN retired" and a candidate dated 14 October sat
  above four detectors that had retrained that morning at 08:21. Both payloads now carry the
  newest training per model, and both panels say it.
- **A disagreement is named, not smoothed over.** When a card says retired and the engine is still
  training that model, the panel says exactly that and says which record is older — the registry.
- **The retrain panel distinguishes a candidate from the schedule.** Keep/Trash act on the
  operator's candidate; the sentence next to them states when the engine last trained and on what
  window, so a month-old candidate cannot read as the current model.

## 0.23.83 — 2026-11-19

THE FEED CAN BE BUCKETED, AND NOTHING DISAPPEARS WHEN IT IS.

- **Group by service, port, destination segment, or source host.** NetFlow rows have no service
  name, so in the service view they are bucketed by the port they went to, said plainly rather than
  guessed at: a Zeek row reads `ssl`, a NetFlow row to 443 reads `port 443`.
- **A bucket is a heading, not a filter.** Every row stays in the feed; grouping only changes how
  the rows are stacked, and each bucket states how many patterns and hosts it covers, with its
  flows and bytes.
- **One click normalizes a class.** The bucket's checkbox selects every member pattern, so "all
  ssl" is one click and still writes one honest entry per pattern — nothing claims more scope than
  it covers, and the sheet still shows exactly what each entry will say.

## 0.23.82 — 2026-11-19

AN IMAGE THAT IS GONE IS A POD THAT CANNOT COME BACK.

- **The drift check now verifies the images exist, not only that the workloads point at them.**
  `weirvern-zeek:0.5.0` is a local-only tag — there is no registry to pull it from — and k3s pruned
  it while the DaemonSet had been running 34 days. Nothing noticed until a tap-image change
  recreated the pod: it sat in ImagePullBackOff and capture was down for ten minutes. The image was
  rebuilt and imported, the pod returned 2/2, and `image_drift.sh` now names every image a workload
  references that is absent from containerd and fails the run, because the next restart is exactly
  when it matters.

## 0.23.81 — 2026-11-19

SETTINGS IS ALWAYS OPEN.

- **Expand all and Collapse all are gone** (operator, 2026-11-19: "just remove the the expand and
  collapse options and have it always be expanded"). The card headings are not controls any more:
  clicking one used to hide the values, and a settings page that can be collapsed into looking
  empty is a page that lies about itself.
- **The counts stay**: each heading still says how much it holds ("Access and security · 6
  settings"), so a card's size is readable at a glance without a control to open it.
- The search box still narrows the stack and the jump-to-pending button still works; neither
  depends on a collapsed state.

## 0.23.80 — 2026-11-19

THE THIRD LANE: ZEEK, AND THE SOURCE FILTER SAYS WHAT IT MEANS.

- **Zeek is a source in the feed.** `zeek_conn` sessions in their own lane, with the service Zeek
  named (http, ssl, ssh, dns) carried as the row's label and the responder's own byte and packet
  counts instead of a sampler's estimate. Proto is normalised to a number in every lane, so a Zeek
  row and a NetFlow row mean the same thing to the writer and the sheet.
- **The filter is DNS · Zeek · Netflow.** The stored value for Netflow is still `flow`; only the
  words changed, so old entries keep their meaning.
- **Zeek rows normalize like any other claim**: destination scope, port and protocol in the sheet;
  the service travels with the entry as its label.

## 0.23.79 — 2026-11-19

A NORMALIZE ROW OPENS A SHEET, AND THE FEED PAGES BACK IN TIME.

- **The row is the door.** Clicking any row in the Normalize feed opens the same right-hand sheet
  as the weirlings fleet (one primitive, `sheets.js`): the pattern as it was counted, then the two
  ways to change the claim.
- **Broaden or reduce.** Destination scope is a choice of this one address (/32), this segment
  (/24), the wider block (/16), or anywhere; port and protocol are editable; a DNS claim can be
  the exact name or its parent domain, with the record type widened separately. The written prefix
  is derived from the destination address server-side, so a sheet can never write a prefix the
  address does not cover.
- **A normalized row offers removal from the same sheet**, and the button only appears when there
  is a claim to remove.
- **The feed pages backwards in time.** One page is one window: `‹` walks back, `›` returns toward
  now, and the range line states which window you are reading. It is the house pager — same
  `.pager` row, same arrows, same range wording as Assets and Logs — because a long list should
  page the same way wherever it lives.
- **The retrain header stops quoting one detector as the run.** "4 of 4 detectors trained on
  9,520 host-windows" sat above a table whose Isolation Forest row said 11,900; each detector
  trains on its own matrix, so the header now names every trained detector with its own count and
  unit (windows, a window sample, hosts) — the same facts as the table, in one line.
- **The model registry is compared with what is installed.** The cards were seeded on 2026-11-11
  and nothing updated them, so the tab showed v4 while v5 artifacts were written that morning.
  The panel now reads the model directory and says, per card, which version is on disk — and
  states how many cards are behind the engine instead of quietly looking current.
- **A month-old candidate cannot look ready.** The retrain panel says how long ago the candidate's
  training window closed; keeping a stale candidate would install a model built on traffic that
  old.
- **An empty page never offers a dead arrow:** the feed probes for one row older than the window
  before enabling `‹`, and says "the oldest traffic we hold" when there is nothing further.

## 0.23.78 — 2026-11-19

THE NORMALIZE TAB: NORMAL TRAFFIC IS LEARNED, NOT SILENCED.

- **A feed, not a form.** Near-similar traffic — flows *and* DNS — in one filterable log: window,
  source, segment, port, minimum bytes, free text. Select the rows that are normal for this
  network and press Normalize; the row turns green and stays marked afterwards.
- **Normalizing changes the baseline, not the alerts.** The pattern is pooled into that host's
  adaptive baseline (combined mean/variance, percentiles only ever widen, and only once the seed
  has 20+ samples), so the models stop finding the traffic anomalous. There is no suppression
  list, and the alert path never reads the decision — the test suite fails if the feature grows
  the vocabulary of silencing.
- **DNS is a first-class lane.** A normalized domain joins the host's known-domain set in the
  Zeek history CTE, which is what `zeek_dns_new_domain_ratio` measures against.
- **Permanent until removed.** `normal_traffic` has no TTL. Removal supersedes the row
  (`status='removed'`, who and when); the history stays.
- **What it does not do:** it does not hide anything. Normalized rows remain in every view, and
  the feed marks them so the claim is visible.

## 0.23.77 — 2026-11-19

ONE JOIN FOR A NIC LIST.

- **The fleet table printed whatever the payload happened to send**: the hub reports `eth1, eth2`
  and a remote weirling reports `eth1,eth2`, so two identical rows looked different. Every row now
  goes through one normaliser, which also accepts an array and renders a missing list as an em dash.

## 0.23.76 — 2026-11-18

THE ML TAB GETS A SPINE.

- **Four sections, in the order an operator asks the questions.** *Production* — what is scoring
  traffic now (overview, retraining, model cards, freshness, the adaptive baseline, training
  history, score distribution and agreement). *Verification and review* — what evidence says it
  works (source coverage, SLO, verification coverage, evaluation history, program review, promotion
  ledger). *Shadow* — what is being tried without controlling alerts (channels, shadow ML, ripple,
  calibration, asset posture). *Host baselines and findings* — baseline deviations, near misses and
  the anomaly list.
- **Nothing was removed and no data changed**: the same 21 cards ship, regrouped, with the house
  section eyebrow (the same rule the Settings tab uses) between the groups.
- **The summary card is called Overview**, not Models — the page title already says Models and
  repeats the same counts, so the card's heading was doing no work.

## 0.23.75 — 2026-11-18

SETTINGS OPENS WITH ITS VALUES SHOWING.

- **The cards are open on arrival.** Every settings card used to boot collapsed, so ten headings
  and no values read as a settings page with nothing in it until Expand all was pressed (operator,
  2026-11-18). Collapsing is still there, one click away, and the header still says Expand all.
- **A collapsed card says how much it holds** — "Detection · 6 settings" — so the collapsed state
  is informative rather than blank. The count is rendered after the rows load and refreshed on
  every reload, and the badge carries its own separator dot because the generic h2 dot rule never
  reached these headings once they were demoted to h3.

## 0.23.74 — 2026-11-18

THE SLUICE PAGE JOINS THE CONSOLE, AND THE SMALL DEAD ENDS ARE DOORS.

- **Sluice Gate rebuilt on the house pattern.** The page's private header (`.sl2-head`), its
  gate wrappers and its own table class are gone: it now uses the standard view header, cards,
  tables and controls, and its copy says "Domain gate" / "Traffic gate" in sentence case like
  every other heading. The orphaned info icon that floated beside the title is inside the first
  card's heading, where the other views keep theirs.
- **Every gate number is now a door.** Enabled lists → the blocklists, DNS hits and packets
  blocked → Blocks, live packet rules and rules in store → the rules table filtered to the
  traffic gate. Fleet gate rows open that weirling; rule rows open their sheet.
- **Clickable things say so at rest.** A muted chevron marks clickable rows and stat tiles,
  because a hover state is invisible to anyone scanning and to a screenshot. This also fixed a
  real bug: the JS wrote `sl2-rule-row` while the CSS styled `sl-rule-row`, so rule rows opened
  their sheet with no pointer and no hover at all.
- **The "show revoked" checkbox sits on its label's line.** It inherited `.controls label`'s
  column direction and floated a line above its own text.
- **A CNAME answer in DNS is a domain filter.** Only address answers were clickable; a hostname
  answer was inert text.
- **Flow detail says what it is waiting for.** Headers over an empty body read as a broken table.
- **The Models description no longer claims DBSCAN is production.** Its model card is `retired`,
  and a retired card is not a production model: the sentence now says so and points at the cards
  as the authority.

## 0.23.73 — 2026-11-18

THE MIX SAID HOW MUCH; THE SERIES SAYS WHETHER IT IS STILL COMING.

- **The Interfaces card gains a trend**: one line per NIC, bytes per bucket, on the same bucket
  width as the volume chart above it so the two read together. A NIC that carried 40% of the day
  in one hour and a NIC that carried it all day produce the same share in the table — only the
  series tells them apart.
- **A flow with no interface is drawn as "unattributed"**, not dropped: it still happened, and
  hiding it would understate the window.
- **A failed series read reports unavailable with its reason** rather than drawing an empty series,
  which would read as "every NIC went quiet" — the same distinction the talkers panel learned.
- The series obeys the dashboard filters, including the `iface` chip, and reads the RAW table for
  the same reason the mix does: `flows_aggregated` has no `in_iface`.

## 0.23.72 — 2026-11-18

A NIC YOU ADD IS A SETTING, NOT A MANIFEST EDIT — AND THE FLOWS HAVE A PANEL.

- **The Netflow view has an Interfaces card**: NIC, flows, bytes and share, with each row a door
  that filters the whole view to that NIC. `iface` is a first-class chip: it is validated as an
  interface name (not an index) and it forces the RAW table, because `flows_aggregated` has no
  `in_iface` and would otherwise ignore the chip without saying so.
- **One collector container, one process per NIC** (`k8s/35-goflow2-launcher.yaml`). The launcher
  reads `NETFLOW_IFACE` and opens `127.0.0.<n>:2055` for each NIC, writing `flows.jsonl` for the
  first and `flows-<nic>.jsonl` for the rest. goflow2 v2.2.6 still panics on two netflow listeners
  in one process, so the launcher spawns one process each — and if any collector dies it stops the
  others and exits, because a dead collector looks exactly like a quiet segment.
- **The ingester derives the same list** from `NETFLOW_IFACE` when `TAIL_FILES` is empty, so both
  sides read one rule; adding a NIC is `NETFLOW_IFACE=eth1,eth2,eth3` and Apply.
- **`NETFLOW_IFACE` now restarts the collector and the worker** as well as the capture sensor,
  because all three have to learn the new NIC; before, only the sensor restarted and the flow was
  silently unattributed.

## 0.23.71 — 2026-11-18

THE FLOWS KNEW THEIR NIC; THE CONSOLE DID NOT SAY SO.

- **The Netflow summary prints the split**: `1.4 MB across 3,240 flows — by NIC: eth1 2,100 ·
  eth2 1,140`. It reads `flows.in_iface` from the RAW table (the aggregate has no such column)
  and obeys the same dashboard filters as every chart beside it.
- **An empty interface prints as `unattributed`** — it is never folded into a NIC. A flow whose
  export did not arrive on a NIC's loopback socket is a gap the console admits; a guessed NIC
  would be a fact the sensor does not have. A failed read prints `unavailable`, not silence.
- **The ClickHouse client has a 60 s send/receive timeout** (the library default is 300 s).
  Measured 2026-11-18: a DELETE mutation held an insert for ~4 minutes and the ingest thread
  stopped passing entirely, with nothing in the log to read. It now fails, logs, and the next
  pass retries.
- **The third goflow2 listener is committed** (the node's own address on 2055, where a LAN
  router exports) along with `TAIL_FILES` — the manifest the live pod already runs, which had
  been applied but not recorded.

## 0.23.70 — 2026-11-18

A FLOW COULD NOT SAY WHICH NIC IT CAME THROUGH.

- **One collector per NIC, on ONE port** (`k8s/31-goflow2.yaml`, `tap.collector_for`): eth1's
  exports go to `127.0.0.1:2055`, eth2's to `127.0.0.2:2055`. Two listeners may share a port when
  they bind different addresses, and Linux routes all of `127.0.0.0/8` locally -- so every
  exporter, firewall rule and doc keeps saying 2055, and no interface is invented. The wildcard
  bind had to go, or it would have swallowed `127.0.0.2`; the node's own address is bound as well
  so a LAN router can still export to this host on 2055.
- **The file names the NIC** (`flows.in_iface`, migration 054): the ingester tails every
  collector's file (`TAIL_FILES`) and stamps the interface that file belongs to onto each record.
  An unattributed flow reads as empty, never as a guessed NIC.
- **Measured first, then built**: softflowd cannot report an interface when it reads a pcap --
  plain, `-i idx:iface`, `-e <exporter ip>` and `-S <name>` were each replayed on the box, and the
  collector recorded `in_if=0` and one sampler address every time. That is why the separation
  happens at the socket, where it is a fact, rather than in the record.

## 0.23.69 — 2026-11-18

A REVIEW THAT SHOWS THE WRONG PORT IS A REVIEW THAT LOSES THE OPERATOR'S TRUST.

- **The staged change says what moves, in words** (`describePlan`, `describePlanChange` in
  `app.js`): the intercept plan is stored as JSON keyed by NIC, and the pending-changes list printed
  it verbatim. An operator staging eth2 read `{"eth1":{...},"eth2":{...}}` left to right, saw eth1
  first, and twice concluded the console was about to apply the change to the wrong port. The review
  now reads `eth2: adds siphon 198.51.100.0/24, address 198.51.100.233, gateway 198.51.100.1` -- the
  NIC that moved, and only that NIC. An untouched plan reads `no change`; a NIC leaving the plan
  reads `removed`.
- **The sheet describes its own NIC** (`renderStageMirror`): with eth2's settings open, the row is
  `intercept · eth2 -> siphon 198.51.100.0/24, ...` rather than the whole plan, in the same
  vocabulary as the Zeek and NetFlow rows beside it.
- **The after-apply receipt uses the same sentences** (`renderApplyInto`): the write the operator is
  checking is described the way the change was reviewed, not as the raw ConfigMap value.
- **The formatter is tested against the shipping source** (`scripts/plan_review_text.js` extracts
  the functions from `app.js` and runs them under node; `tests/test_plan_review_text.py` pins the
  sentences and asserts all three call sites use it). A helper nothing calls would pass every case
  and fix nothing.

## 0.23.68 — 2026-11-17

A SWEEP THAT CANNOT SHOW IT IS RIGHT IS NOT A MEASUREMENT.

- **Segment rollup** (`scopes.segment_hour_profiles`, `scopes.rank_segments`): the same merged
  host-window rows, summed into the /24 that contains them. Bytes are additive; peers are the
  widest host's, because a distinct count cannot be recovered from its parts -- a floor on the
  segment's diversity, never an overstatement. One host departing can be a backup; a whole subnet
  departing cannot be, and a subnet survives the DHCP churn that moves addresses between hosts.
- **Two controls on every detection sweep** (`weirvern/models/controls.py`): a 100x departure must
  outrank a larger ordinary transfer (`exfil_fires`), and the host with the widest peer set must
  not read as anomalous (`umbrel_quiet` -- measured live: 2.18x, sixth of seven, while two ordinary
  hosts reached 45x and 100x). A failure logs `Detection run DEGRADED` and is written beside the
  cursor; the window is not re-opened, because it was examined either way.
- **An eleventh health check** reads the last verdict from `detection_controls.json`: fresh and
  passing is green, a failed control is red and names it, a verdict older than three sweeps is red,
  and a worker that never ran the controls is NOT APPLICABLE rather than a silent pass.

Also: `rank_from` is the ranking rule split out as a pure function, so the exfil control exercises
the product's own rule rather than a re-implementation that passes when both are wrong. Segment
rollup measured live after deploy: see the handover.

## 0.23.67 — 2026-11-17

THE HEALTH PANEL COULD NOT TELL A QUIET NETWORK FROM A DEAD TAP.

- **The tap publishes its own state** (`weirvern.tap.publish_state`) once per tick to a hostPath
  that the tap, the worker and the GUI all mount: PID, targets, segments summarised, ring size and
  the last error. Atomic by rename, so a reader never sees half a file; a read-only mount is DEBUG,
  not a warning, because a capture process must not be noisy about a reporting failure.
- **New `capture` health probe**, tri-state like the rest: no state file on a box with no active
  tap is NOT APPLICABLE; no file with `netflow_mode=active`, a file older than three publish ticks,
  or a live tap that is not capturing are failures — each naming the next thing to check.
- Why this is not cosmetic: every other probe infers capture from the rows that arrive, and "no
  rows" is the same fact whether the network is quiet, the filter is wrong, softflowd is stuck or
  the tap is dead. That ambiguity is what let a sixteen-hour gap, and then a twenty-hour wedged
  cursor after it, read as a quiet night with every light green.
- **The sluice teardown warning is no longer once a minute.** `nft list tables` fails permanently
  for a uid-10001, capability-free worker; the condition is now reported once with the remedy
  instead of ~1,440 times a day in the log that also carries the detection sweep's verdicts.

## 0.23.66 — 2026-11-17

AN EMPTY WINDOW BEHIND AN OUTAGE RE-EXAMINED ITSELF FOREVER, AND THE LOG THAT WOULD HAVE SAID SO
WAS BURIED.

- **The detect cursor could wedge permanently.** The rule "never advance the cursor over an empty
  read" is right for rows that are still arriving and wrong when the emptiness is permanent. Flows
  died at 19:12Z on 2026-11-16; the cursor stopped at 19:17:59Z; the next catch-up chunk
  (19:17 → 20:17) could never fill. Every cycle re-read that dead hour, logged `examined NOTHING`
  and returned without saving — so when flows returned four hours later, detection stayed dark for
  **twenty hours** with the pod green. A second stale cursor on the box
  (`detect_cursor.json.stuck-20261112`) shows the same failure five days earlier.
  An empty chunk is now re-covered inside a 15-minute grace window (three bucket cycles after the
  last row can land) and **stepped over, loudly, outside it** — `CURSOR_GAP_GRACE_S`.
- **The ingest log drowned the detection log.** The Zeek tailer re-opens every log on every 5 s
  pass and logged one line per file per pass: ~50,000 lines per ten minutes, against a 10MiB
  container log that then rotated every few minutes and took every other message with it. The
  per-file cursor is now DEBUG; the pass still reports work at INFO. This is why the wedge above
  was invisible.
- **The tap's segment ring has a disk budget.** `-C 16 -W 240` is a 3.84 GB worst case, and it is
  reachable exactly one way: softflowd starts, hangs, and tcpdump keeps rotating. `prune_ring()`
  drops the oldest completed segments above 512 MB (after the sweep, never before, never the live
  segment) and says which segments were dropped. A healthy ring is two files, ~20 KB.

ALSO IN THIS RELEASE, DEPLOYED 2026-11-17 BUT NOT YET CHANGELOGGED: the tap moved to the capture
boundary (`weirvern/tap.py`, run as a Zeek DaemonSet sidecar on the hub and by the agent container
on a weirling) and the worker's capture path was deleted in the same commit. The worker ran as uid
10001, and Kubernetes drops an added capability for a non-root container — measured `CapEff
0000000000000000` despite `add: ["NET_RAW"]`, which is why flows stopped while every surface read
"configured".

## 0.23.65 — 2026-11-12

CLICKHOUSE'S OWN LOGS WERE 37 GiB OF A 42 GiB VOLUME.

- Measured live: the `weirvern` database held 519 MiB of product data while the server's diagnostic
  tables held ~37 GiB — text_log 19.0 GiB at trace level (472M rows), query_log 5.5 GiB,
  processors_profile_log 4.8 GiB, trace_log 3.7 GiB, part_log 2.7 GiB. The volume was 75% full.
- `zz-weirvern-logs.xml` (a config.d drop-in, like the backup one) sets text_log to `warning` and
  gives every diagnostic table a TTL: 3 days for text/trace, 7 for query/part/metric/asynchronous/
  processors. The file log keeps its own level, so an operator still has the full server log.
- The live tables were also given the same TTLs directly, which drained 35.5 GiB of expired parts
  and took the volume from 24 GB free to 52 GB.

## 0.23.64 — 2026-11-12

THE MATRIX PROFILE BUILT AN n x n x m ARRAY, AND THE RESTORED FLOW FEED MADE n LARGE.

- `temporal.matrix_profile` computed the pairwise window distance as
  `np.linalg.norm(win[:, None, :] - win[None, :, :], axis=2)`: an n x n x 12 float64 intermediate,
  96 bytes per window PAIR. Its own comment assumed an ~864-point series (71 MB). Measured live: the
  busiest host has **6,961 points** over three days, which is **4.6 GB in one expression** -- the
  worker OOM-killed at 4 GiB, and still at 7 GiB, every ~35 seconds, once the NetFlow tap was
  restored and hosts carried real series again.
- The distance now comes from the z-normalised identity ||a-b||^2 = 2m - 2<a,b>, accumulated a
  BLOCK of rows at a time: the intermediate is `block_rows x n`, never `n x n x m`.
- The series is bucket-averaged to `MAX_POINTS` (2048) before profiling, so a host's traffic volume
  cannot size the job; buckets are consecutive runs, so the reduced series stays chronological and
  the reported window maps back to a real row.
- Tests: the blocked profile is bit-for-bit the broadcast definition on a small series; a
  20,000-point series stays bounded and still finds its discord.

## 0.23.63 — 2026-11-12

TRIM IN PLACE: A RENAME WAS SWAPPING THE INODE UNDER THE COLLECTOR.

- `enforce_netflow` wrote the kept tail to a temporary file and `replace()`d the log. That gives
  the log a new inode while goflow2 still holds the old one open, so every record it wrote
  afterwards went into the unlinked file: flows stopped at 19:17:57, the log on disk froze at the
  trim point, and the disk filled to 17.9 GB through a handle nothing could see. Restarting the
  collector then failed with "permission denied" on a file owned by the prune's user.
- The kept bytes are now written back into the same inode at offset 0 and the file truncated. The
  collector opens this log for append, so its handle stays valid and its next record lands after
  the trim; ownership and mode cannot change because the file is never replaced.
- The trim hint is still recorded (the reader's cursor is past the end and must be shifted).
- Tests: the trim preserves the inode, and the mode the writer needs.

## 0.23.62 — 2026-11-12

OBSERVED IS NOT FRESH: THE WEIRLINGS TAB CAN NOW SEE A DEAD EXPORTER.

- The NetFlow evidence line counted flows over 24 hours, so an exporter that stopped at 01:17 still
  read as "9,000 flows in 24h" and the row looked healthy until the next day. Measured live:
  zero packets on 2055/6343 for two hours while the tab said observed.
- `fleet_store.flow_evidence` now returns the age of the newest flow, computed by ClickHouse
  (`dateDiff`) in the database's own clock so the timezone skew that query exists to avoid cannot
  come back through Python. The fleet payload carries `fresh`, `stale` and `age_s`, and the reason
  names the silence ("exporter silent for 2h").
- The Weirlings sheet states the last flow's age for a live feed and calls a silent one
  `NetFlow STALE`, instead of implying a 24-hour-old count means it is working.

## 0.23.61 — 2026-11-12

THE TRIM MUST NOT TAKE THE WRITER'S ACCESS WITH IT.

- Replacing the flow log creates a new inode owned by whoever ran the prune. On the live
  deployment that is uid 10001 (mode 644), while goflow2 runs as uid 100 — so after a trim the
  collector could not append to its own log and NetFlow went dark. The rewrite now carries the
  original uid, gid and mode across the replace; a chown the process is not allowed to perform is
  not fatal.
- Verified live before the fix: `open /data/flows.jsonl: permission denied for file transport` on
  restart. After restoring ownership the collector binds 2055 and 6343 again.
- Test: a 664 log survives a trim with its mode intact.

## 0.23.59 — 2026-11-12

ANY COLLECTED SOURCE CAN CARRY A RIPPLE.

- `models/generic_channels.py` adds six sources that were collected but never reached the ripple
  layer: zeek_http (116k rows), zeek_files (81k), zeek_ssh (19k), zeek_weird (1.6M), zeek_quic
  (5.9k), zeek_dhcp (1.3k). A source becomes a channel by declaration (table, host column,
  diversity column, family); the score is the same everywhere — this window's volume and diversity
  against the host's own trailing seven days — and the p-value is that score's rank among the
  host's own historical windows.
- Absence is absence: a host with less than two hours of history for a source produces no evidence,
  and one broken source cannot silence the others. The two-family rule still applies, so a new
  source must be corroborated before anything becomes a ripple.
- Query cost measured on the live deployment: 0.41 s for zeek_weird over seven days (15,186
  host-windows), 0.40 s for zeek_http; the whole pass adds roughly 2.5 s per hour.

## 0.23.58 — 2026-11-12

PRUNE STREAMS THE FLOW LOG, AND THE RIPPLE THRESHOLD IS DERIVED, NOT CHOSEN.

- `enforce_netflow` read the remainder of the flow log into memory (`fh.read()`) before rewriting
  it. Live, that file reached 17.9 GB against a 1024 MB cap, so the prune CronJob was OOM-killed
  at its 256Mi limit every five minutes (exit 137, BackoffLimitExceeded) and the cap was never
  enforced while the disk filled. The trim now streams with `shutil.copyfileobj` in 1 MiB chunks;
  a regression test asserts the peak allocation stays bounded on a 26 MB file.
- `models/operating_point.py`: the fused decision no longer takes a hand-picked `max_p`. The
  deployment states a budget (1% of host-evaluations may become a ripple) and the threshold is
  derived from the quantile of its own fused p-values, bounded by the 0.05 it replaces. Measured
  live on 0.23.57, the constant called 6 of 44 host-evaluations a ripple (13.6% of hosts, hourly).
- Cold start: below 100 evaluations per monitored host, every host is reported `unknown` with the
  counts in the reason. A new install says "learning baseline" instead of calling one host in
  seven anomalous on its first day. The worker log carries the threshold, sample count and warm
  or cold state.

## 0.23.57 — 2026-11-12

RIPPLE FUSION WIRED, AND A COVERAGE CONTRACT THAT MEASURES HOSTS.

- RIP-5: `models/ripple_shadow.py` reads the three shadow stores, calibrates every model against
  its own recent population (2000 scores/model, 7 days), fuses per host with `ripple.fuse()` and
  records one row per host in the new `ml_ripple` table. Missing channels are named, unknown
  stays unknown, `pageable` is always 0 and the alert path is untouched.
- `GET /api/ml/ripple` returns the latest fused evaluation with contributors, families, scales,
  named unknown channels and the reason it did or did not fire; a failed read is
  `available:false` with the reason, never an empty success.
- The Models tab gains a Ripple evidence card: what fired, on which host, at which scales, from
  which channels, and which channels were dark.
- Fixes `fuse()`: an absent channel is `missing`, not `no p-value` (the p-value check ran first).
- Fixes the gate failure left by 240eaad: the schema audit read the adapter's caller-built row
  keys as phantom columns; they are a contract pinned by tests.
- DATA-0: `weirvern/data/data-coverage-contract.json` plus `models/data_contract.py` and
  `GET /api/ml/data-contract`. Coverage is measured against the monitored host population
  (the same predicate the detectors train on), with required/optional, accepted missingness,
  per-host observation status, a named top-gap report and a per-family usability verdict.
  The contract ships inside the package: kept under `docs/design/` it was absent from the
  image, and the live endpoint answered `available:false` with a file-not-found error.
- Ripple evidence is collapsed to one entry per channel and scale, keeping the most
  significant. HDBSCAN writes hundreds of correlated candidates per host, and feeding all of
  them into Fisher's combination violates its independence assumption: the first live pass
  called 3 of 22 hosts ripples and returned 187 KB for 22 hosts.
- Fixes the monthly review and program gate judging archived 2026-10 boards: they now read the
  active boards, so the ledger reflects the programme that is actually running.
- Fixes the 30-day episode window: the source only covers ~14 days, so the window is now
  `not measured` with the source's real span instead of a 14-day number wearing a 30-day label.
- Fixes `scripts/bump_version.sh` for the README's `<strong>` release line, which had drifted.

## 0.23.56 — 2026-11-11

SHADOW DISPOSITIONS, EVALUATION ARCHIVE, PROMOTION POLICY AND PROGRAM LEDGER.

- Adds the CE-2 shadow-channel inventory: every channel has one disposition (merge/retire), a
  named consumer or reason, and `not measured` evidence rather than an invented budget win.
- Adds CE-3 `scripts/ml_eval_report.py`: archived fixed-budget reports with seed, scenario,
  generator and auto-label versions, confidence intervals, previous-report regression checks and
  live precision `not measured`.
- Adds PR-2 `models/promotion.py`: one automatic promotion in flight, 14-day shadow soak,
  canary p95/error rollback, degraded telemetry block and kill-switch freeze.
- Adds PR-3 `models/ledger.py` and `scripts/ml_program_gate.py`: append-only decisions and a gate
  that fails on every blocked phase card, missing model-card identity or missing verification.
- Adds GT-2 scenario fields and the simulator-generated `auto_labels` manifest, including the
  TLS/JA4 churn scenario and the benign-heavy-day descriptor.

## 0.23.55 — 2026-11-11

MONTHLY PROGRAM REVIEW: A PASSING REVIEW CANNOT HIDE A BLOCKED CARD.

- Adds `scripts/ml_monthly_review.py`: reads drift/SLO, calibration FAR, source coverage,
  model cards, verification and shadow freshness, then archives a JSON and Markdown review.
- A blocked or missing phase card fails the review and is named by id and title.
- Missing verified attacks, verified negative hours or a generator version fails the review;
  an unlabelled zero is never accepted.
- Adds `/api/ml/review` and a Models program-review card showing status, next review and the
  named blocked cards. No model is deleted; retirement remains a status with provenance.

## 0.23.54 — 2026-11-11

SOURCE COVERAGE, QUALITY SLO AND VERIFIED EVIDENCE.

- Adds `/api/ml/coverage`: per-source rows/newest/state/usable, unknown-role hosts, and a
  promotion gate that refuses a missing required source.
- Adds `/api/ml/slo`: 7/14/30-day alerts/day, precision `not measured`, false alarms, latency,
  episodes/pageable, drift and shadow freshness.
- Promotion requires synthetic/canary/background verified evidence; weak-only labels are
  reported and rejected, and live precision remains `not measured`.
- Models view shows source coverage, ML quality SLO and verification coverage.

## 0.23.53 — 2026-11-11

MODEL CARDS: A NAME IN A SCORE IS NOT A MODEL.

- Adds `ml_model_cards` with artifact hash, feature/calibration versions, evaluation and
  rollback reference, and status (`shadow`/`canary`/`production`/`retired`).
- Eligibility now requires a current `production` card; a missing or retired card bars the
  model from the fused score. Existing four families are seeded from measured artifacts;
  DBSCAN is retired.
- `/api/models` and Models → Model cards show the card in words.

## 0.23.34 — 2026-11-04

VR-HDR follow-up: COUNTS WHERE THE VIEW HAS THEM.

- Host copies its address/subtitle into the header count; Settings falls back to its card
  count and Evidence to its five stages when their summary line is empty. No header shows a
  bare dash as its count.

## 0.23.33 — 2026-11-04

VR REMEDIATION: HEADER COUNTS STAY CURRENT.

- The view-header count refreshes on a one-second timer as well as the DOM observer, so a
  summary line that finishes loading after the view switch still reaches the header.

## 0.23.32 — 2026-11-04

VR REMEDIATION: ONE VIEW HEADER.

- Every view now has one header: a title, a count copied from that view's own summary, and one
  primary verb (the view's existing primary moved into the header, or Refresh for a read view).
- Old card/sheet `<h2>`s are demoted to `<h3>` at boot; only the header keeps the `<h2>`.
  Counts follow their summary lines through a debounced observer.

## 0.23.31 — 2026-11-04

VR REMEDIATION: THE TYPE RAMP IS THE ONLY TYPE.

- Every `font-size` in `style.css` now uses `--fs-1/2/3/4/6`; the last `font:` shorthand
  uses `var(--fs-2)`. There are no raw px sizes left, and all five tokens are referenced.
- Canon baseline regenerated with `font_size: 0`; a pytest pins the rule.

## 0.23.30 — 2026-11-04

VR REMEDIATION: ANOMALIES ROWS FIT THE LINE AND THE BUDGET.

- The review chip and row disclosure share one flex line; stacked they made every row 97px.
- A full 100-row measurement now renders at ~58px per row and under 8,000px, with the default
  limit at 68 rows so a cold load stays under the 6,000-element DOM budget.

## 0.23.29 — 2026-11-04

VR REMEDIATION: ANOMALIES ROWS ARE READING LINES.

- Compact the two timestamp columns, clamp the matched rule and host name to one line and
  the why sentence to two, and move the full rule/model/why prose into the existing row
  disclosure. Default limit drops 90 to 80 so a cold load fits the DOM budget.
- Measured in the authenticated live console at 1440; 100-row and 390 measurements follow.

## 0.23.28 — 2026-11-04

VR REMEDIATION: SERIES COLOUR TOKENS, NO HEX IN JS.

- Added `--series-1..10` to the root palette. MODEL_COLORS, SOC_COLORS and SOC_PALETTE now
  reference those tokens; fallbacks use `--muted` / `--bad`. No raw hex remains in `web/*.js`.
- Replaced the last non-root CSS hex (`#fff`, `#66a8ff`) with `--fg` and `--accent`, so the
  canon's hex count is zero. `canon_lint.py` now scans JS with the same rule and baseline.
- Baseline regenerated after the debt was paid; a pytest pins the JS scan and the tokens.

## 0.23.27 — 2026-11-04

VR REMEDIATION: ONE GATE STATE, TWO LABELLED COUNTS.

- Sluice keeps one packet-gate state (`#sl-gate-state`) plus the Domain Gate's own state; the
  old duplicate `#sl-state` is absent. The Rules header now says `N in the store`, while the
  fleet table names its column `Packet rules installed (active / total)` and its note states
  the distinction. A pytest pins the single surfaces and the labels.

## 0.23.26 — 2026-11-04

VR REMEDIATIONS: THE RULE IS THE RULING; THE CHAIN IS A RECORD.

- Evidence RULED now names the matched rule, or says "no rule — alert only". The review state
  (acknowledged / resolved / false positive) belongs only to DONE.
- Removed the chain's 1–5 numerals and the five equal tracks. Each stage is sized by its own
  record and the chain scrolls rather than pretending to be a stepper.

## 0.23.25 — 2026-11-04

VR REMEDIATION: DNS VERBS BEHIND ONE DISCLOSURE.

- Every DNS row now carries one native `<details>` summary; Block lives inside it, closed
  at rest. 100 rows no longer put 100 verbs in the reading path. The summary is named,
  stops the row's detail click, and the verb keeps its own keyboard target.
- Pinned by pytest source contract and jsdom: one disclosure per row, closed at rest,
  open in place, no detail row triggered by the summary.

## 0.23.24 — 2026-11-04

VR REMEDIATIONS: ONE AUTO-REFRESH STATE, KEYBOARD-OPERABLE RULES.

- Removed the duplicate header auto-refresh checkbox. The one pill now reads `live · 15s`
  or `paused`, and only it starts/stops the timer.
- Sluice rule rows are tabbable, announce as buttons, open their sheet on Enter/Space,
  and carry a visible focus ring; the row checkbox keeps its own keys.

## 0.23.23 — 2026-11-04

AUDIT FIXES: URL-BACKED HUNTING.

- Host pages now write their address into the URL (`h.addr`); a cold host URL restores the
  host page, and host -> peer -> Back returns to the previous host instead of Assets.
- Evidence is a pivot surface: Open host page for the alert host, DNS rows filter DNS to the
  host and name, Zeek service rows filter Zeek to host + service, and JA4 opens the fingerprint
  lookup. Flow destinations already opened their host.
- Zeek filters serialize as `zk=field:value`; a host-page service pivot carries both host and
  service, so it no longer silently becomes a fleet-wide question.
- DNS answer addresses are entity links that open their host page.
- Models summary reports the window total/severity spread independently of the 500-row points
  sample and labels the sample; a feature-deviation bar offers `alerts` to open Anomalies
  filtered by that feature, and Anomalies accepts a bound `feature` filter in the queue and its
  counts.

## 0.23.22 — 2026-11-03

SLUICE GATE ALIGNMENT.

- Gate overview is the leading status surface; the standalone explanatory paragraphs and the
  read-only Blocking-on-detections card are gone. Detection policy is a compact policy strip
  inside the Traffic Gate card.
- Domain Gate and Traffic Gate keep their separate DNS/packet facts and fleet table.
- Rules gains one primary `New rule`; bulk selection is entered by a `Select` control, so the
  table carries no checkbox column at rest. The rule sheet remains the only editor.
- Policy rows now state their cost in one compact line; the current policy stays visible.

## 0.23.21 — 2026-11-03

HUNTING PIVOTS.

- Zeek log volume, services and DNS names are clickable cross-filters; the selected hosts
  follow through to the drill-down and the empty state names the filter.
- Host-page destinations, NetFlow bars, graph peers, DNS queries, Zeek services and anomalies
  are pivots: destination/source filters land in NetFlow, DNS lands filtered to host+name,
  graph peers open their host page, and anomalies open their evidence chain.
- NetFlow and the Flows drill accept a `dst` filter, so a top destination can answer "who
  else is talking to this box" instead of only "what did this host do".
- Models now labels its baseline card truthfully and reports N of 77 model inputs; the
  Adaptive Baseline gains per-host flow-count, port-diversity, port-entropy, regularity and
  burstiness statistics for the first baseline tranche.

## 0.23.20 — 2026-11-03

QUEUE TABLE LABELS.

- The Anomalies table and the incident queue now carry an explicit **Hostname** column beside
  the address. The Host column stays the fact (the IP); the name is the convenience and is never
  substituted for it.
- The queue's `windows` heading is now **Windows**.
- The default Anomalies view is **All anomalies**, matching the Network graph's alert count;
  Incidents and Leads are explicit views over the same evidence. The graph and the list now
  bound anomaly rows by `window_start`, not by the later ingestion pass.
- No detection, budgeting, or episode-identity behavior changed; this is display-only.

## 0.23.19 — 2026-11-02

INCIDENT QUEUE CONTRACT.

- The Anomalies tab now opens on **Incidents**: one row per high/critical, pageable episode, with
  the measured signal (primary deviation feature or independent family count) in the row.
- Low/medium episodes and high/critical episodes with no named feature or independent family are
  **Leads**. They remain one selection away, carry their reason, and never read as paging work.
- **All anomalies** keeps every raw scored window and every existing filter; no evidence becomes
  unreachable. A model-only episode is a lead, not an incident.
- The episode evidence join is a batch read; if it fails, the queue says the evidence read failed
  and does not silently promote or hide an episode.
- Regressions cover the incident/lead contract and the broken-evidence path.

## 0.23.18 — 2026-11-02

EPISODE IDENTITY FIX.

- `episodes.refresh()` now reads a 30-day episode lookback instead of the 24-hour display window.
  A continuous incident keeps one start timestamp, so the next refresh updates its row instead of
  inserting a new keyed copy.
- Overlapping older episode rows are merged into the canonical episode and marked `superseded`
  in the existing `page_reason` column. They remain as history, are hidden from the incident view
  and cannot claim a page.
- The default incident view filters by `last_detected` rather than `episode_start`, so an incident
  that began before the display window but is still active remains visible.
- Added a regression that slides the anomaly window between refreshes and verifies one active
  episode; a second verifies duplicate prior rows become superseded.
- The worker now refreshes the episode view every cycle, not only on cycles that produced
  verdicts. A quiet cycle previously left `alert_episodes` stale while detection kept writing
  anomalies; the page budget and dashboard were reading the old view.
- Pre-existing duplicate rows are collapsed even when they sit before the current incident and
  do not overlap it: any two prior rows with overlapping intervals are one episode, and the
  later copy is marked superseded.
- Overlapping rebuilt episodes and future-dated ends left by the earlier timezone-shifted view
  are collapsed/clamped before the page budget runs, so a stale row cannot extend an incident
  past the current clock or hide it from the upper-bounded view.
- Live audit before the fix: 2,487 episode rows for 19 hosts in 24 hours versus 68 rebuilt
  episodes. The review is `docs/research/ml-full-review-2026-11-02.md`.

## 0.23.17 — 2026-11-02

MITRE ATT&CK REMOVED.

- Removed the ATT&CK mapper, the alert line, the evidence-page block, the API fields and the
  export path. Detection and alerting do not depend on a technique label.
- The evaluator no longer expects or prints techniques for the flow-only scenarios; it asserts
  severity and latency only.
- The legacy `attack_techniques` / `attack_label` database columns remain for schema
  compatibility and are written empty. No migration drops historical data.
- `attack.py`, its tests and the MITRE-specific checks are gone. The tool now reports what it
  measured and what changed, without claiming an ATT&CK technique it cannot observe.
- New deployments now have a named warm-up state (`weirvern/models/readiness.py`): detections
  are recorded but do not page until the local baseline has 24h, 12 distinct windows and at
  least one host by default. The knobs are `ML_WARMUP_HOURS`, `ML_WARMUP_MIN_WINDOWS` and
  `ML_WARMUP_MIN_HOSTS`; an unreadable readiness query is `unknown` and also does not page.
- Added a portability guard that rejects identity fields in the feature vectors and proves the
  same behaviour under a renamed address plan produces the same vector.

## 0.23.16 — 2026-11-01

ML DETECTION PROGRAM — COVERAGE, SPECIALISTS, AND A USABLE BUDGET.

- The source-to-feature registry maps every harvested table and field to used, planned,
  join-only or excluded, with its presence rule. A source with zero rows is named, never
  silently trained as zero.
- The fixed-budget evaluation harness scores all host-windows, not only alarm rows, holds out
  whole days, and compares a candidate with the baseline on the same time window and the same
  alerts/day budget. Its report carries precision@k, false alarms per host/day by role, seeded
  detection rate and latency, episode count, explanation coverage and runtime. A candidate that
  wins only by alerting more is rejected.
- Incident episodes and a per-host/role page budget are the unit of work. Raw
  `netflow_anomalies` windows remain the audit record; the Anomalies view and pageable path
  consume episodes and state `N occurrences` without hiding the underlying rows.
- DBSCAN is quarantined from the fused score while its observed false-alarm rate is outside the
  configured multiple of target. A direct structural signature can still alert independently.
- Shadow specialists for raw flow/scan, DNS, TLS/JA4, identity/lateral, beacon/periodicity and
  graph/peer features write candidate evidence only; none pages directly. The fused score reads
  detector eligibility rather than letting a saturated family set it.
- Calibration runs on every scored host-window, with a named reference population and age.
  Drift monitoring records PSI per model/host and a manual retrain recommendation; it never
  retrains or changes a threshold automatically.
- Review verdicts produce bounded, reversible calibration or budget adjustments with
  provenance and expiry. A false-positive label is evidence, not a normal-training label, and
  never rewrites the training set.
- Models and status surfaces show calibration target, observed, sample count, age and
  eligibility; specialist shadow state; incidents versus occurrences; and the active source.
  A failed read is named rather than rendered as a measured zero.
- The Zeek trunk probe init container now has a 512Mi limit (64Mi request) instead of 128Mi;
  the 0.23.16 Python import set was OOM-killed at the old limit during the live rollout.
- The capture set now merges the trunk probe's result with `ZEEK_IFACES` instead of replacing
  it. With `ZEEK_IFACES=eth1,eth2` and a one-line `eth1` state file, the second port was
  silently dropped; Data-segment DNS, TLS/JA4 and lateral coverage return when both ports
  are captured.

Schema additions 037–040 are additive. This changelog and version bump do not deploy anything;
the live cluster remains on the last approved release until the release ritual and operator
approval are completed.

## 0.23.15 — 2026-10-29

SLUICE GATE: TWO ENFORCEMENT PATHS, ONE FLEET.

- The overview is split into a DNS summary and a packet summary. Domain rules, DNS hits and
  blocklists no longer share an unlabelled strip with packet rules and gate state.
- Domain Gate now carries only DNS facts: lists/domains, DNS hits and names, last sync. The
  Traffic Gate carries only packet facts: fleet state, per-weirling rows, interfaces, packet
  rules, packets blocked, last check and enforcement path.
- The Traffic Gate is fleet-shaped. Every reporting weirling gets a row; its capture interfaces
  are listed as a set, so five weirlings produce five rows instead of one global interface tile.
- Rules stay in the one store and one sheet, but every row names its gate (`Domain` or
  `Traffic`) and a Domain/Traffic filter can isolate either family, with hidden counts stated.
- No rule, alert, review or gate semantics changed.

## 0.23.14 — 2026-10-28

ALERT EVIDENCE KEEPS ITS VERDICT.

- The alert-evidence window lookup selected 11 columns but indexed `row[11]` and `row[12]`
  for `strong_families` and `severity_basis`. The resulting IndexError was caught as a
  failed lookup, so the page said "no verdict stored for this window", left EXPLAINED
  unknown, and rendered no Acknowledge / Resolve / Ignore controls even though the alert
  existed. The two columns are now selected, and a regression test uses a query-width-aware
  fake client so a positional mismatch cannot hide behind padded test rows.
- No alert semantics, review-state writes, or external-peer behavior changed.

## 0.23.13 — 2026-10-27

EXTERNAL EXPOSURE, SHADOW ONLY.

- Network coverage now carries an **External exposure** reading: inbound external peers to
  monitored destinations, outbound external destinations from monitored sources, bytes, flows,
  top-peer concentration and the top presentation prefixes. It is marked observed and creates
  no alert entity.
- The host page shows the same reading for one monitored endpoint after an external peer is
  clicked; an address outside a monitored scope says why it has no exposure reading.
- The hourly shadow pass writes `External exposure` rankings to the existing
  `ml_candidate_scores` table. The score ranks the measured peer-population features; it does
  not write `netflow_anomalies`, `alert_events`, or Sluice state, and it is not a probability.
- The external layer deliberately keeps individual addresses for evidence and click-through,
  while the model-facing view is the aggregate peer dimension. This is the first phase of the
  design in `docs/design/external-peer-layer.md`; promotion needs a 30-day backtest at the
  current internal-host alert budget.

## 0.23.12 — 2026-10-27

EXTERNAL PEERS OPEN THEIR HOST PAGE.

- Each row in Network coverage → External peers is now a real button. It opens the same
  host page as any other address, so an unexplained internet peer can be inspected through
  its flows, ports and last-seen evidence instead of being a dead-end reading.
- The rows keep the ranked byte bar and window count; the change is navigation, not a new
  external alert source.

## 0.23.11 — 2026-10-27

NIC STAGING KEEPS THE PENDING INTERFACE LIST.

- The NIC sheet now reads its feed checkboxes and its staging baseline from the **pending**
  settings, not the last applied cluster values. Opening eth2 after staging eth1 used to
  replace the pending NetFlow/Zeek list with the stored one, so Apply wrote only the last NIC.
- Both feeds now accumulate in `NETFLOW_IFACE` / `ZEEK_IFACES` while the operator moves between
  NICs. The cluster-side apply had already succeeded with `eth1,eth2`; this fixes the UI path
  that was dropping one of them before it reached the server.

## 0.23.10 — 2026-10-27

CHANNEL MODE CAPTURES ONE SIDE.

- A channel is an **inline pair**: `CHANNEL_UPSTREAM` and `CHANNEL_DOWNSTREAM` are bridged,
  so every frame crosses both. While that pair is configured, the settings writer now refuses
  more than one capture interface for **Zeek** or **active NetFlow**; one side is enough and
  capturing both would record the same conversation twice.
- Applying a channel stages the upstream side into `ZEEK_IFACES` and `NETFLOW_IFACE` in the
  same plan, so the one-side rule is the default rather than a validation surprise.
- Outside channel mode the multi-NIC behavior from 0.23.9 stands: independent capture NICs can
  each run Zeek and an active NetFlow probe.

## 0.23.9 — 2026-10-27

ACTIVE NETFLOW CAN METER MORE THAN ONE NIC.

- `NETFLOW_IFACE` accepts a comma-separated list. The worker starts one supervised tap per
  interface, each with its own rotating segment ring, and sweeps each ring independently.
- The NIC sheet stages that list: checking NetFlow on eth1 and eth2 now leaves both probes
  running instead of moving one probe between them. An interface that dies is stopped and
  retried as a set, rather than silently half-running.
- The per-NIC facts line and fleet feed name the whole active set (`NetFlow active · eth1,
  eth2`), and the "one source at a time" note is gone. Passive mode still leaves the router's
  export alone.
- A flat directory is kept for a single tap; multiple taps use one directory per interface so
  a segment still being written for one NIC cannot hold up another's sweep.

## 0.23.8 — 2026-10-27

NETWORK COVERAGE: A LEDGER, NOT A RUN-ON LIST.

- The external-peers section is now a ranked ledger: position, peer address, a volume bar
  scaled to the top peer, human-readable bytes, window count and last-seen time. The heading
  says the population and the 24-hour scope instead of leaving the reader to infer it.
- A legend under the scope cards makes the colour vocabulary explicit: **green = monitored**
  (per-host scoring and alerts), **grey = observed** (collected, not alertable), **orange =
  unclassified** (outside every declaration). DMZ, INTERNAL and VPN are labels, not colours.
- The NIC sheet now says that active NetFlow has **one source at a time**, and the facts line
  names the current source (`NetFlow active · eth1`). Turning it on for another NIC moves the
  probe; it is not two independent feeds. Passive mode remains the router-feed option.

## 0.23.7 — 2026-10-27

A READ-ONLY UPDATE CHECK, NOT A SELF-UPDATER.

- Settings → Operations gains a **Software update** card: the running version, a **Check
  for updates** button, the latest GitHub release when the feed is public, and a release-notes
  link.
- The server route `/api/update` reads GitHub Releases through `weirvern/admin/update.py`.
  It is deliberately read-only: the LAN console never pulls an image, edits a Deployment or
  restarts a pod. Applying a release remains a deployment-pipeline action with credentials,
  signatures and rollback.
- A private repository returns GitHub's 404; the card says **private feed** instead of
  reporting the deployment as current. Set `WEIRVERN_UPDATE_REPO` and an optional read-only
  `WEIRVERN_UPDATE_TOKEN` in the deployment environment when the repo/feed changes.
- No update button is rendered for the apply step yet. The pipeline can add a guarded update
  action later, with the same `full`→`per-host`-style rule: the web process gets no
  cluster-admin privilege.

## 0.23.6 — 2026-10-27

SAY PER-HOST, NOT FULL.

- Network coverage cards and Settings → Monitored networks now label the `full`
  policy **per-host** — it means per-host baselines and alerts. The stored/API value
  remains `full` so existing scopes and clients are unchanged.
- The policy picker says per-host; the Settings table and card tooltip use the same
  vocabulary.

## 0.23.5 — 2026-10-27

NETWORK COVERAGE CARDS STACK.

- The Weirlings **Network coverage** scope cards now render as vertical readings:
  label, CIDR, policy, then host/alert counts. The cards were buttons, and the global
  button rule (`inline-flex`, centered, `nowrap`, fixed height) made their four child
  rows run across one line, overlap the adjacent card, and spill outside the card edge.
- `.net-card` now explicitly opts out of the single-line button layout: column flex,
  natural height, wrapping text, and `overflow-wrap` for long labels/subnets.

## 0.23.4 — 2026-10-24

PACKET GATE LABEL, TAKE TWO.

- The Traffic Gate line now reads **Packet gate open · no packet rules · DNS gate on · N domains**
  without repeating "packet gate" inside the state value. The packet/DNS distinction introduced
  in 0.23.3 is unchanged; this only removes the duplicate label.
- The Fleet gates table and Traffic Gate tile keep the **Packet state / Packet rules** wording.

## 0.23.3 — 2026-10-24

DNS IS NOT PACKET OPEN.

- Sluice's packet state is now named as such everywhere: **`open · no packet rules`**, not
  **open**, and the Traffic Gate line reads **packet gate open · no packet rules · DNS gate on ·
  N domains**. The fleet table is titled **Packet state / Packet rules** with a note that DNS
  blocking is enforced separately.
- A working Domain Gate (blocklists or domain rules) no longer looks switched off just because
  the packet gate has no live nft rules. The server's packet-gate detail now says "no live packet
  rules" rather than "no live rules".
- The Domain Gate remains a separate enforcement path and keeps its own state, counts and
  control.

## 0.23.2 — 2026-10-24

OPEN IS NOT DEGRADED.

- A gate with **no live rules** now reports `disarmed` (shown as **open**) at the sensor
  aggregate, not `degraded`. The aggregate used to treat every non-armed NIC as a failure, so an
  operator who had simply filed no rule saw "degraded" beside a healthy sensor and went looking
  for an enforcement fault that did not exist.
- `degraded` is now reserved for a real enforcement failure: a missing/unavailable backend, a
  ruleset that did not install, or no verified enforcement path.
- Sluice shows **open** for a disarmed gate in the fleet table and Traffic Gate tile, and the
  status line reads **open · no live rules** with the server's reason visible.
- Tests pin the all-disarmed aggregate and prove one failed NIC still degrades the sensor.

## 0.23.1 — 2026-10-24

AUTO-FILL SCOPES FROM MONITORED NETWORKS.

- Settings now offers **Auto-fill from monitored networks** when the scope table is empty. It
  reads only `INTERCEPT_PLANS` segments already configured by the operator, labels their
  interface description when available, and creates internal/full monitored scopes after one
  explicit click. It never reads observed traffic or an RFC1918 list.
- The read endpoint returns those segments as `suggested_scopes`; the write endpoint is
  `/api/networks/autofill` and refuses to run once any scope exists.
- Invalid segments are skipped, not guessed; external traffic remains observed unless separately
  declared.

## 0.23.0 — 2026-10-24

SCOPE ENFORCEMENT ACROSS TRAINING AND THE GRAPH.

- Model training now follows the same monitored-network declarations as scoring: with no
  declarations it is legacy, with declarations it filters every detector's training rows to
  monitored scopes, and a declaration set with nothing monitored yields no training data rather
  than silently training on everything.
- Anomaly rows carry `network_scope` (migration 036), so an alert can be filtered and explained
  by the scope that admitted it.
- Weirlings' Network coverage card includes last-seen, a top external-peer aggregate (bytes,
  windows, last seen) outside every declared scope, and a flagged catch-all warning.
- The connection graph carries scope labels: monitored nodes keep their normal fill, observed
  nodes are muted, and unclassified nodes get a warning outline with a legend entry.
- Catch-all (`/0`) scopes are allowed but visibly flagged when monitored.

## 0.22.1 — 2026-10-24

NETWORK COVERAGE UI FOLLOW-UP.

- The Settings network card now listens for Edit/Delete on the card, not only on the add form;
  the row actions previously sat outside that listener and did nothing.
- Tests use documentation ranges only, so the sanitation guard keeps its meaning without
  weakening the scope assertions.

## 0.22.0 — 2026-10-24

OPERATOR-DECLARED NETWORK SCOPES.

- New `network_scopes` table and Settings → Monitored networks card. Each declaration is a
  CIDR, a label (`internal`, `vpn`, `dmz`, `external`), a policy (`full`, `aggregate`,
  `observe`, `off`) and an independent `monitored` flag. Overlaps resolve by longest prefix;
  unmatched addresses are `unclassified`, never silently assumed private or external.
- The worker scores only hosts in monitored scopes. When no scopes are declared it preserves
  the previous behaviour so an upgrade cannot silently stop alerting; once declarations exist,
  unmonitored and unclassified traffic is collected and visible but does not create per-host
  alerts. Scope application is logged with kept/unclassified counts every sweep.
- Weirlings gains a Network coverage card showing each declared scope, whether it is monitored,
  its 24h host/alert counts, and an explicit Unclassified card for traffic outside every scope.
  Settings and Weirlings read the same declarations; neither derives scope from an address.
- The read API is `/api/networks`; writes are `/api/networks/save` and
  `/api/networks/delete`, admin-gated like every other configuration write.

## 0.21.0 — 2026-10-24

DNS SHAPE AND GRAPH RELATIONSHIP FEATURES.

- The production Zeek block grows from 50 to 63 columns. The full Isolation Forest / Gradient
  Boosting vector grows from 64 to 77; DBSCAN keeps its deliberately small 19-column subset.
- DNS: unique-query ratio, maximum query entropy, query-length spread, NXDOMAIN ratio, TXT and
  NULL query ratios, mean answer count, and the share of domains never queried by the host in
  the previous 72 hours.
- Graph: fan-in (distinct sources that initiated traffic to this host), destination
  concentration, peer rarity, reciprocity, and new-peer ratio against the host's 72h history.
  Fan-out was already represented by `zeek_unique_dst_ips`; it is not duplicated.
- All values are computed from Zeek tables already in ClickHouse; no new sensor and no packet
  payload. FEATURE_SCHEMA_VERSION is 4, so v3 artifacts are refused at load and every detector
  retrains into v4 rather than being scored on a longer vector it was never fitted on.
- The candidate HDBSCAN matrix now filters its collapsed aggregate with an outer `WHERE`, not a
  `HAVING` whose alias collided with the source column.

## 0.20.9 — 2026-10-24

CANDIDATE SQL ALIAS FIX.

- The deduped candidate subquery filtered on `total_bytes` after aliasing `sum(total_bytes)` to the
  same name; ClickHouse rejected it as an aggregate in WHERE. The filter is now `HAVING
  sum(total_bytes) > 0`, so HDBSCAN sees one row per host-window.

## 0.20.8 — 2026-10-24

CANDIDATE DEDUPE AND CALIBRATION VERDICT.

- The HDBSCAN candidate now collapses fragmented aggregate rows before clustering. The first live
  sample had 5,000 rows but only 327 unique host-windows, so its clusters were measuring duplicate
  insert blocks. Each side table is grouped before the join; additive fields sum.
- Calibration rows carry a factual `verdict` (`within budget`, `over budget`, `insufficient
  samples`) and the Models card names the models within the requested budget. Nothing is promoted
  automatically; the production alert path is unchanged.

## 0.20.7 — 2026-10-24

DETECTION CURSOR TIMEZONE FIX.

- The sweep formatted its aware UTC cursor directly into a comparison against ClickHouse's naive
  local `window_start`. On the live box the cursor sat five hours in the future (23:45Z vs 21:30
  CDT), every sweep matched zero aggregates, and detection stopped while the pod stayed green.
  Format the cursor in the worker's local zone — the same host zone the database uses.

## 0.20.6 — 2026-10-23

MODELS TAB ALIGNED WITH THE ML LAYER.

- The intro now calls the four trained detectors the production ensemble and states that the
  calibration/shadow layer cannot create or change an alert.
- New Shadow ML card reports each channel independently: HDBSCAN candidate rows/clusters,
  Matrix Profile rows/metrics, change-point rows/hosts and calibration rows. A broken channel
  is named as unavailable, never rendered as an empty success.

## 0.20.5 — 2026-10-23

NETFLOW TAP TOOLTIP TRUTH.

- A non-owner NIC's netflow chip no longer carries the owner's scope sentence in its title; the
  title names the active source and stops there. The visible chip remains `netflow`.

## 0.20.4 — 2026-10-23

WEIRLINGS NETFLOW CHIP.

- The NetFlow chip is named `netflow`, not `netflow · sensor feed`; the scope stays in the title.
- An active feed belongs to its own NIC (`NETFLOW_IFACE`): the source NIC carries the measured
  state and every other NIC says which interface owns the probe. Passive/auto remains explicitly
  sensor-scoped, because there is no per-NIC probe to claim.

## 0.20.3 — 2026-10-23

CHANGE-POINT NOISE FIX.

- Page-Hinkley now runs on a z-normalised series and uses a standard-deviation threshold, not an
  absolute 5-unit allowance against raw byte/packet counts. The first live pass wrote 31k shadow
  rows on ordinary jitter; the test still detects a synthetic step and ignores noise.
- Each host/metric records at most five change points per pass; a shadow table is evidence, not a
  log of every sample.

## 0.20.2 — 2026-10-23

HDBSCAN CANDIDATE FIX.

- The candidate read `centers_`, but sklearn stores medoid centres in `medoids_` when
  `store_centers="medoid"`. The first live run found 56 clusters and still reported zero centres,
  leaving the candidate table empty. Read the attribute the requested mode populates and assert
  the regression with a three-blob test.

## 0.20.1 — 2026-10-23

POST-RELEASE CORRECTIONS.

- The severity basis now says when a high-deviation row sits below the score band (`score below
  alert band`, `medium band`) instead of looking like an unexplained downgrade.
- The HDBSCAN shadow challenger falls back to smaller cluster sizes when the live matrix produces
  zero centres, and reports the size it used; zero centres remains an explicit unusable state.
- The historical severity backfill was applied for the seven-day window: 49 critical, 61 high,
  580 medium, 1,122 low; every row carries a basis string.

## 0.20.0 — 2026-10-23

ML TRUTH AND SHADOW CHANNELS.

- Severity now requires independent model families and material evidence. Isolation Forest and
  its Gradient Boosting student are one family; DBSCAN and Adaptive Baseline are separate. A
  critical/high label carries its basis (`severity_basis`) beside the score.
- Calibration: conformal threshold and split-validation false-alarm rate, stored in
  `ml_calibration`/history; Models has a shadow budget readout. No alert path changes.
- Host roles/scope proposals (`host_roles`) and Assets role column, with operator override.
- Shadow channels: HDBSCAN candidate scores, Matrix Profile temporal discords, Page-Hinkley
  change points, all in append-only tables and hourly behind `ML_SHADOW`; ECOD offline benchmark.
- Schema 029–034. Historical severity backfill is explicit and dry-run-first.

## 0.19.27 — 2026-10-23

THE PHONE HOME-SCREEN ICON IS THE MARK, NOT A LETTER TILE.

- iOS ignored the previous touch link's missing size/path convention and generated a "W"
  letter tile. The page now names the conventional `/apple-touch-icon.png` at 180×180 with
  an explicit size and serves it from the static allow-list.
- The launcher icons are the opaque dragon mark, not a transparent crop and not the tiny
  wordmark canvas: transparent strips were being left for the OS to interpret, and the
  wordmark is illegible at launcher size.

## 0.19.26 — 2026-10-23

THE INSTALLED WEB APP WEARS THE LOGO.

- Added `manifest.webmanifest` with the Weirvern name, standalone display and 192/512
  launcher icons derived from the mark; Chrome/Edge installs no longer fall back to a
  generic page thumbnail.
- Added the iOS web-app meta tags and kept the existing 180px apple-touch-icon.
- Added a network-only service worker (`sw.js`). It provides the fetch handler the installed
  shell needs and deliberately caches nothing, so an installed console cannot show stale
  health after a pod dies.

## 0.19.25 — 2026-10-23

THE NETWORK DEDUP AND THE NFS CLIENT PORT.

- Folded edges now carry the protocol, so a merged request/reply edge and its one-sided reply
  half stopped appearing twice after the service fold.
- A curated service port now outranks the broad low-port range: NFS on 2049 with a client
  source port of 978 is a request, not two services.

## 0.19.24 — 2026-10-23

THE NETWORK GRAPH FOLDS CONNECTIONS, NOT DIRECTIONS.

- Grouping by the 5-tuple made direction correct but drew one line per client port. After the
  exact reverse tuples are merged and the direction is decided, connections to the same service
  between the same hosts are folded into one edge. Unknown edges are never folded across a
  reverse observation.
- The graph caption now says "connections", matching what the total counts.

## 0.19.23 — 2026-10-23

THE NETWORK GRAPH SEPARATES SERVICES BEFORE IT DECIDES DIRECTION.

- The graph was grouping every conversation between two hosts into one edge, so SMB on 445,
  DNS on 53 and a reply on 59837 could land in one port list and make the direction
  undecidable. The query now groups by the 5-tuple; only exact reverse tuples merge.
- This also fixes tracked-host graphs, which use the same query shape and merge.
- The total is conversations, not host pairs, and the cap is applied after the merge.

## 0.19.22 — 2026-10-23

THE NETWORK DIRECTION FALLBACK: REGISTERED SERVICES ABOVE THE OLD LINE.

- The previous change used the curated service table alone, which left real services such as
  NNTP on 5563 and Bitcoin on 8333 as `unknown`. The graph now falls back to the client-port
  shape — destination ports all ≥32768 with source ports all <32768 is a reply shape — and
  records that evidence as `ephemeral-shape`, not as a proven service port.
- A one-sided reply remains oriented client → server, with the service port on the destination
  and the client's source port on the source card.

## 0.19.21 — 2026-10-23

THE NETWORK MAP USES THE SAME DIRECTION EVIDENCE AS FLOWS.

- The graph's direction test now calls `soc._is_service_port` — system ports plus the curated
  service list — instead of treating every port below 32768 as a service. IANA's user range
  (1024–49151) is not ephemeral; 32768 is only the usual Linux ephemeral start.
- A one-sided reply (`server:service -> client:ephemeral`) is re-oriented `client -> server`.
  The service port belongs on the destination; the client's source port stays on the source.
  The detail states that the request half was not captured, rather than drawing it backwards.
- Tracked-host graphs use the same merge and orientation, so filtering does not change an
  arrow. The direction evidence and confidence ride the edge payload.

## 0.19.20 — 2026-10-23

THE WEIRLINGS ROW NAMES THE NETFLOW FEED.

- The feed chip read `sensor feed` for NetFlow, hiding the feed's name. It now reads
  `netflow · sensor feed`: the indicator is visible, and the scope still says the hub sees one
  sensor-wide feed rather than a per-NIC measurement. Observed/not-observed, last-at and the
  reason remain in the title and the `on`/`off` state.

## 0.19.19 — 2026-10-23

THE PRE-COMPLETION SWEEP: THE LAST PHONE FIELDS.

- Assets' lookup/sort/scope fields, the DNS filter fields and Discover's selectors now take the
  44px phone height. The connection graph's minimum-edges field and show-names box already did.
- This is the final mechanical touch pass; the remaining sub-44px items are the icon-sized pager
  arrows (42px wide, 44px tall), which stay at the button system's base width rather than
  inventing a second button size.

## 0.19.18 — 2026-10-23

THE PRE-COMPLETION SWEEP, CONTINUED: TABLET TARGETS AND ONE BOOT FETCH.

- A row's disclosure now meets the 36px secondary floor in both dimensions at tablet widths.
  Filter chips get the 44px phone height, covering DNS and Discover facets as well as Network.
- A deep-linked boot no longer fetches the selected view twice: `applyURLState()` has already
  started the view loader, so the boot refresh now loads the shared health/status data and skips
  the duplicate view request. This takes Weirlings from 16 API reads to the low teens on load.

## 0.19.17 — 2026-10-23

THE REST OF THE FIRST SWEEP.

- The Network minimum-edges field and show-names checkbox now meet 44px on a phone; the pager
  arrows meet the 44px width floor at 320/390.
- The anomaly queue defaults to 90 rows so its first paint stays under the 6000-DOM budget; the
  operator can still type a larger limit.
- `#v=identity` and bare `#v=host` aliases now actually retarget to Assets. The retarget variable
  is `let`; as `const` the assignment threw and the boot fell back to Health, so the old links
  never moved.

## 0.19.16 — 2026-10-23

THE PRE-COMPLETION SWEEP: LESS PER-ROW FURNITURE, NO CLIPPED HOSTS, TOUCH-SIZED FILTERS.

- Anomaly rows had **two** per-row controls at rest: the `evidence ›` button in the Why cell and
  the disclosure that already contains Evidence, Block, Watch and Tune. The duplicate button is
  gone; Evidence lives in the one disclosure, and the row itself still opens the evidence page.
- The Host cell no longer clips a long name/address behind an ellipsis with no way to read it; it
  wraps, while the table keeps its horizontal scroll.
- Phone-width anomaly filters, the Weirlings view selector/revoked box and the header auto-refresh
  checkbox now meet the 44px touch target (the audit measured 13–31px).
- Weirlings' flow trend and sparkline carry an `aria-label` as well as a title, so the meaning is
  not hover-only.
- `#v=identity` and bare `#v=host` aliases now land on Assets instead of silently leaving Health
  active under a stale URL.

## 0.19.15 — 2026-10-23

THE NETWORK STATUS FILTER IS ITS OWN COLOUR KEY.

- Blocked and Alerted buttons carry the same red/amber swatch as the nodes and edges they
  filter. The legend moved above the canvas: at a 900px viewport the graph pushed the legend
  below the fold, and a key nobody scrolls to is not a key.

## 0.19.14 — 2026-10-23

THE NETWORK MAP SHOWS WHICH HOSTS ARE BLOCKED, WHICH ARE ALERTED, AND WHY.

- The graph payload now carries each host's `blocked` / `alerted` status, its reasons, and the
  status of both ends of every edge. Blocked means a live Sluice block rule names the host as a
  source/destination CIDR or through a domain rule's currently-resolved address. Alerted means
  the host has an anomaly window in the graph's range. These are separate facts; a host can be
  both, and the detail says so.
- The map colours blocked hosts and their edges red, alerted hosts and their edges amber, and
  adds a legend for both. Normal and tracked hosts keep their existing blue/green treatment.
- `All` / `Blocked` / `Alerted` buttons filter the graph from the cached payload. A status
  reading keeps the flagged hosts' direct peers as context, names the counts in the caption, and
  gives an explicit empty state when no host matches.
- Connection detail now names both endpoint statuses and the rule/anomaly evidence. A status
  source that cannot be read is `status_available: false` with a reason; it never renders as a
  normal-looking map.

## 0.19.13 — 2026-10-23

THE GATE'S DROP COUNTERS SURVIVE ITS OWN RE-ARM.

- `arm()` deletes and recreates the nft tables every pass, so the kernel counters start at zero
  immediately after each arm. The supervisor read them only after arming and therefore reported
  `0 packets blocked` forever — while live nft counters showed traffic being dropped. Measured
  on the `sabnzbd.home` rule: 34 packets / 2,040 bytes dropped on eth2, dashboard 0.
- The supervisor now reads the counters before the re-arm, carries the monotonic total, and
  reads again after arming. A failed arm leaves the table in place and is not counted twice.
- `disarm()` also reads the final counters before deleting the tables, so turning the gate off
  does not erase the evidence of what it blocked. The Blocked and Sluice summaries now show the
  real packet/byte counts.

## 0.19.12 — 2026-10-22

ONE BACK CONTROL, IN ONE PLACE.

- Evidence and Host now both lead with the same quiet back button at the LEFT edge of the
  header, before the title. Evidence used to put it at the right; the two drill pages looked like
  two different products even after the blue crumb was removed.
- The Host button names its origin too (`Back to alerts`, `Back to evidence`, `Back to assets`),
  so a Host page opened from an evidence page no longer says just `Back`.

## 0.19.11 — 2026-10-22

ONE BACK CONTROL ON A DRILL PAGE.

- Evidence had two exits in two visual languages: a blue underlined `Anomalies` crumb at the
  top and a quiet `Back to alerts` button at the right. The crumb is gone; the labeled button
  is the only exit and it also appears on a fresh evidence deep link.
- The Host page had the same duplicate crumb and button; it now uses its existing `Back` button,
  labelled with the destination (`Back to alerts` / `Back to assets`) and still restoring the
  origin's filters and scroll.
- Crumbs that remain on Blocked and the Weirlings detail are quiet outline buttons, not blue
  hyperlinks; the current segment stays plain text. No navigation control changes colour or
  shape just because it is a breadcrumb.

## 0.19.10 — 2026-10-22

THE LOGS TAB READS AS ONE AUDIT SURFACE, NOT THREE UNRELATED TABLES.

- Alert audit: the one-row outcome summary and the event list now stack instead of sitting in
  two columns, which left a large dead area beside the 15-row list. Single-page pagers are
  hidden; the audit's severity now uses the shared glyph + word + colour ramp instead of an
  unstyled `sev low` span, and an empty detail cell says `—` rather than rendering blank.
- Setting changes: the 50-entry trail is a bounded scroll with a sticky header, so it no longer
  makes the Logs tab two thousand pixels tall. Phone filter selects get the 44px touch target.
- The audit's own pager hides when there is only one page; the remaining pager keeps its range.

## 0.19.9 — 2026-10-22

THE DETECTION POLICY CARD IS NOT EMPTY WHEN THERE ARE NO RULES.

- `renderSluicePolicies()` ran after the rules loop. The empty-rules branch returns before that
  loop, so a fresh store or a fully revoked one left "Blocking on detections" blank and the
  current-policy note empty. The policy is a trust setting, not a property of the rows; it now
  renders before either branch.
- jsdom pins four policy rows and the `Current policy: high` note with `rules: []`.
- Flows now join a page of NetFlow records to Zeek's `conn.log` on the exact 5-tuple in either
  orientation, using the nearest timestamp within 300s. A match is `zeek-conn` evidence and
  outranks the service-port inference; a missing match leaves the old evidence untouched.
- The direction cell shows `→ request`, `← reply`, or `· unknown`; the arrow appears only where
  the evidence supports it. The Flows row detail names the Zeek evidence.

## 0.19.8 — 2026-10-22

THE PALETTE OBEYS THE SHEET CONTRACT, AND IDENTITY STOPS PRETENDING TO BE WINDOWED.

- The quick-links palette now captures the opener when it opens, restores focus when it closes,
  and traps Tab/Shift+Tab inside the overlay (issue #64). Escape, the backdrop, and a command
  that navigates all use the same close path. jsdom pins opener focus, Tab containment and the
  navigating-command case; a mutation removing either guarantee turns its checks red.
- Identity is a current snapshot, not a windowed read (issue #63). The client no longer sends
  `hours` (the route discards it), both callers use `/api/identity`, and the payload states
  `snapshot`, `window_independent`, and its seven-day observation window. The Identity card
  names the snapshot in its heading and coverage copy; the global time control says the Identity
  snapshot is the exception.

## 0.19.7 — 2026-10-22

THE FLEET SHOWS THE CONFIGURED CAPTURE PORT WHEN THE HEARTBEAT CANNOT SEE IT.

- The local hub's worker runs in a pod network namespace: its heartbeat can report only the pod's
  `eth0` while the host capture port is `eth1`. The NIC table was built from the reported list
  alone, so filtering management `eth0` left no rows and the Fleet tab showed headers with no
  interfaces.
- The table now adds the configured capture interface (`plan.iface` or the sensor's `iface`) when
  the heartbeat did not report it. That row is explicitly `configured, not reported`, has no mode
  claim, and still carries its known segment, sensor-scoped flow trend and feeds. A reported NIC
  is unchanged.

## 0.19.6 — 2026-10-22

SLUICE GATE SHOWS THE STATE IT ACTUALLY HAS.

- A stale gate now says `stale` on its state line and on its fleet row, and the server's warning is
  visible text instead of a hover title. "Degraded" is no longer allowed to stand in for "this
  gate stopped reporting and its counters are historical".
- Gate overview and Blocks now share the selected time window. The old "recent hits" was an
  unbounded latest-50 read: five six-day-old hits beside a Blocks view that correctly showed zero
  in 24h. The chip names the window it counted.
- The rules empty state names hidden revoked rules and says Domain blocking is a separate gate,
  instead of denying that any blocking exists while the Domain Gate is on.
- The rule composer starts with the rule's unit — Domain or Address — names the gate that will
  enforce it, hides the fields that do not apply, and never sends a hidden target field. The
  blocking confirmation names the target, gate and duration, expires after five seconds, and
  disarms on any field edit; domain rules say DNS, not kernel drop.
- "Arm the gate" is disabled with a visible reason when there is no nft backend or no rule to
  enforce; a stale state alone does not forbid a real repair.
- A fresh `#v=blocked` load opens Blocks with the Sluice tab lit, and the tab's filter checkboxes
  are full 44px touch targets on phones.

## 0.19.5 — 2026-10-22

HEALTH EXPLAINS CAPACITY — AND NETFLOW SAYS IT IS SENSOR-WIDE.

- The Health System card now shows a capacity bar and used/total for memory, CPU cores and
  1/5/15m load per core, per-core bars, available memory and swap, uptime, running/blocked
  tasks, physical-network throughput with drops/errors, and whole-disk read/write. A missing
  reading is a dash with its reason, never a zero.
- `/api/system` now names its scope. This deployment reads the kernel host's procfs (the
  container cannot see the sensor LXC's 10 GiB boundary), and the card says exactly that
  instead of presenting 40 GiB of kernel memory as "the sensor". HOST_PROC, when a deployment
  mounts a real boundary, is named as the configured boundary.
- NetFlow evidence is explicitly `scope=sensor`. The NIC lines render `sensor feed` with the
  reason, instead of repeating a chip that implied every NIC owned a local probe.

## 0.19.4 — 2026-10-22

TRUNK OBSERVATION SURVIVES VLAN OFFLOAD — AND A SYNTHETIC TRUNK PROVES IT.

- The packet reader now enables PACKET_AUXDATA and reinserts a VLAN tag the NIC (or a veth)
  stripped into skb metadata. Measured on a synthetic trunk: without this, three tagged VLANs
  arrived as untagged frames and the adapter called the port an access port.
- The trunk manager ignores frames whose source MAC is the parent port itself. Its own VLAN
  devices inherit that MAC, and their IPv6 neighbour discovery is emitted tagged on the parent;
  counting it kept the port classified as a trunk forever and blocked the return to access.
- `scripts/synthetic-trunk-test.sh` builds a veth trunk, sends 802.1Q frames for VLANs 10/20/30,
  asserts the VLAN devices exist, runs a capture probe on one, then removes the tags and asserts
  the devices are removed. It needs root but touches no existing NIC; it removes everything on
  exit.

## 0.19.3 — 2026-10-22

MTLS IS THE WHOLE REMOTE PATH — AND A BAD HEARTBEAT IS A 400, NOT A DROPPED CONNECTION.

- Verified live: enrollment (201), plan, heartbeat, flows and gate routes all return 200 with
  an enrolled client certificate; every data route returns 401 without one. The server chain
  verifies to the root and TLS 1.3 is in use.
- The gateway now checks heartbeat field names against the fields `status.heartbeat` accepts.
  A stray field used to raise TypeError inside the request thread and close the connection
  with no response; it now returns `400 unknown heartbeat field(s): ...`.
- Corrected the module docstring: the sensor agent uses the gateway whenever
  `WEIRLING_GATEWAY_URL` is set; direct ClickHouse is the explicit `--legacy-clickhouse` path.

## 0.19.2 — 2026-10-22

INLINE IS A TOPOLOGY, NOT A TOGGLE.

- Weirling registrations carry an explicit `topology` (`capture` default, `inline`). It is a
  declaration, never inferred from a mode or heartbeat; old rows read `capture`.
- `scripts/weirling-inline.sh` creates/tears down a reviewed two-NIC transparent bridge with
  `dry-run|create|status|teardown`. It refuses the management/default-route port, address-bearing
  ports, and never deletes a bridge it did not create.
- `deploy-weirling.sh --inline` validates an EXISTING bridge with exactly two enslaved ports and
  refuses `--gate` on it; `--no-trunk` disables the VLAN probe for a bridge. The deploy helper
  does not rewire a host silently.
- The fleet payload/detail header now shows the declared topology.

## 0.19.1 — 2026-10-22

REMOTE CAPTURE-LIVENESS TEST.

- A remote weirling can now be asked for a bounded, READ-ONLY capture probe. The hub queues it
  over mTLS; the sensor's own agent reads its NIC counters and its Zeek conn-log growth for the
  window and posts the evidence back. No mode, plan, interface or sysctl is written.
- `observed:false` is a valid measurement (silent mirror/segment), not a failed test; a probe
  that cannot read its inputs says why in `error`.
- The Weirlings sheet has **Test capture (30s)** beside Sonar. It measures the named NIC, not
  the hub's. In-path/ARP testing remains a separate capability and is not served by this route.
- New schema: `027_weirling_probe.sql`.
- The sheet waits 90 seconds for a result: a sensor may need one 30-second plan poll before it
  claims the request, then the 30-second measurement itself.

## 0.18.1 — 2026-10-22

REMOTE HOST TELEMETRY.

- A sensor heartbeat now carries a compact host reading (CPU, memory, proc boundary) in
  `sensor_status.host_stats`. Remote weirlings show their own CPU and memory in the fleet
  row instead of a dash, and an unmeasured value still renders as a dash rather than 0%.
- The schema migration is `026_sensor_host_stats.sql`.

## 0.18.0 — 2026-10-22

TRUNK BY DEFAULT; THE REMOTE SENSOR GROWS UP.

- A sensor observes its capture port before capture starts. No 802.1Q tags means the parent
  port is captured; tags mean one host VLAN device per tag (`eth1.10`, `eth1.20`) and one
  Zeek per VLAN. There is no trunk/access mode to choose. The state lives on the node and
  moving the cable back to an access port removes the devices the manager created.
- Remote weirlings ship parsed Zeek/DNS/HTTP/TLS/conn records through the authenticated
  gateway (`/v1/zeek`), mapped by the hub's own `ZEEK_MAPPERS`. They also renew certificates
  inside the 30-day window and stop an in-path intercept on a revoked identity (403) rather
  than preserving it as a transient read failure.
- **mTLS is the default edge.** The hub installer creates the root/intermediate/server
  certificates and applies the ingest gateway before anything else; `deploy-weirling.sh`
  adopts every new unit over mTLS without an operator certificate decision. The old
  per-sensor ClickHouse credential is available only through `--legacy-clickhouse`.
- The remote agent now carries `NET_ADMIN` as well as `NET_RAW`, so an adopted unit can run
  an in-path plan rather than only reporting the refusal.
- The remaining gaps are documented in `docs/weirling-remote-gaps.md`: remote resolver
  blocking, host telemetry, the remote test run, install-time NetFlow/capture changes,
  hub-driven updates, and remote domain-hit records.
- Trunk design and limits: `docs/design/trunk-default.md`.

## 0.17.89 — 2026-10-22

FLOWS SAY WHICH HALF THEY ARE.

- The Flows table now has a **direction** column and every row says `request`, `reply`, or
  `unknown`. The detail panel names the opener and the evidence behind the claim.
- Direction is classified from the strongest available evidence: a bare TCP SYN or SYN-ACK in
  the record, a handshake in the reverse 5-tuple, then service ports. Cumulative TCP flags are
  not treated as handshakes; port-only classification is labelled an inference; flows with no
  evidence are left `unknown` instead of being reversed.
- The reverse-half lookup is one bounded query for the page. Its failure does not fail the page.
- Rationale and limits are in `docs/design/flow-direction.md`.

## 0.17.88 — 2026-10-22

SETTINGS FINDS ITS FRONT DOOR.

- Removed the redundant opening card and gave Settings the same view-header treatment as
  the rest of the console: title, version, a **Find** control, **Expand all**, **Collapse
  all**, and a **Review pending** jump that appears only while changes are staged.
- Grouped the card stack under **Access and security**, **Detection**, **Operations**, and
  **Changes**. The one pending-changes card is sticky on wide screens and static on phones.
- No settings value, write route, apply semantic, account control or blocklist behavior
  changed. The audit notes live in `docs/design/settings-audit.md`.
- Gateway JSON responses now serialize datetimes (the remote gate state carries
  `updated_at`), and the mTLS remote-gate/rules boundary is documented.

## 0.17.87 — 2026-10-22

REMOTE TRAFFIC GATES OVER mTLS.

- The Sluice gate's rule/state store now has a gateway-backed adapter. A remote gate
  fetches the live rule set (including resolved domain addresses) and writes its state
  through `/v1/gate/rules`, `/v1/gate/state` and `/v1/gate/events`; it never needs a
  ClickHouse credential. The compiler, supervisor and safety checks remain the hub's
  own, and a remote gate still never derives rules.
- `WEIRVERN_ROLE=gate` checks the gateway environment before opening ClickHouse; the
  legacy direct-ClickHouse gate path is unchanged.
- The gate container runs as root with NET_ADMIN because Docker does not grant an
  effective capability to a non-root UID.
- Domain rules are enforced as resolved-address packet drops on the remote gate. This
  is not DNS-answer blocking; the resolver remains a hub-side action.

## 0.17.86 — 2026-10-22

SONAR REACHES THE REMOTE SENSOR.

- The Weirlings "Sonar for this weirling" action now queues a durable survey request in
  `weirling_sonar_requests` instead of creating a hub-side Job. The remote agent claims
  it over mTLS, runs `sonar.survey()` on its own capture interface with NET_RAW, and
  posts the measured result back; the hub route waits and returns it stamped with the
  sensor id.
- A legacy direct-ClickHouse sensor has no queue poller. It now times out with an
  explicit explanation rather than returning a survey of a hub interface with the same
  name.
- The remote agent container gains NET_RAW (the same capability the capture container
  already has) so the ARP survey can run on the sensor's network namespace. In mTLS
  mode it runs as root because Docker does not grant an effective NET_RAW capability
  to a non-root UID; the certificate directory is root-owned in that mode.
- Schema 022 adds the request/result handoff with a one-day TTL.

## 0.17.85 — 2026-10-22

WEIRLING ADOPTION REACHES THE SENSOR.

- New `weirvern.weirling_client`: generates the sensor's P-256 key and CSR locally, redeems
  a one-time token over HTTPS, writes the leaf+intermediate chain and root, and exposes the
  authenticated heartbeat, plan and flow calls.
- `weirvern.admin.sensor_agent` now has an opt-in gateway mode (`WEIRLING_GATEWAY_URL` plus
  certificate paths). It reports heartbeat/plan/flows over mTLS and never falls back to a
  database credential when the gateway is configured. Units without these variables keep
  the existing ClickHouse path unchanged.
- `scripts/deploy-weirling.sh --mtls` obtains a token (or accepts `--mtls-token`), enrolls
  the target, writes only certificates under `/etc/weirvern-weirling`, and starts the agent
  in gateway mode. The default direct-ClickHouse install is untouched.

## 0.17.84 — 2026-10-22

ANOMALIES: THE COUNT IS THE COUNT.

- Removed the occurrence trend line beneath the anomaly count column. The count, the
  click-to-list occurrence interaction, the review/severity/model cells and every other
  surface are unchanged. The explanation no longer promises a line that is not there.

## 0.17.83 — 2026-10-22

WEIRLING TRUST: mTLS ENROLLMENT AND A HUB INGEST GATEWAY.

- A separate **Weirling Intermediate CA** under the Weirvern root signs sensor client
  certificates; the console certificate issuer is unchanged. Sensor keys and CSRs are
  generated on the sensor; the private key never reaches the hub.
- New `weirvern.weirling_gateway` service: one-time token enrollment, URI-SAN
  (`spiffe://weirvern/sensor/<id>`) identity, plan delivery, heartbeat and flow ingest,
  and certificate renewal. It writes ClickHouse with hub credentials and rejects
  unknown, disabled and revoked sensors.
- `weirvern weirlings token` issues a one-time, hashed, expiring adoption token. The
  token is the operator's declaration and is consumed by the first successful enrollment.
- `k8s/mtls` deploys the gateway on NodePort 30443 behind a server certificate issued by
  the Weirling intermediate. It is deliberately separate from the console TLS overlay.
- The existing `sensor_agent` direct-ClickHouse path is unchanged in this release; moving
  it onto the gateway is the migration boundary, so an existing sensor cannot change
  behavior silently.

## 0.17.82 — 2026-10-22

WEIRVERN ISSUES ITS OWN CERTIFICATES: THE CONSOLE NOW HAS A LOCAL HTTPS 443 EDGE.

- A local two-tier PKI: the **Weirvern Local Root CA** signs an intermediate, and
  cert-manager issues a 90-day `weirvern-gui` leaf from that intermediate. The root key
  stays off-cluster; only the intermediate is in a Secret, and cert-manager renews the leaf
  30 days before expiry.
- `k8s/tls` adds the Traefik TLS Ingress for `sensor.example`, a redirect-only HTTP Ingress,
  and a `ClusterIP` GUI Service. The base NodePort 30088 remains only as a break-glass path
  and is removed from the user path by the overlay.
- The app now redirects HTTP to HTTPS when the ingress says `X-Forwarded-Proto: http`, and
  emits HSTS only when the ingress says `https`; a direct port-forward is not mislabelled.
- The sign-in gate and the operator-token note now state the HTTPS path and the one-time
  root trust step instead of telling users passwords cross the network in clear text.
- Local certificate setup and verification are documented in `k8s/tls/README.md`.

## 0.17.81 — 2026-10-21

THE OPEN GITHUB BATCH: THE QUEUE HONOURS THE RANGE, THE FLEET NAMES ITS STATE, AXES
USE SI MAGNITUDES.

- GitHub #54: `/api/anomalies` now receives and applies the global time range. Rows, the
  severity tiles, the fired/acted line and the "of Y" total all answer the same window; an
  absolute range still wins through the existing timewindow context.
- GitHub #56: every fleet row carries the state word (`alive`, `stale`, `never seen`,
  `unregistered`, `disabled`) beside the sensor name, not only as a border colour. The
  never-seen summary TILE and saved VIEW remain removed.
- GitHub #57: timeline Y axes use one SI formatter (`1k`, `10k`, `100k`, `1M`, `10M`, `100M`,
  `1G`), so a byte series no longer prints `100000k`. Values and legends keep `fmtBytes`.
- #51 is resolved by removal (no raw byte tile remains); #55 is measured fixed (the header
  stays one row at 1280 and the tab strip scrolls at 1024). The rest of the open issue batch
  is verified fixed in the tree by the tests named on its kanban cards.

## 0.17.80 — 2026-10-21

THE COUNT STANDS ALONE; THE TREND IS A DOTTED LINE BENEATH IT.

- The count column no longer carries a "trend" label that crowded the next header. `count` is
  the number of distinct windows. The dotted blue line below it is the occurrence timing — one
  line, inside the count cell, with no second metric beside the host.

## 0.17.79 — 2026-10-21

THE TREND READS THE WINDOW OBJECTS THE REVIEW MERGE ACTUALLY SENDS.

- 0.17.78 fixed the range but still parsed each `windows` entry as a bare ISO string. By render
  time the review merge has turned every entry into `{window, review_state, ...}`, so
  `new Date(object)` was Invalid Date and every trend stayed empty beside a real count. Both
  shapes are accepted now.

## 0.17.78 — 2026-10-21

THE TREND KEEPS THE WINDOWS THE TABLE ACTUALLY RETURNED.

- Live verification found the blue occurrence line empty on recent rows: the table's timestamps
  can sit ahead of the browser clock (server timezone offset), and the trend filtered them out
  as future. The selected range still leads; the occurrence span now widens just enough to
  include every window in the payload. A count of 2 can no longer draw a blank line.

## 0.17.77 — 2026-10-21

THE ANOMALY COUNT FOLDS THE VISIBLE VERDICT, NOT ITS LAST DECIMAL.

- 0.17.76 removed `detected_at` from the group key, but still grouped every detector score,
  confidence and per-feature z value. Two windows the operator saw as identical differed only by
  a 0.0005 model score, so the count stayed 1. The group key is now what the row displays --
  host, score, severity, models, primary feature, why -- and the per-model detail is carried as
  MAX for display. Counts rise for the same visible verdict; a re-seen window still cannot
  inflate them.

## 0.17.76 — 2026-10-21

SLUICE OWNS THE GATE; BLOCKS IS ITS DRILL, AND ANOMALY COUNTS ACCUMULATE.

- The Blocked tab is gone. Sluice Gate is the one enforcement surface; its Gate overview carries
  one `View blocks` control, the Sluice tab stays lit on the Blocks drill, and `#v=blocked`
  remains a compatible URL with a visible crumb back.
- Blocks no longer carries a second rule editor or the duplicate `Blocking now` / `Alerting`
  rule tables. It is the recorded-block ledger: a row opens a detail card with the hit, the
  matching rule, the reason, the mode and the action actually taken. A hit's rule chip opens
  the existing Sluice rule sheet.
- Anomalies group by the stable verdict, not by `detected_at`. Two sweeps of the same
  host/score/models/why now produce ONE row whose count is the number of distinct windows; a
  re-seen window cannot inflate it. The count cell carries a blue occurrence sparkline showing
  when those windows happened in the selected range. Clicking the count still expands every
  occurrence.

## 0.17.75 — 2026-10-21

THE ATT&CK SECTION IS ALWAYS ON THE EVIDENCE PAGE.

- The evidence page drew nothing when no network-observable technique matched. That is
  indistinguishable from a page that does not show ATT&CK at all — the operator reported
  "I am not seeing mitre attack frame work when I select an anomaly." The section is now
  stable: mapped techniques render with their evidence, confidence and network visibility;
  no match renders an explicit sentence saying the mapping found nothing and that this is
  not a benign verdict.
- The empty state is pinned in the test suite and the jsdom harness, so a future cleanup
  cannot turn the section back into a conditional extra.

## 0.17.74 — 2026-10-20

THE GRAPH IS CENTRED BY ITS BOX, NOT ITS BUSIEST HUB.

- A few high-degree hubs pull the mean to one side; recentring the settled force map by its
  bounding box removes the empty third of the panel that the mean left behind. The independent
  X/Y fit from 0.17.73 now starts from a centred cloud.

## 0.17.73 — 2026-10-20

THE FRONT PAGE IS A PRODUCT PAGE, AND THE GRAPH USES ITS FULL WIDTH.

- README is now a product page: hero, badges, real console screenshots, a concise feature
  summary, a Mermaid pipeline diagram, the three deployment shapes, quick start, trust notes
  and the documentation index. The old 200-line architecture essay is reduced to the places
  a new reader needs first; the detail remains in docs/.
- Added `docs/screenshots/anomalies.png` and `docs/screenshots/network.png`, captured from the
  shipping console against synthetic RFC 5737 data. No private addresses are in the images.
- The connection graph fits X and Y independently instead of one shared scale, so a circular
  force cloud uses the wide tile rather than occupying only its centre.

## 0.17.72 — 2026-10-20

THE LOCAL WEIRLING'S FLOW FILTER VALUE IS THE ONE NETFLOW USES.

- DNS and Zeek payloads carried the local weirling as `0.0.0.0` because every loopback spelling
  mapped to the same name. Selecting it and switching back to NetFlow produced zero rows: the
  NetFlow facet uses `127.0.0.1`. The local facet now prefers `127.0.0.1`, and the hub's row
  sorts first.

## 0.17.71 — 2026-10-20

BROWSER BACK/FORWARD, AND A WEIRLING FILTER ON EVERY FLOW FEED.

- View changes now push a browser history entry; filter and time-range edits replace it. The
  Back and Forward buttons restore the page, its evidence drill, its filters and its time
  range. `popstate` and hash edits both restore through the same URL state reader.
- The Flows tab's weirling selector now appears for DNS and Zeek as well as NetFlow. The hub's
  own weirling returns its DNS/Zeek records; another registered weirling returns an explicit
  empty reason ("captured by the hub's Zeek") instead of silently showing the hub's rows.
- DNS and Zeek payloads now carry a weirlings facet, so the selector is populated without
  visiting NetFlow first.

## 0.17.70 — 2026-10-20

ACKNOWLEDGE AND IGNORE BESIDE BLOCK; THE GRAPH USES THE WHOLE TILE.

- The evidence page's verdict now carries **Acknowledge**, **Resolve** and **Ignore** beside
  Block. They use the existing review API and refresh the evidence page after the write, so
  the ruling changes where the operator is reading instead of only in the anomalies table.
- Review button labels are words now: Acknowledge, Resolve, Ignore. The anomaly table keeps
  its disclosure layout, but the same three dispositions.
- The connection graph clamps to an **ellipse**, not a rectangle. The old square boundary put
  every outer host on one of four walls; the ellipse scales to the widest normalised radius
  and keeps a 34px node/label margin. The tile height is responsive
  (`clamp(420px, 62vh, 760px)`; `clamp(320px, 52vh, 480px)` on phone) so it uses the space it
  is given.
- The evidence Block action still opens the Sluice rule sheet from 0.17.69 (source/reason
  prefilled, all rule fields editable).

## 0.17.69 — 2026-10-20

AN ALERT'S BLOCK ACTION OPENS THE SLUICE RULE SHEET.

- On the evidence page, Block… now opens the same rule sheet the Sluice Gate uses, prefilled
  with the alert's source and its score/window reason. Destination, direction, protocol,
  port and duration are all editable there; the alert path no longer grows a second, weaker
  inline form.
- The anomalies table keeps its compact inline form so row triage does not change; the
  evidence pivot is the full composer. The composer still asks for the second click before a
  block rule is filed.
- Harness 869 checks; the evidence job now asserts the sheet opens with the source and files
  the rule through the composer.

## 0.17.68 — 2026-10-20

EVERY ALERTING DECISION IS AT THE TOP OF LOGS.

- The alert audit moved from Health to the top of the Logs tab. It still carries sent,
  suppressed (cooldown/cap), and log-only decisions, with the same outcome counts and paged
  event table; Logs loads the deep-health payload directly so the audit is never blank because
  Health was not visited first.
- The blocklist tier migration now converts the stored `fetched_at` ISO text back to a datetime
  before inserting; the 0.17.67 seed failed on the live box with `'str' object has no attribute
  'timestamp'`. Five tiers will seed on the worker's next pass.
- The system-card VM-boundary experiment was reverted after its 10 GiB pod limit prevented the
  GUI from starting; the System card remains on the existing host reading until its own card is
  implemented. The GUI is back on the 512 MiB limit and running.

## 0.17.67 — 2026-10-20

FIVE HAGEZI TIERS, A FORMAT-AWARE ADD FORM, A BIGGER NETWORK CANVAS, AND REVOKED OFF.

- The blocklist preload now carries the five Multi tiers — LIGHT (hand brush: basic), NORMAL
  (broom: all-round), PRO (big broom: extended, recommended), PRO++ (sweeper: advanced), and
  ULTIMATE (ultimate sweeper: maximum). They build on each other, so enabling one turns the
  other four off; exactly one tier is active. Each uses the portable one-domain-per-line
  `wildcard/*-onlydomains.txt` file. Existing Light/Pro rows are migrated to that format
  without changing the operator's on/off state.
- The Settings blocklist card now has an add-list form: URL, optional name, and an explicit
  format. The help text requires one domain per line (wildcards normalized), and also accepts
  hosts and dnsmasq; Adblock and RPZ are refused by name instead of importing zero domains.
- The Network connection graph gets a taller canvas (620px desktop, 380px at the phone
  breakpoint), 40px plot insets, and a 34px node/label boundary; nodes no longer sit on the
  frame or clip their labels at the top.
- The quick alert block form now exposes **source**, **destination**, **direction**,
  protocol and port as explicit fields, with the blast-radius sentence naming both ends. This
  is the same rule contract the full composer already used; the alert shortcut no longer
  hard-codes "all traffic from this host".
- Revoked registrations are opt-in again: the include-revoked box starts unchecked, so the
  Weirlings list shows the active fleet by default.

## 0.17.66 — 2026-10-20

THE SYSTEM CARDS REPORT THE SENSOR'S BOUNDARY, NOT THE KERNEL'S BIGGER VIEW.

- `proc_root()` preferred the candidate with the largest `MemTotal`. On this box the pod's
  `/proc` reports the 40 GiB kernel view, while the sensor is a 10 GiB LXC; `/host-proc` as a
  directory reported the 512 MiB pod limit. The cards therefore showed the wrong machine.
- The GUI now mounts `/proc/meminfo` and `/proc/stat` as host FILES into `/host-proc`, sets
  `HOST_PROC=/host-proc`, and the reader treats a configured boundary as authoritative. The
  live sample reports `MemTotal 10,485,760 kB` and 4 CPUs — the sensor's own allocation.
- Size comparison remains only the fallback when no configured procfs is readable.

## 0.17.65 — 2026-10-20

THE LOCAL EXPORTER IS LOOPBACK, AND THE PLAN OWNS THE CAPTURE PORTS.

- The fleet's flow evidence queried the sensor's heartbeat address first. Once the hub was
  registered with its management address, it looked for `192.0.2.176` while every row in
  ClickHouse came from `127.0.0.1`: `netflow observed=false`, `flows=0`, no trend — beside a
  Netflow tab full of flows. The local row now queries loopback (and its address, if present);
  a remote row still queries only its own address.
- The per-NIC settings sheet read the legacy `ZEEK_IFACES` list while the fleet row read the
  per-NIC plan. Opening an unassigned NIC showed "capture / Zeek on" next to a row that said
  unassigned. The sheet now uses the plan whenever a plan exists; the legacy list is the
  fallback only when there is no plan.
- Applying `INTERCEPT_PLANS` now reconciles `ZEEK_IFACES` to the plan's capture plus siphon
  ports, and moves `CAPTURE_IFACE` to a plan port when the old one is not in it. Zeek no longer
  sniffs a port the plan leaves unassigned, and Settings and the fleet row read one authority.

## 0.17.64 — 2026-10-20

REVOKED REGISTRATIONS ARE INCLUDED BY DEFAULT.

- The Weirlings table's **include revoked** box starts checked, so an operator opening the tab
  sees the registration history without discovering a filter first. It remains a checkbox: the
  active fleet is still the primary list; revoked rows sit below it and are visually muted.
- A revoked row now spans all seven columns (first cell + `colspan=6`). It previously used a
  five-column span, so it stopped one column short and drifted under the wrong header.

## 0.17.63 — 2026-10-20

THE MANAGEMENT ADDRESS IS NEVER AN INTERCEPT TARGET, EVEN ON ITS OWN SUBNET.

- `never_intercept_hits` knew the management address only from `MGMT_ADDR`. The documented
  deployment shape sets `MGMT_IFACE` alone, so a whole-segment siphon whose subnet contains the
  box's management address could forge that mapping — the exact conflict that can cut off the
  console while the sensor is still relaying.
- The management interface's IPv4 addresses are now read from the kernel (`ip -4 addr`) and
  added to the never-intercept set, alongside the resolver, API server, own address and gateway.
  A named target still refuses with the role named; a whole-segment sweep excludes it and logs
  the exclusion.
- The NIC row also falls back to the page's staged `INTERFACE_NETWORKS` value for its label, so
  `eth2=Data` survives a list payload built before the setting was applied.
- Regression test covers `MGMT_IFACE` with no `MGMT_ADDR`; the live shape is 203.0.113.176 on
  eth0 inside a monitored 203.0.113.0/24.

## 0.17.62 — 2026-10-20

NETWORKS REPLACES PROBLEMS, AND EVERY NIC LINE KEEPS ITS FLOW AND FEEDS.

- The Weirlings summary's **Problems** tile is replaced by **Networks**, counting the distinct
  non-empty segments the fleet has a plan or a report for. Two NICs on the same subnet count
  once; a blank plan is not a network. It is a coverage count, not a filter, so it is shown
  without the worklist state controls.
- The flow trend and both feed indicators were gated on `capture`. A siphon NIC — the one
  actually carrying traffic in path — therefore showed a dash in both columns even while the
  sensor had a measured flow series and both feeds were observed. The cells are now rendered on
  every non-management NIC line.
- The trend is the sensor's measured series (the hub does not split flows per NIC); its title
  says so, and the indicators keep their existing evidence-based on/subdued states.
- A per-NIC name could disappear when the fleet payload was built before an
  `INTERFACE_NETWORKS` apply: the row then fell back to its CIDR while the other NIC showed its
  label. The NIC row now falls back to the settings rows already in the page, so `eth2=Data`
  reads as `Data` even from a stale list payload.
- A per-NIC Sluice table from an older plan could survive a plan change or a disable: the group
  that owned it was gone, so its disarm only knew the current NICs. The worker now reconciles the
  kernel against the current target set and removes every `weirvern_sluice*` table not in it —
  including all of them when `SLUICE_ENABLED=0`.
- The UI harness now builds a real siphon NIC row and asserts its flow SVG and both `.tap`
  indicators, and checks the Networks tile has replaced Problems with the summary count.

- The flow cell and the two feed indicators were gated on `capture`. A siphon NIC — the one
  actually carrying traffic in path — therefore showed a dash in both columns even while the
  sensor had a measured flow series and both feeds were observed. The cells are now rendered on
  every non-management NIC line.
- The trend is the sensor's measured series (the hub does not split flows per NIC); its title
  says so, and the indicators keep their existing evidence-based on/subdued states.
- The UI harness now builds a real siphon NIC row and asserts its flow SVG and both `.tap`
  indicators, so this cannot regress behind a capture-only fixture.

## 0.17.61 — 2026-10-20

A PER-NIC GATE OWNS TWO TABLES; DISARM DELETES BOTH.

- `NftBackend(suffix=iface)` compiled input rules into `weirvern_sluice_<iface>_in`, but
  `arm()`, `disarm()`, `installed()` and `counters()` still named the legacy module-level
  `weirvern_sluice_in`. A per-NIC inbound block survived every re-arm and every disarm, and
  `disarm()` reported the gate removed while that table was still installed — a block that
  outlived being turned off, the worst failure this gate can have.
- All four methods now use `self.table_in`. With no suffix the name is identical to the legacy
  table, so single-gate kernels are unchanged.
- The matrix now asserts a suffixed backend deletes its own forward and input tables and never
  touches the legacy input table.

## 0.17.60 — 2026-10-20

A REVOKED SENSOR IDLES. IT DOES NOT SNIFF THE MANAGEMENT PORT.

- Clearing `ZEEK_IFACE`/`ZEEK_IFACES` on revoke exposed a hidden default: the capture script
  fell back to `eth0` when no interface was configured. On this host that is the management
  NIC, so the revoked sensor immediately started capturing the box's own traffic and broadcast
  noise while logging a warning that it was doing so. An unconfigured sensor now prints
  `no capture interface configured — capture disabled` and idles; it never guesses a port.
- The check is in both places the script resolves the interface list, including the per-NIC
  loop, so a future edit cannot reintroduce the default in only one path.

## 0.17.59 — 2026-10-20

REVOKING A WEIRLING CLEARS ITS SETTINGS. A ROW IS NOT A CONFIGURATION.

- Revocation used to flip `enabled=0` and stop there. The local hub's worker did not read the
  registry for its plan -- it read the ConfigMap -- so the sensor kept forwarding, kept
  intercepting, and kept its old per-NIC plan after the operator removed it. Re-adopting it
  therefore brought the same cross-polluted settings straight back.
- `fleet.revoke()` now clears the registry plan, including the per-NIC JSON, while keeping the
  row and its heartbeat evidence.
- Revoking the **local** sensor now writes the sensor-role keys to their resting values
  (`SENSOR_MODE=loch`, empty capture/Zeek/plan/channel/NetFlow/Sluice-interface values,
  `SLUICE_ENABLED=0`) through the same verified ConfigMap path, records the revoke reason in the
  provenance annotation, and restarts `ds/zeek` and the worker. Detection thresholds, block
  lists and account settings are untouched: they belong to the deployment, not the registration.
- The route reports `settings_cleared` separately from `ok`, so a registry revoke that could not
  clear the ConfigMap is visible instead of looking clean.
- The deploy wrapper builds with `--network host`, which is what made the 0.17.58 image
  buildable here; the default build network could resolve the registry host but not PyPI.

## 0.17.58 — 2026-10-20

A SURVEY BELONGS TO THE NIC THAT RAN IT, AND THE PLAN IS THE MODE.

- Sonar on a NIC staged the legacy global `intercept_segment`, `intercept_gateway` and
  `intercept_addr` rows as well as its per-NIC plan. Surveying eth2 therefore changed the
  values eth1 displayed and the next Apply wrote. The NIC scan now suppresses that global
  staging and writes only that interface's entry in `INTERCEPT_PLANS`.
- The NIC line now reads its own plan: segment, mode and channel come from that interface's
  entry, not from the sensor-level legacy values. A siphon on eth1 no longer marks eth2's
  channel enabled, and a capture-only eth2 reads `loch`.
- A siphon entry in the plan is sufficient to arm: the forwarding init reads the plan before
  the legacy `SENSOR_MODE` check, and the heartbeat reports `siphon` from the plan. Applying
  the plan no longer requires a second enable.
- Applying `INTERCEPT_PLANS` now restarts `ds/zeek` as well as the worker, because the
  forwarding init reads the plan at pod start. A checked `Sluice` role also stages
  `SLUICE_ENABLED=1`, so the gate is enabled by the same Apply.
- The synthetic harness now runs a two-NIC plan through the real `wlNicFacts` and pins all
  three properties above (864 checks).

## 0.17.57 — 2026-10-20

THE NIC SHEET CAN BLOCK, NOT ONLY INTERCEPT.

- Each NIC sheet now carries a `Sluice — block on this NIC` control. It writes the `sluice`
  role into that interface's own plan, so a sensor can capture + siphon on eth1 and block on
  eth2 without either entry editing the other.

## 0.17.56 — 2026-10-20

THE PER-NIC SIPHON INIT KEEPS ITS HELPER.

- The 0.17.55 rewrite of the siphon init container accidentally dropped the `write_sysctl`
  function while adding the per-NIC loop, so a siphon deployment with a plan still exited
  with `write_sysctl: not found`. The helper is restored, and the per-NIC path is pinned by
  the runtime test.

## 0.17.55 — 2026-10-20

EVERY NIC GETS ITS OWN PLAN.

- A sensor is now a set of per-interface plans, not one global mode. `INTERCEPT_PLANS` is JSON
  keyed by NIC with `capture`, `siphon` and `sluice` roles. The NIC sheet writes only its own
  entry, so configuring eth2 cannot erase eth1.
- Siphon gets one supervisor and one policy table per NIC. The table is derived from the
  interface name, so a second relay cannot flush the first one's default route.
- Sluice gets one gate and one nft table per blocking NIC. Arming eth2 does not replace eth1's
  sets, and the sensor row is ARMED only when every blocking NIC is armed.
- Zeek starts one process and one log directory per capture NIC. The old comma-separated
  `ZEEK_IFACES` path passed repeated `-i` flags to one process and crash-looped; the ingester
  now walks the per-NIC directories, and the siphon init reads every siphon NIC from the plan.
- Remote units can store a per-NIC set in the registry (`plan_nics`), so a weirling is not
  limited to the hub's single-plan shape.

## 0.17.54 — 2026-10-19

SIPHON CAN OPEN ITS OWN FORWARDING PATH, AND A NIC SHEET DOES NOT BORROW ANOTHER NIC'S PLAN.

- The `siphon-forwarding-init` container passed `comment weirvern siphon` to nft without
  quoting. nft parsed the comment as two tokens and exited with a syntax error, so zeek
  stayed Pending and every intercept refused to poison — on eth1 and eth2 alike. The comment
  is now shell-quoted (`comment '"weirvern siphon"'`); a regression test pins the quoting.
- The per-NIC sheet copied the sensor-level `INTERCEPT_*` plan into whichever NIC was open, so
  eth2 displayed eth1's network, gateway and intercept IP. Only the capture interface owns
  those values now; every other NIC shows blank, read-only fields and does not stage blanks
  over the capture port's plan.

## 0.17.53 — 2026-10-19

THE APPLY RECEIPT SHOWS LOCAL TIME, AND A CAPTURE_IFACE CHANGE IS ACTUALLY CHECKED.

- The receipt and the settings provenance line printed the server's UTC ISO time by slicing
  `HH:MM` out of it, with no zone: 02:50 UTC read as "02:50" even where the operator's clock
  said the previous evening. Both now format the timestamp in the browser's local zone with
  its abbreviation.
- The "capture interface is one the sensors report" apply-time check read only
  `INTERCEPT_IFACE`; the GUI writes `CAPTURE_IFACE`, so a real interface change was skipped
  with "the change does not name a capture interface". It now checks the key that changed
  (preferring `CAPTURE_IFACE`) and validates it against the heartbeats.
- The other skip was accurate: `BASE_THRESHOLD` was not part of that apply, so the threshold
  check had nothing to test. Its hover already says so.

## 0.17.52 — 2026-10-19

THE SIPHON GATE READS THE PROCESS THAT ACTUALLY INTERCEPTS.

- The GUI's mode gate asked the **zeek** DaemonSet for CAP_NET_ADMIN, but `weirvern intercept`
  runs in the **worker** pod, and the passive capture container is deliberately the narrower
  one. The gate now reads the worker Deployment.
- With the existing worker overlay (hostNetwork + NET_RAW + NET_ADMIN) and the privileged
  `siphon-forwarding-init` container, siphon can be enabled without granting the packet
  parser NET_ADMIN. The refusal text now says "worker" rather than "sensor".
- The CLI's `weirvern mode siphon` prerequisite check reads the same Deployment.

## 0.17.51 — 2026-10-19

SONAR SHOWS THE STEP IT IS ON.

- The survey endpoint can stream NDJSON progress (`stream: true`) and the Weirlings sheet
  reads it: DHCP, passive capture, ARP probe, then the final result. The Settings tab's
  Sonar note shows the same steps.
- The Job prints `SONAR_PROGRESS` lines; the GUI tails its pod while waiting and relays them
  to the browser. A normal non-streaming request still gets the same single JSON payload.

## 0.17.50 — 2026-10-19

THE DHCP PROBE ACTUALLY RUNS ON THE LIVE PATH.

- 0.17.49 gated the DHCP probe on an injected `sweep` being absent, but `survey` replaces
  `sweep` with its default before that check, so the live path recorded `attempted: false`.
  The live-path flag is now captured before defaults are applied; a real Sonar run sends the
  DHCP DISCOVER first and falls back to passive capture only if no OFFER arrives.

## 0.17.49 — 2026-10-19

SONAR ASKS THE SEGMENT INSTEAD OF ASSUMING.

- **DHCP first.** Sonar sends one DHCPDISCOVER and reads the OFFER's option 1 (subnet mask)
  and option 3 (router). That makes the segment and gateway measured, not inferred, on any
  network with a DHCP server. The lease is not accepted and no address is assigned.
- **ARP duplicate-address check.** The offered address, or a random candidate from a passive
  survey, is probed with an ARP request from 0.0.0.0. If another host answers, the candidate
  is rejected; if none answers, it is reported as evidence, not proof.
- **Passive fallback.** If DHCP gets no OFFER, the existing capture learns what it can, then
  picks a random address from the learned segment and probes it before recommending it.
- The reply says which source produced the segment, gateway and intercept address, and
  distinguishes DHCP-measured values from ARP-probed candidates and unprobed assumptions.

## 0.17.48 — 2026-10-19

A PASSIVE SONAR OFFERS A CANDIDATE INTERCEPT ADDRESS.

- When the capture port cannot transmit, Sonar has no measured free-address list. It now
  offers the conventional first host after the gateway as an explicit CANDIDATE, with a note
  that it was not probed, so the settings sheet is filled for review instead of looking like
  the survey found nothing.
- The scan note distinguishes a measured address from a candidate; siphon still stages the
  value through the ordinary review path.

## 0.17.47 — 2026-10-19

SONAR SURVIVES A QUIET PASSIVE WINDOW.

- A passive survey that observed only one address inferred a `/32` segment. On CPython 3.11
  `IPv4Network.hosts()` returns a list for a single-host network, and Sonar's gateway
  fallback called `next()` on it, so the job failed with `'list' object is not an iterator`.
  The segment is now widened to the conventional `/24` with an explicit assumption note, and
  the gateway fallback accepts either a list or an iterator.
- Regression test covers the single-observed-host case.

## 0.17.46 — 2026-10-19

THE NIC HEADERS SIT UNDER THE SENSOR NAME AGAIN.

- Restored the layout the operator preferred: the sensor row carries the CPU/memory reading
  with no CPU or memory headers, and the `interface`, `mode`, `channel`, `networks`,
  `throughput`, `flow` and `feeds` headers follow it above that sensor's NIC lines.
- Each NIC line names its interface and the operator's network label (`eth1 capture -
  Servers`); the removed CPU/memory columns leave no empty dashes behind.

## 0.17.45 — 2026-10-19

REMOVE THE EMPTY CPU/MEMORY COLUMNS, KEEP THE READING.

- The fleet headers stay at the top but no longer include CPU or memory; those columns had
  only dashes in the NIC rows. The sensor row keeps its value-over-label CPU/memory reading.
- Each NIC line now carries its network name beside the interface (`eth1 capture - Servers`)
  instead of leaving the removed columns empty.

## 0.17.44 — 2026-10-19

THE NIC HEADERS SIT UNDER THE SENSOR NAME.

- Removed the CPU and memory column headers. The sensor row keeps the value-over-label
  readings; the remaining `interface`, `mode`, `channel`, `networks`, `throughput`, `flow`
  and `feeds` headers are rendered beneath each sensor name, directly above its NIC lines.

## 0.17.43 — 2026-10-19

CPU AND MEMORY KEEP THEIR ORIGINAL READING; THROUGHPUT IS ONE COLUMN.

- The sensor row's CPU and memory cells show the value over its label again, instead of a
  bare percentage in a wide cell.
- The per-interface `eth1`/`eth2` columns collapse back to one `throughput` column; each NIC
  row reports its own rate there.

## 0.17.42 — 2026-10-19

EACH SNIFFING INTERFACE GETS ITS OWN THROUGHPUT COLUMN.

- The single `throughput` column is replaced by one column per sniffing interface in the
  visible fleet (`eth1`, `eth2`, ...). A NIC row's own rate sits under its own header; the
  management port and virtual interfaces stay out of the table.

## 0.17.41 — 2026-10-19

PERFORMANCE SITS WITH THE SENSOR NAME.

- The separate Performance card is gone. Each sensor row carries its own left-to-right strip:
  CPU, memory, then the sniffing interfaces only (management and loopback excluded). The
  labels sit beneath their values, so the numbers are the first thing scanned.
- A remote sensor that has not reported host counters says so in its row instead of showing
  the hub's numbers.

## 0.17.40 — 2026-10-19

THE SYSTEM CARDS READ THE HOST, NOT THE POD'S MEMORY LIMIT.

- A `hostPath: /proc` mount can be cgroup-sized: on this cluster `/host-proc/meminfo` reported
  the GUI pod's 512 MiB limit while `/proc` reported the host's 40 GiB. The sampler now picks
  the candidate procfs with the larger MemTotal instead of trusting the mount's name.

## 0.17.39 — 2026-10-19

SONAR NEEDS AN IN-PATH MODE, AND PERFORMANCE NAMES ITS SENSOR.

- **Sonar** is disabled unless **Siphon** is selected; in loch mode there is no ARP/spoof plan
  to stage, so the button no longer offers a survey that cannot be used.
- The Weirlings **Performance** card has a sensor selector and asks `/api/system` for that
  sensor. The hub's own host supplies CPU/memory and interface counters; a remote sensor that
  has not reported host metrics says so instead of wearing the hub's numbers.
- The System percentages use the console's 19px reading size, not the old oversized 27px.

## 0.17.38 — 2026-10-19

INTERFACE COUNTERS COME FROM SYSFS.

- `/proc/net` follows the pod's network namespace even when procfs is mounted from the host,
  so the interface table only ever saw the pod's own eth0. The sampler now reads the host's
  `/sys/class/net/*/statistics` (read-only `/host-sys`) and falls back to procfs when that
  mount is absent. CPU and memory still come from the host procfs.

## 0.17.37 — 2026-10-19

THE SYSTEM IS A READING, AND THE POP-OUTS LOOK LIKE THE CONSOLE.

- **Health** opens with a **System** card: host CPU and memory, each with its own trend line
  and the sampler's history. **Weirlings** gains **Performance** with the same two readings,
  plus per-interface throughput and drop counters. The host procfs is read read-only from
  `/host-proc`; a database outage cannot blank these cards.
- Identity and the sensor/channel pair now use the same `card sheet` surface as the Weirling
  interface settings, so both pop-outs sit on the console's background rather than bare text.
- **Network name** is a section heading matching **Mode**, and **Sonar** surveys the selected
  interface; its ARP/spoof recommendations stage through the ordinary plan.

## 0.17.36 — 2026-10-19

THE CHANNEL PAIR BELONGS TO THE SENSOR ROW.

- The **Channel** pair moved off the per-NIC settings panel and onto the sensor's own sheet,
  opened by clicking the row with the sensor name. A NIC panel no longer offers a sensor-wide
  choice.
- While a channel is enabled, the NIC panel greys out **Siphon** and **Passive NetFlow**. Applying
  the channel writes `channel_upstream`/`channel_downstream` together with `sensor_mode=loch`
  and `netflow_mode=active`, so a bridge cannot be left fighting an in-path or router-feed choice.
- The **network name** is back above Mode. **Networks** now carries the measured network CIDR,
  gateway and intercept IP; **Sonar** fills all three from the segment it surveys, and staging
  the interface writes them with the rest of the plan.
- Clicking **Identity** in Assets opens the evidence as a sheet, not a card at the bottom: four
  headline metrics (identity, confidence, sources, last updated), one strongest-evidence
  call-out, then the checkable signal list.

## 0.17.35 — 2026-10-19

APPLY FROM THE WEIRLINGS SHEET DOES NOT ASK FOR A SECOND REASON.

- The sheet's **Apply changes** button writes the staged set directly: no costly-change
  confirmation and no second reason prompt. The BF-9 in-path confirmation and its reason field
  remain on the Settings tab; the Weirlings surface records `applied from the Weirlings sheet`
  as the origin in the write trail instead of interrupting the operator after they already
  pressed Apply.
- The per-NIC sheet gains a **Network** row: the interface's network name, a **Scan Network**
  line, and a **Sonar** button. Sonar surveys the segment, stages its findings through the
  ordinary plan, and writes nothing itself.
- A **Channel** row selects the upstream and downstream NICs that should be joined into one
  in-line channel. The picks stage `channel_upstream` and `channel_downstream` through the same
  plan as every other setting.
- **Siphon forwarding is configured in the background.** The capture DaemonSet now runs a
  privileged `siphon-forwarding-init` before Zeek: in siphon mode it enables IPv4 forwarding,
  disables reverse-path filtering and send-redirects on the capture port, and ensures the
  interface-scoped FORWARD accepts that k3s's default `DROP` policy requires. It is inert in
  loch mode. The operator no longer has to set sysctls or firewall rules before going in-path.
- **Assets carries identity.** The duplicate Hosts table at the bottom is retired. The asset
  inventory gains an Identity column; clicking a label opens the evidence pop-out with
  confidence, agreeing sources, strongest evidence and last updated — the same verdict, one
  place closer to the host it describes.

## 0.17.34 — 2026-10-19

THE OLD WHOLE-HUB SETTINGS GRID IS OUT OF THE WEIRLING SHEET, AND ETH2 SHOWS ETH2.

- The per-NIC panel no longer sits above a second, global settings grid. That grid was the
  old interface settings page: selecting eth2 still showed eth1's `ZEEK_IFACE` and
  `CAPTURE_IFACE` values underneath, which made the two interfaces look connected. The grid
  remains on Settings; the sheet renders only the selected interface's controls.
- A sensor row now opens its first non-management NIC automatically, so the per-NIC panel is
  always the settings surface; a NIC row opens exactly that NIC.
- The Weirlings summary no longer draws a **never seen** tile. The state and its saved view
  remain; the tile was removed at the operator's request.

## 0.17.33 — 2026-10-19

THE PER-INTERFACE SHEET HAS A MODE AND A FEEDS SECTION, AND NETFLOW SAYS WHERE IT COMES FROM.

- **Mode** — Siphon and Loch are the two mutually exclusive choices. Choosing siphon makes this
  the capture port and requires Zeek; choosing loch returns the sensor to passive capture.
- **Feeds** — Zeek and NetFlow are separate checkboxes. The Zeek choice edits the capture list;
  NetFlow is governed by the source statement beside it.
- **NetFlow source** — Passive means this sensor listens for NetFlow another device sends to it.
  Active means the sensor summarises its own capture: the verified siphon relay while
  intercepting, or the selected mirrored port in loch mode. Active loch uses `NETFLOW_IFACE`
  (or the Zeek interface when empty); auto preserves the historical behaviour. Passive stops
  any sensor-generated probe and leaves the received feed untouched.
- The panel still speaks only about the selected NIC; pending changes name that NIC's mode,
  feeds and NetFlow source rather than the global lists.

## 0.17.32 — 2026-10-19

THREE MODEL-INTEGRITY FIXES: HONEST RARITY, STABLE SAMPLES, AND HONEST TRAINING.

- **#62 — a missing service history is not a baseline of one.** A failed `zeek_baseline_sql`
  left the baseline dict without `baseline_service_count`; rarity then used a floor of 1 and
  manufactured novelty for every host with more than one service. The extractor now leaves
  rarity at 0.0 unless the key is present. The volume baseline still trains when the history
  query fails.
- **#61 — training samples are deterministic.** Both the Isolation Forest and DBSCAN queries
  ended with an unordered `LIMIT`, so the same window could train from different rows. Both now
  order by `sipHash64(src_addr, window_start)` before the outer limit, and a SQL-text test pins
  the clause.
- **#60 — "trained" now means "can score".** Gradient Boosting's return value is captured on
  both scheduled paths, so a failed student no longer gets a training-history row. DBSCAN returns
  false when it finds zero cluster centres. Candidate reports carry `usable` beside `trained`, and
  the Models freshness table has a separate **Last usable** column; a detector with a recent
  training run but no usable model reads **not scoring**, never "current".

## 0.17.31 — 2026-10-19

A KEPT MODEL KEEPS ITS HOME, AND ZEEK COUNTS ARE LOGGED ONCE.

- **#59 — the candidate cannot redirect the live detector.** `BaseDetector.load()` adopted the
  artifact's pickled `model_dir`, so keeping a retrained candidate pointed the live detector at
  `candidate/`, which the keep then deleted. The live home and the in-process prediction-error
  counter are preserved across a load. `apply_candidate` now verifies the reload: if it refuses,
  the archived live artifact is restored, the detector is reported in `failed`, and the keep is
  not described as installed.
- **#58 — one log transform, not two.** `zeek_window_summary_sql` log1p-scales seven count
  columns; `extract_zeek_features` log1p'd them again, so training saw `log1p(n)` and scoring saw
  `log1p(log1p(n))`. Scoring now passes SQL values through unchanged, and service rarity inverts
  the logged window count before comparing it with the raw baseline. Tests pin all seven counts at
  raw 0, 1, 10, 100 and 10,000, and the baseline-1/baseline-5 rarity cases.

## 0.17.30 — 2026-10-19

A NIC'S PENDING DIFF NAMES ONLY THAT NIC. The per-interface sheet was scoped, but its pending
changes rendered the stored Zeek list verbatim, so editing eth1 printed `eth1,eth2`. The mirror
now states the selected interface's effect — capture on/off, siphon on/off, its network name —
while the stored value remains the one list the backend needs. The settings panel itself was
already interface-only; a regression check now keeps eth0 and eth2 out of it.

## 0.17.29 — 2026-10-19

INTERFACE NAMES REACH THE ALERTS. The per-interface settings now carry a network name
(`eth1=Servers,eth2=DMZ`), staged with the same capture choices. The anomaly list resolves the
source address to its segment as before, then adds the interface's name, so a row reads
`weirvern · Servers` with the CIDR in its title. The name is a label; it never changes addressing.

## 0.17.28 — 2026-10-19

THE TABLE-SIZE HISTORY BOUNDS, ROUND TWO. The table held samples while the Health query returned
none: the driver's aware-datetime binding selected no rows for a `DateTime64(…, 'UTC')` column
through the HTTP interface. Bind the window as wall-clock strings instead; the history is a
read-only diagnostic and both sides parse that form.

## 0.17.27 — 2026-10-19

THE HEALTH TRENDS HAVE DATA ON THE FIRST VISIT. The history read grouped by hour and lost the
fresh samples; it now reads the worker's five-minute samples directly, so a table shows a line as
soon as two samples exist. The read also no longer uses a bound `IN` list, which the driver
returned empty for, making every table say "collecting" while the rows were present.

## 0.17.26 — 2026-10-19

THE FLOWS TRENDS ROUTE, AND A CURSOR THAT STOPPED DETECTION. `/api/discover/trends` was added to
the handler but not to the dispatcher, so the three feed boxes received a 404. Separately, a
detection cursor written before zones were normalised compared naive to aware and raised on every
worker cycle after a restart, stopping detection and the new table-size sampling with it. Old
cursors are now read as UTC.

## 0.17.25 — 2026-10-19

INTERFACES CONFIGURE THEMSELVES, AND THE CONSOLE SAYS WHAT IT MEANS.

- **Per-NIC settings**: clicking a NIC on this hub’s weirling scopes the sheet to that port, with
  Zeek-capture and siphon toggles. “All hub settings” returns to the global pane; a NIC edit can
  no longer quietly change another port’s configuration.
- **Automatic capture config**: Zeek captures `CAPTURE_IFACE` when no explicit `ZEEK_IFACES` list
  is set; NetFlow follows the actual siphon port; a siphon-mode sensor starts its flow tap
  automatically once the intercept is verified live, without a separate flag.
- **Flows, not Discover**: the tab and its heading are named Flows. Its header carries three
  live feed trend boxes — NetFlow, Zeek, DNS — each clickable to that feed.
- **Health table trends**: `table_size_history` is sampled by the worker every five minutes and
  the Table sizes card draws a 24-hour line per table: green building, yellow static, red
  shrinking; a single sample says “collecting” rather than inventing a flat line.
- **Copy link removed**; the quick-jump entry is named **Quick links**, which is what it does.

## 0.17.24 — 2026-10-19

THE SLUICE GATE READS ACROSS THE PAGE. Domain Gate and Traffic Gate were two full-width cards
stacked vertically, and each card's four measurements sat in a `.stat-row` that had no CSS
behind it -- so the page was a single narrow column of numbers. The two cards now share one
responsive grid, the measurements are tiles across the card (2×2 on a phone), and the fleet
table is its own full-width card below them. Gate overview's chips sit in the title row.

## 0.17.23 — 2026-10-19

A PASSIVE SURVEY STAGES WHAT IT ACTUALLY LEARNED. The passive result returned no recommendations,
so a perfectly good survey of `198.51.100.0/24` left every field empty. It now offers the segment,
gateway and targets, and deliberately omits the intercept address: no sweep ran, so a free
address would be an invention. The note says "no ARP sweep ran" instead of printing a null count.

## 0.17.22 — 2026-10-19

SONAR RUNS ON A PASSIVE PORT, AND ITS ANSWER LANDS IN THE FIELDS. `iface_ipv4` raises when an
interface has no address; the passive watcher below it was therefore unreachable, so Sonar
refused on the live capture port (eth1 carries only link-local IPv6). The default reader now
returns empty and lets the watcher learn the segment. On success the recommendations are staged
**and written into the setting controls**, which is what the note already claimed; before, the
pending list stayed empty and every field read `(not set)`.

## 0.17.21 — 2026-10-19

THE NIC LIST KEEPS THE PORT ZEEK ALREADY WATCHES. Selecting eth2 for siphon staged
`ZEEK_IFACES=eth2`, which would have dropped eth1 from Zeek's capture. The list is seeded with
ZEEK_IFACE when it is empty, so the click stages `eth1,eth2`. A gate row whose stored interface or
backend is empty is also treated as stale and rewritten from the running supervisor, so the
Traffic Gate tile names eth1/nft instead of "—".

## 0.17.20 — 2026-10-19

"(not set)" IS NOT AN INTERFACE. The settings payload renders an empty key as `(not set)`, so the
NIC click appended it to `ZEEK_IFACES` and staged `(not set),eth2`. Empty display values are
filtered; the staged list is just the port that was clicked.

## 0.17.19 — 2026-10-19

THE NIC CLICK STAGES THE FIELD IT FINDS. Settings rows carry their key lowercased in the DOM
(`capture_iface`) while the registry key is uppercase (`CAPTURE_IFACE`); the NIC click queried
the uppercase form, found nothing, and silently staged no change — the sheet opened with eth1
still selected. The lookup is case-insensitive now, and the Zeek list lookup accepts either
spelling. Verified by driving the click and reading the staged value.

## 0.17.18 — 2026-10-19

THE OPERATOR'S RULE WORK, AND MULTI-PORT CAPTURE.

- **Gate overview leads the Sluice page** (renamed from "At a glance").
- **Delete selected**: the bulk bar takes a required reason and revokes every checked rule.
  Revoked rules are hidden by default (`show revoked` brings them back) — before, a successful
  delete left the row in place with a disabled Delete button, which read as "deleting doesn't work".
- **A rule opens to edit**: the sheet carries mode and domain (domain rules only), a Save that
  calls the existing mode/domain endpoints, and the existing enable/disable toggle. Revoked rules
  stay read-only.
- **Clicking a NIC on this hub's own weirling selects it for siphon**: the click stages
  `CAPTURE_IFACE=<nic>` in Settings (and adds the port to `ZEEK_IFACES`) instead of doing nothing.
- **Zeek can watch several ports**: `ZEEK_IFACES=eth1,eth2` compiles to repeated `-i` arguments.
  `CAPTURE_IFACE` names the one port the siphon intercept borrows, so Zeek keeps every mirrored
  segment while only one is redirected.
- The weirling sheet's top prose is trimmed to the state/evidence lines.

## 0.17.17 — 2026-10-19

THE TRAFFIC GATE NAMES ITS INTERFACE AND BACKEND. Writing the default `GateState` on a disabled
restart left `iface` and `backend` empty, so the split card read "interface —" and warned about a
`''` backend on a gate that uses nft on eth1. A stale row now goes through `disarm()` before it is
recorded, which fills both from the running supervisor. Domain Gate also counts the recorded hits
list correctly and says plainly that it answers DNS rather than dropping packets.

## 0.17.16 — 2026-10-19

TWO GATES, TWO JOBS. The Sluice page showed one gate state for two independent enforcement paths,
so a working DNS gate read as broken because the packet gate was disarmed.

- **Domain Gate** leads: lists enabled / domains imported / hits recorded / last sync, the
  domain-blocking switch, and a link to the blocklists in Settings. It states plainly that it
  answers DNS and works with no nft rules.
- **Traffic Gate** follows: its own state / interface / rules / packets-blocked tiles, the
  arm-disarm control, and the fleet gates table (now "Fleet gates"). It states that it drops
  packets and needs a rule and an armed nft backend.
- The duplicate "Sluice Gate" card, the shared status line and the separate "Blocking on domain
  blocks" card are gone; their controls live in the gate they actually govern.

## 0.17.15 — 2026-10-19

A DISABLED RESTART CLEARS A STALE GATE ROW. 0.17.14 stopped an absent nft table from reading as
present, but the panel still said "degraded" after a restart: the old worker had recorded that
detail while shutting down, and the fresh supervisor — already disarmed — skipped its write, so
the stale row survived. The disabled branch now reads the prior row once per process and writes
"disarmed" when the stored state is not disarmed (a genuinely empty table stays empty and still
says "has not run yet"). Pinned by a regression test.

## 0.17.14 — 2026-10-19

THE GATE'S "DEGRADED" WAS A FALSE ALARM. `NftBackend.installed()` and `disarm()` verified a table
by asking `nft list table inet <name>` and then testing whether the name appeared in the output.
On a box with no such table nft exits non-zero and prints the requested name in its stderr
("list table inet weirvern_sluice"), so every ABSENCE read as a leftover table: the live gate
reported "degraded — these tables are still present after deletion" while `nft list tables`
showed neither table anywhere. Presence now requires a successful list (`ok and ...`), with a
regression test built from the exact ENOENT text. The gate's capture path was never the problem;
this was the cleanup check lying about it.

## 0.17.13 — 2026-10-19

THE HOST VIEW ACTUALLY OPENS. 0.17.12 added `#view-host` but `showView("host")` still carried the
old compatibility alias that folded `host` back into `assets` — so the host click landed on the
inventory again, exactly the defect the page was built to fix. The alias is gone; `#v=host` is
its own surface, the back crumb is built for it, and the host page's address is `hp-title`.
Harness expectations that pinned the old alias are updated to the host view.

## 0.17.12 — 2026-10-19

THE INVESTIGATION PAGE, and the sensor row becomes a menu.

- **A host has its own page.** Clicking a host in Anomalies or Assets opens `#v=host` for that
  address — not the whole Assets inventory. It carries a connection picture (the host and its
  top peers, edge weight by bytes), a NetFlow bar chart by hour, DNS queries, Zeek sessions by
  service, top destinations and that host's anomalies. The server's `/api/host` now returns
  `dns_queries`, `zeek_timeline` and `zeek_peers` beside the existing totals.
- **The weirling row is a menu; the NIC lines are the settings.** Clicking the sensor name opens
  exactly Adopt / Enable / Disable / Delete. Clicking a non-management NIC line opens that NIC's
  settings with its interface selected. The selection checkboxes and the bulk bar are gone.
- **A selected criterion wears a white outline** on the Weirlings summary tiles and the
  Anomalies severity tiles, so the active filter is visible against any tile colour.
- **Anomalies columns:** host narrowed, matched rule and why widened, row height down; **Owner
  became Location** — the weirling that sees the host's network and that network (`unplaced`
  when no declared segment contains it). The server resolves it against the fleet's segments,
  most specific first.
- **Assets review:** a four-tile summary (hosts / active in the last hour / with anomalies /
  external), a `new` badge for hosts first seen inside the window, and clickable column headers
  for address, name, bytes, flows and anomalies. The scope, search, service facets and pager
  remain.
- **Discover is now Flows** in the tab strip (the view id stays `discover` for links).
- **`wl=` no longer leaks.** The weirling deep link is written only while a weirling sheet is
  open on the Weirlings view, and only a Weirlings URL honours it; an anomalies link can no
  longer carry `wl=...` or hijack the next reload back to Weirlings.
- Gate passed; pytest green; harness green (842 checks).

## 0.17.11 — 2026-10-19

**EACH NON-MANAGEMENT NIC IS A LINE INSIDE ITS SENSOR'S ROW.** The `NICs (n)` disclosure is gone:
every non-management interface the heartbeat reports is rendered directly under its weirling, one
line each, with its own **name and role**, **mode**, **channel**, **networks**, **flow trend** and
**feeds**. The management NIC is excluded (it is not a capture path), and a fact the hub does not
have renders as a dash rather than a guess. The sensor row above keeps the sensor-wide summary;
the NIC lines carry the per-interface view. Harness checks pin the inline rows, the six cells and
the capture NIC's trend and both feed indicators.

## 0.17.10 — 2026-10-19

TWO FOLLOW-UPS FOUND BY READING THE LIVE BOX AFTER 0.17.9 WAS DEPLOYED.

- **The weirling sheet now gets the LIST's evidence.** `/api/weirlings/detail` is the
  classification payload and does not carry `channel`, `netflow`, `zeek` or `flow_series`;
  the sheet therefore said "flow capture configured on" beside no channel and no observed
  flows. It merges the enriched row from the list it was opened from, keyed by sensor id.
  Measured before: `channel=None, netflow=None, zeek=None` on the detail payload.
- **The Reverse DNS card title.** The Settings card is static markup, so renaming the API
  group was not enough; the visible heading is now **Reverse DNS**.

## 0.17.9 — 2026-10-19

THE OPERATOR'S WALKTHROUGH BATCH. Every item came from reading the live console, and the
live measurement is quoted where it changed the design.

- **The tiles were taller than their boxes (fleet and severity).** BTN-1 gives every button
  `height: var(--btn-h)` (28px) and `nowrap`; the fleet summary tiles and the Anomalies severity
  tiles are buttons that carry a label and a 27px number (51px of content). Measured live: a
  28px box with the number at y=257.5–293.5 — the digits sat outside the rounded panel. Both
  tile rules now size from their content. Pins: `tests/test_buttons.py` and the jsdom computed
  style checks; mutations turn both checks RED.
- **The fleet table answers the questions an operator actually asks.** Columns are now
  **weirling · mode · channel · networks · flow · feeds**: mode is only `loch`/`siphon` (a
  disagreeing declaration is in the title, not the cell), **channel** is the in-path channel's
  evidence (enabled only when siphon has live mappings; disabled with the reason otherwise),
  netflow and zeek share **feeds** while keeping their own indicators, and **flow** says
  `0 flows` when the exporter is known and produced nothing instead of a bare dash. The sheet
  now separates *configured* from *observed*: measured live, the settings said flow capture was
  on while the table said no flows for 24h — both true, now both stated.
- **Each NIC, on demand.** A `NICs (n)` control expands a sub-table: nic · role · mode ·
  networks · flow · feeds, with roles from the local sensor's settings (management / capture /
  channel ends) or the remote plan's interface. A fact the agent did not report says so.
- **The Assets tab now contains Identity.** One tab, both datasets, with a **networks**
  selector: all networks · monitored networks · external network. "Monitored" is a private or
  link-local address (the sensor's own side); "external" is global. The filter applies to the
  inventory and the identity table from one value, so the two panels cannot disagree.
- **Sluice Gate leads with Enforcing gates.** The state tiles and the cleanup sentence
  ("these tables are still present after deletion") are gone; the server's reason survives as
  the state word's tooltip. The gates table is the first thing on the page.
- **Settings loses the decoration.** The "N settings in effect" line is gone, the DNS group is
  titled **Reverse DNS**, and Pending changes is the last card on the page.
- **Logs moved to the far right** of the tab strip.
- New pins: `tests/test_channel_state.py` (5), harness 838 → 845 (tile heights, channel/feeds,
  per-NIC expansion, Assets scope, Sluice order). Full pytest green; gate passed.

## 0.17.8 — 2026-10-19

TWO OPERATOR-FILED IMPROVEMENTS (GitHub #51, #52).

- **#51 — the Sluice Gate byte tile.** Already fixed by the formatter batch (#23, `056c8e3`)
  and pinned by the harness check *"the gate tiles group packet counts and scale byte totals"*.
  The issue quoted a pre-`056c8e3` line. Verified against `e34e468` and on the box: the tile
  renders through `fmtBytes`, the packet count through `toLocaleString`, and a missing value
  still renders "—". No code change was needed; the mutation (back to `String(...)`) turns the
  check RED with the raw `987654` in the failure text.
- **#52 — the alert evidence drill has a visible entry and exit.** Every anomaly row now carries
  a quiet **"evidence ›"** control at rest (it stops propagation, so the row drill, the count
  unfold and the per-cell filters keep their own clicks), and the evidence view's header carries
  **"Back to alerts"** (named for the origin) that returns to `view-anomalies` with the queue's
  filters untouched. The crumb trail remains as the secondary path. Harness 834 → 838.
  Mutations: renaming `.ev-open` turns the entry check RED; forcing the back control hidden
  turns the exit check RED.
- 0.17.8.

## 0.17.7 — 2026-10-18

THE HARDENING BATCH. GitHub issues #17, #18, #22, #24, #25, #26, #27, #28 and #32, verified
against `6ccc19c`, imported to the `weirvern-hardening` board and fixed here. **#8 (README
screenshots) is deliberately not in this release.**

- **One clock (HD-28).** Every stored, computed or queried time is now aware UTC: 79 naive
  `datetime.now()` / `fromtimestamp()` sites across the worker, ingester, host identity, alerts,
  detectors, the admin API and Zeek windows. `weirvern/clock.py` owns the convention;
  `tests/test_clock.py` runs it under `TZ=America/Chicago`, asserts no negative ages, and parses
  the package to forbid a naive call from returning. Legacy naive values are read as LOCAL
  (`clock.as_aware`), never relabelled UTC.
- **The dialog contract (HD-17).** The modal shell is labelled by the moved node's own heading,
  focus moves into it, Tab cannot leave it, and focus returns to the opening control.
  `.dcell` filter cells are tabbable, carry `role=button` and an accessible name from their
  title, and Enter/Space performs the click. Harness 828 → 834.
- **Images pinned by digest (HD-18).** busybox 1.37 (the 1.36 drift is gone), ClickHouse 26.8,
  goflow2 v2.2.6, `python:3.11-slim` and `zeek/zeek:lts` now carry `@sha256` in every manifest,
  overlay, unit template and Containerfile.
- **CI and manifest hardening (HD-22).** kubeconform pinned to v0.8.0 and verified against its
  CHECKSUMS; kustomize reads `install.sh`'s pin instead of keeping a second version; every
  `overlays/*/` is rendered; the unit templates are parsed; the prune container gets
  `allowPrivilegeEscalation: false`, `drop: ALL`, a read-only root and a writable `/tmp`.
- **The installer is honest (HD-24).** If pods never become Ready it still prints the full
  picture, then exits **1** with an `INCOMPLETE:` line naming them and the command to re-check.
- **Per-weirling credentials (HD-25).** `deploy-weirling.sh` creates `wv_<sensor>` with
  `GRANT INSERT ON weirvern.*` and nothing else, generates the password locally, writes it only
  to the target's 0600 env file, records sensor → user on the hub
  (`/var/lib/weirvern/sensor-credentials.tsv`), and drops the user on `--remove`. It refuses to
  fall back to the hub's shared password.
- **Documented security and recovery (HD-26, HD-27, HD-32).** `docs/security.md` now states the
  transport boundary with a worked nginx TLS example and the port-forward alternative, the
  secrets-at-rest position (fresh installs use `--secrets-encryption`; existing clusters are
  warned and given the k3s migration), and per-weirling credential revocation.
  `docs/operations.md` carries the upgrade and rollback contract: code rolls back, data does
  not, with the `IfNotPresent` caveat and the model archive path.
- New pins: `tests/test_hardening.py` (8), `tests/test_dialog_contract.py` (4),
  `tests/test_clock.py` (8). Full pytest green; harness 834; gate passed.

## 0.17.6 — 2026-10-18

THE SHEET IS THE STANDARD.

The operator, 2026-10-18: *"Make that pop out a standard."*

The Sluice rule sheet was built with `class="card sheet"`, but `style.css` only fixed
`#wl-detail-card.sheet`. `.sheet` was a name two screens shared, not a primitive: the new sheet
rendered **inline in the view** — no pop-out, no scrim, no Escape. The scrim, Escape and focus
code were duplicated between `weirlings.js` and `sluice.js`.

- **`.sheet` is a real class**: fixed to the right edge, `min(480px, 94vw)`, full height, full
  width at ≤720, one `sheet-in` motion (`prefers-reduced-motion` honoured). Both sheets pop.
- **`sheets.js` is the one implementation**: `openSheet` / `closeSheet` / `sheetIsOpen` /
  `wireSheet`; one scrim factory, one Escape handler for the top sheet (capture phase, so a
  sheet open over a confirmation modal loses the key to the modal), focus into the sheet and
  back to the control that opened it, Tab contained. Neither view module builds a scrim or binds
  Escape any more.
- **`role="dialog" aria-modal="true" aria-labelledby`** on both sheets; one `.sheet-close` each.
- **`.sheet-actions`**: the primary verb sits in a sticky foot bar, in thumb reach on a phone.
- **`docs/design/sheets.md`**: when a sheet (one object) vs a modal (one blocking question) vs
  inline; anatomy; sizes; behaviour; accessibility; a checklist for a new surface; the
  anti-patterns (form at rest on a tab, per-row destroy icons, bulk delete, a second composer).
- **`tests/test_sheet_standard.py`** pins it (6 tests). Harness 826 → 828: the rule sheet is a
  labelled dialog and Escape closes it, scrim and all. `responsive_audit.py --open-sheet new-rule`
  measures the rule sheet in a real browser.
- Known debt, recorded in the standard rather than hidden: the Blocked view's rule card is still
  a modal; it edits one object and belongs in a sheet next.

## 0.17.5 — 2026-10-18

DELETING A RULE ASKS FOR THE REASON THE SERVER REQUIRES.

Found on the live box during the 0.17.4 create/delete check: `/api/sluice/revoke` refuses a
request with no reason ("a reason is required to revoke a rule; it is recorded with your name
and the time"), and the sheet posted only the rule id, so the delete button could never work.

- The rule sheet's detail section gains a required reason field. Delete without a reason refuses
  to arm and explains why; with a reason it arms on the first click and writes on the second,
  sending both the id and the reason.
- Harness: 825 → 826 checks — "delete without a reason refuses to arm" and "delete arms before
  it revokes" both pin the behaviour; live create → revoke → read-back verifies the write.

## 0.17.4 — 2026-10-18

RULES ARE ADDED AND DELETED IN A SHEET, NOT ON THE SLUICE TAB.

The operator, 2026-10-18: "Sluice gate needs refining. Adding or deleting rules should be a
similar pop out like weirling settings. Not added on the main sluice gate tab."

- The inline "Block a host or network" card is gone from the Sluice view. "New rule" opens
  `#sl-rule-sheet` — the same right-side sheet the weirlings use — with the source, destination,
  domain, mode, protocol, port, direction, duration and reason fields.
- A rule row opens that same sheet: its state, origin, expiry, reason and id, with Enable/Disable,
  Delete and "Open on the Blocked page". Delete arms on the first click and writes on the second;
  the confirm and the audit trail are unchanged.
- The per-row trash/ban icons and the bulk "Delete selected" button are gone. The bulk bar parks
  and restores rules (reversible); deleting is one rule at a time, in its sheet.
- One composer: the DNS/Blocked "block this domain" button opens this sheet with the name filled
  in; the separate `#rule-composer` modal is retired.
- Blocking rules still ask twice: the create button arms before it writes. Alert rules write on
  one click.

Harness 821 → 825 checks; full suite green.

## 0.17.3 — 2026-10-18

A WEIRLING'S SETTINGS LIVE IN ITS OWN SHEET.

The operator, 2026-10-18: "remove weirling settings from the settings tab and move it to the
weirling pop out on the weirling tab. Selecting a weirling opens the settings for that specific
one."

- The Settings tab's Sensor card is gone. This hub's own weirling now carries its mode, Sonar,
  the 30-second test run and its capture settings in the sheet that opens when you select it.
  It is a MOVE: every control exists once, and the retired pin
  `test_the_sensor_controls_live_on_settings_and_nowhere_else` is replaced by its inverse with
  the operator's instruction in the docstring.
- The sheet's pending-changes bar is the same `STAGE` Settings uses: one key, one plan, one
  `/api/settings/apply`, one receipt. A Detection change staged on Settings can be applied from
  the sheet, the result is shown in both places, and Discard clears both.
- `reverse_dns` leaves the Weirling group for a new **DNS** card on Settings: it changes how the
  DNS view names addresses, not what a sensor captures.
- A remote weirling's sheet keeps its registry plan and one sentence naming what this hub cannot
  reach. An unadopted local weirling shows its settings and Adopt together, because adoption is
  a fleet declaration, not a prerequisite for configuring the box this console runs beside.
- The host-health "Weirling" card's explainer now describes itself instead of pointing at the
  deleted Settings panel.

Harness 817 → 821 checks; the full suite passes; design of record: `docs/design/weirling-settings.md`.

## 0.17.2 — 2026-10-18

THE CONSOLE WEARS THE README'S MARK.

- The header, the sign-in gate, the forced-password gate and the tab icon now use the supplied
  raster emblem from `docs/logo.png`, cropped above the wordmark. The header already renders the
  name beside it, so a second wordmark at 28px would only be an illegible smudge. The asset is
  180×180 (Apple's touch-icon size) and is drawn at 28/36 CSS pixels.
- The geometric "flow through a gate" SVG is retired from the chrome — it was a placeholder for
  the real mark, not a second identity. The file stays served so no route breaks; the pins that
  required it in the header are inverted, and a new harness check requires the README mark in
  every slot.

## 0.17.1 — 2026-10-18

THREE FIXES ON THE WEIRLINGS TAB, all from the operator's own reading of the live fleet.

- An UNADOPTED weirling is listed only while it is online and still talking. `sensor_status`
  keeps seven days of heartbeats, so a sensor identity that stopped -- a pod name from an
  earlier rollout, a decommissioned unit, a host renamed once -- kept producing `unregistered`
  rows that no operator could act on. Measured on the box: a stale `Weirvern` identity 78,403s
  old sat beside the sensors that were feeding the hub. The view now applies the same
  `HEARTBEAT_STALE_S` window every other panel uses, before the header is counted, so the rows
  and the counts cannot disagree. Registered sensors are untouched: `stale` still says a
  declared sensor went quiet.
- Selecting a row no longer opens it. The checkbox's click bubbled to the row's own drill-down
  handler, so the one control meant to be a quiet selection also opened the sensor sheet.
- Every row carries a checkbox, including an undeclared one, and the bulk bar offers only what
  the selection can do: `Adopt selected` for undeclared sensors, the declared-only verbs
  (enable, disable, re-apply, revoke) for adopted ones.

## 0.17.0 — 2026-10-17

THE THEME AND BUTTONOLOGY PROGRAM — all twenty cards, shipped and evidenced.

The console was studied against production consoles (Elastic, Security Onion, OPNsense/pfSense,
the commercial fleet tools) and rebuilt around what those products got right: one vocabulary,
flows that survive an outage, and destructive actions that cannot lie.

WHAT SHIPPED, BY CARD:

- Settings: a full audit of every control; a runtime-vs-apply semantics badge derived from the
  writer's own table (a row cannot promise "no restart" while the writer restarts);
  apply-time checks that BLOCK a write and name themselves (plan completeness via the fleet's
  own validator, capture-interface vs live heartbeats, threshold vs the last 24h baseline),
  with skips that carry their reasons; a no-JS panic page for the outage the console must
  help fix.
- Sluice Gate: the auto-block is loud wherever the fleet is and pausable in one click.
- Weirlings: the fleet is a triage worklist (counts ARE filters, filters ride the URL, built-in
  and saved views, bulk actions, inline enable/disable) with a right-edge slide-in sheet for
  the drill-down (one exit, four doors; focus moves in).
- Alerts: a detector registry where names are load-bearing, `may_page` gates the pager FIRST,
  and a budget line says the open difference aloud.
- Health: a pipeline self-audit whose classes read INDEPENDENTLY ("nothing found" and "the
  check did not run" can never look alike), each finding next to its one-click fix.
- Navigation: fourteen tabs become six labelled groups in one row (nothing hidden, no
  sub-menus), breadcrumbs carry a drill-down's path back, and a command palette (Ctrl/Cmd-K or
  /) reaches tabs, sensors, settings and actions by DRIVING the real controls.
- Tiles and charts: label-above-value metric tiles with micro sparklines only where a series
  exists (current bucket in accent, the past in the chart's area colour, a stub for zero).
- Accessibility: color-scheme dark, aria-live on staged/apply status, a 2px focus ring with no
  holes, reduced motion honoured everywhere, themed scrollbars; the theme's token rule ("no
  hex outside the root block") is now a test.
- Destructive actions: an echo naming the exact target and blast radius with a REQUIRED reason
  recorded with the actor and the time (append-only `fleet_audit` trail), and a read-back that
  says pending until the world agrees — or "NOT APPLIED — check the sensor", a different word
  on purpose.

Underneath: a jsdom harness grown from 452 to 626 checks, mutation proofs for every behavioural
change, and a gate that has caught real defects on nearly every card.

## 0.16.0 — 2026-10-17

THE PER-WEIRLING INTERCEPT PLAN — siphon, per sensor.

Until now the intercept plan was DEPLOYMENT-GLOBAL: `INTERCEPT_*` in `weirvern-env` describes
exactly one sensor — the one whose worker reads that ConfigMap — so a second sensor had no way to
say "my segment is this, my gateway is that", and the hub had no way to tell it. The plan now
lives on the sensor's own registration in the hub's registry (`020_weirling_plan.sql`): mode
(`loch` or `siphon`), capture interface, segment, redirect address, gateway and targets, each
validated on write by the intercept's OWN rules (`intercept.parse_cidr`, the supervisor's target
expansion), so a plan the hub accepts is a plan the intercept honours. An incomplete plan is a
state, not an error: it is stored, and the sensor says what is missing.

The sensor's own agent now supervises the intercept **in its own deployment**, driving the SAME
`SiphonSupervisor` the hub's worker runs — same `weirvern intercept` child, same fail-open
watchdog restore, same bounded runs and self-destruct deadline, same capability gate — reading
its plan from its own registry row every 30 seconds. The hub's `SENSOR_MODE` is deliberately NOT
consulted (a unit inherits it through `envFrom`; obeying it would arm every weirling at once). A
failed plan read changes nothing, an unchanged plan is never rebuilt, and the one-writer rule for
the `(sensor_id, 'siphon')` heartbeat row is the same rule the worker follows.

The capability grant is opt-in per unit (`k8s/units/weirling-unit-siphon.yaml.template`: NET_RAW +
NET_ADMIN on the agent, `runAsUser: 0` because Kubernetes drops added capabilities for non-root,
and the privileged sysctl init container that saves the node's pre-change values under the unit's
own path and refuses to start a unit that believes it is intercepting but cannot forward). A unit
without the patch refuses to arm and says why on its own heartbeat.

The fleet view is where a person flips it: a registered, non-local weirling's drill-down offers
its own plan editor — mode, Sonar for that sensor's capture port, and the five plan fields —
through the same staged-then-applied shape as Settings (`/api/weirlings/plan`, then
`/api/weirlings/apply`): the preview validates with the write's own parser and carries the in-path
cost on the mode change. Selecting `siphon` surveys that sensor's port first and stages what it
measured. The reply says the sensor applies it within about 30 seconds — the panel never claims it
armed, because only the sensor's heartbeat can say that, and a plan that cannot arm yet says what
is missing on the row. Controls that could not mean anything are not rendered: this hub's own
sensor keeps the Settings grid, and an undeclared sensor has to be adopted first.

## 0.15.0 — 2026-10-17

THE ALERT ACTION CELL. Every anomaly row now carries its three one-click actions -- Evidence
(the raw records behind the alert), Block... (the Sluice Gate form: all traffic or one
service), and Watch: a new persistent, server-side "track this host" list (schema
021_host_watches, ReplacingMergeTree keyed by address) with a watched-only filter beside the
existing queue filters. Watch follows the host across windows; it is not an anomaly
disposition (that stays the Review chip, and the column is now labelled Actions). The watch
read is fail-soft in the house style: a deployment whose schema job has not re-run shows
"Watch unavailable" on the rows and disables the filter rather than claiming nothing is
watched, and the filter is skipped entirely when the read failed.

## 0.14.4 — 2026-10-17

Chips catch up, and native controls join the palette. The fleet's state chips
(alive/stale/never seen/unregistered/disabled) rendered neutral since the fleet shipped -- the
state colour lived only in the row's left bar; they now wear the same wash fills as every
other chip, so word and colour arrive together. The review dispositions follow (ack/resolved
washed; "review unavailable" keeps its deliberately-different dashed edge). Native
checkboxes and radios adopt the accent via accent-color.

## 0.14.3 — 2026-10-17

THE VISIBLE LAYER — the theme becomes unmistakable. Filled accent buttons (a primary action
is a blue button now, not an outlined one), status chips wear soft wash fills instead of
outlines, severity tiles are raised and rounded, headers/nav/tables breathe (bigger type,
more space, hover states), the login card floats like every other surface, and the chart
series are retinted onto the palette. Phase 1 changed the tokens; this pass changes what the
eye lands on.

## 0.14.2 — 2026-10-17

THE VISUAL THEME, PHASE 1 — the console stops looking like a code host. Palette: one neutral
ramp on near-black (canvas #131416 -> surface #1c1e21 -> raised #282b2f), hairline dividers,
one accent spent only on active/selected/primary, offline/disabled neutral (never red),
statuses re-tuned. Typography: a 13px UI on the Inter stack, 19/28 page title at weight 400,
15/24 sentence-case card titles, uppercase retired everywhere, metric values the one loud
number (27/36, tabular). Cards: shadow + hairline ring instead of drawn borders. New:
docs/theme.md — the authoritative spec (principles, tokens, recipes, phases, deliberate
refusals).

## 0.14.1 — 2026-10-17

EVERY HEARTBEAT WRITER REPORTS INTERFACES. The weirling agents' own beat path
(`sensor_agent.py`) and two more call sites predated the interfaces column, so their rows
carried `[]` while the hub's carried its NICs — found on the box, where the panel showed
one sensor with NICs and its siblings without. The interface list now comes from one shared
`status.sensor_interfaces()` that every writer (hub worker, agents, final beats) calls.

## 0.14.0 — 2026-10-17

ONE SENSOR, ONE PANEL. The weirlings drill-down now owns the sensor's runtime surface: status,
its NICs (reported by the sensor's own heartbeat — new `sensor_status.interfaces` column,
schema 019), a mode selector that enables siphon in one action (Sonar first when needed, then
the ordinary plan-and-apply path with every server-side gate), the Sonar survey and the test
run — with the full settings grid under ``Advanced``. The Settings page no longer carries a
Weirling-settings card, and the standalone Register card is gone: registration is the sensor
panel's one-click button, from the sensor's own reports. Netflow renders as a single checkbox
(``channel_netflow`` as a valued toggle staging ``upstream``/``off``). Also: the heartbeat's
sensor identity mirrors the worker's (``SENSOR_ID → NODE_NAME → HOSTNAME``), so a host name
that differs from the node name can no longer split one sensor into two rows.


## Unreleased — flow records from wherever the traffic is

TWO WAYS A SENSOR CAN BECOME A FLOW SOURCE, both of them gated on evidence rather than on
configuration, because a tap started on the strength of a ConfigMap produces records of traffic
that is not crossing the box -- landing in the very table the volume baselines train on.

**A LIVE SIPHON INTERCEPT CAN NOW BE METERED.** `SIPHON_NETFLOW=1` runs the same probe the channel
uses (bounded rotating capture segments, each summarised into IPFIX, into the same `flows` table),
against the interface the intercept's traffic actually relays through -- and only while the
intercept is VERIFIED live, through the same liveness check the gate uses. It stops the moment the
intercept does. ONE TAP PER BOX: when the channel selection is collecting, it wins, because two
taps would count the same conversation twice.

**AND ANY SENSOR CAN RECEIVE NETFLOW, IF ENABLED.** A unit can now run a collector of its own
(goflow2, the hub's own image and arguments) so that an exporter on *its* segment has somewhere to
send, and the unit's agent ships what arrives into the hub's `flows` table through the ingester's
own code path -- same parser, same byte cursor across restarts, same exclusion filter. No second
transport to secure and no second definition of what a flow row is. The shipping half is one env
var (`WEIRLING_NETFLOW`), the collector ships disabled with the unit, and a unit whose collector has
never seen an exporter ships nothing at all: that is a state, not an error. `deploy-weirling.sh
--netflow` installs both on a remote box.

## Unreleased — force a retrain, then keep it or trash it

CAN WE SEE THAT ML IS ACTUALLY WORKING? Yes, and the honest form of that answer is not a green
dot: it is to train the same detectors again on the traffic you have now, show what they built,
and let the operator decide whether that is what should be watching the segment. The Models view
gains the control.

TWO RULES MAKE IT TRUSTWORTHY, and both exist because the alternative fails quietly. A forced
retrain NEVER touches the live artifacts: it trains into `<MODEL_DIR>/candidate`, reports, and
stops -- nothing scoring traffic changes until Keep, so "was that a good idea?" is answered BEFORE
the model watching the network is replaced. And the report says WHAT THE WINDOW CONTAINED: a
retrain learns from whatever it is shown, so a window holding an attack teaches the new model that
the attack is normal. The machine cannot know whether the traffic was friendly; the operator can.
The count of detections this deployment already recorded inside the window is computed and put
beside the decision, in one sentence, with the per-detector rows it trained on.

Keep installs the candidate over the live artifacts and ARCHIVES what it replaced (a worse retrain
must be undoable without re-running anything), then reloads the running detectors in place so the
pod starts scoring with them immediately. Trash deletes the candidate and the live models were
never touched. Keep is offered only when the candidate actually trained something: a retrain that
found no data has nothing to install, and a button there would offer to replace working models with
an empty set.

THE WORK HAPPENS IN THE WORKER, which owns the model directory; the GUI files a request and reads
the result back. The channel between the two pods is ClickHouse (`weirvern.model_actions`), for the
same reason the gate's rule store is: a decision made in one process and read in another must be
visible in both and survive a restart of either. A request that cannot be carried out becomes
`failed` WITH ITS REASON -- a row that sits in `requested` forever looks like a worker that is busy.

## Unreleased — the gate follows the capability: any sensor that can enforce, does

`WEIRVERN_ROLE=gate` turns a weirling into a second ENFORCER. One rule store, many gates: the hub
derives the rules from detections, and every sensor that sits in the path installs the same rules on
its own segment -- with the hub's own checks, because it is the hub's own code. A box with an in-line
path (its own channel bridge, or a live siphon intercept) and the ability to install a ruleset is a
place traffic can be stopped; a box without one reports DEGRADED and blocks nothing. Nothing is taken
on faith from a ConfigMap: the path is VERIFIED, the ruleset must be READABLE (an unreadable one
leaves the gate as it is and never reopens it), and the interface is never the management NIC.
`SLUICE_ENABLED=0` disarms on a weirling exactly as it does on the hub.

A WEIRLING GATE DERIVES NOTHING. The hub is the single writer: a second deriver would mint a second
rule for the same detection, and the operator who revoked one would keep being blocked by the other
-- the worst possible way for two gates to disagree. It also does not ingest, detect, or train, so a
sensor cannot double-count its own segment in the hub's database.

THE FLEET'S GATES ARE VISIBLE. The Sluice view lists every gate with its state, interface, rules
active/total and packets blocked, marked for this hub, and a gate that has STOPPED reporting is
called out: four missed intervals -- or an unreadable timestamp -- marks it stale, because a segment
the operator believes is filtered and is not is the worst state this feature can produce.

The delivery matches the design: the unit template carries the gate container (NET_ADMIN, host
network) and ships it DISABLED, because each sensor in its own configuration is the point of a fleet;
and `deploy-weirling.sh --gate --gate-iface IFACE` installs one on a remote box, refusing the
management NIC and refusing to default to the capture port -- a mirror enforces nothing.

## Unreleased — the operator's hand on the gate: block from an alert, and a threshold that blocks for you

Two instruments for the operator, plus the two JA4 gaps the audit left open.

THE ALERT CAN BE SENT TO THE GATE DIRECTLY. Every row on the anomalies list (and the verdict on
the evidence page) now carries the action, so an operator reading an alert does not have to
remember the host, walk to the gate view and retype it. The control is OFFERED ONLY WHEN IT WOULD
DO SOMETHING: it reads the gate's own state, and when the gate is off -- or on, but with no
verified enforcement path, which is loch with no channel and no live intercept, where a block
compiles, counts its own drops and stops nothing -- it states that reason in the row instead of
offering a button. A disabled button still reads as "this is possible" to someone skimming. The
form is the Gate view's own vocabulary (src_cidr / protocol / dst_port / direction / ttl_minutes /
reason), so a rule filed from an alert is the same object in the same store with the same revoke
path; the reason is PRE-FILLED from the alert (score, host, window) because a block whose reason
is empty is unanswerable three weeks later, and the server still refuses an empty one.

AUTO-BLOCK OVER A CUSTOM THRESHOLD. `SLUICE_AUTO_SCORE` (Settings → Sluice Gate, or the
ConfigMap) is the operator's own line on the fused 0-1 score: any detection at or above it is
blocked on the gate's next pass, independent of the severity policy -- two ways in, and a
detection clearing either is blocked. It defaults to 0, which means off, so the shipped behaviour
is unchanged; a score-triggered block takes a 30-minute TTL, always capped by
`SLUICE_MAX_BLOCK_S`, and the reason string names the threshold, because "why is this blocked" is
asked weeks later. The worker reads detections when EITHER instrument is set -- reading them only
for a policy above Off would have made the threshold silently inert, the exact defect the JA4
novelty audit found elsewhere.

TWO THINGS THE OPERATOR ASKED FOR AFTER USING IT (2026-10-16): the reason is now OPTIONAL on a
manual block, and a duration of 0 means UNTIL REVOKED. The reason stays mandatory in the one place
it matters -- a derived block always writes one, because that is the block nobody was watching --
and the form still pre-fills it from the alert; a blank one is stored blank rather than replaced by
a placeholder that would read like a fact in an audit row. For the duration, `expires_at` becomes
NULLABLE (schema/014) and NULL means indefinitely: deliberately not a far-future timestamp, which
every view would format as a plausible date and which would be a lie in the store. Both places that
filter live rules -- the SQL and `Rule.is_live()` -- treat NULL as LIVE, and a row with no expiry
reads as "until revoked" in the rules list rather than "never". The old behaviour was the reverse
in both directions: a non-positive TTL was refused outright and a null expiry was treated as inert.
That was the right default and the wrong ceiling, and the operator's instruction is the override.

THE EVIDENCE PAGE CAN SHOW THE TLS RECORDS. `/api/evidence` now carries a `zeek_ssl` section
(timestamp, destination, port, version, server name, ja4, ja4_orig), so a JA4-driven alert pivots
to the sessions that carried the new stack -- before this, the page showed every signal except
the one the verdict was about.

AND THE LOOKUP THAT POINTS THE OTHER WAY: the identity view takes a JA4 fingerprint and lists
every host that presented it in the last seven days, with session counts and first/last sighting,
each row opening the host's drill-down. The card answered "what does this host run?"; this
answers "who else presents this stack?", which is the direction an analyst arrives from. It reads
the raw session records, so it works while a fleet is still being identified, and a lookup with
no hits SAYS it found nothing in the window rather than implying the fingerprint is unused.

## Unreleased — the alert's why-line can see a new TLS stack

The models score the JA4 features; the explanation spoke only about volume, so an alert whose
score came from a never-before-used TLS stack said "bytes normal" -- true, and useless, on the
one page an analyst reads for the WHY. The comparison sentence now carries the clause when the
window holds fingerprints the host has not used before: "1 of 2 TLS fingerprints in this window
is new for this host", computed with the same exact-membership arithmetic the feature uses (and
the same conservative count-based lower bound when only a count is available -- it never claims
more novelty than the model saw). A TLS-only anomaly, where every volumetric measurement is
unremarkable, gets its sentence instead of "no comparable measurements"; a familiar stack adds
nothing; and with no baseline there is no history to compare against, so no clause is invented.

## Unreleased — DBSCAN gets the JA4 pair

The clustering specialist\'s Zeek subset gains `zeek_ja4_count` and `zeek_ja4_novelty`
(appended, never inserted), so a host presenting a TLS stack it has never used before is
visible to every model that scores, not only the two wide ones. The cost is stated rather than
hidden: two more dimensions on a feature space kept small on purpose, and most host-windows
carry a zero there (a host with no TLS is 0 for both, exactly as it is for the logs it never
speaks). DBSCAN\'s answer to sparse density is unchanged and honest -- "no opinion" rather than
a fabricated one -- so a wider vector cannot make it lie, only quieter.

This changes the DBSCAN vector\'s SHAPE, so `FEATURE_SCHEMA_VERSION` moves to 2: v1 artifacts
are refused at load and the detectors retrain into `_v2.pkl`; the v1 files stay on disk for
rollback. The source-coverage proof pins the new membership in the same direction as every
other claim: removing the pair again fails the proof.

## Unreleased — JA4 novelty learns to see history: the two links that were never connected

"Verify that JA4 is being assessed by all the models." The verification found that the feature
built for exactly that — `zeek_ja4_novelty`, the share of a window's TLS fingerprints the host
has never presented before — was not live anywhere, in three separate ways:

  * `zeek_baseline_ja4_sql`, the query that computes the host's fingerprint HISTORY, had no
    production caller. Scoring handed the extractor a baseline with no `baseline_ja4_set`, the
    extractor took its conservative floor, and novelty reported "entirely novel" (1.0) for
    every host-window that used TLS at all.
  * In every TRAINING matrix, `zeek_ja4_novelty` and `zeek_service_rarity` were constant `0`
    placeholders — "filled by the caller that holds the baseline", and the caller that trains
    never had one. A model cannot use a column it never saw vary.
  * The seven Zeek counts were log-scaled at scoring and RAW in training: the same window meant
    different numbers on the two sides of the pipeline.

All three are fixed and pinned by tests. The summary now computes both comparison features from
`hist_ja4` / `hist_svc` windows — 72h, ending exactly where the feature range begins, the same
span the Adaptive Baseline holds — the baseline detector carries `baseline_ja4_set`,
`baseline_ja4_count` and `baseline_service_count` into every host baseline (with a
`hosts_with_fp_history` metric), and the counts are log1p'd in SQL exactly as the scoring path
does them. Verified against a live ClickHouse with seeded fingerprints — two familiar, one new
means novelty is exactly 0.5; service rarity exactly 1/3; SQL and Python parity — and that run
caught a bug only a server can find: ClickHouse has no `size()`, it is `length()`.

## Unreleased — the source-coverage proof, and a README that says what ships

"Verify with proof that JA4 and every Zeek log are assessed by every model." The answer is a
matrix, now enforced mechanically by `tests/test_ml_source_coverage.py`: the two wide models
carry the full Zeek block — JA4 included, both features, with the runtime supply asserted end
to end (the worker attaches the window row, the ensemble hands over the host baseline) — the
Adaptive Baseline trains on every Zeek feature and scores three named signals, DBSCAN's
six-feature subset derives to conn/notice/weird, and the logs without host features are exactly
the earned exemptions the sibling coverage file asserts, checked in both directions. A renamed
aggregate, a moved log or a dropped feature now fails the proof instead of quietly changing
what the deployment assesses.

The README loses its ASCII architecture diagram for plain words and gains the channel mode,
the Sluice Gate's kernel-verified enforcement story, and the channel/Sluice settings that were
missing from the configuration table.

## Unreleased — the channel's traffic becomes NetFlow: a selection, not a second pipeline

When the box is IN LINE, every frame crossing it is visible to it — and that visibility stopped
at Zeek's logs. A new selection (Settings → Sensor → "channel flow capture": off / upstream /
downstream) runs a supervised `softflowd` probe on the chosen channel port and exports NetFlow
to the deployment's OWN collector, so the records land in the same `flows` table the Netflow tab
and the models already read. One port is enough: either port sees every frame crossing the
bridge, so sampling both would count each conversation twice.

The probe is supervised like every other child in this worker: started only when the selection
and a VERIFIED-active channel agree (the same kernel checks the gate uses), stopped the moment
either changes, stopped on worker shutdown so softflowd flushes its pending flows, and retried
on a five-minute cooldown after a crash — a missing capability cannot produce a log line and a
doomed child every minute. The image contract gains a `softflowd` clause: without the binary the
selection would be silently inert, the same class the nftables clause exists for.

**The capture is a tcpdump tap piped into softflowd — every part of that choice measured.** The
first live run produced the probe running, the channel verified, and zero records: softflowd's
own live-capture loop is broken on this kernel (its libpcap counter grew with every packet while
"Packets processed" stayed 0, on a bridge port and a plain NIC alike; strace shows its poll on
the packet-ring socket never firing, while tcpdump's blocking read from the same socket captures
fine). softflowd reading a pcap STREAM processes perfectly, and goflow2 ingests its IPFIX (v10)
but silently DROPS its v9. So the probe runs tcpdump → softflowd → IPFIX on 127.0.0.1:2055, and
the records land in the same `flows` table the Netflow tab and the models read. The image
contract pins both binaries; the supervision matrix runs against fake processes.

**And the tap runs with `-Z root`, because Debian's tcpdump drops privileges to a `tcpdump`
user that cannot be switched to inside this container** — "Couldn't change to 'tcpdump' ...:
Operation not permitted" — and exits instantly, taking the summariser with it (EOF on the
pipe). Measured, as was the swallowing half of the bug: both children's stderr now goes to the
pod log instead of /dev/null, so the next failure of this kind is legible rather than silent.

**The stream is SEGMENTED, because softflowd blocks forever on a live pipe — measured.** With
the tap alive and packets demonstrably written into a pipe (tcpdump: 58 captured, 2760 bytes in
6s), softflowd reading that live pipe processed zero and did not even answer SIGTERM; the same
softflowd reading those same bytes after EOF (a file, or `cat file |`) processed 30/30 and its
exports landed in goflow2. So the tap writes bounded rotating segments (-C 16MB, -G 30s, -W 240)
and every pass summarises each COMPLETED segment with a one-shot softflowd — deleting it on
success, keeping it on failure so the evidence is not discarded. "Off" removes the tap AND the
pending segments: captured traffic must not survive the switch.

**Four more measured repairs followed, each pinned by its own test.** The segment directory
moved to the pod's own `/tmp`, because the flow-data mount is read-only BY DESIGN — the worker
reads goflow2's output and must not be able to corrupt it. The sweep learned the names
tcpdump's `-W` actually writes (`…pcap000`; a `.pcap` suffix filter matched nothing and said
nothing). The one-shot summariser dropped its pidfile and control socket — that form hung for
the runner's whole timeout while the same file summarised cleanly without them. And the sweep's
age check was given wall time: handed the tick's monotonic clock, `monotonic − mtime` is a huge
negative and every segment read as "too young" while the sweep ran on schedule.

## Unreleased — everything clickable: the gate gets its switches, and the console gets its circle-i

Two requests, one theme: nothing important should require kubectl or a manual.

**The Sluice Gate is operator-clickable.** All five of its switches — enabled, enforcement
interface, block-on-detections policy, longest block, re-check interval — were ConfigMap-only:
operating the gate meant patching the cluster and restarting the worker. They are now settings
rows like every other control, with the same contract as the rest of the tab: a natural control
(toggle / dropdown / bounded number), a plain-language explanation of what each does and what it
costs, a stated restart target, and server-side validation that refuses a dangerous value before
it is written (`SLUICE_IFACE` pointing at the management interface is refused at author time,
with the same reasoning the gate itself uses at arm time; the criticality dropdown offers exactly
the policies the validator accepts — asserted against the policy table itself).

**The re-check promise is now kept.** The worker claimed the gate ran on its own cadence, and
the panel promised rule changes land "within 60s" — but the pass ran inside the 300-second
detection loop, so the real cadence was five minutes (measured live: 301s between passes). The
loop now sleeps in slices no longer than the gate's interval, so a filed block enforces and a
lapsed one lifts on the stated timescale. Shutdown responsiveness is unchanged: a stop still
interrupts a slice immediately.

**"Disabled" now means gone, even across restarts.** Measured on the test box: a worker starting
with `SLUICE_ENABLED=0` left the (inert, empty-sets) `table inet weirvern_sluice` behind, because
the in-memory "armed" flag cannot see a table armed by a *previous* process. The disabled path
now asks the kernel once per process (`installed()`) and removes any leftover, naming it in the
log. Both behaviours carry tests that fail on the old code.

**One "i" in a circle, everywhere.** The operator asked for it by name: circle-i buttons that
open more information, throughout the console. Every view's explainer is now that button beside
the panel title — Network, Netflow, Zeek, Anomalies, Identity, Models, Sluice, Weirlings, Health
and Assets — with the old "?" glyph retired; one glyph for one habit. The settings rows keep
their per-row server-driven help, same glyph, same interaction. The jsdom harness clicks one and
asserts the panel opens and `aria-expanded` follows; `tests/test_gui_info.py` holds the contract
that a button never points at a panel that does not exist.

## Unreleased — the GUI fits a pocket: the same console on a phone and on a desk

The console assumed a wall display, and it read that way on a phone: eleven tabs in a fixed
row, tables wider than the screen dragging the whole page sideways, and settings rows whose
controls sat at the far edge of a label. Nothing about the desktop layout changed -- the
breakpoints only describe what happens below it:

- **The grid track cap.** `minmax(380px, 1fr)` overflowed every viewport narrower than the
  track's own minimum -- a phone in portrait, a split window -- before any table was involved;
  the minimum is now `min(380px, 100%)`.
- **The nav strip scrolls.** Eleven tabs stopped fitting around 1100px, which was already true
  on a laptop half-screen. Tabs keep their intrinsic width; the strip scrolls.
- **Every table gets its own horizontal scroll box** (`wrapTables()` in app.js, boxes styled as
  `.tablewrap`): a wide table must scroll ITSELF, not widen the page. The DOM harness checks
  the wrapping, that boot calls it, and that a second call cannot nest the boxes.
- **Phone breakpoints (720px / 420px):** 16px form controls (iOS Safari zooms the whole page
  under that on focus and every tap after that lands slightly wrong), settings rows stacked
  with full-width controls, a shorter force-map canvas, larger tap targets, and the active tab
  kept in view when a row click changes views.
- **The harness cannot see @media rules** -- jsdom ignores them in getComputedStyle, measured --
  so the breakpoint behaviour was verified in a real browser at phone and desktop widths. The
  harness holds the base rules and the JS half; `tests/test_gui_responsive.py` holds the source
  contract, so deleting the responsive section fails a machine rather than a phone.

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
under its own shebang, and runs the jsdom DOM harness (309 checks; it executes the
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

**The fleet view registers what it can see, in one click.** The undeclared sensor's guidance
said "Register it above" while the id sat in the row in front of the operator; the first
question the view produced at the first deployment was "where do i get the sensor id". An
undeclared sensor's drill-down now carries a **Register this sensor** button that files the
declaration from the sensor's OWN reports -- its id, its reported mode, its observed address --
and leaves the declared segment empty on purpose, because copying the reported one in would
manufacture a declaration nobody made.

**And the Weirlings controls had never been wired at all.** `wireWeirlings()` existed and
nothing called it: the detail panel's Close / Enable / Switch off / Revoke and the register
form's own button all RENDERED and did nothing -- a dead panel that looked perfect, this
project's most-repeated defect class in its best costume yet. It was found by the first click
assertion ever written against this tab (the register button's POST), and the fix is the
guarded bootstrap call beside `wireSluice()` that the one-place-wiring convention always
intended. The harness now pins BOTH halves: the observed-identity POST, and two clicks proving
the panel and the form are bound rather than decorative.

**The sensor's settings live with the sensor now.** "Configure each weirling" -- the sensor's
controls (mode, the siphon plan, Sonar, the test run) moved out of the global Settings tab and
into the Weirlings drill-down. The honest boundary shaped it: a runtime can only be changed on
the box that runs it, so the fleet payload marks the LOCAL row (this deployment's own sensor
identity, the same helper the Sluice gate reads) and the panel mounts only there; every other
sensor gets the sentence saying where its settings are, instead of knobs that would write to
the wrong machine. Settings keeps a pointer, the stage/apply queue stays the one write surface,
and the harness drives the moved controls in their new home -- the local row offers them, a
remote row does not, and the moved row's "?" still explains itself.

**The sensor unit: a weirling you can run twice.** One capture port, one identity, reportable
as its own fleet row — the piece both "a sensor installed elsewhere" and "two sensors on one
host" needed, because a deployment's worker speaks for exactly one sensor identity. It reuses
the product's own halves rather than restating them: `sensorwatch.observe()` derives the
heartbeat from the LOGS (newest mtime = capturing; Zeek's capture_loss.log = loss and counters;
`None` stays not-measured, never a fake 0.0), and the capture-port check runs the same probe
`weirvern interfaces` runs, refusing outright — SystemExit, not a warning — when `ZEEK_IFACE`
is the default-route (management) NIC. Entrypoint: `python3 -m weirvern.admin.sensor_agent`;
pinned by ten tests (the refusals, the identity and port contracts, observed-state beats, a
dead capture reading as not-running, and the module being runnable as the manifest's
entrypoint).

**A weirling installs on another box with one command.** `scripts/deploy-weirling.sh` runs where
the operator is, reaches the hub and the target over ssh, and leaves two containers plus a small
local helper (`weirvern-weirling status|start|stop`) behind: Zeek on one dedicated NIC and the
heartbeat agent, reporting into the hub's database under their own identity. The management NIC
is refused on BOTH sides of the wire — at deploy time against the target's live default route,
and again by the helper before it starts — and registration is deliberately NOT done for you:
the row appears in the Weirlings view as UNREGISTERED until someone declares it. Its own first
live runs shaped it: every target now uses ONE door (`clickhouse-external`; the in-cluster
`clickhouse` Service is headless, and the first version shipped the literal string "None" into
the agent's config), a reachability knock with the real client runs before anything starts (the
agent retries forever by design, so a wrong address would otherwise spin silently), and the
NodePort is opened by changing only the service TYPE — rebuilding the ports list tripped over
`targetPort: http`, a named port (a string), which interpolated as bare JSON. Exercised
end-to-end: dry-runs refusing the management NIC / a missing port / a bad identity, a full
install whose heartbeat was verified in the hub's database, and the removal path.

**The firewall check could not read its own host, and its own remedy could not satisfy it.** Found
running the first live siphon bursts on CT 111 — both defects refusing a correctly configured node:
(1) the worker image ships `nft` and NOT `iptables` (the Sluice Gate needs nft; the image-contract
test pins it), so `forward_policy()` read UNKNOWN and refused every intercept, while `nft` could
read the same iptables-nft ruleset perfectly; (2) the check only ever read the policy LINE, so the
two interface-scoped ACCEPT rules its refusal message tells the operator to insert — the measured
working state ("59.9 Gbits/sec" in this module's own test notes) — could never satisfy it. The
check now reads via `nft` as a last-resort fallback, passes when its printed remedy is actually in
place, still refuses on DROP without the rules, and still refuses when nothing is readable. Five
new tests; the two pinning the defects fail on the previous code.

**A channel: a weirling wired IN LINE, and the gate verifies it before claiming anything.** An
upstream port and a downstream port joined into one bridge put this host physically in the traffic
path, so the Sluice Gate's blocks drop REAL traffic while the sensor stays in passive `loch` mode —
nothing forged, nothing redirected, enforcement no longer tied to siphon. And the gate stops
trusting configuration: `enforcement_pass` now resolves and RECORDS the live path — `channel` /
`siphon` / `none` (new column on `sluice_state`, migration 013) — where siphon counts only with
LIVE intercept evidence (a configured siphon with no running intercept degrades, loudly) and a
channel only when the kernel agrees: both ports on one forwarding bridge with carrier, and
bridge-nf enabled for both families (without it, bridged traffic never reaches the inet forward
hook the rules live on — the rules would install, count nothing, and read ARMED). The worker
resolves its enforcement interface from that verified topology (SLUICE_IFACE, else the channel's
bridge, else the capture port) and rebuilds the supervisor when it moves, so a relocated gate
cannot inherit a stale "recently confirmed" age. `CHANNEL_UPSTREAM` / `CHANNEL_DOWNSTREAM` are
editable Settings rows with help text. Tests: `tests/test_channel.py` — every check, and the whole
verdict matrix.

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

## 0.13.0 — 2026-09-24

Everything below this heading existed at the 0.13.0 version bump (`c774d3d`, 2026-09-24) and
shipped in that release; everything above it was added afterwards and is unreleased.

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
- The deleted `tests/test_attack_wiring.py` asserted that the *invented* names exist — written against the
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
