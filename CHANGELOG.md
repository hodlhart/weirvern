# Changelog

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
