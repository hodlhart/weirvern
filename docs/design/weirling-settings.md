# Weirling settings: one home per value

**Status:** design for the `weirvern-settings-merge` board (WSM-1). Implementation lives in
WSM-2..WSM-9.

**The operator's instruction (2026-10-18):** "remove weirling settings from the settings tab and
move it to the weirling pop out on the weirling tab. Selecting a weirling opens the settings for
that specific one."

This reverses the 2026-10-18 arrangement that pinned the sensor controls to Settings (see
`tests/test_settings_tab.py::test_the_sensor_controls_live_on_settings_and_nowhere_else`). That
arrangement was itself a retreat from the 2026-10-17 attempt, which **duplicated** the sensor grid
inside the weirling sheet, left Settings' Sensor card empty, and put the copy behind an "Advanced"
disclosure. The lesson is the rule below, not "never put settings in the sheet".

## The rule

**One control surface per value.** A value is rendered where its owner works, exactly once. The
weirling sheet is the change surface for a weirling; Settings is the change surface for deployment
behaviour that is not a property of a sensor.

The sheet opens for a specific sensor. What it can change is decided by which sensor that is:

- **This hub's own weirling** (`local: true`): the deployment's sensor settings — the ConfigMap
  the hub's own daemon reads — plus Sonar and the 30-second test run. These are the same writes
  Settings used to offer, moved, not copied.
- **A remote weirling** (registered, not local): its per-sensor intercept plan (mode, capture
  interface, segment, address, gateway, targets), which travels in its registry row and its own
  agent applies. The box's runtime settings are not reachable from this hub; the sheet says so in
  one sentence and renders no dead control.
- **An undeclared weirling**: Adopt only. Settings appear once it is declared (and, for a local
  row, they are available even before adoption — see "fresh hub" below).

## The decision table

Every key in `_SETTINGS_GROUPS` group `("sensor", "Weirling", ...)` appears exactly once below.
"Staged" means the ordinary `/api/settings/plan` → `/api/settings/apply` path with its plan,
confirmation and apply-time checks.

| Key | What it configures | Owner surface | Write route | Why |
|---|---|---|---|---|
| `sensor_mode` | loch / siphon for this hub's capture | local weirling sheet | staged (`sensor_mode`) + destructive echo | It is this box's mode; the fleet row reports it. |
| `zeek_iface` | Zeek's capture interface on this hub | local weirling sheet | staged | A property of this box's capture, not of the deployment's detectors. |
| `mgmt_iface` | management interface on this hub | local weirling sheet | staged | Same box, used to avoid capturing its own management traffic. |
| `zeek_log_dir` | where Zeek writes on this hub | local weirling sheet | staged | Box-local path. |
| `tail_file` | the NetFlow tail this hub reads | local weirling sheet | staged | Box-local path. |
| `intercept_targets` | default targets for this hub's intercept | local weirling sheet | staged | The CLI fallback on this box; a REMOTE sensor's targets live in its plan. |
| `intercept_segment` | default segment for this hub's intercept | local weirling sheet | staged | Same: ConfigMap fallback for this box, not a fleet-wide declaration. |
| `intercept_addr` | default borrowed address | local weirling sheet | staged | Same. |
| `intercept_gateway` | default gateway to relay | local weirling sheet | staged | Same. |
| `channel_upstream` | in-line channel upstream port | local weirling sheet | staged | The channel runs on this box. |
| `channel_downstream` | in-line channel downstream port | local weirling sheet | staged | Same. |
| `channel_netflow` | whether channel traffic becomes flow records | local weirling sheet | staged | Same. |
| `siphon_netflow` | whether intercept traffic becomes flow records | local weirling sheet | staged | Same. |
| `exclude_cidrs` | traffic excluded from learning | local weirling sheet | staged | The capture's own exclusion list. |
| `capture_exclude_cidrs` | traffic excluded at capture | local weirling sheet | staged | Same. |
| `reverse_dns` | reverse-DNS on/off for the DNS view | **Settings**, new `dns` group | staged | It changes the DNS view's behaviour, not what the sensor captures. Keeping it in the sensor group is what made "weirling settings" mean two different things. |

Rows that are NOT in the sensor group stay where they are: Detection (`detect`), Sluice Gate
(`sluice`), Blocklists (`blocklists`), Storage and runtime (`runtime`).

### What the sheet says for a remote sensor

> "This weirling applies the plan above itself. Its capture interfaces, Zeek paths and exclusion
> lists are configured on that box; this hub cannot change them."

No disabled inputs, no "Open Settings" (the card no longer exists), no invented values.

### Fresh hub (the local row is not registered yet)

The local sensor's row is marked `local` whether or not it has been adopted, so its settings
remain reachable: the sheet shows the settings section and the Adopt action together. Adoption is
a fleet declaration, not a prerequisite for configuring the box the console runs beside.

## The write path, unchanged

The moved controls keep their server contract: `/api/settings/plan` proposes and validates,
`/api/settings/apply` writes and reports per-item results, apply-time checks can block, and every
write is audited. The sheet gains a compact view of the SAME pending set — one `STAGE`, one
persisted key, one apply route — so a change staged in the sheet can be applied there and is also
visible on Settings, and the reverse. This is WSM-2 and is the card that must land before the
controls move.

## What is deliberately NOT in the sheet

- Detection thresholds, retraining cadence, Sluice enforcement, blocklists, ClickHouse/Pushover
  runtime: deployment behaviour, not this weirling's.
- A second copy of any sensor control. If a value needs to be visible in two places, the second
  place is a read-only summary with a link to the one control — never a second input.
- A plan editor for the hub's own sensor: the ConfigMap rows ARE its plan. A second editor would
  produce two modes for one sensor.

## Acceptance

- Every key in this table maps to exactly one owner surface and one write route.
- Every control the merged sheet renders exists exactly once in the document (a source assertion
  enumerating the keys finds none of them inside `#view-settings`).
- The retired pin is replaced by its inverse, with this document's date and the operator's
  instruction in the docstring.
- A live stage→apply→read-back from the sheet succeeds on the test box.
