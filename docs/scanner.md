# Asset scanning: Nmap, executed by the weirlings

*Part of the [Weirvern](../README.md) documentation.*

Weirvern's active inventory is **Nmap -sV plus safe NSE identity scripts**. There is no Nuclei
pass, no template tree and no vulnerability verdict: a scan measures which services a host
exposes and what those services call themselves. That is evidence, not proof a host is patched.

## Who runs a scan

**Every weirling can scan, and only a weirling can.** The hub has no central scanner Deployment:
the old central scanner Deployment is gone. Each unit runs the sensor agent, which:

1. measures its own Nmap at startup (and re-measures every five minutes, so installing Nmap does
   not require a restart);
2. reports that capability — with its `/etc/os-release` distro and version — to the hub;
3. asks the hub for at most one queued manual job at a time, and **only if Nmap is present**;
4. runs `nmap -sV … -oX -` against the one address and sends the measured services and NSE
   observations back over the authenticated mTLS gateway. The hub writes them with the same
   recorder it has always used. On a unit that measured `syn/udp` the command omits
   `--unprivileged`, so Nmap uses SYN and UDP probes; a `connect`-only unit passes
   `--unprivileged` instead and the console says which mode it is.

A weirling that cannot scan reports `nmap missing` and never claims. The hub enforces the same
rule at claim time, so a queued job cannot be held by a node that cannot execute it.

## Scope: the networks the weirling declares

A weirling may only claim a job whose target is inside **the networks it declared** in its own
registration (`networks`, plus a `segment`/`plan_segment` that parses as a CIDR). The hub checks
this at claim time; an out-of-scope row stays queued for a weirling that can reach it. Job
creation is refused up front when **no registered weirling monitors the target**, and again when
weirlings can reach it but none reports Nmap. Both refusals are sentences the console shows:

```
0 of 1 weirling can scan: weirvern unknown (no capability report in 3d). Install Nmap on a
weirling ('sudo apt-get install -y nmap' or the command for its OS) and restart its agent.

no registered weirling monitors 198.51.100.57: wl-a declares 203.0.113.0/24.
Add the network to a weirling's registration first.
```

## Installing Nmap on a weirling

There are **two deployment shapes**, and the install path depends on which one you run. They do
not contradict each other: the agent always measures the filesystem IT runs in, so a package
installed on the host is invisible to a containerised agent and vice versa.

### A. Containerised weirling (the shipped installer): Nmap is in the image

Nothing is installed at runtime and there is nothing to click. `install.sh` builds
`weirvern-scan:<tag>` from `Containerfile.scanner`; that image installs `nmap` and
`libcap2-bin`, and runs

```bash
setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap
```

so a non-root agent receives both capabilities as file capabilities at exec.
`scripts/deploy-weirling.sh` selects `weirvern-scan:<worker tag>` for the agent container and
starts it with `--cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN`. **Both halves are
required:** a file capability outside the container's bounding set is ignored at exec, and a
bounding set with no file capability gives a non-root process nothing effective.

The agent reports `scan_mode: syn/udp`, so `/api/scan-readiness` reads:

```
1 of 1 weirling can scan (nmap 7.95, syn/udp)
```

and the Weirlings card hides **Install nmap** — there is nothing to install, and a container
cannot install into its own image (an install would also vanish on the next recreate). If the
hub lacks the scan image the installer says so, and the unit honestly reports `nmap missing`.
Build and import it on the hub:

```bash
docker build -t weirvern-scan:sha-<commit> -f Containerfile.scanner .
docker save weirvern-scan:sha-<commit> | k3s ctr images import -
```

`--agent-image <ref>` overrides the image selection when the tag does not follow the worker's.

**Size (measured).** The `nmap` + `libcap2-bin` layer is **29.1 MB** (`docker history`). The
whole scan image measures 518 MB against the worker's 521 MB because it does not copy the
archived `docs/reviews` directories the worker ships; older scan tags measured ~714 MB for that
reason. Nmap is still **not** in `Containerfile`: every hub workload (worker, GUI, ingest, schema
Job, prune CronJob) runs the worker image, and only a sensor's agent runs the scan image, so the
package cost is paid per weirling rather than per cluster workload.

The installer also verifies the result after starting the container: it runs `nmap --version`
inside `weirvern-agent-<id>`, reports the binary, the container capabilities, the uid and
`getcap`, and prints the readiness line the hub will show. A missing binary or incomplete
capability is a warning at install time, not a discovery in the console later.

### B. Non-containerised (or worker-image) weirling: install on the host

For a unit whose agent runs directly on the host — or an older unit still running the worker
image — install Nmap **on that host**. Two supported ways to give the agent the privilege, in
order of preference:

**B1. Scoped sudoers: one command, no password (recommended).** Give the agent's user one
sudoers entry that permits exactly the install command for that host's distro. The agent reports
`sudo_state=passwordless`, the console's **Install nmap** button appears with no password field,
and one click runs it. The grant is the allow-listed package-manager command, not root.

**B2. One-click prompt: the fallback, with a sudo password.** When the agent reports
`sudo_state=password`, the card shows *sudo password for &lt;host&gt;*. The password goes to the
console in a POST body, then over the cluster network to the ingest gateway, which holds it in
memory for at most five minutes; the weirling picks the request up on its own mTLS poll and
pipes the password to `sudo -S`. It is never stored in ClickHouse, never an environment variable,
never logged and never written to the audit row — which records the actor, host, command, exit
code and the FACT that a password was used. Three attempts per host per ten minutes.

After either install, run `sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap` on the host
so the agent reports `syn/udp` instead of `connect`; without it the scan is a TCP connect scan.

The console renders the exact command from the OS the agent reported, for every path:

| distro (`/etc/os-release` ID) | command |
| --- | --- |
| debian, ubuntu, linuxmint, pop, raspbian, kali, devuan, elementary | `sudo apt-get update && sudo apt-get install -y nmap` |
| fedora, rocky, almalinux, ol, rhel, centos (8+) | `sudo dnf install -y nmap` |
| centos, rhel (7 and older) | `sudo yum install -y nmap` |
| alpine | `sudo apk add --no-cache nmap` |
| arch, manjaro, endeavouros, garuda | `sudo pacman -S --noconfirm nmap` |
| opensuse-leap, opensuse-tumbleweed, sles | `sudo zypper install -y nmap` |
| **anything else** | the card says the OS is unknown and shows the generic instruction — it never guesses a package manager |

When neither a package manager nor a privilege path can be established, the **Prepare this
weirling** button copies the command for the operator to run by hand — never a password prompt
that cannot work. The full two-path tradeoff is in
[deployment.md](deployment.md#installing-nmap-on-a-weirling-two-paths).

## The shipped installer: Docker containers, not a systemd unit

`scripts/deploy-weirling.sh` is the only shipped way to put a weirling on a box. It runs where you
are, reaches the hub and the target over ssh (`--target local` means the box it runs on), and
leaves Docker containers on the target plus a local operator helper:

```bash
scripts/deploy-weirling.sh --hub <hub-ssh> --target <target-ssh> \
        --iface <capture-port> --sensor-id <id> [--segment <label>]
```

| Container | Role | Started by |
| --- | --- | --- |
| `weirvern-capture-<id>` | Zeek on the capture port (host network, `NET_RAW` only) | always |
| `weirvern-agent-<id>` | the sensor agent: heartbeats, capability, plans, flows, scan jobs | always |
| `weirvern-netflow-<id>` | goflow2 collector on 2055/6343 | `--netflow` |
| `weirvern-gate-<id>` | the enforcement gate | `--gate` |

Every container is started with `--restart unless-stopped`, so it returns after a Docker or host
restart until an operator stops it.

**There is no systemd unit.** `weirvern-weirling` is the name of the shell helper the installer
writes to `/usr/local/bin/weirvern-weirling` (`status|start|stop`); it is not a service, and no
`weirvern-weirling.service` file exists on a target. A systemd unit was an earlier design that was
never shipped in a release; those instructions were removed rather than left beside the real path.

### The agent container, exactly

The agent is `python3 -m weirvern.admin.sensor_agent` in the release image:

| Setting | Value |
| --- | --- |
| image | `weirvern-scan:<tag>` — Nmap, `libcap2-bin` and file capabilities on `/usr/bin/nmap` — selected from the RUNNING `deploy/weirvern-worker` tag. `weirvern-worker:<tag>` is the fallback and **cannot scan**. `--agent-image` overrides. |
| network | `--network host` |
| user | `0:0` on the default mTLS transport (the remote ARP probe needs an effective `NET_RAW`); `10001:10001` with `--legacy-clickhouse` |
| capabilities | `--cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN` |
| restart policy | `unless-stopped` |
| entrypoint | `--entrypoint python3 … -m weirvern.admin.sensor_agent` |

Environment comes from `--env-file /etc/weirvern-weirling.env` (0600, rewritten on every install),
then per-container `-e` values:

- **mTLS (default):** `WEIRLING_GATEWAY_URL`, `WEIRLING_CLIENT_CERT`, `WEIRLING_CLIENT_KEY`,
  `WEIRLING_ROOT_CA`. No database credential is written to the target.
- **`--legacy-clickhouse`:** `CLICKHOUSE_HOST`, `CLICKHOUSE_PORT`, `CLICKHOUSE_USER`,
  `CLICKHOUSE_PASSWORD`, `WEIRLING_ALLOW_DIRECT_CLICKHOUSE=1`.
- **per container:** `SENSOR_ID`, `ZEEK_IFACE`, `ZEEK_LOG_DIR=/zeek/logs`, `MGMT_IFACE`,
  `TRUNK_STATE_DIR=/state`, `TRUNK_DISABLE`, `WEIRLING_NETFLOW`,
  `WEIRLING_FLOW_FILE=/flows/flows.jsonl`.

Volumes on `weirvern-agent-<id>`:

| Host path | Container path | Mode |
| --- | --- | --- |
| `/var/lib/weirvern-weirling/logs` | `/zeek/logs` | read-only |
| `/var/lib/weirvern-weirling/flows` | `/flows` | read-only |
| `/var/lib/weirvern-weirling/trunk-<id>` (`inline-<id>` with `--inline`) | `/state` | read-write |
| `/etc/weirvern-weirling/pki` | `/etc/weirvern-weirling/pki` | read-only |
| `/etc/os-release` | `/etc/os-release` | read-only |

The last mount is why the capability row names the **host's** distro — `Ubuntu 26.04 LTS (debian
family — apt)` — instead of the container image's Debian.

### Check that it is running

On the target:

```bash
# what the installer left, and whether it is up
weirvern-weirling status
# the same thing without the helper
docker ps --filter "name=weirvern-.*-<id>" --format '{{.Names}} {{.Status}}'
# the agent's state and restart policy, which must be running + unless-stopped
docker inspect --format '{{.State.Status}} {{.HostConfig.RestartPolicy.Name}}' weirvern-agent-<id>
```

The installer's own last step is the strongest check: it waits up to 60 s for a fresh
`sensor_status` heartbeat for that `sensor_id` and exits non-zero with the log commands if none
arrives.

### Read its logs

```bash
docker logs --tail 200 -f weirvern-agent-<id>     # agent: enrollment, heartbeats, capability, scans
docker logs --tail 100 weirvern-capture-<id>      # Zeek's own output
ls -l /var/lib/weirvern-weirling/logs/<iface>/    # the Zeek logs themselves (host path)
```

The agent re-measures Nmap every five minutes, so installing Nmap does not require a restart; the
next capability report flips the row. A unit that stops reporting is shown as `stale` with its age
(see [Readiness is capability](#readiness-is-capability-never-a-setting)).

## Install-time provisioning (privileged once, never at runtime)

**Can Weirvern install nmap on a weirling?** For a **host-installed** unit, yes, through one of
the two host paths above. For the **containerised** default there is nothing to install: the
image ships Nmap and the installer grants the two capabilities, so the unit is scan-capable from
its first heartbeat and the console hides the install action.

The host-installed agent stays unprivileged by default: no sudoers rule, no setuid helper and no
privileged container. The containerised agent is the deliberate exception, and its privilege is
narrow: every capability is dropped except `NET_RAW` and `NET_ADMIN`, there is no shell channel,
and `nmap` carries the same two capabilities as file capabilities for the non-root case. A unit
that has neither the image nor the host package reports `nmap missing` and claims nothing.

For a **host-installed** unit the setup step does exactly three things, as root (or through an
installer that runs as root):

```bash
# 1. install the package for this host's distro (see the table above)
sudo apt-get update && sudo apt-get install -y nmap

# 2. let SYN/UDP scans run without root: file capabilities on the binary only
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap

# 3. start the agent through the shipped installer -- there is no systemd unit to edit
scripts/deploy-weirling.sh --hub <hub-ssh> --target local --iface <capture-port> \
        --sensor-id <id>
```

Under the default mTLS transport the containerised installer runs the agent as uid 0 because the
remote ARP probe needs an effective `NET_RAW` capability, which Docker does not grant to a
non-root UID. That is not root on the host: the container drops every capability except `NET_RAW`
and `NET_ADMIN` and has no shell channel. The capture container additionally sets
`no-new-privileges`; the agent container deliberately does not, because that flag would also
disable the file capabilities on `nmap`. With `--legacy-clickhouse` the agent runs as
`10001:10001` and relies on those file capabilities.

On a host-installed unit, after step 2 the agent reports `nmap present with raw-socket
capabilities (SYN/UDP available)`. Without it, the honest readiness line is `nmap present,
unprivileged (connect scan only)`: a finished TCP connection is a weaker measurement than a SYN
scan and the console does not pretend otherwise.

**There is no blanket sudoers rule.** Do not give the sensor passwordless sudo over every
command (a rule whose command list is `ALL`): it would let a compromised sensor install anything
on the host, and the agent needs no write privilege to scan. If an installer creates a scoped
entry at all, it is ONE line for the package install only, and it is removable:

```bash
# optional, single purpose, and the only entry the installer may write
echo 'weirvern ALL=(root) NOPASSWD: /usr/bin/apt-get install -y nmap' | sudo tee /etc/sudoers.d/weirvern-nmap
sudo chmod 0440 /etc/sudoers.d/weirvern-nmap
# remove it again when the install is done:
sudo rm -f /etc/sudoers.d/weirvern-nmap
```

The agent treats the presence of `/etc/sudoers.d/weirvern-nmap` (or being root) as
"this host can install nmap". The Weirlings sheet prints one of two sentences for the host:

```
Weirvern can install nmap here (privileged installer path)
Weirvern cannot install nmap here — run this as root
```

with the exact package and `setcap` commands beneath it. The **Prepare this weirling** button
copies them; it cannot send them.

## Readiness is capability, never a setting

`GET /api/scan-readiness` reads the fleet: how many **registered, enabled** weirlings have a
`scanner_status` row that is BOTH fresh (within 15 minutes) and says Nmap is available. A stale
row is not capability — a removed workload's last row would otherwise promise a scan nothing can
execute. The Assets table, the host page and the Scanner readiness card all read the same
sentence, and the POST refuses with it, so the button and the refusal cannot drift.

`GET /api/scanner` applies the same window to every row it lists. A row past it comes back as
`state: "stale"` with `age_s`/`age`, never as `state: "reported"`; the card says
`No report from this weirling in <age> — no agent is reporting.` and offers no install, because
the last report cannot say what that host runs now. Both endpoints call
`scanner.freshness(last_check)`, so the window cannot differ between them.

## The manual-scan queue

A manual job is one ClickHouse row keyed by `job_id` (`weirvern.scan_jobs`), claimed under a
lease (`SCAN_JOB_LEASE_S`, default 900s):

- `queued` → `claimed` (a weirling took it) → `done` | `error`;
- `abandoned` is **derived** at read time: a queued row nobody claimed within the lease, or any
  queued row while no weirling can scan. It is never written to the table;
- `stale` is derived for a claimed row whose lease ran out with no result (another weirling may
  reclaim it);
- `cancelled` is a real terminal row written by the operator's **Cancel this job** action. A
  claimed job is refused with a sentence — a cancel cannot stop a running scan.

Every invocation is recorded in `asset_scans`, including failures. "No services" and "the scan
did not run" never look the same.

## What a scan writes

`asset_registry` (state + last scan), `asset_services` (current snapshot), `asset_service_history`
(every observation, for the change ledger), `asset_observations` (NSE identity facts),
`asset_changes` and `asset_posture_scores` (a service that opened since the last successful
scan). NSE output is an **observation**, not a finding: `vuln`, `intrusive`, `brute` and `dos`
script categories are excluded from the profile.

## Tables

| Table | Purpose |
|---|---|
| `asset_registry` | One row per identity: address, MAC, hostname, first/last seen, scan state, last scan error. `pending` is the durable inventory queue. |
| `asset_services` | Open services from Nmap: port, protocol, service, product, version, CPE. |
| `asset_observations` | Safe NSE identity facts: script, key, value, port. Observations, not vulnerability findings. |
| `asset_scans` | Append-only audit of every scan attempt, including failures and the command line. |
| `scan_jobs` | Manual jobs and leases (queued/claimed/done/error/cancelled; abandonment is derived). |
| `scanner_status` | Each weirling's measured capability: Nmap path/version, NSE availability, OS, last check. |

The Assets inventory reads these tables when they exist and annotates its rows with a **scan
state**: `scanned`, `scanning`, `not scanned`, `failed` or `unknown`. None of those is proof the
host is patched. The Host page carries the same reading as a **Scanned exposure** card with the
measured services.

## Removing Nuclei

Nuclei is removed everywhere: the binary is not installed, the `SCAN_NUCLEI_*` settings are gone,
the code paths and the UI are gone, and migration `049_drop_nuclei.sql` drops
`weirvern.asset_findings` (its only producer). That is a real deletion: a Nuclei match cannot be
re-derived without the template set this deployment deliberately does not carry.

## Hub-side inventory

The discovery helpers remain in `weirvern/scanner.py` for a hub-side inventory pass: union the
Nmap sweep of the declared networks with hosts seen passively in the last `SCAN_PASSIVE_MINUTES`,
record unknown hosts as `pending`, and rescan completed hosts on `SCAN_RESCAN_S`. The first pass
is a baseline (`known`, not scanned) unless `SCAN_BOOTSTRAP=1`, so deploying it cannot look like
a hundred new devices.

## Boundaries

- **The agent container holds exactly two capabilities, and only when it scans.** `NET_RAW` and
  `NET_ADMIN`, with `--cap-drop ALL`; nothing else is added. They are what make SYN/UDP scans
  possible, and `nmap` carries the same two as file capabilities so the non-root (`10001:10001`)
  path works too. A unit that cannot obtain them reports `connect`, not `syn/udp`: the console
  never claims a SYN scan from a node that can only complete TCP connections. The hub itself
  runs no scanner and needs no packet-socket capability.
- **A containerised unit cannot install into its image.** The Install action is for host-installed
  units; on the scan image it is hidden because the capability is already present.
- **No automatic blocking.** A scan result is evidence. Sluice actions remain an operator
  decision.
- **Nmap service banners are hints.** Backported distro patches routinely make a version string
  look vulnerable when it is not. Credentialed package checks are the next layer, not this one.
- **No shell channel.** The hub queues scans; it never queues arbitrary commands.

## Failure is visible

A scan that fails writes an `error` row in `asset_registry` and an `asset_scans` row with the
error. The Assets row shows `failed` and the detail in its tooltip. A scan that never ran is not
allowed to look like a host with no services.

## Verification

```bash
# on the weirling: the agent is up and comes back after a restart
docker inspect --format '{{.State.Status}} {{.HostConfig.RestartPolicy.Name}}' weirvern-agent-<id>

# the container can ACTUALLY scan: binary, file capabilities, granted capabilities
docker exec weirvern-agent-<id> nmap --version | head -1
docker exec weirvern-agent-<id> getcap /usr/bin/nmap
docker inspect --format '{{json .HostConfig.CapAdd}}' weirvern-agent-<id>

# the fleet's own answer, from the hub -- expect "(nmap <version>, syn/udp)"
curl -s http://127.0.0.1:30088/api/scan-readiness | python3 -m json.tool

# the same rows the card renders: `state` must be reported or stale, never a stale `reported`
curl -s http://127.0.0.1:30088/api/scanner | python3 -m json.tool

# the capability rows behind both
kubectl -n weirvern exec sts/clickhouse -- clickhouse-client --query \
  "SELECT sensor_id, profile, nmap_available, nmap_version, os_id, last_check
   FROM weirvern.scanner_status FINAL"

# the queue
kubectl -n weirvern exec sts/clickhouse -- clickhouse-client --query \
  "SELECT job_id, ip, state, lease_owner, requested_at, finished_at, result, error
   FROM weirvern.scan_jobs FINAL ORDER BY requested_at DESC LIMIT 20"
```
