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
4. runs `nmap --unprivileged -sV … -oX -` against the one address and sends the measured services
   and NSE observations back over the authenticated mTLS gateway. The hub writes them with the
   same recorder it has always used.

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

The agent container is not root and has no privileged channel, so the hub **cannot** install
anything on a sensor — and it deliberately has no shell channel. Two supported paths:

**1. Use the scan image (recommended).** `install.sh` builds `weirvern-scan:<tag>` from
`Containerfile.scanner` (Nmap + safe NSE scripts, no Nuclei). `scripts/deploy-weirling.sh`
resolves that image from the running worker's tag and uses it for the agent container, so the
unit can scan as soon as it starts. If the hub does not have it, the script says so and the unit
reports `nmap missing` until it is built:

```bash
docker build -t weirvern-scan:sha-<commit> -f Containerfile.scanner .
docker save weirvern-scan:sha-<commit> | k3s ctr images import -
```

**2. Install it on the host yourself.** If you run the agent outside the provided image, install
Nmap with the package manager for that host. The console's Scanner readiness card renders the
exact command from the OS the agent reported:

| distro (`/etc/os-release` ID) | command |
| --- | --- |
| debian, ubuntu, linuxmint, pop, raspbian, kali, devuan, elementary | `sudo apt-get update && sudo apt-get install -y nmap` |
| fedora, rocky, almalinux, ol, rhel, centos (8+) | `sudo dnf install -y nmap` |
| centos, rhel (7 and older) | `sudo yum install -y nmap` |
| alpine | `sudo apk add --no-cache nmap` |
| arch, manjaro, endeavouros, garuda | `sudo pacman -S --noconfirm nmap` |
| opensuse-leap, opensuse-tumbleweed, sles | `sudo zypper install -y nmap` |
| **anything else** | the card says the OS is unknown and shows the generic instruction — it never guesses a package manager |

The **Prepare this weirling** button on the card copies that command for the operator to run. It
cannot send it: the hub has no shell channel to a weirling, and an install inside the agent
container would not survive a restart.

## Install-time provisioning (privileged once, never at runtime)

**Can Weirvern install nmap on a weirling?** Only if the operator runs a privileged setup step
once. The agent itself stays unprivileged: it has no sudoers rule by default, no setuid helper and
no privileged container, and the hub has no shell channel to it. A unit that has not been
provisioned reports `nmap missing` and claims nothing.

The setup step does exactly three things, as root (or through an installer that runs as root):

```bash
# 1. install the package for this host's distro (see the table above)
sudo apt-get update && sudo apt-get install -y nmap

# 2. let SYN/UDP scans run without root: file capabilities on the binary only
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap

# 3. run the agent as the unprivileged user under systemd
sudo systemctl edit --full weirvern-weirling   # or the unit deploy-weirling.sh installed
#   [Service]
#   User=weirvern
#   ExecStart=/usr/bin/python3 -m weirvern.admin.sensor_agent
```

After step 2 the agent reports `nmap present with raw-socket capabilities (SYN/UDP available)`.
Without it, the honest readiness line is `nmap present, unprivileged (connect scan only)`: a
finished TCP connection is a weaker measurement than a SYN scan and the console does not pretend
otherwise.

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

- **No NET_RAW / NET_ADMIN.** Nmap runs `--unprivileged` connect scans. This is slower than a
  SYN scan and cannot do ARP-only discovery; that is the deliberate trade for not granting a
  packet-socket capability to a network-facing workload.
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
# the fleet's own answer, from the hub
curl -s http://127.0.0.1:30088/api/scan-readiness | python3 -m json.tool

# the capability rows behind it
kubectl -n weirvern exec sts/clickhouse -- clickhouse-client --query \
  "SELECT sensor_id, profile, nmap_available, nmap_version, os_id, last_check
   FROM weirvern.scanner_status FINAL"

# the queue
kubectl -n weirvern exec sts/clickhouse -- clickhouse-client --query \
  "SELECT job_id, ip, state, lease_owner, requested_at, finished_at, result, error
   FROM weirvern.scan_jobs FINAL ORDER BY requested_at DESC LIMIT 20"
```
