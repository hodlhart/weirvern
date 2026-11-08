# Active asset scanner (Nmap + NSE)

*Part of the [Weirvern](../README.md) documentation.*

Weirvern's asset inventory started passive: every host in `flows` and Zeek. That answers "what
exists on the wire" but not "what is exposed and is it patched". This scanner adds the second
answer without adding a host: it runs as a Deployment in the existing cluster and uses the
sensor node's network path.

## What runs

```
passive flows ─┐
               ├─> asset_registry ─> pending ─> Nmap -sV + safe NSE ─> asset_services
Nmap -sn ──────┘                                      └─────────────> asset_observations
```

The scanner is `python -m weirvern.scanner`; `Containerfile.scanner` builds the image with Nmap
and its bundled safe NSE scripts. Nuclei is deliberately **not installed**: identity must work on
any network without a template tree, an update lifecycle, or a vendor controller.

**The scope is not a separate list.** A network is monitored because a weirling says it covers it.
The scanner reads the `weirlings` registry on every pass, so registering, disabling, or revoking
a weirling changes the scan scope without editing a second configuration value.

The authoritative field is **`networks`** — an explicit list of CIDRs on each weirling. This is
separate from `segment`, which is where the sensor sits and may be free text ("third floor IDF").
Rows written before the `networks` column existed fall back to their CIDR-valued `segment` and
`plan_segment`, so an upgrade does not blind an existing deployment. If no enabled weirling declares
a CIDR, the scanner logs that and scans nothing.

## New hosts are scanned in the same pass

Every pass:

1. reads the enabled, non-revoked weirlings and takes their declared CIDR `segment` and validated
   `plan_segment` as the scan scope, then sweeps it with `nmap -sn`;
2. reads the last `SCAN_PASSIVE_MINUTES` of `flows`, so a host that never answers a probe is
   still discovered;
3. merges the two views by address and hardware identity;
4. inserts any unknown host with `scan_state='pending'`;
5. drains pending rows immediately: Nmap service/version scan plus safe identity scripts
   (`http-title`, `ssl-cert`, `smb-os-discovery`, `snmp-sysdescr`, SSH/RDP/UPnP facts);
6. rescans hosts whose `last_scan_at` is older than `SCAN_RESCAN_S` (default one hour), capped by
   `SCAN_MAX_HOSTS`. Pending-only scanning is a new-host queue, not a change detector: without
   this second look, a service that opens on an existing host would never appear in
   `asset_changes`. Set `SCAN_RESCAN_S=0` to disable it.

The first pass is deliberately different. Existing hosts are recorded as `known`, not scanned,
unless `SCAN_BOOTSTRAP=1`. Without that baseline, deploying the scanner would look like a hundred
new devices and launch a scan storm. After the baseline, a genuinely new address or MAC is
pending at once.

## Registry identity

`asset_registry` prefers `mac:<address>` when Nmap supplies a MAC, and falls back to
`ip:<address>`. The distinction matters on DHCP: an IP can move to another device, and a finding
attached to the old IP would then describe the wrong machine. If a known IP is later seen with a
different MAC, it is treated as a new asset.

## Tables

| Table | Purpose |
|---|---|
| `asset_registry` | One row per identity: address, MAC, hostname, first/last seen, scan state, last scan error. `pending` is the durable queue. |
| `asset_services` | Open services from Nmap: port, protocol, service, product, version, CPE. |
| `asset_observations` | Safe NSE identity facts: script, key, value, port. Observations, not vulnerability findings. |
| `asset_findings` | Historical/optional Nuclei matches; no new rows while Nuclei is disabled. |
| `asset_scans` | Append-only audit of every scan attempt, including failures and the command line. |

The Assets inventory reads these tables when they exist and annotates its rows with **Exposure**
and **Scan**. Exposure is one word plus the recorded finding count: `critical`, `high`, `medium`,
`low`, `clear`, `not scanned`, `failed`, or `unknown`. A done scan with no recorded finding is
**clear**; a host with no scan is **not scanned**; a failed scan is **failed**. None of those is
proof that the host is patched. The Host page carries the same reading as a **Scanned exposure**
card with its services and findings. If the tables are missing, the passive inventory still
renders; the annotation is not allowed to break the inventory.

## Nuclei is off

Nuclei is an opt-in future exposure layer, not a dependency of the identity pipeline. The default
image does not contain the binary or a template tree; `SCAN_NUCLEI_ENABLED` defaults to `0`.
The code path remains for a reviewed exposure profile, but enabling it requires a separately
built image and the same safety exclusions that were used before removal (`dos`, `intrusive`,
`fuzz`, `brute-force`, `headless`, `code`, plus `CVE-2019-5544` by ID). Do not make it a default:
template selection and updates are a product decision, not an installer step.

## Enable it

```bash
kubectl -n weirvern patch cm weirvern-env --type merge -p '{"data":{"SCAN_ENABLED":"1"}}'
kubectl -n weirvern rollout restart deploy/weirvern-scanner
```

There is no scanner CIDR setting to fill in. Register the weirlings with their monitored
`segment`/`plan_segment`; the scanner follows that registry. An unreadable or CIDR-less registry
makes it idle, not guess.

To seed the inventory by scanning existing hosts once:

```bash
kubectl -n weirvern patch cm weirvern-env --type merge -p '{"data":{"SCAN_BOOTSTRAP":"1"}}'
```

Turn it back to `0` after the first pass; otherwise every restart would rescan the whole scope.

## Build

```bash
podman build -t weirvern-scanner -f Containerfile.scanner .
podman push <registry>/weirvern-scanner
```

The scanner Deployment uses `image: weirvern-scanner`. Pin it through the same image-tag process
as the worker when releasing.

## Boundaries

- **No new LXC.** It is a Deployment in the existing cluster, pinned to the sensor node and
  using `hostNetwork` so it sees the LAN rather than the pod overlay.
- **No NET_RAW / NET_ADMIN.** Nmap runs `--unprivileged` connect scans. This is slower than a
  SYN scan and cannot do ARP-only discovery; that is the deliberate trade for not granting a
  packet-socket capability to a network-facing workload.
- **No automatic blocking.** Findings are evidence. Sluice actions remain an operator decision.
- **Nuclei findings are template matches, not proof of exploitability.** A missing finding is
  not proof that a host is patched.
- **Nmap service banners are hints.** Backported distro patches routinely make a version string
  look vulnerable when it is not. Credentialed package checks (Vuls/OpenVAS or image scanning)
  are the next layer, not this one.

## Failure is visible

A scan that fails writes an `error` row in `asset_registry` and an `asset_scans` row with the
error. The Assets row shows `error` in the Scan column and the detail in its tooltip. A scanner
that never ran is not allowed to look like a host with no findings.
