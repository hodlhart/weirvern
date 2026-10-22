# Remote weirling capability audit — 2026-10-22

A remote unit is a capture box outside the hub's Kubernetes cluster. These are the
features that do and do not cross that boundary.

## Working

- **Adoption** — one-time token, local key/CSR, mTLS certificate, no database credential.
- **Plan refresh** — the agent polls its own plan every 30 seconds; mode and per-NIC plan
  changes land on that poll. The hub never pushes into the sensor.
- **Heartbeat** — every 15 seconds, with interfaces, mode, refusal notes and a host
  CPU/memory reading.
- **Trunk ports by default** — the sensor observes 802.1Q tags at start. No tags means the
  parent port is captured; tags mean one host VLAN device per tag (`eth1.10`, `eth1.20`) and
  one Zeek per VLAN. There is no trunk/access mode to choose.
- **NetFlow** — when the unit is installed with `--netflow`, goflow2 runs locally and the
  agent ships its JSONL to the hub over mTLS.
- **Zeek/DNS/HTTP/TLS/conn logs** — the agent ships parsed records from every supported
  Zeek log over `/v1/zeek`; the hub maps them with the same `ZEEK_MAPPERS` used for its own
  capture.
- **Sonar** — a hub request is queued durably; the remote agent runs the survey against
  its own NIC and posts the measured result back.
- **Capture-liveness test** — the hub queues a bounded, read-only 30-second probe; the
  sensor measures its own NIC packet counters and Zeek `conn.log` growth and posts the
  evidence. A silent port returns `observed:false`; it is not a failed test. No mode,
  plan, interface or sysctl is written.
- **Traffic gate** — an mTLS gate reads live rules and writes state through
  `/v1/gate/rules`, `/v1/gate/state` and `/v1/gate/events`; it still needs `--gate`,
  `--gate-iface`, `NET_ADMIN`, and a genuinely in-path port.
- **Inline topology declaration** — a registration can declare `topology: inline`; the unit is
  expected to capture on a two-NIC bridge. `scripts/weirling-inline.sh` creates/tears down the
  bridge explicitly, and `deploy-weirling.sh --inline` refuses unless that bridge already has
  exactly two address-free ports. The deploy helper never rewires a host on its own.
- **Certificate renewal** — the agent renews inside the 30-day window, reusing its private
  key and atomically replacing the chain.
- **Revocation** — the gateway refuses a revoked client on its next request; the agent stops
  a live intercept on the 403 instead of preserving it as a transient read failure.

## Missing or incomplete

1. **Remote domain blocking.** Domain blocking is a DNS/resolver action. A remote unit
   does not answer DNS for its segment, so it cannot return a block answer. A gate can
   drop resolved addresses as packets, which is not the same guarantee.
2. **Remote in-path test / live probe.** The capture-liveness test is available, but it
   measures capture evidence only. The hub's 30-second siphon probe (ARP forging, kernel
   relay, drop enforcement) has no remote equivalent; that is an inline-topology capability,
   not a flag on a capture-only unit.
3. **Remote capture/NIC changes after install.** Trunk VLAN devices are automatic; turning
   the NetFlow collector on/off or changing the capture parent is still install-time.
4. **Remote update/rollout.** There is no hub-driven image update or health-driven restart
   for a unit; the helper is operated on the box.
5. **Remote gate domain records.** The mTLS gate enforces packet rules but does not run the
   hub's `_sluice_dns_maybe` hit recorder; domain-hit evidence remains a hub-side pass.
