# Remote weirling capability audit — 2026-10-22

A remote unit is a capture box outside the hub's Kubernetes cluster. These are the
features that do and do not cross that boundary today.

## Working

- **Adoption** — one-time token, local key/CSR, mTLS certificate, no database credential.
- **Plan refresh** — the agent polls its own plan every 30 seconds; mode and per-NIC plan
  changes land on that poll. The hub never pushes into the sensor.
- **Heartbeat** — every 15 seconds, with interfaces, mode and refusal notes.
- **NetFlow** — when the unit is installed with `--netflow`, goflow2 runs locally and the
  agent ships its JSONL to the hub over mTLS.
- **Sonar** — a hub request is queued durably; the remote agent runs the survey against
  its own NIC and posts the measured result back.
- **Traffic gate** — an mTLS gate reads live rules and writes state through
  `/v1/gate/rules`, `/v1/gate/state` and `/v1/gate/events`; it still needs `--gate`,
  `--gate-iface`, `NET_ADMIN`, and a genuinely in-path port.
- **Revocation** — the gateway refuses a revoked client on its next request.

## Missing or incomplete

1. **Remote DNS/Zeek ingestion.** The remote capture writes Zeek logs on its own box; the
   agent ships NetFlow only. DNS, HTTP, TLS, conn and notice records from a remote segment
   are not in the hub database, so the DNS, Zeek, Anomalies and Assets views are blind to
   that segment.
2. **Remote domain blocking.** Domain blocking is a DNS/resolver action. A remote unit
   does not answer DNS for its segment, so it cannot return a block answer. A gate can
   drop resolved addresses as packets, which is not the same guarantee.
3. **Remote host telemetry.** The hub reports its own CPU, memory and disk; a remote unit
   reports no host counters. The UI says "unavailable", not a fake zero.
4. **Remote SIPHON capability.** The mTLS agent carries NET_RAW for Sonar but not
   NET_ADMIN. A plan can declare siphon, and the agent will report the refusal, but the
   intercept itself cannot configure forwarding/addresses without that capability.
5. **Remote test run / live probe.** The hub's bounded test run drives its own ConfigMap;
   it does not reach a remote unit. There is no remote equivalent of the 30-second probe.
6. **Remote certificate renewal.** `/v1/renew` exists, but the agent does not call it
   automatically. A 90-day certificate will expire unless the unit is re-enrolled or a
   renewal loop is added.
7. **Immediate revoke while in path.** A plan-read failure is deliberately fail-safe: it
   keeps the current intercept. A revoked sensor with a live siphon can therefore keep
   relaying until restarted. Revocation needs a distinguishable "stop now" response.
8. **Remote capture/NIC changes.** `ZEEK_IFACE`, the collector, and the helper's container
   set are install-time. A plan can change siphon fields but not add a capture NIC or turn
   the NetFlow collector on.
9. **Remote update/rollout.** There is no hub-driven image update or health-driven restart
   for a unit; the helper is operated on the box.
10. **Remote capture-loss and forwarding evidence.** The heartbeat carries what the local
    agent can observe, but the hub has no independent path to the remote kernel's counters
    beyond that report.
11. **Remote gate domain records.** The mTLS gate enforces rules but does not run the
   hub's `_sluice_dns_maybe` hit recorder; domain-hit evidence remains a hub-side pass.

## Order I would build next

1. Remote Zeek log shipping (turns every remote unit into a real sensor, not just a flow
   exporter).
2. Remote siphon capability and its safety evidence (the plan is already there).
3. Certificate renewal loop and a hard revoke/stop response.
4. Remote test-run parity.
5. Remote host telemetry.
