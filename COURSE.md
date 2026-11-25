# INF601 - Advanced Programming in Python
# Samuel Hart
# Final Project

This file records the INF 601 Advanced Programming in Python requirements for the final project.
The product README covers the software itself.

## The project

Weirvern is a network detection and enforcement console: a Flask app, a ClickHouse database, a
dashboard, a sensor fleet, and two agentic pieces, the `fathom` MCP server and the `threat-hunt`
skill. It reads NetFlow, Zeek, DNS and JA4 metadata, explains every alert with the measurements
behind it, and can enforce a decision inline or by ARP.

## Where this came from

Weirvern is a generational improvement on FlowForge, a network-flow program I wrote completely
before this one. FlowForge started as a single-process tool for reading NetFlow records and
answering which host changed its behaviour and what it talked to. It proved that flow metadata
could carry a detection story, but every layer above the flow table was manual: one collector, one
machine, no fleet, no evidence trail, no enforcement.

Weirvern keeps the premise and rebuilds the system. The flow table now feeds five independently
trained detectors, a per-host adaptive baseline, a fused verdict and a ripple layer that groups
evidence into incidents. The console shows the measurements behind every alert, the sensor fleet
can sit on several segments, and the Sluice Gate can enforce a decision inline or by ARP. This is a
ground-up generation beyond FlowForge, not a fork.

## The graded surface

- **Flask app:** `/login`, `/register`, `/home` and `/block`, with a session and CSRF on every form.
- **Registration:** self-registration is open, but a new account stays pending until an admin
  approves it from **Settings -> Users**. The seeded demo admin is already approved.
- **Form:** the block form writes a rule and is audited.
- **Database:** the ClickHouse schema, the demo seeder, and the data the console reads.
- **Dashboard:** the console home renders from live API payloads.
- **Agentic pieces:** `fathom` (MCP server, ten tools) and `threat-hunt` (the investigation skill).

## AI Usage

Claude Code was the coding harness: it scaffolded modules, carried refactors across the tree, wrote
first drafts of tests, and ran the project gate. An AI assistant was the second pair of eyes: it
read diffs against the design documents, ran the test suite and the DOM harness, reproduced
failures, and pointed at the file and line that explained them. The author made the design
decisions and accepted or rejected each suggestion, including declining style-only changes with
the reason recorded.

The agentic pieces are part of the product. `fathom` exposes ten console tools over MCP, nine reads
and one proposal write; `threat-hunt` encodes the investigation method. The write path files a
proposal and a person decides, so a model cannot block traffic on its own.

Every AI-generated change was reviewed, run and verified before commit. No AI system had
unsupervised write access to the repository.

## Demo notes

- Seed: `weirvern demo-seed --scope`.
- Sign in with the seeded demo admin.
- The MCP live check serves ten tools and answers eight checks against the console.
- A loch sensor's channel column reports its runtime state. A plan pair is declared but not active
  until the sensor brings the bridge up.
