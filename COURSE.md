# INF 601 final project: course context

This file records the INF 601 Advanced Programming in Python requirements for the final project.
The product README covers the software itself.

## The project

Weirvern is a network detection and enforcement console: a Flask app, a ClickHouse database, a
dashboard, and two agentic pieces, the `fathom` MCP server and the `threat-hunt` skill.

## The graded surface

- **Flask app:** `/login`, `/register`, `/home` and `/block`, with a session and CSRF on every form.
- **Registration:** self-registration is open, but a new account stays pending until an admin
  approves it from **Settings -> Users**. The seeded demo admin is already approved.
- **Form:** the block form writes a rule and is audited.
- **Database:** the ClickHouse schema, the demo seeder, and the data the console reads.
- **Dashboard:** the console home renders from live API payloads.
- **Agentic pieces:** `fathom` (MCP server, ten tools) and `threat-hunt` (the investigation skill).

## AI Usage

The product README carries the `## AI Usage` section the syllabus requires. The short version:
Claude Code was the coding harness; an AI assistant was the second pair of eyes; every change was
reviewed, run and verified before commit. The author made the design decisions and accepted or
rejected each suggestion. The `fathom` MCP server and the `threat-hunt` skill are part of the
product, not a bolt-on demo.

## Demo notes

- Seed: `weirvern demo-seed --scope`.
- Sign in with the seeded demo admin.
- The MCP live check serves ten tools and answers eight checks against the console.
- A loch sensor's channel column reports its runtime state. A plan pair is declared but not active
  until the sensor brings the bridge up.
