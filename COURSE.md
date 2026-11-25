# INF 601 final project: course context

This file is the course-facing record for the INF 601 Advanced Programming in Python final
project. It is deliberately separate from the product README and can be removed when the course
is over; the product and its documentation do not depend on it.

## The project

Weirvern is a network detection and enforcement console: a Flask app, a ClickHouse database, a
dashboard, and two agentic pieces, the `fathom` MCP server and the `threat-hunt` skill. Start with
the product README for the software itself.

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

## Instructor feedback and what changed

The Week 13 outline review said the gradeable surface is the Flask app (register/login plus a
form), the database, the dashboard, and the two agentic pieces demonstrated live, and warned
against letting the detection engine crowd them out. That is now the order of the Week 16 demo:
the seeded console signs in, opens the dashboard, submits the block form, and only then walks the
detection surfaces. The demo data is seeded into synthetic and RFC 5737 documentation ranges, so
the run exposes no live traffic. Both agentic pieces are demonstrated live.

Self-registration is open, but a new account stays pending until an admin approves it; the seeded
demo admin is already approved.

## Demo notes

- Seed: `weirvern demo-seed --scope`.
- Sign in with the seeded demo admin.
- The MCP live check serves ten tools and answers eight checks against the console.
- A loch sensor's channel column reports its runtime state. A plan pair is declared but not active
  until the sensor brings the bridge up.

## What can be removed

Delete this file when the course is over. The required
`# INF601 - Advanced Programming in Python` header in `scripts/demo_coverage.py` is a course
requirement; remove it only if the course no longer needs it.
