# Evidence-first incident surface — 2026-10-31

**Purpose:** PRD-3 evidence. The queue could show a score and a window, but an analyst had to
join the episode, role, model, review and raw-record tables by hand. This puts them in one
read-only object and shows it where the alert is read.

## Object

`GET /api/incident?addr=<host>&start=<inside-episode>` returns:

- **actor** — the host being judged, never an external peer.
- **asset** — `host_roles.role` and `.scope`; `unknown` when no role is recorded.
- **window** — the episode's start/end, not a widened display range.
- **occurrences / severity / max score** from `alert_episodes`.
- **families** — the anomaly's strong families.
- **source coverage** — row counts for flows, Zeek conn/DNS/TLS and notices in the page window.
- **model versions** — distinct `ml_window_scores.model_version` values for the page window; an
  empty list is reported as `not recorded`, not as a version.
- **page budget** — `pageable`, `page_reason`, `paged_at`.
- **evidence** — the same `alert_evidence` pivot the evidence page already renders.
- **review** — state, note, `reviewed_by`, `reviewed_at`, and the review's 30-day expiry.
- **evidence_error** — a named per-source read failure. A failed read never becomes an empty
  success.

The lookup accepts any timestamp **inside** an episode, not only its exact start, so the
evidence page can pass the detection window it already has.

## UI

The evidence page (`#view-evidence`) now renders an **incident context** block between the
five-stage chain and the raw tables. It shows the actor/role, episode window, occurrences,
severity, families, source coverage, model version, review provenance/expiry and page-budget
decision. The existing raw-flow, Zeek, TLS and DNS tables remain the pivot to individual rows.

## Review posture

- Review reads use `alert_reviews FINAL`; there is **no write** on this path.
- Review provenance and expiry are displayed; expiry is the same 30-day TTL the review row
  carries, derived from the episode start.
- Normal-training writes are not part of this surface. A review label does not train a model.

## Verification

- Unit tests: actor/asset/window/families/coverage/version, review provenance/expiry, named
  episode-read failure, JSON serialisation, read-only SQL, and the UI hook.
- Disposable ClickHouse probe: a page window inside an existing episode returned `available:
  true`, actor `203.0.113.77`, 2 occurrences, high severity, a review expiry, and a named
  `page_reason`; raw evidence was empty in that disposable seed and the object said so.
- Seeded eval: PASSED, 308 verdicts; scanner/beacon/exfil all final, benign hosts quiet,
  deterministic within the run. The seed-day count differs from the earlier 263-day run; this
  surface touches no detection code.
- `./scripts/gate.sh`: PASS.

## Limits

- `model_versions` stays empty until schema 038 is deployed and the worker records
  `ml_window_scores`; the UI says `not recorded`.
- An asset with no `host_roles` row is `unknown`; the surface does not infer a role from traffic.
- Deployment is a separate operator decision; this card changes no alert path or schema.
