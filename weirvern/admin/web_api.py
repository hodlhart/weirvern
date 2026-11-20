"""The web GUI's HTTP API.

WHY A SEPARATE MODULE FROM THE GUI SERVER: the web UI answers questions about
detection state, and it shares `weirvern/admin/status.py` for every query rather
than duplicating SQL. Putting the SQL here would mean two implementations of
"what is an anomaly", and they would drift — the browser and the terminal would
eventually disagree about the same deployment.

WHAT THIS IS NOT: it is not a second control plane. Lifecycle actions (start,
stop, apply) stay in the CLI, which the operator runs knowingly. This
serves READ-ONLY views, which is why it is safe to expose on a LAN port at all:
there is no code path from an HTTP request to a mutating cluster operation.

SERIALISATION IS THE SUBTLE PART. ClickHouse returns `datetime` objects (often
with a tzinfo), `Decimal` for some aggregates, and tuples keyed positionally.
Handing any of those straight to json.dumps raises TypeError, and the failure
appears only when a real row exists — an empty deployment looks fine. Everything
goes through `_jsonable` for that reason.
"""
from __future__ import annotations

import datetime as _dt
import decimal
import logging
from typing import Any

logger = logging.getLogger(__name__)


def _hostname(addr: str | None) -> str | None:
    """Best-effort reverse DNS for display, never raising.

    Imported lazily and wrapped defensively: the GUI must render even if the
    resolver is misbehaving, and revdns already returns None for every failure
    path, so this is a second belt for an unexpected import-time problem.
    """
    if not addr:
        return None
    try:
        from weirvern.admin import revdns
        return revdns.lookup(str(addr))
    except Exception:  # noqa: BLE001
        return None


def _jsonable(value: Any) -> Any:
    """Recursively convert a ClickHouse result into JSON-safe types.

    Handles the three things that actually appear in practice:
      * datetime/date  -> ISO 8601 string (the browser parses these natively)
      * Decimal        -> float (bytes and score aggregates can be Decimal)
      * tuple/list     -> list (ClickHouse returns rows as tuples, and a nested
                          tuple would serialise as a JSON array anyway, but being
                          explicit keeps the shape stable for the frontend)
    Anything else is returned as-is and will raise loudly on serialisation, which
    is preferable to silently str()-ing an unexpected type into the payload.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (_dt.datetime, _dt.date, _dt.time)):
        return value.isoformat()
    if isinstance(value, decimal.Decimal):
        return float(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    # bytes appear if a table ever returns a FixedString/blob column.
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    return value


def calibration_payload(data: dict) -> dict:
    """Serialise the shadow calibration table for the Models view.

    Every row carries `target_far` and `observed_far` side by side; the frontend must not have to
    infer a budget from a threshold. `computed_at` is already ISO from status.calibration_overview.
    """
    rows = []
    for raw in (data.get("rows") or []):
        row = dict(raw)
        target = float(row.get("target_far") or 0.0)
        observed = row.get("observed_far")
        samples = int(row.get("sample_count") or 0)
        if samples < 100:
            verdict = "insufficient samples"
        elif row.get("eligibility") == "quarantined":
            verdict = "quarantined"
        elif row.get("eligibility") == "eligible":
            verdict = "eligible"
        elif observed is not None and target > 0 and float(observed) <= target * 1.5:
            verdict = "within budget"
        else:
            verdict = "over budget"
        row["verdict"] = verdict
        rows.append(row)
    return {"available": bool(data.get("available")),
            "reason": str(data.get("reason") or ""),
            "rows": rows}


def health_payload(report) -> dict:
    """Serialise a HealthReport."""
    return {
        "ok": report.ok,
        "fetched_at": _jsonable(_dt.datetime.fromtimestamp(report.fetched_at, _dt.UTC)),
        "checks": [
            {"name": p.name, "ok": p.ok, "detail": p.detail,
             "value": _jsonable(p.value), "latency_ms": round(p.latency_ms, 1)}
            for p in report.probes
        ],
    }


def anomalies_payload(rows: list[dict], *, severity_counts: dict | None = None,
                      discipline: dict | None = None,
                      watch_error: str | None = None,
                      total_unfiltered: int | None = None,
                      fused: dict | None = None) -> dict:
    """Serialise anomaly rows plus the severity tiles' counts.

    An OBJECT now, not a bare list (2026-10-16): the page's header needs how many anomalies carry
    each severity, and a JSON array cannot carry that beside its rows. `severity_counts` rides
    with the rows because the two must describe the same filters -- a counts read that failed is
    carried as `available: false` with its reason, never as zeros that would read as a calm page.

    The column holds JSON text (it is a String in the schema). Decoding it here
    means the frontend gets an object rather than a string it has to parse, and a
    malformed value degrades to None instead of breaking the page.
    """
    import json

    out = []
    for r in rows:
        row = {k: _jsonable(v) for k, v in r.items()}
        contrib = row.get("feature_contributions")
        if isinstance(contrib, str) and contrib.strip():
            try:
                row["feature_contributions"] = json.loads(contrib)
            except (ValueError, TypeError):
                row["feature_contributions"] = None
        else:
            row["feature_contributions"] = None
        # Reverse DNS for display, alongside the raw address. Both are sent: the
        # IP is the fact (needed to correlate with a firewall or DHCP lease) and
        # the name is the convenience. Replacing one with the other would lose
        # information the operator cannot recover from the UI.
        row["hostname"] = _hostname(row.get("src_addr"))
        out.append(row)
    return {"rows": out,
            # US-6: the unfiltered count beside the rows, so the list can say "showing X of Y".
            # None when the read failed -- the line then omits the "of Y" rather than inventing it.
            "total_unfiltered": total_unfiltered,
            "watch_error": watch_error,
            # THE FUSED-SCORE STATUS: the strongest row, the configured bar, and every detector
            # that contributed to the rows. One sentence on the page, not a second derivation.
            "fused": fused or {"score": None, "target": None, "detectors": []},
            "discipline": discipline or {
                "available": False, "reason": "fired/acted-on counts were not read"},
            "severity_counts": severity_counts or {
                "available": False, "reason": "severity counts were not read", "counts": []}}


def panic_page(*, fleet: dict | None, audit: dict | None, alerts: dict | None,
               rendered_at: str, gate_note: str = "") -> str:
    """The degraded-console fallback (BF-14, research #10): a NO-JS server-rendered page.

    Assume the console runs during the outage it must help fix (the AWS/Facebook/Roblox
    postmortems): this page is plain HTML with inline CSS and NO script tag -- it renders
    with JavaScript off, broken, or blocked. What it carries is the panic set: sensor
    liveness with the data's own staleness stamp, the 24h alert counts, and the pipeline
    self-audit (whose findings ARE the degraded view). Every section that could not be read
    says so WITH ITS REASON -- a fallback page that silently drops a section would be the
    calm-empty failure this project keeps refusing.

    Timestamps are UTC and labelled UTC (single-zone; the console's local-time hover is a
    JS affordance this page deliberately does not have).
    """
    import html as _html  # noqa: PLC0415

    def esc(v: object) -> str:
        return _html.escape(str(v if v is not None else ""))

    def section(title: str, body: str) -> str:
        return f"<h2>{esc(title)}</h2>{body}"

    parts: list[str] = [
        "<!doctype html><html><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        "<title>Weirvern — panic view</title>",
        "<style>body{font-family:system-ui,sans-serif;margin:24px;max-width:960px;"
        "background:#131416;color:#dee0e3}h2{margin-top:28px;font-size:15px;"
        "text-transform:uppercase;letter-spacing:.4px;color:#9aa0a6}"
        "table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:4px 10px;"
        "border-bottom:1px solid #2a2d31;font-size:14px}th{color:#9aa0a6;font-weight:600}"
        ".muted{color:#9aa0a6}.warn{color:#e8b84b}.fail{color:#f06d72}.mono{font-family:ui-monospace,"
        "monospace}.stamp{color:#9aa0a6;font-size:13px}</style></head><body>",
        "<h1 style=\"font-size:20px\">Weirvern <span class=\"muted\">\u2014 panic view "
        "(no JavaScript required)</span></h1>",
        f"<p class=\"stamp\">rendered at {esc(rendered_at)} (UTC). "
        "This page shows what the hub can read right now; nothing here is cached.</p>",
    ]
    if gate_note:
        parts.append(f"<p class=\"warn\">{esc(gate_note)}</p>")

    # ── sensors
    if not fleet:
        parts.append(section("sensors", "<p class=\"fail\">The fleet could not be read.</p>"))
    elif not fleet.get("available"):
        parts.append(section("sensors",
                             f"<p class=\"fail\">Fleet unknown \u2014 {esc(fleet.get('reason'))}</p>"))
    else:
        rows = []
        for r in fleet.get("sensors") or []:
            rows.append(
                "<tr><td class=\"mono\">" + esc(r.get("sensor_id")) + "</td>"
                "<td>" + esc(r.get("state")) + "</td>"
                "<td>" + esc(r.get("age_s")) + "s ago</td>"
                "<td>" + ("enabled" if r.get("enabled") else "switched off") + "</td></tr>")
        if not rows:
            rows.append("<tr><td colspan=\"4\" class=\"muted\">No sensors are registered.</td></tr>")
        data_as_of = ""
        raw_stamp = str(fleet.get("data_as_of") or "")
        if raw_stamp:
            # SINGLE-ZONE, ENFORCED (BF-14): the heartbeat's own timestamp can carry a
            # sensor-local offset, and labelling that "(UTC)" would be a lie in the one
            # place an operator checks how fresh the data is. Normalise, then label.
            try:
                import datetime as _dt  # noqa: PLC0415

                parsed = _dt.datetime.fromisoformat(raw_stamp)
                if parsed.tzinfo is not None:
                    parsed = parsed.astimezone(_dt.UTC)
                data_as_of = parsed.strftime("%Y-%m-%d %H:%M:%S UTC")
            except ValueError:
                data_as_of = raw_stamp
        stamp = (f"<p class=\"stamp\">data as of {esc(data_as_of)} \u2014 "
                 "the newest heartbeat the hub has (all times on this page are UTC).</p>") \
            if data_as_of else \
            "<p class=\"stamp warn\">No heartbeat has ever been recorded.</p>"
        if fleet.get("heartbeats_available") is False:
            stamp = (f"<p class=\"stamp warn\">Heartbeats are unreadable "
                     f"({esc(fleet.get('heartbeat_reason'))}) \u2014 states below are "
                     "registrations only.</p>")
        parts.append(section("sensors", stamp +
                             "<table><tr><th>sensor</th><th>state</th><th>last heard</th>"
                             "<th></th></tr>" + "".join(rows) + "</table>"))

    # ── alerts (24h)
    if not alerts:
        parts.append(section("alerts, last 24h", "<p class=\"fail\">The counts could not be read.</p>"))
    elif not alerts.get("available"):
        parts.append(section("alerts, last 24h",
                             f"<p class=\"fail\">Counts unavailable \u2014 {esc(alerts.get('reason'))}</p>"))
    else:
        parts.append(section("alerts, last 24h",
                             f"<p><span class=\"mono\">{esc(alerts.get('fired'))}</span> fired \u00b7 "
                             f"<span class=\"mono\">{esc(alerts.get('acted'))}</span> acted on</p>"))

    # ── the pipeline's own audit
    if not audit or not audit.get("available"):
        reason_bit = (" \u2014 " + esc(audit.get("reason"))) if audit else ""
        parts.append(section("self-audit",
                             f"<p class=\"fail\">The self-audit could not be read"
                             f"{reason_bit}.</p>"))
    else:
        findings = audit.get("findings") or []
        if findings:
            rows_html = "".join(
                "<tr><td class=\"warn\">" + esc(f.get("class")) + "</td>"
                "<td class=\"mono\">" + esc(f.get("subject")) + "</td>"
                "<td>" + esc(f.get("detail")) + "</td></tr>" for f in findings)
            body = "<table><tr><th>class</th><th>who</th><th>detail</th></tr>" + rows_html + "</table>"
        else:
            body = "<p class=\"muted\">The pipeline passes its own checks.</p>"
        errs = audit.get("errors") or {}
        if errs:
            body += "<p class=\"warn\">Checks that could not run: " + \
                esc(", ".join(f"{k} ({v})" for k, v in errs.items())) + ".</p>"
        parts.append(section("self-audit", body))

    parts.append("<p class=\"stamp\">staged changes live in the browser tab, not on the "
                 "server, so this page cannot see them; the console names them when it is "
                 "working.</p>")
    parts.append("</body></html>")
    return "".join(parts)


def host_payload(detail: dict) -> dict:
    """Serialise the host drill-down, filling gaps so the frontend never guesses.

    ClickHouse omits hours with no traffic. The sparkline needs a continuous axis
    or a quiet period looks like a rendering bug, so the timeline is densified
    over the requested window before it leaves the API.
    """
    hours = int(detail.get("hours", 24) or 24)
    src = detail.get("src_addr")

    # Densify: one bucket per hour, oldest first, zero-filled.
    by_hour: dict[str, dict] = {}
    for row in detail.get("timeline") or []:
        if len(row) >= 3:
            by_hour[str(_jsonable(row[0]))[:19]] = {"bytes": row[1] or 0, "flows": row[2] or 0}

    now = _dt.datetime.now(_dt.UTC).replace(minute=0, second=0, microsecond=0)
    timeline = []
    for i in range(hours - 1, -1, -1):
        hour = now - _dt.timedelta(hours=i)
        key = hour.isoformat()[:19]
        bucket = by_hour.get(key, {"bytes": 0, "flows": 0})
        timeline.append({"hour": key, "bytes": bucket["bytes"], "flows": bucket["flows"]})

    totals = detail.get("totals")
    totals_obj = None
    if totals:
        totals_obj = {
            "bytes": _jsonable(totals[0]), "packets": _jsonable(totals[1]),
            "flows": _jsonable(totals[2]), "unique_destinations": _jsonable(totals[3]),
            "unique_ports": _jsonable(totals[4]),
            "first_seen": _jsonable(totals[5]), "last_seen": _jsonable(totals[6]),
        }

    return {
        "src_addr": src,
        "hostname": _hostname(src),
        "hours": hours,
        # THE FAILURES TRAVEL WITH THE DATA. status.host_detail records a failed sub-query in
        # `_errors`; dropping it here made a broken query render as "No flows from <addr>" --
        # the same class of defect as the Zeek chart that drew an empty axis over a correct
        # payload. A zero and an unmeasured value must not look alike.
        "errors": detail.get("_errors") or None,
        "totals": totals_obj,
        "top_destinations": [
            {"dst_addr": r[0], "hostname": _hostname(r[0]),
             "bytes": _jsonable(r[1]), "flows": _jsonable(r[2]),
             "ports": _jsonable(r[3])}
            for r in (detail.get("top_destinations") or []) if len(r) >= 4
        ],
        "top_ports": [
            {"dst_port": _jsonable(r[0]), "proto": _jsonable(r[1]),
             "bytes": _jsonable(r[2]), "flows": _jsonable(r[3])}
            for r in (detail.get("top_ports") or []) if len(r) >= 4
        ],
        "timeline": timeline,
        "anomalies": [
            {"detected_at": _jsonable(r[0]), "window_start": _jsonable(r[1]),
             "anomaly_score": _jsonable(r[2]), "severity": r[3],
             "detected_by_models": r[4], "primary_deviation_feature": r[5],
             "baseline_comparison": r[6]}
            for r in (detail.get("anomalies") or []) if len(r) >= 7
        ],
        "zeek_services": [
            {"service": r[0], "conns": _jsonable(r[1]), "bytes": _jsonable(r[2])}
            for r in (detail.get("zeek_services") or []) if len(r) >= 3
        ],
        "external": detail.get("external") or {"available": False,
                                              "reason": "external exposure was not read"},
    }


def _summary(d: dict) -> dict | None:
    """Name the flow-summary columns.

    THE BUG THIS FIXES: flow_summary was passed through as the raw ClickHouse row --
    a positional TUPLE. The frontend reads `summary.bytes`, `summary.packets`, etc.,
    so every value came back undefined and the panel rendered "0 BYTES / — PACKETS".
    A positional row must be labelled before it crosses the API boundary; relying on
    the browser to know the column order is how that silently broke.

    Field order matches the SELECT in status.alert_evidence and is asserted by a test.
    """
    row = d.get("flow_summary")
    if not row:
        return None
    fields = ("bytes", "packets", "flows", "unique_destinations", "unique_ports",
              "first_seen", "last_seen")
    if len(row) != len(fields):
        logger.warning("flow_summary has %d values, expected %d", len(row), len(fields))
        return None
    return {f: _jsonable(v) for f, v in zip(fields, row, strict=True)}


def incident_payload(d: dict) -> dict:
    """Serialise the incident object; every nested timestamp goes through `_jsonable`."""
    return _jsonable(d)


def evidence_payload(d: dict) -> dict:
    """JSON for the alert-evidence pivot.

    Serialises every timestamp the same way as the rest of the API (ISO 8601 with
    offset) because the browser formats them; a raw datetime object is not JSON.
    """
    def rows(items, fields):
        out = []
        for r in items or []:
            # strict=True so a column-count mismatch raises instead of silently
            # TRUNCATING. Without it, adding a column to a query but not to this
            # list drops the last field from every row with no error anywhere --
            # exactly the class of silent failure this codebase keeps hitting
            # (an empty panel that looks like a quiet network).
            out.append({f: _jsonable(v) for f, v in zip(fields, r, strict=True)})
        return out

    def evidence_rows(items, fields):
        """Like rows(), but resolves the DESTINATION hostname for each record.

        The evidence tables are the ones an analyst reads line by line, and a column of
        bare IPs makes them cross-reference every address by hand. The lookup is served
        from the shared cache, so this costs one resolution per distinct destination
        rather than one per row.
        """
        out = rows(items, fields)
        for row in out:
            dst = row.get("dst_addr")
            if dst:
                row["hostname"] = _hostname(dst)
        return out

    return {
        "src_addr": d.get("src_addr"),
        "hostname": _hostname(d.get("src_addr")),
        "window_start": _jsonable(d.get("window_start")),
        "window_end": _jsonable(d.get("window_end")),
        "anomaly": d.get("anomaly"),
        "flow_summary": _summary(d),
        # Every raw source behind the evidence, with its own age and state. The page must not
        # present a verdict as fresh when a source is stale, failed or simply absent.
        "source_freshness": d.get("source_freshness") or {},
        "flows": evidence_rows(d.get("flows"), [
            "time_flow_start", "dst_addr", "dst_port", "proto", "bytes",
            "packets", "duration_ms"]),
        "zeek_conn": evidence_rows(d.get("zeek_conn"), [
            "ts", "dst_addr", "dst_port", "proto", "service", "duration",
            "orig_bytes", "resp_bytes", "conn_state"]),
        # The TLS sessions, with the fingerprints the models score. A JA4-driven alert has to
        # pivot to the records that carried the new stack; before this section existed the page
        # showed every signal EXCEPT the one the verdict was about.
        "zeek_ssl": evidence_rows(d.get("zeek_ssl"), [
            "ts", "dst_addr", "dst_port", "version", "server_name", "ja4", "ja4_orig",
            "validation_status"]),
        "zeek_dns": rows(d.get("zeek_dns"), [
            "ts", "query", "qtype", "rcode", "answers", "query_entropy"]),
        "notice": rows(d.get("notice"), ["ts", "note", "msg", "actions"]),
        # Errors are surfaced, not swallowed: an empty evidence table and a broken
        # query look identical otherwise.
        "errors": d.get("_errors") or None,
    }


def overview_payload(services: list, report, anomalies: list[dict],
                     talkers: dict, caps, data_error: str | None = None,
                     sensor: dict | None = None) -> dict:
    """One payload for the landing page, so the browser makes ONE request.

    The dashboard is a single screen; making it fetch four endpoints in parallel
    means four independent failure modes and a visibly half-rendered page. One
    response with explicit nulls is both simpler to render and easier to reason
    about when something is down.
    """
    return {
        # Non-null when the data panels could not be populated. The frontend shows
        # this as a banner: empty panels with no reason given look like a broken
        # deployment, which is exactly how an earlier in-cluster tunnel bug hid.
        "data_error": data_error,
        "health": health_payload(report) if report is not None else None,
        # What the SENSOR says it is doing, which is not the same as its configured
        # mode: a siphon process that died still has SENSOR_MODE=siphon in the ConfigMap.
        # The query reports a stale heartbeat as not-running, so this cannot show
        # "intercepting" for a sensor that has stopped.
        "sensor": sensor or {},
        "workloads": [
            {"name": s.name, "state": s.state, "health": getattr(s, "health", ""),
             "detail": getattr(s, "detail", "")}
            for s in (services or [])
        ],
        # The overview wants the ROWS of the anomalies payload, not the tiles block it now
        # carries beside them (the shape grew an object on 2026-10-16).
        "anomalies": anomalies_payload(anomalies or [])["rows"][:25],
        "top_talkers": [
            {"src_addr": r[0], "hostname": _hostname(r[0]),
             "bytes": _jsonable(r[1]), "flows": _jsonable(r[2]),
             "destinations": _jsonable(r[3])}
            for r in ((talkers or {}).get("points") or []) if len(r) >= 4
        ],
        "capabilities": {
            "cluster_available": bool(getattr(caps, "cluster_available", False)),
            "reason": getattr(caps, "reason", "") or "",
        },
    }

def retrain_payload(row: dict | None, decision: dict | None, *, available: bool = True,
                    reason: str = "", training: dict | None = None) -> dict:
    """The state of the operator's forced retrain, and what it produced.

    EVERYTHING HERE COMES FROM THE ROW, not from the artifact directory: the GUI pod does not mount
    MODEL_DIR (the worker owns it), so a payload that listed files would report an empty candidate on
    a deployment where the candidate exists. The worker wrote the report; this layer only carries it.

    `can_keep` is the honest gate on the button: a candidate that trained NOTHING has nothing to
    install, and offering Keep would be offering to replace working models with an empty set.
    """
    import json as _json  # noqa: PLC0415

    if not available:
        return {"available": False, "reason": reason or "the model actions could not be read",
                "state": "", "report": {}, "summary": "", "can_keep": False, "decision": None,
                "training": training or {}}
    if row is None:
        return {"available": True, "reason": "", "state": "none", "action_id": "",
                "requested_by": "", "requested_at": None, "note": "",
                "report": {}, "summary": "", "can_keep": False, "decision": None,
                "training": training or {}}
    try:
        report = _json.loads(row.get("report") or "{}")
    except (TypeError, ValueError):
        report = {}
    state = str(row.get("state") or "")
    return {
        "available": True, "reason": "",
        "state": state,
        "action_id": str(row.get("action_id") or ""),
        "requested_by": str(row.get("requested_by") or ""),
        "requested_at": _jsonable(row.get("ts")),
        "note": str(row.get("note") or ""),
        "report": report if isinstance(report, dict) else {},
        # DERIVED, NOT FROZEN (0.23.79): the stored note was written by whichever build filed the
        # retrain, so a month-old candidate kept reporting the old sentence -- one detector's count
        # presented as the run's -- long after the formatter was fixed. Recompute from the report.
        "summary": _retrain_summary(report, row.get("note")),
        "training": training or {},
        "can_keep": (state == "done" and bool((report or {}).get("trained_any"))),
        "decision": ({"state": str(decision.get("state") or ""),
                      "note": str(decision.get("note") or ""),
                      "at": _jsonable(decision.get("ts"))} if decision else None),
    }


def _retrain_summary(report: object, note: str | None) -> str:
    """The header sentence for a stored retrain report, or the note when there is no report."""
    if isinstance(report, dict) and report.get("detectors"):
        try:
            from weirvern.models.retrain import report_summary  # noqa: PLC0415

            return report_summary(report)
        except Exception:  # noqa: BLE001 - a summary must never take the panel down
            pass
    return str(note or "")


def gates_payload(fleet: dict, local_name: str, stale_after_s: int,
                  now: _dt.datetime | None = None) -> dict:
    """Every sensor's gate state, plus the two facts only this layer can add.

    ONE RULE STORE, MANY GATES. In a distributed deployment the hub is not the only place traffic
    can be stopped: every weirling that sits in the path installs the same rules on its own
    segment. The store knows each gate's own last words; what the operator cannot read off them:

      * WHICH ONE IS MINE -- "armed" on somebody else's box means nothing for the traffic here;
      * WHETHER IT HAS STOPPED -- a gate that quit reporting is a segment the operator believes is
        filtered. `None` age counts as stale; unknown must never read as fresh.

    Staleness is four missed intervals by default (the caller passes the threshold), and its own
    gate is NEVER marked stale on the strength of somebody else's clock: the row is compared with
    `now` here, which is the hub's clock and the one the operator's browser is closest to.
    """
    if now is None:
        now = _dt.datetime.now(_dt.UTC)
    rows = []
    for g in fleet.get("gates", []):
        updated = g.get("updated_at")
        age: int | None = None
        if isinstance(updated, _dt.datetime):
            if updated.tzinfo is None:
                # ClickHouse can hand back naive values; subtracting one from an aware `now` RAISES,
                # and the row would then render as neither fresh nor stale.
                updated = updated.replace(tzinfo=_dt.UTC)
            age = int((now - updated).total_seconds())
        rows.append({
            **{k: v for k, v in g.items() if k != "updated_at"},
            "age_s": age,
            "local": g.get("sensor") == local_name,
            "stale": (age is None or age > max(1, int(stale_after_s))),
        })
    return {
        "gates": rows,
        "gates_available": bool(fleet.get("available")),
        "gates_reason": str(fleet.get("reason") or ""),
    }


def baselines_payload(data: dict) -> dict:
    """Serialise baselines_overview() for the frontend.

    Passes `available`/`reason` through intact: "the store could not be read" and "no
    host has a baseline yet" need different words on screen, and only the server knows
    which is true.
    """
    if not data.get("available", True):
        return {"available": False, "reason": data.get("reason", "unavailable")}
    return {
        "available": True,
        "host_count": data.get("host_count", 0),
        "refreshed_at": data.get("refreshed_at"),
        "refreshed_age_s": data.get("refreshed_age_s"),
        "behavioural_hosts": data.get("behavioural_hosts"),
        "fingerprint_hosts": data.get("fingerprint_hosts"),
        "last_trained": data.get("last_trained"),
        "fired_24h": data.get("fired_24h"),
        "last_fired": data.get("last_fired"),
        # The reverse-map name beside the address, like every other host row in this console:
        # the IP is the fact and the name is the convenience, never a replacement.
        # THE CARD RENDERS TWELVE ROWS; THE PAYLOAD CAN HOLD THOUSANDS. Resolving every
        # hostname here made /api/baselines take >25s on a 2,935-host baseline: the SQL is
        # fast, the per-host PTR loop is not. Name only the rows the card can display; the
        # rest keep their address (and the UI already falls back to it).
        "hosts": [{**h, "hostname": _hostname(h.get("src_addr")) if i < 12 else None}
                  for i, h in enumerate(data.get("hosts") or [])],
        "errors": data.get("errors"),
    }


def _dispositions() -> dict:
    from weirvern.models import dispositions
    return dispositions.build_record()


def _promotion_policy() -> dict:
    from weirvern.models import promotion
    return {"available": True, "policy_version": promotion.POLICY_VERSION,
            "max_in_flight": promotion.MAX_IN_FLIGHT,
            "shadow_min_days": promotion.SHADOW_MIN_DAYS,
            "canary_max_p95_ratio": promotion.CANARY_MAX_P95_RATIO,
            "note": "automatic inside the charter envelope; the ledger records every action"}


def _ledger_tail(limit: int = 5) -> dict:
    from pathlib import Path

    from weirvern.models import ledger
    path = Path(__file__).resolve().parents[2] / "docs" / "ledger" / "ml-decisions.jsonl"
    rows = ledger.read(path)
    return {"available": bool(rows), "path": str(path), "rows": rows[-limit:],
            "reason": "" if rows else "no decision ledger archive"}


def _latest_eval_report() -> dict:
    from pathlib import Path

    from weirvern.models import eval_report
    return eval_report.latest_report(Path(__file__).resolve().parents[2])


def _latest_review() -> dict:
    from pathlib import Path

    from weirvern.models import review
    return review.latest_report(Path(__file__).resolve().parents[2])


def models_payload(data: dict) -> dict:
    """Serialise model_overview() for the frontend.

    Adds a hostname to each anomaly point alongside its address (the IP is the fact and
    the name is the convenience -- replacing one with the other would lose information
    the analyst cannot recover from the UI).

    Keeps `available`/`reason` intact so the frontend can distinguish "no models have
    trained yet" from "the query failed", which need different words on screen.
    """
    if not data.get("available", True):
        return {"available": False, "reason": data.get("reason", "unavailable")}

    out = {
        "available": True,
        "hours": data.get("hours"),
        "run_count": data.get("run_count", 0),
        "training_history": data.get("training_history", {}),
        # Per-detector recency. The training history alone cannot show staleness: a model whose
        # last retrain was 16 hours ago renders as a line with plenty of points, identical to one
        # retrained a minute ago. These three fields are what let the view say "overdue".
        "staleness": data.get("staleness", []),
        "retrain_interval_h": data.get("retrain_interval_h"),
        "scores": data.get("scores", {}),
        "model_counts": data.get("model_counts", {}),
        "feature_deviations": data.get("feature_deviations", []),
        "feature_coverage": data.get("feature_coverage", {}),
        # The sample is not the window: the points panel is capped, so carry the independent
        # window counts beside it or the headline inherits the cap.
        "severity_counts": data.get("severity_counts", {}),
        "anomaly_window": data.get("anomaly_window", {}),
        # SOC-2: what almost alerted, and WHY it did not. `available` is separate from the
        # list so the panel can say "the near-miss table does not exist yet" instead of
        # rendering an empty list, which would read as "nothing nearly alerted".
        "near_misses": data.get("near_misses", []),
        "near_misses_available": data.get("near_misses_available", False),
        "near_misses_reason": data.get("near_misses_reason", ""),
        # PR-1: the model card is the durable identity behind a name in the score. The
        # view renders status and rollback in words; a missing registry is a named failure,
        # not an empty list that looks like "no models".
        "model_cards": [{k: _jsonable(v) for k, v in row.items()}
                        for row in data.get("model_cards", [])],
        "model_cards_available": data.get("model_cards_available", False),
        "model_cards_reason": data.get("model_cards_reason", ""),
        # WHAT IS INSTALLED, AND WHAT THE ENGINE HAS BEEN DOING (0.23.86). This function is a
        # whitelist, so fields added in payloads.models die here unless they are named -- which is
        # exactly what happened to artifacts, the engine's training log, and the normalized-pattern
        # count: computed on every request, then dropped, and the page fell back to the registry.
        "model_artifacts": data.get("model_artifacts", {}),
        "model_cards_behind": data.get("model_cards_behind", []),
        "model_training": data.get("model_training", {}),
        "normalized": data.get("normalized", {}),
        # THE DETECTORS TABLE. Derived rows and one derived sentence, computed in
        # payloads.models from training + artifacts + calibration + the card veto. Named here because
        # this whitelist is a wall: an unnamed field dies silently at it, which is how the training
        # log and the artifact inventory went missing before.
        "detectors": data.get("detectors", []),
        "detector_summary": data.get("detector_summary", ""),
        # CE-4: the fixed-budget report's verification fields. No live auto-label evidence is
        # wired into this read yet; say `not measured` rather than presenting a silent zero.
        "review": data.get("review") or _latest_review(),
        "eval_report": data.get("eval_report") or _latest_eval_report(),
        "dispositions": data.get("dispositions") or _dispositions(),
        "promotion_policy": data.get("promotion_policy") or _promotion_policy(),
        "ledger": data.get("ledger") or _ledger_tail(),
        "verification": data.get("verification", {
            "available": False,
            "reason": "no auto-label verification report is attached to the live view",
            "verified_attack_windows": None,
            "verified_negative_hours": None,
            "verification_coverage": None,
            "live_precision": "not measured",
        }),
        "points": [],
    }
    for pt in data.get("points", []):
        row = {k: _jsonable(v) for k, v in pt.items()}
        row["hostname"] = _hostname(row.get("src_addr"))
        out["points"].append(row)

    # A one-line reading of the state, so an analyst does not have to infer it from the
    # charts. Deliberately factual: it describes what is present, not what it means.
    n = len(out["points"])
    runs = out["run_count"]
    window = out.get("anomaly_window") or {}
    total = window.get("total")
    counts = (out.get("severity_counts") or {}).get("counts") or []
    if n == 0 and runs == 0:
        out["summary"] = "No training runs and no anomalies in the selected window."
    elif n == 0:
        out["summary"] = f"{runs} training run(s); no anomalies in the selected window."
    else:
        sev: dict[str, int] = {}
        if total is not None and counts:
            for row in counts:
                sev[row.get("severity") or "unknown"] = int(row["count"] or 0)
            display_total = int(total)
        else:
            for pt in out["points"]:
                sev[pt.get("severity") or "unknown"] = sev.get(pt.get("severity") or "unknown", 0) + 1
            display_total = n
        spread = ", ".join(f"{k} {v}" for k, v in sorted(sev.items()))
        sample = (f" Latest {n} shown in the points sample."
                  if total is not None and display_total > n else "")
        out["summary"] = (
            f"{display_total} anomaly(ies) from {runs} training run(s) ({spread}).{sample}"
        )
    return out


# ── SOC views: Netflow, Zeek, Health ────────────────────────────────────────────────────────
#
# Each payload carries `available` and `reason` straight through from the query layer rather
# than flattening to a bare list. A chart drawn from an empty list and a chart whose query
# failed look identical on screen, and the two need different actions from the operator --
# so the distinction is preserved all the way to the DOM, where the panel states it in words.


def netflow_payload(volume: dict, proto: dict, ports: dict, spread: dict,
                    talkers: dict, noise: dict | None = None,
                    interfaces: dict | None = None) -> dict:
    """Netflow view payload.

    NAMES RIDE WITH EVERY ROW THAT CARRIES AN ADDRESS. The talkers list has had
    `hostname` since the view was built; the SPREAD rows did not, so the fan-out chart
    labelled every bar with a bare IP even though the same address was named two charts
    over -- an inconsistency an operator reads as "naming is broken". Both now resolve
    through the shared revdns cache, so the cost is one lookup per distinct address for
    the whole payload.
    """
    spread_out = dict(spread or {})
    if spread_out.get("points"):
        spread_out["points"] = [
            {**p, "hostname": _hostname(p.get("src_addr"))} for p in spread_out["points"]
        ]
    return {
        "volume": volume,
        "protocols": proto,
        "ports": ports,
        "spread": spread_out,
        # The STATED omission: rows the host-only lists left out because their address cannot
        # be a host (multicast/link-local/broadcast -- weirvern/addressing.py).
        "noise": noise or {"available": False, "reason": "not counted", "flows": 0, "bytes": 0},
        # TALKERS KEEP THEIR STATE (issue #13): the list used to be flattened here, dropping the
        # `available`/`reason` the helper had just produced -- which is how a failed query reached
        # the panel as an empty list and rendered as a quiet network. Same shape as every sibling.
        # WHICH NIC EACH FLOW CAME THROUGH (0.23.70). Its own key so a failure here cannot
        # blank the charts beside it -- the same shape rule every sibling follows.
        "interfaces": interfaces or {"available": False, "reason": "not read", "points": [],
                                     "total_flows": 0},
        "talkers": {
            "available": bool((talkers or {}).get("available", True)),
            "reason": (talkers or {}).get("reason", ""),
            "points": [
                {"src_addr": r[0], "hostname": _hostname(r[0]),
                 "bytes": _jsonable(r[1]), "flows": _jsonable(r[2]),
                 "destinations": _jsonable(r[3])}
                for r in ((talkers or {}).get("points") or []) if len(r) >= 4
            ],
        },
    }


def zeek_payload(counts: dict, timeline: dict, services: dict, dns: dict) -> dict:
    return {
        "counts": counts,
        "timeline": timeline,
        "services": services,
        "dns": dns,
    }


def health_deep_payload(report, ingest: dict, sizes: dict, sensor: dict,
                        audit: dict | None = None) -> dict:
    """The DEEP health payload -- reads ClickHouse, unlike /api/healthz.

    The Kubernetes probe must not touch the database: a probe that fails when the database is
    slow restarts the GUI and hides the real problem, which is why /api/healthz answers a
    bare {"ok": true} and says so in its comment. That is right for liveness and useless for
    an operator asking "is data still arriving". This endpoint is the second question.

    `audit` is the SOC-8 alert audit -- every alerting decision, not just the delivered
    ones. Optional so callers that predate it (and tests that exercise the other panels)
    keep working; it degrades to an explicitly unavailable block, never to silence.

    The fallback carries `total`/`truncated`/`names` as well as the lists, because the panel
    reads those unconditionally: a key present only on the success path makes the pager and
    the truncation note throw on the error path, taking down the whole view with a TypeError
    in place of the explanation the operator needed.
    """
    return {
        "health": health_payload(report) if report is not None else None,
        "ingest": ingest,
        "tables": sizes,
        "sensor": sensor or {},
        "alerts": audit if audit is not None else {
            "available": False, "reason": "alert audit was not collected",
            "by_reason": [], "recent": [], "suppressed": 0,
            "total": 0, "truncated": False, "names": {},
        },
    }
