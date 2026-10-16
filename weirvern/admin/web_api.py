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


def health_payload(report) -> dict:
    """Serialise a HealthReport."""
    return {
        "ok": report.ok,
        "fetched_at": _jsonable(_dt.datetime.fromtimestamp(report.fetched_at)),
        "checks": [
            {"name": p.name, "ok": p.ok, "detail": p.detail,
             "value": _jsonable(p.value), "latency_ms": round(p.latency_ms, 1)}
            for p in report.probes
        ],
    }


def anomalies_payload(rows: list[dict]) -> list[dict]:
    """Serialise anomaly rows, decoding the JSON `feature_contributions` string.

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
    return out


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

    now = _dt.datetime.now().replace(minute=0, second=0, microsecond=0)
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
                     talkers: list[tuple], caps, data_error: str | None = None,
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
        "anomalies": anomalies_payload(anomalies or [])[:25],
        "top_talkers": [
            {"src_addr": r[0], "hostname": _hostname(r[0]),
             "bytes": _jsonable(r[1]), "flows": _jsonable(r[2]),
             "destinations": _jsonable(r[3])}
            for r in (talkers or []) if len(r) >= 4
        ],
        "capabilities": {
            "cluster_available": bool(getattr(caps, "cluster_available", False)),
            "reason": getattr(caps, "reason", "") or "",
        },
    }

def retrain_payload(row: dict | None, decision: dict | None, *, available: bool = True,
                    reason: str = "") -> dict:
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
                "state": "", "report": {}, "summary": "", "can_keep": False, "decision": None}
    if row is None:
        return {"available": True, "reason": "", "state": "none", "action_id": "",
                "requested_by": "", "requested_at": None, "note": "",
                "report": {}, "summary": "", "can_keep": False, "decision": None}
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
        "summary": str(row.get("note") or ""),
        "can_keep": (state == "done" and bool((report or {}).get("trained_any"))),
        "decision": ({"state": str(decision.get("state") or ""),
                      "note": str(decision.get("note") or ""),
                      "at": _jsonable(decision.get("ts"))} if decision else None),
    }


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
        # SOC-2: what almost alerted, and WHY it did not. `available` is separate from the
        # list so the panel can say "the near-miss table does not exist yet" instead of
        # rendering an empty list, which would read as "nothing nearly alerted".
        "near_misses": data.get("near_misses", []),
        "near_misses_available": data.get("near_misses_available", False),
        "near_misses_reason": data.get("near_misses_reason", ""),
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
    if n == 0 and runs == 0:
        out["summary"] = "No training runs and no anomalies in the selected window."
    elif n == 0:
        out["summary"] = f"{runs} training run(s); no anomalies in the selected window."
    else:
        sev: dict[str, int] = {}
        for pt in out["points"]:
            sev[pt.get("severity") or "unknown"] = sev.get(pt.get("severity") or "unknown", 0) + 1
        spread = ", ".join(f"{k} {v}" for k, v in sorted(sev.items()))
        out["summary"] = f"{n} anomaly(ies) from {runs} training run(s) ({spread})."
    return out


# ── SOC views: Netflow, Zeek, Health ────────────────────────────────────────────────────────
#
# Each payload carries `available` and `reason` straight through from the query layer rather
# than flattening to a bare list. A chart drawn from an empty list and a chart whose query
# failed look identical on screen, and the two need different actions from the operator --
# so the distinction is preserved all the way to the DOM, where the panel states it in words.


def netflow_payload(volume: dict, proto: dict, ports: dict, spread: dict,
                    talkers: list[tuple], noise: dict | None = None) -> dict:
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
        "talkers": [
            {"src_addr": r[0], "hostname": _hostname(r[0]),
             "bytes": _jsonable(r[1]), "flows": _jsonable(r[2]),
             "destinations": _jsonable(r[3])}
            for r in (talkers or []) if len(r) >= 4
        ],
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
