#!/usr/bin/env python3
"""Export the observed network topology as an Obsidian vault.

WHY THIS EXISTS. Obsidian's graph view is a force-directed layout over [[wikilinks]]
between notes. The connection graph this project already computes -- hosts as nodes,
observed host-to-host traffic as weighted edges -- is exactly a set of notes and links
waiting to be written out. One note per host, one link per observed pair, and the vault's
graph view *is* the topology: draggable, zoomable, offline -- no dashboard, no plugin, and
nothing added to what the deployment runs.

WHAT A NOTE CARRIES. The note is named by the host's ADDRESS -- the fact -- and shows the
name alongside it when reverse DNS resolves one, never instead of it. Its body lists the
observed peers as [[links]] annotated with the measured bytes, flows and ports, plus a
recent-anomaly section for hosts flagged in the window. Flagged hosts also carry an
`anomaly` tag, so an Obsidian color group (`tag:#anomaly`) lights them up in the graph.

HONESTY RULES, inherited from the views this reads:
  * a source that could not be read is stated in the vault's README, never silently
    rendered as "nothing there";
  * the edge cap is reported when it truncates the graph;
  * every link is checked to resolve to a note after writing, because a dangling link
    is a node that vanishes from the graph without a trace.

USAGE
    # against a deployment's ClickHouse (port-forward it first):
    #   kubectl -n weirvern port-forward svc/clickhouse 8123:8123
    CLICKHOUSE_HOST=127.0.0.1 CLICKHOUSE_PORT=8123 \
        python scripts/obsidian_export.py --out ~/weirvern-vault

    Then, in Obsidian: "Open folder as vault" -> Graph view.

EXIT CODES: 0 = written (warnings may be printed); 1 = written, but the link check
failed; 2 = cannot run (no database, or nothing to draw).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
from pathlib import Path

# ── Formatting helpers ──────────────────────────────────────────────────────────────────────
# Where a figure has a canonical shape in the GUI, mirror it: two surfaces showing the same
# measurement must not disagree about it.

_UNSAFE = str.maketrans({c: "-" for c in ':\\/|?*<>"'})

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

MAX_ANOMALIES_PER_NOTE = 8


def _note_name(addr: str) -> str:
    """The vault filename -- and therefore the link target -- for a host.

    NAMED BY ADDRESS ON PURPOSE: an address is the fact; a name is a convenience that can
    be wrong, shared, or absent. Characters a filesystem cannot carry (the colons of an
    IPv6 address) are transliterated to '-', and links use the same string, so a link and
    its file can never disagree.
    """
    return (addr or "").strip().translate(_UNSAFE)


def _link(addr: str, name: str = "") -> str:
    """A wikilink to a host, using the resolved name as display text when one exists."""
    target = _note_name(addr)
    return f"[[{target}|{name}]]" if name else f"[[{target}]]"


def _fmt_bytes(n: int | float | None) -> str:
    """Bytes as the GUI writes them (SI units, one decimal), so the two cannot disagree."""
    value = float(n or 0)
    for unit, div in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if abs(value) >= div:
            return f"{value / div:.1f} {unit}"
    return str(round(value))


def _compact_ts(value: object) -> str:
    """A timestamp as 'YYYY-MM-DD HH:MM', from whatever the driver returned."""
    if value in (None, ""):
        return ""
    fmt = getattr(value, "strftime", None)
    if callable(fmt):
        return str(fmt("%Y-%m-%d %H:%M"))
    try:
        return _dt.datetime.fromisoformat(str(value)).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return str(value)[:16]


# ── Reads ───────────────────────────────────────────────────────────────────────────────────


def fetch_anomalies(client, hours: int, limit: int = 2000) -> dict[str, list[dict]] | None:
    """Recent anomalies for every host in the window, grouped by source address.

    Returns None when the read fails -- and the caller SAYS so -- because a host rendered
    without an anomaly section must never conflate "not flagged" with "we could not look".

    One read for the whole segment; the per-host drill-down in status.py is six queries
    per host, which is the wrong shape for a bulk export.
    """
    try:
        rows = client.query(
            "SELECT src_addr, detected_at, anomaly_score, severity, primary_deviation_feature "
            "FROM weirvern.netflow_anomalies "
            "WHERE detected_at >= now() - INTERVAL %(h)s HOUR "
            "ORDER BY detected_at DESC LIMIT %(n)s",
            parameters={"h": hours, "n": limit + 1},
        ).result_rows
    except Exception as exc:  # noqa: BLE001 - a failed read is reported, not fatal
        print(f"  ! anomaly read failed: {str(exc)[:160]}")
        return None

    capped = len(rows) > limit
    grouped: dict[str, list[dict]] = {}
    for r in rows[:limit]:
        grouped.setdefault(str(r[0]), []).append({
            "detected_at": _compact_ts(r[1]),
            "score": float(r[2] or 0.0),
            "severity": str(r[3] or ""),
            "feature": str(r[4] or ""),
        })
    if capped:
        print(f"  ! anomaly list reached the read cap ({limit}); older anomalies are not listed")
    return grouped


def merge_peers(addr: str, edges: list[dict]) -> list[dict]:
    """One entry per peer, merging the two directional rows when both were observed.

    The graph payload keeps observed direction (src -> dst rows); a topology note reads
    better as one line per peer, so A->B and B->A merge into one line with the sums. A
    glyph still says which directions were actually seen: '->' outbound only, '<-' inbound
    only, '<->' both.
    """
    peers: dict[str, dict] = {}
    for e in edges:
        src, dst = str(e.get("source") or ""), str(e.get("target") or "")
        if src == addr:
            peer, direction = dst, "out"
        elif dst == addr:
            peer, direction = src, "in"
        else:
            continue
        p = peers.setdefault(peer, {
            "peer": peer, "bytes": 0, "flows": 0, "ports": [],
            "first": "", "last": "", "dirs": set(),
        })
        p["bytes"] += int(e.get("bytes") or 0)
        p["flows"] += int(e.get("flows") or 0)
        for port in e.get("ports") or []:
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            if port not in p["ports"]:
                p["ports"].append(port)
        first, last = str(e.get("first_seen") or ""), str(e.get("last_seen") or "")
        if first and (not p["first"] or first < p["first"]):
            p["first"] = first
        if last and (not p["last"] or last > p["last"]):
            p["last"] = last
        p["dirs"].add(direction)
    return sorted(peers.values(), key=lambda p: p["bytes"], reverse=True)


def _segment_of(addr: str) -> str:
    """The /24 an address belongs to (IPv4); 'other addresses' otherwise."""
    return addr.rsplit(".", 1)[0] + ".0/24" if _IPV4_RE.match(addr) else "other addresses"


# ── Rendering ───────────────────────────────────────────────────────────────────────────────


def _yaml_str(value: object) -> str:
    """A string as a valid YAML/JSON scalar (double-quoted, escaped)."""
    return json.dumps(str(value))


def render_frontmatter(addr: str, name: str, inv: dict, anomaly_count: int | None) -> str:
    """The note's frontmatter: only fields that carry a value are written.

    `anomaly_count=None` means the anomaly read failed and nothing else stated a count --
    the field is then OMITTED rather than written as 0: a frontmatter `anomalies: 0` from an
    unread source is the read claiming an absence it never established."""
    fields: list[tuple[str, str]] = [("address", _yaml_str(addr))]
    if name:
        fields.append(("name", _yaml_str(name)))
    if inv.get("first_seen"):
        fields.append(("first_seen", _yaml_str(inv["first_seen"])))
    if inv.get("last_seen"):
        fields.append(("last_seen", _yaml_str(inv["last_seen"])))
    for key, label in (("flows", "flows"), ("bytes_out", "bytes_out"),
                       ("bytes_in", "bytes_in"), ("dst_count", "destinations")):
        if key in inv and inv.get(key) is not None and inv.get(key) != "":
            fields.append((label, str(int(inv[key] or 0))))
    if anomaly_count is not None:
        fields.append(("anomalies", str(int(anomaly_count or 0))))
    if inv.get("services"):
        fields.append(("services", "[" + ", ".join(_yaml_str(s) for s in inv["services"]) + "]"))
    tags = ["host"] + (["anomaly"] if anomaly_count else [])
    fields.append(("tags", "[" + ", ".join(tags) + "]"))
    body = "\n".join(f"{k}: {v}" for k, v in fields)
    return f"---\n{body}\n---\n"


def render_host_note(addr: str, name: str, inv: dict, peers: list[dict],
                     anomalies: list[dict] | None, anomalies_ok: bool,
                     hours: int, names: dict[str, str]) -> str:
    """The full markdown for one host note."""
    lines: list[str] = []
    lines.append(f"# {addr}" + (f" — {name}" if name else ""))
    lines.append("")

    # The activity paragraph claims only what the inventory actually read.
    activity: list[str] = []
    if inv.get("flows"):
        activity.append(f"{int(inv['flows']):,} flows")
    if inv.get("bytes_out") is not None and inv.get("bytes_in") is not None:
        activity.append(f"{_fmt_bytes(inv.get('bytes_out'))} out / {_fmt_bytes(inv.get('bytes_in'))} in")
    elif inv.get("bytes"):
        activity.append(f"{_fmt_bytes(inv['bytes'])} sent")
    if inv.get("dst_count"):
        activity.append(f"{int(inv['dst_count'])} distinct destinations")
    if activity:
        lines.append(f"Activity, last {hours}h: " + " · ".join(activity) + ".")
    if inv.get("services"):
        lines.append(f"Services observed (Zeek): {', '.join(str(s) for s in inv['services'])}.")
    if inv.get("first_seen") or inv.get("last_seen"):
        lines.append(f"First seen {_compact_ts(inv.get('first_seen')) or '—'}"
                     f" · last seen {_compact_ts(inv.get('last_seen')) or '—'}.")
    lines.append("")

    # Connections: one line per observed peer, the note's links and the graph's edges.
    n = len(peers)
    lines.append(f"## Connections — {n} peer" + ("" if n == 1 else "s") + f" in the last {hours}h")
    if peers:
        for p in peers:
            arrow = "↔" if p["dirs"] == {"in", "out"} else ("→" if p["dirs"] == {"out"} else "←")
            bits = [_fmt_bytes(p["bytes"]), f"{p['flows']:,} flows"]
            if p["ports"]:
                bits.append("ports " + ", ".join(str(x) for x in p["ports"][:5]))
            if p["last"]:
                bits.append(f"last seen {_compact_ts(p['last'])}")
            lines.append(f"- {arrow} {_link(p['peer'], names.get(p['peer'], ''))} — " + " · ".join(bits))
    else:
        lines.append("No host-to-host traffic was observed for this host in the window — it is "
                     "listed because the inventory has seen it on the segment.")
    lines.append("")

    # Anomalies: present, absent, or UNREAD -- three different states.
    if anomalies:
        lines.append(f"## Anomalies — {len(anomalies)} in the window")
        for a in anomalies[:MAX_ANOMALIES_PER_NOTE]:
            bits = [a["detected_at"] or "time unknown",
                    f"**{a['severity'] or 'severity unknown'}**",
                    f"score {a['score']:.2f}"]
            if a["feature"]:
                bits.append(f"feature: {a['feature']}")
            lines.append("- " + " · ".join(bits))
        if len(anomalies) > MAX_ANOMALIES_PER_NOTE:
            lines.append(f"- …and {len(anomalies) - MAX_ANOMALIES_PER_NOTE} more, newest first")
        lines.append("")
    elif not anomalies_ok:
        lines.append("## Anomalies")
        lines.append("The anomaly table could not be read for this export (see the export log) — "
                     "this is not a clean bill.")
        lines.append("")
    return "\n".join(lines)


def render_topology(rows: list[dict], hours: int, now: str) -> str:
    """Topology.md: a hub note linking every host, grouped by /24 segment."""
    total_conns = sum(r["peers"] for r in rows)
    flagged = sum(1 for r in rows if r["anomalies"])
    lines = [
        "# Topology — weirvern",
        "",
        f"Observed by this deployment in the last **{hours}h**: **{len(rows)} hosts** · "
        f"**{total_conns} connections** · **{flagged} flagged**. Generated {now}.",
        "",
        "Every host is linked below, quiet ones included; each host's note lists its peers as links.",
        "",
    ]
    groups: dict[str, list[dict]] = {}
    for r in rows:
        groups.setdefault(_segment_of(r["addr"]), []).append(r)
    for segment in sorted(groups):
        lines.append(f"## {segment}")
        lines.append("")
        for r in sorted(groups[segment], key=lambda x: (x["anomalies"], x["bytes"]), reverse=True):
            name = f"|{r['name']}" if r["name"] else ""
            bits = []
            bits.append(f"{r['peers']} peer" + ("" if r["peers"] == 1 else "s") if r["peers"]
                        else "no observed connections this window")
            if r["bytes"]:
                bits.append(_fmt_bytes(r["bytes"]))
            if r["anomalies"]:
                bits.append(f"{r['anomalies']} anomalies")
            lines.append(f"- [[{_note_name(r['addr'])}{name}]] — " + " · ".join(bits))
        lines.append("")
    return "\n".join(lines)


def render_readme(out: Path, stats: dict) -> str:
    """README.md: what this vault is, how to read it, and what was NOT readable."""
    src_read = ", ".join(stats["sources_read"]) or "none"
    src_failed = ", ".join(stats["sources_failed"]) or "none"
    lines = [
        "# weirvern topology — Obsidian vault",
        "",
        f"Generated {stats['now']} by `scripts/obsidian_export.py` from this weirvern "
        f"deployment's own reads (the connection graph and the asset inventory) — window: "
        f"the last {stats['hours']}h.",
        "",
        "Open this folder as a vault in Obsidian, then open the graph view: every host is a node, "
        "every observed host-to-host connection is an edge, laid out with forces.",
        "",
        "## Reading it",
        "",
        "- Notes are named by **address** — the fact. A reverse-DNS name follows it when one resolves.",
        "- A host flagged in the window carries an `anomaly` tag and an Anomalies section. Add a",
        "  graph color group `tag:#anomaly` to light flagged hosts up.",
        "- `Topology.md` links every host so nothing is hidden; to see only observed traffic,",
        "  filter the graph with `-file:Topology`.",
        "- Connection lines carry the measured bytes, flow count, top destination ports, and the",
        "  last observed time — they are measurements, not estimates.",
        "",
        "## What this window held",
        "",
        f"- hosts: {stats['hosts']} ({stats['quiet']} with no observed connections)",
        f"- connections: {stats['conns']}",
        f"- anomalies: {stats['anomalies']} across {stats['flagged']} hosts"
        + (" (the anomaly read failed — see the export log)" if not stats["anomalies_ok"] else ""),
        "",
        "## Sources",
        "",
        f"- read: {src_read}",
        f"- failed: {src_failed}",
    ]
    if stats["unreadable"]:
        lines.append(f"- Zeek tables unreadable: {', '.join(stats['unreadable'])}")
    if stats["truncated"]:
        lines.append(f"- **the edge cap truncated the graph**: {stats['conns']} of "
                     f"{stats['total_edges']} observed pairs are drawn")
    lines += [
        "",
        "## Regenerate",
        "",
        "From a checkout, with `CLICKHOUSE_*` environment pointing at the deployment:",
        "",
        f"    python scripts/obsidian_export.py --out {out} --hours {stats['hours']} "
        f"--limit {stats['limit']}",
        "",
        "Re-running replaces the files it manages -- recorded in `.weirvern-manifest.json`, so "
        "it can tell its own notes from yours -- and removes notes for hosts no longer seen. "
        "Anything else you add to this folder is left alone.",
        "",
    ]
    return "\n".join(lines)


def _graph_settings() -> str:
    """The `.obsidian/graph.json` written on FIRST generation only.

    Presets the view for a topology read: flagged hosts red, everything else calm, arrows
    on (links carry an observed direction), orphans hidden (README carries no links; every
    host is linked from Topology.md). Written once — a re-run must not stomp settings the
    operator has since tuned.
    """
    settings = {
        "collapse-filter": False,
        "search": "",
        "showTags": False,
        "showAttachments": False,
        "hideUnresolved": True,
        "showOrphans": False,
        "collapse-color-groups": False,
        "colorGroups": [
            {"query": "tag:#anomaly", "color": {"a": 1, "rgb": 16733525}},
            {"query": "path:Hosts", "color": {"a": 1, "rgb": 8895998}},
        ],
        "collapse-display": True,
        "showArrow": True,
        "textFadeMultiplier": 0,
        "nodeSizeMultiplier": 1.2,
        "lineSizeMultiplier": 1,
        "collapse-forces": True,
        "centerStrength": 0.4,
        "repelStrength": 12,
        "linkStrength": 0.8,
        "linkDistance": 120,
        "scale": 1,
    }
    return json.dumps(settings, indent=2)


# ── The vault ───────────────────────────────────────────────────────────────────────────────


def _verify_links(vault: Path, written: set[str]) -> list[str]:
    """Every [[target]] in the managed files must resolve to a written note.

    A dangling link is a node that vanishes from the graph without a trace, so this runs
    after every generation rather than being trusted to the writer.
    """
    pattern = re.compile(r"\[\[([^\]|#^]+)")
    targets: set[str] = set()
    files = sorted((vault / "Hosts").glob("*.md")) + [vault / "Topology.md"]
    for f in files:
        if f.exists():
            for m in pattern.finditer(f.read_text(encoding="utf-8")):
                targets.add(m.group(1).strip())
    return sorted(t for t in targets if t not in written)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Export the observed network topology as an Obsidian vault.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, help="vault directory to create or update")
    ap.add_argument("--hours", type=int, default=24, help="traffic window in hours (default 24)")
    ap.add_argument("--limit", type=int, default=400,
                    help="edge cap passed to the connection graph (default 400)")
    ap.add_argument("--anomaly-hours", type=int, default=0,
                    help="anomaly window in hours; default: same as --hours")
    args = ap.parse_args()
    anomaly_hours = args.anomaly_hours or args.hours

    from weirvern import db
    from weirvern.admin import assets
    from weirvern.config import get_settings

    settings = get_settings()
    out = Path(args.out).expanduser()
    print("=== obsidian export ===")
    print(f"  reading {settings.clickhouse_host}:{settings.clickhouse_port} "
          f"(db {settings.clickhouse_db}), window {args.hours}h")

    try:
        client_cm = db.connect(settings, retries=3, delay_s=1)
    except Exception as exc:  # noqa: BLE001 - the honest failure path
        print(f"  ! cannot reach ClickHouse at {settings.clickhouse_host}:"
              f"{settings.clickhouse_port}: {str(exc)[:200]}")
        print("    on a workstation, port-forward first: "
              "kubectl -n weirvern port-forward svc/clickhouse 8123:8123")
        return 2
    with client_cm as client:
        return _export(client, assets, out, args, anomaly_hours)


def _export(client, assets, out: Path, args: argparse.Namespace, anomaly_hours: int) -> int:
    now = _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%d %H:%M UTC")

    graph = assets.connection_graph(client, hours=args.hours, limit=args.limit)
    if not graph.get("available"):
        print(f"  ! no graph to draw: {graph.get('reason', 'unknown reason')}")
        print("    (widen --hours, or check that flows are arriving: weirvern status)")
        return 2
    nodes = {str(n.get("id")): n for n in graph.get("nodes", [])}
    edges = graph.get("edges", [])

    inv = assets.asset_inventory(client, hours=args.hours)
    inv_hosts: dict[str, dict] = {}
    if inv.get("available"):
        inv_hosts = {str(h.get("addr")): h for h in inv.get("hosts", [])}
        print(f"  inventory: {inv.get('count', len(inv_hosts))} hosts; "
              f"sources failed: {', '.join(inv.get('sources_failed') or []) or 'none'}")
    else:
        print(f"  ! inventory not readable ({inv.get('reason', 'unknown')}); "
              "notes will carry connections only")

    anomalies = fetch_anomalies(client, anomaly_hours)
    anomalies_ok = anomalies is not None
    if anomalies_ok:
        n_anom = sum(len(v) for v in anomalies.values())
        print(f"  anomalies: {n_anom} across {len(anomalies)} hosts (last {anomaly_hours}h)")

    # Names: the graph and the inventory both resolve through revdns; either may have one.
    names: dict[str, str] = {}
    for nid, n in nodes.items():
        if n.get("name"):
            names[nid] = str(n["name"])
    for addr, h in inv_hosts.items():
        if h.get("name") and addr not in names:
            names[addr] = str(h["name"])

    addrs = set(nodes) | set(inv_hosts) | set(anomalies or {})

    vault_hosts = out / "Hosts"
    vault_hosts.mkdir(parents=True, exist_ok=True)
    written: set[str] = set()
    topo_rows: list[dict] = []
    flagged_total = 0

    # What the PREVIOUS run created, so this run only ever replaces its own files. The README
    # promises "anything else you add to this folder is left alone" -- without this record the
    # cleanup below could not tell a note it wrote from one the operator wrote, and deleted the
    # operator's. A missing manifest means "nothing is known to be ours": the run still writes
    # every note it can derive, and cleans nothing.
    manifest_path = out / ".weirvern-manifest.json"
    try:
        old_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(old_manifest, dict):
            old_manifest = {}
    except (OSError, ValueError):
        old_manifest = {}
    old_notes = {str(n) for n in (old_manifest.get("hosts") or [])}

    for addr in sorted(addrs):
        inv_h = inv_hosts.get(addr, {})
        host_anomalies = (anomalies or {}).get(addr, []) if anomalies_ok else []
        anomaly_count = len(host_anomalies) if anomalies_ok else int(inv_h.get("anomalies") or 0)
        anomaly_known = anomalies_ok or inv_h.get("anomalies") is not None
        flagged_total += 1 if anomaly_count else 0
        peers = merge_peers(addr, edges)
        note = (render_frontmatter(addr, names.get(addr, ""), inv_h,
                                   anomaly_count if anomaly_known else None)
                + "\n"
                + render_host_note(addr, names.get(addr, ""), inv_h, peers,
                                   host_anomalies if anomalies_ok else None,
                                   anomalies_ok, args.hours, names))
        name = _note_name(addr)
        (vault_hosts / f"{name}.md").write_text(note, encoding="utf-8")
        written.add(name)
        topo_rows.append({
            "addr": addr, "name": names.get(addr, ""), "peers": len(peers),
            "bytes": sum(p["bytes"] for p in peers), "anomalies": anomaly_count,
        })

    stale = sorted(n for n in old_notes if n not in written
                   and (vault_hosts / f"{n}.md").exists())
    for stem in stale:
        (vault_hosts / f"{stem}.md").unlink()

    quiet = sum(1 for r in topo_rows if not r["peers"])
    n_anom = sum(r["anomalies"] for r in topo_rows)
    stats = {
        "now": now, "hours": args.hours, "limit": args.limit,
        "hosts": len(topo_rows), "quiet": quiet,
        "conns": len(edges), "total_edges": graph.get("total_edges", len(edges)),
        "truncated": bool(graph.get("truncated")),
        "anomalies": n_anom, "flagged": flagged_total, "anomalies_ok": anomalies_ok,
        "sources_read": list(inv.get("sources_read") or []) if inv.get("available") else [],
        "sources_failed": list(inv.get("sources_failed") or []) if inv.get("available") else ["inventory"],
        "unreadable": list(inv.get("unreadable") or []),
    }

    readme_path = out / "README.md"
    topo_path = out / "Topology.md"
    # Same rule as the notes: a file this exporter never wrote is not its file to replace.
    # An existing README/Topology from a pre-manifest run is left alone (and said so on stdout);
    # delete it once if you want the exporter to take the name over.
    wrote_readme = (not readme_path.exists()) or bool(old_manifest.get("readme"))
    wrote_topo = (not topo_path.exists()) or bool(old_manifest.get("topology"))
    if wrote_topo:
        topo_path.write_text(render_topology(topo_rows, args.hours, now), encoding="utf-8")
    if wrote_readme:
        readme_path.write_text(render_readme(out, stats), encoding="utf-8")
    manifest_path.write_text(json.dumps(
        {"hosts": sorted(written), "readme": wrote_readme, "topology": wrote_topo},
        indent=2) + "\n", encoding="utf-8")
    graph_json = out / ".obsidian" / "graph.json"
    if not graph_json.exists():
        graph_json.parent.mkdir(parents=True, exist_ok=True)
        graph_json.write_text(_graph_settings(), encoding="utf-8")

    dangling = _verify_links(out, written)

    print(f"  vault: {out}")
    print(f"    hosts: {len(topo_rows)} notes ({quiet} quiet) · connections: {len(edges)} edges"
          + (f" (capped; {stats['total_edges']} total observed pairs)" if stats["truncated"] else ""))
    if stale:
        print(f"    removed {len(stale)} stale note(s) no longer seen")
    if not wrote_readme:
        print("    README.md exists and was not written by this exporter -- left alone")
    if not wrote_topo:
        print("    Topology.md exists and was not written by this exporter -- left alone")
    if dangling:
        print(f"  ! {len(dangling)} link(s) do not resolve: {', '.join(dangling[:10])}")
        return 1
    print("    link check: all links resolve")
    print("  open: Obsidian -> Open folder as vault -> Graph view")
    return 0


if __name__ == "__main__":
    sys.exit(main())
