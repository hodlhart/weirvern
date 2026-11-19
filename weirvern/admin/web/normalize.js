/* The Normalize tab — a feed of near-similar traffic the operator reads, filters and marks.
 *
 * WHAT NORMALIZING DOES (operator, 2026-11-19): the selected pattern is added to that host's
 * adaptive baseline, permanently, so the models learn it as normal. It is NOT a mute: there is no
 * suppression list anywhere in this file, and nothing in the alert path reads this decision.
 *
 * The feed is one read of /api/normalize; the selection lives here and is never guessed at from
 * the DOM, so a re-render cannot lose it. */
(function () {
  "use strict";

  const SELECTED = new Map();   // key -> the row object it came from
  let ROWS = [];
  let ENTRIES = [];
  let WINDOW = { offset: 0, hours: 24, older: false };   // where the feed is looking             // the active entries, so a row can find its own claim
  let LOADED = false;

  // THE THREE LANES, NAMED THE WAY THE OPERATOR NAMES THEM (2026-11-19: "For source do DNS,
  // Zeek, Netflow"). The stored value for Netflow is still `flow`; only the label changed.
  const SOURCE_LABEL = { dns: "DNS", zeek: "Zeek", flow: "Netflow" };

  function keyOf(r) {
    return r.source === "dns"
      ? `dns|${r.src_addr}|${r.dns_name}|${r.dns_qtype}`
      : `flow|${r.src_addr}|${r.dst_prefix}|${r.dst_port}|${r.proto}`;
  }

  function coversText(e) {
    if (e.source === "dns") return `${e.dns_name} (qtype ${e.dns_qtype})`;
    const port = e.dst_port ? `:${e.dst_port}` : "";
    return `${e.dst_prefix || "anywhere"}${port}${e.proto ? ` / proto ${e.proto}` : ""}`;
  }

  function num(n) {
    return Number(n || 0).toLocaleString();
  }

  function hours() {
    const sel = document.getElementById("nz-hours");
    return sel ? String(sel.value || "24") : "24";
  }

  function updateApply() {
    const btn = document.getElementById("nz-apply");
    if (!btn) return;
    const n = SELECTED.size;
    btn.textContent = n ? `Normalize selected (${n})` : "Normalize selected";
    btn.disabled = n === 0;
    btn.setAttribute("aria-disabled", n === 0 ? "true" : "false");
  }

  function renderFeed(rows) {
    ROWS = rows || [];
    const body = document.querySelector("#nz-feed tbody");
    if (!body) return;
    body.replaceChildren();
    if (!ROWS.length) {
      body.appendChild(el("tr", {}, [el("td", {
        class: "muted", attrs: { colspan: 9 },
        text: "No traffic matches these filters. Widen the window or clear a filter.",
      })]));
      updateApply();
      return;
    }
    for (const r of ROWS) {
      const k = keyOf(r);
      const box = el("input", {
        class: "nz-box", attrs: { type: "checkbox", "aria-label": `select ${k}` },
        on: { change: (ev) => {
          if (ev.target.checked) SELECTED.set(k, r); else SELECTED.delete(k);
          ev.target.closest("tr").classList.toggle("nz-selected", ev.target.checked);
          updateApply();
        } },
      });
      if (SELECTED.has(k)) { box.checked = true; }
      const tr = el("tr", { class: (r.normalized ? "nz-normal" : "") +
                                     (SELECTED.has(k) ? " nz-selected" : "") }, [
        el("td", {}, [box]),
        el("td", { class: "mono", text: (r.last_seen || "").replace("T", " ").slice(0, 19) }),
        el("td", { text: SOURCE_LABEL[r.source] || r.source }),
        el("td", { class: "mono", text: r.src_addr }),
        el("td", { class: "mono", text: r.dst_prefix || "—" }),
        el("td", { class: "mono", text: r.source === "dns" ? "—" : `${r.dst_port}/${r.proto}` }),
        el("td", { class: "mono", text: r.dns_name || "—" }),
        el("td", { class: "mono", text: fmtBytes(r.bytes) }),
        el("td", { class: "mono", text: num(r.flows) }),
      ]);
      tr.dataset.key = k;
      // A ROW IS THE DOOR (operator, 2026-11-19): "clicking a normalize row should have the same
      // type of slide out from the right settings piece as weirlings". The checkbox stays a
      // checkbox: clicking it must not also open the sheet.
      tr.tabIndex = 0;
      tr.setAttribute("role", "button");
      tr.setAttribute("aria-label", `open ${r.source === "dns" ? r.dns_name : r.src_addr + " to " + (r.dst_prefix || "anywhere")}`);
      tr.addEventListener("click", (ev) => {
        if (ev.target.closest("input")) return;
        openNormalizeSheet(r, tr);
      });
      tr.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); openNormalizeSheet(r, tr); }
      });
      body.appendChild(tr);
    }
    updateApply();
  }

  function renderEntries(entries) {
    ENTRIES = entries || [];
    const body = document.querySelector("#nz-entries tbody");
    const note = document.getElementById("nz-active-note");
    if (!body) return;
    body.replaceChildren();
    if (note) note.textContent = entries.length ? `${entries.length} in force` : "none yet";
    if (!entries.length) {
      body.appendChild(el("tr", {}, [el("td", {
        class: "muted", attrs: { colspan: 8 },
        text: "Nothing is normalized. Rows you normalize above appear here, permanently, until removed.",
      })]));
      return;
    }
    for (const e of entries) {
      body.appendChild(el("tr", {}, [
        el("td", { class: "mono", text: (e.created_at || "").replace("T", " ").slice(0, 19) }),
        el("td", { text: e.created_by || "operator" }),
        el("td", { text: e.source === "dns" ? "DNS" : "Flow" }),
        el("td", { class: "mono", text: e.src_addr }),
        el("td", { class: "mono", text: coversText(e) }),
        el("td", { class: "mono", text: num(e.flows) }),
        el("td", { class: "mono", text: fmtBytes(e.bytes) }),
        el("td", {}, [el("button", {
          class: "quiet nz-remove", text: "Remove",
          attrs: { type: "button", "data-entry": e.entry_id, "aria-label": `remove ${coversText(e)}` },
          on: { click: () => remove(e.entry_id) },
        })]),
      ]));
    }
  }

  /* THE HOUSE PAGER, pointed at time. Every long list in this console carries `.pager` with the
   * same ‹ › arrows and the same range line (operator, 2026-11-19: "some of our other tabs have
   * that and all long lists should do this and look the same"). Here a page IS one window: ‹ walks
   * backwards in time, › comes back toward now. */
  function renderTimePager(win) {
    WINDOW = Object.assign({ offset: 0, hours: 24, older: false }, win || {});
    const host = document.getElementById("nz-pager");
    if (!host) return;
    host.replaceChildren();
    const arrow = (label, target, disabled, why) => {
      const b = el("button", { class: "pager-btn", text: label,
                               attrs: { type: "button", "aria-label": why } });
      b.disabled = !!disabled;
      if (!disabled) b.addEventListener("click", () => loadNormalize(target));
      return b;
    };
    const back = WINDOW.offset;
    host.appendChild(arrow("\u2039", back + 1, !WINDOW.older, "older traffic"));
    host.appendChild(el("span", { class: "pager-info", text:
      `${WINDOW.hours}h window \u00b7 ${back ? `${back} window${back === 1 ? "" : "s"} back`
                                            : "newest first"}` +
      `${WINDOW.older ? "" : " \u00b7 the oldest traffic we hold"}` }));
    host.appendChild(arrow("\u203a", Math.max(0, back - 1), back <= 0, "newer traffic"));
  }

  function setNote(text) {
    const n = document.getElementById("nz-note");
    if (n) n.textContent = text;
  }

  async function loadNormalize(offset) {
    if (!document.getElementById("view-normalize")) return;
    const page = Math.max(0, Number(offset === undefined ? WINDOW.offset : offset) || 0);
    const q = new URLSearchParams({ hours: hours(), offset: String(page) });
    const src = document.getElementById("nz-source");
    const seg = document.getElementById("nz-segment");
    const port = document.getElementById("nz-port");
    const minb = document.getElementById("nz-minbytes");
    const find = document.getElementById("nz-find");
    if (src && src.value) q.set("source", src.value);
    if (seg && seg.value.trim()) q.set("segment", seg.value.trim());
    if (port && port.value) q.set("port", port.value);
    if (minb && minb.value) q.set("min_bytes", minb.value);
    if (find && find.value.trim()) q.set("q", find.value.trim());
    setNote("Reading traffic…");
    try {
      const data = await getJSON(`/api/normalize?${q.toString()}`);
      if (!data || data.available === false) {
        setNote("Unavailable: " + ((data && data.reason) || "no data"));
        renderFeed([]); renderEntries([]);
        return;
      }
      renderFeed(data.rows || []);
      renderEntries(data.entries || []);
      renderTimePager(data.window || { offset: page, hours: Number(hours()) });
      const c = document.getElementById("nz-count");
      if (c) {
        const s = data.summary || {};
        c.textContent = `${ROWS.length} row${ROWS.length === 1 ? "" : "s"} · ` +
          `${s.active || 0} normalized`;
      }
      setNote("Select the rows that are normal for this network, then press Normalize. " +
              "Normalizing adds them to the host's baseline — nothing is silenced.");
      LOADED = true;
    } catch (e) {
      setNote("Could not read the feed: " + (e && e.message ? e.message : e));
      renderFeed([]);
    }
  }

  async function applySelected() {
    if (!SELECTED.size) return;
    const btn = document.getElementById("nz-apply");
    if (btn) btn.disabled = true;
    const selections = [...SELECTED.values()].map((r) => ({
      source: r.source, src_addr: r.src_addr, dst_prefix: r.dst_prefix,
      dst_port: r.dst_port, proto: r.proto, dns_name: r.dns_name, dns_qtype: r.dns_qtype,
      flows: r.flows, bytes: r.bytes, packets: r.packets, samples: r.samples,
      avg_bytes: r.avg_bytes, var_bytes: r.var_bytes,
      avg_packets: r.avg_packets, var_packets: r.var_packets,
    }));
    try {
      const data = await postJSON("/api/normalize", { selections });
      if (!data || data.ok === false) throw new Error((data && data.error) || "refused");
      SELECTED.clear();
      await loadNormalize();
      // AFTER the reload: loadNormalize sets the standing note, and a confirmation the reader
      // never sees is not a confirmation.
      setNote(`Normalized ${data.added} pattern${data.added === 1 ? "" : "s"}. ` +
              "The host baseline absorbs them at the next retrain.");
    } catch (e) {
      setNote("Could not normalize: " + (e && e.message ? e.message : e));
    } finally {
      updateApply();
    }
  }

  async function remove(entryId) {
    try {
      const data = await postJSON("/api/normalize/remove", { entry_id: entryId });
      if (!data || data.ok === false) throw new Error((data && data.error) || "refused");
      await loadNormalize();
      setNote("Removed. The pattern leaves the baseline at the next retrain; the record stays.");
    } catch (e) {
      setNote("Could not remove: " + (e && e.message ? e.message : e));
    }
  }


/* ——— THE NORMALIZE SHEET ————————————————————————————————————————————————————————————————
 * Opening a row shows the pattern as a claim you can widen or narrow: the destination scope, the
 * port, the protocol, and for DNS the domain and its type. The values arrive as they were counted
 * and every control states what the broader or narrower choice covers, because "normalize this
 * /24" and "normalize this one host" are different claims about the network. */
let SHEET_ROW = null;
let SHEET_ENTRIES = [];

function parentDomain(name) {
  const parts = String(name || "").split(".").filter(Boolean);
  return parts.length > 2 ? parts.slice(1).join(".") : String(name || "");
}

function scopeOptions(row) {
  const host = row.dst_host || "";
  const fam6 = host.includes(":");
  const hostPrefix = host ? (fam6 ? `${host}/128` : `${host}/32`) : "the one address";
  const subnet = row.dst_prefix || (fam6 ? "the /64" : "the /24");
  const supernet = host ? (fam6 ? v6Supernet(host) : v4Supernet(host)) : "the wider block";
  return [
    ["subnet", `This segment — ${subnet}`],
    ["host", `This one address — ${hostPrefix}`],
    ["supernet", `The wider block — ${supernet}`],
    ["any", "Anywhere — ignore the destination"],
  ];
}

function v4Supernet(addr) {
  const p = String(addr).split(".");
  return p.length === 4 ? `${p[0]}.${p[1]}.0.0/16` : "the wider block";
}

function v6Supernet(addr) {
  const parts = String(addr).split(":").filter(Boolean);
  return parts.length >= 2 ? `${parts[0]}:${parts[1]}::/32` : "the wider block";
}

function field(label, control, hint) {
  const wrap = el("label", { class: "nz-field" }, [el("span", { class: "nz-field-label", text: label }), control]);
  if (hint) wrap.appendChild(el("span", { class: "muted nz-field-hint", text: hint }));
  return wrap;
}

function select(options, value, id) {
  const s = el("select", id ? { attrs: { id } } : {});
  for (const [v, text] of options) {
    const o = el("option", { text, attrs: { value: v } });
    if (String(v) === String(value)) o.selected = true;
    s.appendChild(o);
  }
  return s;
}

function renderNormalizeSheet(row) {
  const body = document.getElementById("nz-detail-body");
  const note = document.getElementById("nz-detail-note");
  const remove = document.getElementById("nz-detail-remove");
  const apply = document.getElementById("nz-detail-apply");
  if (!body) return;
  body.replaceChildren();
  const isDns = row.source === "dns";
  note.textContent = isDns
    ? "Narrow this to the exact domain, or widen it to the parent domain. Either way the baseline learns it — nothing is silenced."
    : "Narrow the claim to one address, or widen it to the whole segment or block. The baseline learns whatever this covers — nothing is silenced.";

  body.appendChild(el("p", { class: "mono nz-pattern", text: isDns
    ? `${SOURCE_LABEL[row.source]} · ${row.src_addr} → ${row.dns_name}` +
      (row.source === "dns" ? ` (qtype ${row.dns_qtype || "any"})` : ` · service ${row.dns_name}`)
    : `Flow · ${row.src_addr} → ${row.dst_prefix || "anywhere"}${row.dst_port ? ":" + row.dst_port : ""}${row.proto ? " / proto " + row.proto : ""}` }));
  body.appendChild(el("p", { class: "muted", text:
    `${num(row.flows)} flows · ${fmtBytes(row.bytes)} · ${num(row.packets)} packets · mean ${fmtBytes(Math.round(row.avg_bytes || 0))} per flow` }));

  if (isDns) {
    const input = el("input", { attrs: { type: "text", id: "nz-detail-domain", value: row.dns_name || "" } });
    body.appendChild(field("Domain", input,
      `Matched exactly. The parent domain is ${parentDomain(row.dns_name)} — choose it to widen.`));
    body.appendChild(field("Record type", select(
      [["0", "Any record type"], ["1", "A"], ["28", "AAAA"], ["5", "CNAME"], ["16", "TXT"]],
      String(row.dns_qtype || 0), "nz-detail-qtype"), "Widening the type covers the host's lookups for this name."));
    const parentBtn = el("button", {
      class: "quiet", text: `Use the parent domain (${parentDomain(row.dns_name)})`,
      attrs: { type: "button" },
      on: { click: () => { input.value = parentDomain(row.dns_name); } },
    });
    body.appendChild(el("div", { class: "controls" }, [parentBtn]));
  } else {
    body.appendChild(field("Destination scope", select(scopeOptions(row), "subnet", "nz-detail-scope"),
      "The feed counts by segment; a claim can be wider or narrower than that."));
    body.appendChild(field("Port", el("input", {
      attrs: { type: "number", id: "nz-detail-port", min: "0", max: "65535",
               value: row.dst_port || "", placeholder: "any port" } }),
      "Leave empty to cover every port on that destination."));
    body.appendChild(field("Protocol", select(
      [["0", "Any protocol"], ["6", "TCP"], ["17", "UDP"], ["1", "ICMP"]], String(row.proto || 0),
      "nz-detail-proto"),
      "Any protocol is the broadest claim."));
  }

  const normalized = Boolean(row.normalized);
  if (apply) apply.textContent = normalized ? "Normalize this wider pattern" : "Normalize this pattern";
  if (remove) remove.classList.toggle("hidden", !normalized);
  SHEET_ENTRIES = ENTRIES;
  const entry = normalized ? ENTRIES.find((e) => sameKey(e, row)) : null;
  if (remove) remove.dataset.entry = entry ? entry.entry_id : "";
}

function sameKey(entry, row) {
  if (entry.source !== row.source) return false;
  if (entry.source === "dns") {
    return entry.src_addr === row.src_addr && entry.dns_name === row.dns_name
      && Number(entry.dns_qtype || 0) === Number(row.dns_qtype || 0);
  }
  return entry.src_addr === row.src_addr && entry.dst_prefix === (row.dst_prefix || "")
    && Number(entry.dst_port || 0) === Number(row.dst_port || 0)
    && Number(entry.proto || 0) === Number(row.proto || 0);
}

function selectionFromSheet(row) {
  const base = {
    source: row.source, src_addr: row.src_addr, flows: row.flows, bytes: row.bytes,
    packets: row.packets, samples: row.samples, avg_bytes: row.avg_bytes, var_bytes: row.var_bytes,
    avg_packets: row.avg_packets, var_packets: row.var_packets,
  };
  if (row.source === "dns") {
    const domain = (document.getElementById("nz-detail-domain") || {}).value || "";
    const qtype = Number((document.getElementById("nz-detail-qtype") || {}).value || 0);
    return Object.assign(base, { dns_name: domain.trim(), dns_qtype: qtype });
  }
  const scope = (document.getElementById("nz-detail-scope") || {}).value || "subnet";
  const portEl = document.getElementById("nz-detail-port");
  const proto = Number((document.getElementById("nz-detail-proto") || {}).value || 0);
  return Object.assign(base, {
    dst_host: row.dst_host, scope,
    dst_port: portEl && portEl.value ? Number(portEl.value) : 0,
    proto,
  });
}

async function applySheet() {
  if (!SHEET_ROW) return;
  const sel = selectionFromSheet(SHEET_ROW);
  if (sel.source === "dns" && !sel.dns_name) { setNote("A DNS pattern needs a domain."); return; }
  try {
    const data = await postJSON("/api/normalize", { selections: [sel] });
    if (!data || data.ok === false) throw new Error((data && data.error) || "refused");
    const card = document.getElementById("nz-detail-card");
    if (typeof closeSheet === "function") closeSheet(card); else card.classList.add("hidden");
    await loadNormalize();
    setNote(`Normalized ${data.added} pattern${data.added === 1 ? "" : "s"}. ` +
            "The host baseline absorbs them at the next retrain.");
  } catch (e) {
    setNote("Could not normalize: " + (e && e.message ? e.message : e));
  }
}

async function removeFromSheet() {
  const btn = document.getElementById("nz-detail-remove");
  const entryId = btn && btn.dataset.entry;
  if (!entryId) { setNote("This pattern is not normalized yet."); return; }
  const card = document.getElementById("nz-detail-card");
  try {
    const data = await postJSON("/api/normalize/remove", { entry_id: entryId });
    if (!data || data.ok === false) throw new Error((data && data.error) || "refused");
    if (typeof closeSheet === "function") closeSheet(card); else card.classList.add("hidden");
    await loadNormalize();
    setNote("Removed. The pattern leaves the baseline at the next retrain; the record stays.");
  } catch (e) {
    setNote("Could not remove: " + (e && e.message ? e.message : e));
  }
}

function openNormalizeSheet(row, opener) {
  SHEET_ROW = row;
  const card = document.getElementById("nz-detail-card");
  if (!card) return;
  document.getElementById("nz-detail-id").textContent = row.source === "dns" ? "DNS" : "flow";
  // the sheet's own title names what is being claimed, so it is never a static blank
  document.getElementById("nz-detail-title").textContent =
    row.source === "dns" ? "Normalize this domain" : "Normalize this pattern";
  renderNormalizeSheet(row);
  if (typeof openSheet === "function") {
    openSheet(card, { scrimId: "nz-detail-scrim", initialFocus: "nz-detail-close" });
  } else {
    card.classList.remove("hidden");
  }
  card.dataset.opener = opener ? "" : "";
}

window.openNormalizeSheet = openNormalizeSheet;

  function wire() {
    const view = document.getElementById("view-normalize");
    if (!view || view.dataset.wired === "1") return;
    view.dataset.wired = "1";
    for (const id of ["nz-hours", "nz-source"]) {
      const n = document.getElementById(id);
      if (n) n.addEventListener("change", () => loadNormalize());
    }
    for (const id of ["nz-segment", "nz-port", "nz-minbytes", "nz-find"]) {
      const n = document.getElementById(id);
      if (n) n.addEventListener("change", () => loadNormalize());
    }
    const apply = document.getElementById("nz-apply");
    if (apply) apply.addEventListener("click", applySelected);
    const card = document.getElementById("nz-detail-card");
    if (card && typeof wireSheet === "function") wireSheet(card, { scrimId: "nz-detail-scrim" });
    const close = document.getElementById("nz-detail-close");
    if (close) close.addEventListener("click", () => {
      if (typeof closeSheet === "function") closeSheet(card); else card.classList.add("hidden");
    });
    const cancel = document.getElementById("nz-detail-cancel");
    if (cancel) cancel.addEventListener("click", () => {
      if (typeof closeSheet === "function") closeSheet(card); else card.classList.add("hidden");
    });
    const sheetApply = document.getElementById("nz-detail-apply");
    if (sheetApply) sheetApply.addEventListener("click", applySheet);
    const sheetRemove = document.getElementById("nz-detail-remove");
    if (sheetRemove) sheetRemove.addEventListener("click", removeFromSheet);
  }

  window.loadNormalize = function () { wire(); return loadNormalize(); };
  // The view is a reading surface: like Sluice, it loads when the tab is opened, not on the
  // 15-second refresh the status views ride.
  document.addEventListener("DOMContentLoaded", wire);
})();
