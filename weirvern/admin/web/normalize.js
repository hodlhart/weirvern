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
  let LOADED = false;

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
        el("td", { text: r.source === "dns" ? "DNS" : "Flow" }),
        el("td", { class: "mono", text: r.src_addr }),
        el("td", { class: "mono", text: r.dst_prefix || "—" }),
        el("td", { class: "mono", text: r.source === "dns" ? "—" : `${r.dst_port}/${r.proto}` }),
        el("td", { class: "mono", text: r.dns_name || "—" }),
        el("td", { class: "mono", text: fmtBytes(r.bytes) }),
        el("td", { class: "mono", text: num(r.flows) }),
      ]);
      if (r.normalized) tr.title = "already normalized — remove it below to undo";
      body.appendChild(tr);
    }
    updateApply();
  }

  function renderEntries(entries) {
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

  function setNote(text) {
    const n = document.getElementById("nz-note");
    if (n) n.textContent = text;
  }

  async function loadNormalize() {
    if (!document.getElementById("view-normalize")) return;
    const q = new URLSearchParams({ hours: hours() });
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
      setNote(`Normalized ${data.added} pattern${data.added === 1 ? "" : "s"}. ` +
              "The host baseline absorbs them at the next retrain.");
      await loadNormalize();
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
      setNote("Removed. The pattern leaves the baseline at the next retrain; the record stays.");
      await loadNormalize();
    } catch (e) {
      setNote("Could not remove: " + (e && e.message ? e.message : e));
    }
  }

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
  }

  window.loadNormalize = function () { wire(); return loadNormalize(); };
  // The view is a reading surface: like Sluice, it loads when the tab is opened, not on the
  // 15-second refresh the status views ride.
  document.addEventListener("DOMContentLoaded", wire);
})();
