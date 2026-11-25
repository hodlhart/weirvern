/* THE FILTER BAR — one surface, every view.
 *
 * Operator (2026-11-20): "clicking a value should filter by adding a removable pill at the top;
 * clicking a row opens the right-side sheet; never both." Before this, every view had grown its
 * own chip row (an-filters, nf-chips, dc-chips, nw-status, nz-sev, wl-stat tiles, ...), so the
 * place a filter lived depended on which tab you were on and removing one was a different
 * gesture each time.
 *
 * THE TWO VERBS ARE SEPARATED BY THE EVENT, NOT BY HOPE. A cell that carries
 * `data-filter-field` is captured at the document in the CAPTURE phase: it adds a pill and
 * stops the event before the row's own click handler can also fire. A row without that
 * attribute keeps its established verb (open the sheet, open the host, toggle tracking).
 *
 * THE BAR IS A MIRROR, NOT A SECOND STATE. Each adapter reads the view's existing state and
 * writes through the view's existing setter, so the URL sync, the server query and the bar can
 * never disagree about what is filtered. Every key the adapters expose is already (or is made)
 * URL-backed in app.js's syncURL/applyURLState.
 */
(function () {
  "use strict";

  function txt(id) {
    const node = document.getElementById(id);
    return node ? String(node.value || "").trim() : "";
  }

  function setVal(id, value) {
    const node = document.getElementById(id);
    if (node) {
      node.value = value;
      node.dispatchEvent(new Event("input", { bubbles: true }));
      node.dispatchEvent(new Event("change", { bubbles: true }));
    }
  }

  function after() {
    if (typeof scheduleURLSync === "function") scheduleURLSync();
    const bar = window.FILTER_BAR;
    if (bar) setTimeout(() => bar.render(), 0);
  }

  function pill(key, label, value, remove) {
    return {
      key, value, remove,
      label: `${label}${value ? " = " + value : ""}`,
    };
  }

  /* ── view adapters ─────────────────────────────────────────────────────────────────────── */

  const VIEWS = {
    anomalies: {
      label: "Alerts",
      list() {
        const out = [];
        for (const field of ["host", "severity", "model", "feature"]) {
          if (typeof AN_FILTERS !== "undefined" && AN_FILTERS[field]) {
            out.push(pill(`an.${field}`, field, AN_FILTERS[field], () => {
              AN_FILTERS[field] = "";
              if (typeof anRenderChips === "function") anRenderChips();
              if (typeof loadAnomalies === "function") loadAnomalies().catch(() => {});
              after();
            }));
          }
        }
        if (typeof RIPPLES_STATE !== "undefined" && RIPPLES_STATE.band) {
          out.push(pill("al.band", "ripple band", RIPPLES_STATE.band, () => {
            RIPPLES_STATE.band = "";
            if (typeof renderRipplePage === "function") renderRipplePage(RIPPLES_STATE.data);
            after();
          }));
        }
        return out;
      },
      add(field, value) {
        if (field === "ripple_band") {
          if (typeof RIPPLES_STATE !== "undefined") {
            RIPPLES_STATE.band = String(value || "").toLowerCase();
            if (typeof renderRipplePage === "function") renderRipplePage(RIPPLES_STATE.data);
          }
        } else if (typeof anSetFilter === "function") {
          anSetFilter(field, value);
        }
        after();
      },
    },

    normalize: {
      label: "Normalize",
      list() {
        const out = [];
        if (window.NZ_FEED && window.NZ_FEED.band()) {
          out.push(pill("nz.band", "criticality", window.NZ_FEED.band(), () => {
            window.NZ_FEED.apply("", window.NZ_FEED.kind());
            after();
          }));
        }
        if (window.NZ_FEED && window.NZ_FEED.kind()) {
          out.push(pill("nz.kind", "alert", window.NZ_FEED.kind(), () => {
            window.NZ_FEED.apply(window.NZ_FEED.band(), "");
            after();
          }));
        }
        for (const [id, key, label] of [
          ["nz-source", "nz.source", "source"], ["nz-segment", "nz.segment", "segment"],
          ["nz-port", "nz.port", "port"], ["nz-minbytes", "nz.min", "min bytes"],
          ["nz-find", "nz.q", "search"],
        ]) {
          const value = txt(id);
          if (value) {
            out.push(pill(key, label, value, () => {
              setVal(id, "");
              if (typeof loadNormalize === "function") loadNormalize();
              after();
            }));
          }
        }
        return out;
      },
      add(field, value) {
        if (field === "kind") {
          if (window.NZ_FEED) window.NZ_FEED.apply(window.NZ_FEED.band(), value);
        } else if (field === "band") {
          if (window.NZ_FEED) window.NZ_FEED.apply(value, window.NZ_FEED.kind());
        } else {
          const id = { q: "nz-find", segment: "nz-segment", port: "nz-port",
                       min: "nz-minbytes", source: "nz-source" }[field] || field;
          setVal(id, value);
          if (typeof loadNormalize === "function") loadNormalize();
        }
        after();
      },
    },

    network: {
      label: "Network",
      list() {
        if (typeof ASSETS_STATE === "undefined") return [];
        const out = [];
        if (ASSETS_STATE.status && ASSETS_STATE.status !== "all") {
          out.push(pill("nw.status", "status", ASSETS_STATE.status, () => {
            ASSETS_STATE.status = "all";
            for (const b of document.querySelectorAll("#nw-status [data-nw-status]")) {
              b.setAttribute("aria-pressed", b.dataset.nwStatus === "all" ? "true" : "false");
            }
            if (typeof renderNetwork === "function") renderNetwork();
            after();
          }));
        }
        if (ASSETS_STATE.rippleFilter && ASSETS_STATE.rippleFilter !== "all") {
          out.push(pill("nw.ripple", "ripples", ASSETS_STATE.rippleFilter, () => {
            if (typeof nwSetRippleFilter === "function") nwSetRippleFilter("all");
            after();
          }));
        }
        if (ASSETS_STATE.family && ASSETS_STATE.family !== "all") {
          out.push(pill("nw.family", "family", ASSETS_STATE.family, () => {
            if (typeof nwSetFamilyFilter === "function") nwSetFamilyFilter("all");
            after();
          }));
        }
        if (ASSETS_STATE.subnet) {
          out.push(pill("nw.subnet", "subnet", ASSETS_STATE.subnet, () => {
            ASSETS_STATE.subnet = "";
            setVal("nw-subnet", "");
            if (typeof renderNetwork === "function") renderNetwork();
            after();
          }));
        }
        if (ASSETS_STATE.query) {
          out.push(pill("nw.q", "host", ASSETS_STATE.query, () => {
            ASSETS_STATE.query = "";
            setVal("nw-find", "");
            if (typeof renderNetwork === "function") renderNetwork();
            after();
          }));
        }
        if (ASSETS_STATE.trackedOnly) {
          out.push(pill("nw.tracked", "tracked only", "", () => {
            ASSETS_STATE.trackedOnly = false;
            const b = document.getElementById("nw-only-tracked");
            if (b) b.setAttribute("aria-pressed", "false");
            if (typeof renderNetwork === "function") renderNetwork();
            after();
          }));
        }
        return out;
      },
      add(field, value) {
        if (typeof ASSETS_STATE === "undefined") return;
        if (field === "q") {
          ASSETS_STATE.query = String(value || "");
          setVal("nw-find", ASSETS_STATE.query);
        } else if (field === "subnet") {
          ASSETS_STATE.subnet = String(value || "");
          setVal("nw-subnet", ASSETS_STATE.subnet);
        } else if (field === "status") {
          ASSETS_STATE.status = String(value || "all");
        } else if (field === "ripple") {
          if (typeof nwSetRippleFilter === "function") nwSetRippleFilter(value);
        } else if (field === "family") {
          if (typeof nwSetFamilyFilter === "function") nwSetFamilyFilter(value);
        }
        if (typeof renderNetwork === "function") renderNetwork();
        after();
      },
    },

    discover: {
      label: "Flows",
      list() {
        if (typeof DC_STATE === "undefined") return [];
        return (DC_STATE.filters || []).map((f, i) =>
          pill(`dc.f.${f.field}`, f.field, f.value, () => {
            DC_STATE.filters.splice(i, 1);
            DC_STATE.offset = 0;
            if (typeof loadDiscover === "function") loadDiscover().catch(() => {});
            after();
          }));
      },
      add(field, value) {
        if (typeof dcAddChip === "function") dcAddChip(field, value, `${field} = ${value}`);
        after();
      },
    },

    dns: {
      label: "DNS",
      list() {
        const out = [];
        for (const [id, field, label] of [
          ["dn-domain", "domain", "domain"], ["dn-client", "client", "client"],
          ["dn-qtype", "qtype", "type"], ["dn-rcode", "rcode", "rcode"],
        ]) {
          const value = txt(id);
          if (value) {
            out.push(pill(`dns.${field}`, label, value, () => {
              setVal(id, "");
              if (typeof loadDns === "function") loadDns().then(() => {}).catch(() => {});
              after();
            }));
          }
        }
        return out;
      },
      add(field, value) {
        const id = { domain: "dn-domain", client: "dn-client", qtype: "dn-qtype",
                     rcode: "dn-rcode" }[field];
        if (id) setVal(id, value);
        if (typeof loadDns === "function") loadDns().catch(() => {});
        after();
      },
    },

    netflow: {
      label: "Netflow",
      list() {
        if (typeof NF_FILTERS === "undefined") return [];
        return NF_FILTERS.map((f, i) =>
          pill(`nf.${f.field}`, f.field, f.label || f.value, () => {
            if (typeof nfRemoveChip === "function") nfRemoveChip(i);
            after();
          }));
      },
      add(field, value) {
        if (typeof nfSetFilter === "function") nfSetFilter(field, value, value);
        after();
      },
    },

    zeek: {
      label: "Zeek",
      list() {
        if (typeof ZEEK_FILTERS === "undefined") return [];
        return ZEEK_FILTERS.map((f, i) =>
          pill(`zk.${f.field}`, ZEEK_FIELD_LABELS[f.field] || f.field, f.label || f.value, () => {
            if (typeof zkRemoveFilter === "function") zkRemoveFilter(i);
            after();
          }));
      },
      add(field, value) {
        if (typeof zkSetFilter === "function") zkSetFilter(field, value, value);
        after();
      },
    },

    weirlings: {
      label: "Weirlings",
      list() {
        if (typeof WL_FILTERS === "undefined" || !WL_FILTERS.state) return [];
        return [pill("wl.f", "state", WL_FILTERS.state.replace("_", " "), () => {
          if (typeof wlSetState === "function") wlSetState("");
          after();
        })];
      },
      add(field, value) {
        if (field === "state" && typeof wlSetState === "function") wlSetState(value);
        after();
      },
    },

    assets: {
      label: "Assets",
      list() {
        if (typeof ASSETS_STATE === "undefined") return [];
        const out = [];
        if (ASSETS_STATE.search) {
          out.push(pill("as.q", "search", ASSETS_STATE.search, () => {
            ASSETS_STATE.search = "";
            setVal("as-search", "");
            if (typeof renderAssets === "function") renderAssets();
            after();
          }));
        }
        if (ASSETS_STATE.svc) {
          out.push(pill("as.svc", "service", ASSETS_STATE.svc, () => {
            ASSETS_STATE.svc = "";
            if (typeof renderAssets === "function") renderAssets();
            after();
          }));
        }
        return out;
      },
      add(field, value) {
        if (typeof ASSETS_STATE === "undefined") return;
        if (field === "q") {
          ASSETS_STATE.search = String(value || "");
          setVal("as-search", ASSETS_STATE.search);
        } else if (field === "svc") {
          ASSETS_STATE.svc = String(value || "");
        }
        if (typeof renderAssets === "function") renderAssets();
        after();
      },
    },

    models: {
      label: "Models",
      list() {
        if (typeof M_FILTERS === "undefined") return [];
        return ["host", "feature"].filter((f) => M_FILTERS[f]).map((f) =>
          pill(`m.${f}`, f, M_FILTERS[f], () => {
            M_FILTERS[f] = "";
            if (typeof mRenderChips === "function") mRenderChips();
            if (typeof loadModels === "function") loadModels().catch(() => {});
            after();
          }));
      },
      add(field, value) {
        if (typeof mSetFilter === "function") mSetFilter(field, value);
        after();
      },
    },

    identity: {
      label: "Identity",
      list() {
        if (typeof ID_FILTERS === "undefined") return [];
        return ["os", "confidence"].filter((f) => ID_FILTERS[f]).map((f) =>
          pill(`id.${f}`, f, ID_FILTERS[f], () => {
            ID_FILTERS[f] = "";
            if (typeof idRenderChips === "function") idRenderChips();
            if (typeof loadIdentity === "function") loadIdentity().catch(() => {});
            after();
          }));
      },
      add(field, value) {
        if (typeof idSetFilter === "function") idSetFilter(field, value);
        after();
      },
    },

    findings: {
      label: "Findings",
      list() {
        if (typeof FINDINGS_STATE === "undefined") return [];
        return [["ip", "host"], ["severity", "severity"]].filter(([f]) => FINDINGS_STATE[f]).map(([f, label]) =>
          pill(`fd.${f}`, label, FINDINGS_STATE[f], () => {
            FINDINGS_STATE[f] = "";
            if (typeof loadFindings === "function") loadFindings().catch(() => {});
            after();
          }));
      },
      add(field, value) {
        if (typeof FINDINGS_STATE !== "undefined") FINDINGS_STATE[field] = String(value || "");
        if (typeof loadFindings === "function") loadFindings().catch(() => {});
        after();
      },
    },

    logs: {
      label: "Logs",
      list() {
        if (typeof WTL_STATE === "undefined") return [];
        return [["scope", "scope"], ["action", "action"], ["target", "target"]]
          .filter(([f]) => WTL_STATE[f]).map(([f, label]) =>
            pill(`au.${f}`, label, WTL_STATE[f], () => {
              WTL_STATE[f] = "";
              if (typeof refreshWriteTrails === "function") refreshWriteTrails();
              after();
            }));
      },
      add(field, value) {
        if (typeof WTL_STATE !== "undefined") WTL_STATE[field] = String(value || "");
        if (typeof refreshWriteTrails === "function") refreshWriteTrails();
        after();
      },
    },

    sluice: {
      label: "Sluice",
      list() {
        if (typeof SL2_STATE === "undefined" || !SL2_STATE.filter || SL2_STATE.filter === "all") return [];
        return [pill("sl.gate", "gate", SL2_STATE.filter, () => {
          if (typeof sl2SetGate === "function") sl2SetGate("all");
          after();
        })];
      },
      add(field, value) {
        if (field === "gate" && typeof sl2SetGate === "function") sl2SetGate(value);
        after();
      },
    },

    blocked: {
      label: "Blocks",
      list() {
        const out = [];
        for (const [id, field, label] of [["bl-domain", "domain", "domain"],
                                          ["bl-client", "client", "client"]]) {
          const value = txt(id);
          if (value) {
            out.push(pill(`bl.${field}`, label, value, () => {
              setVal(id, "");
              if (typeof loadBlocked === "function") loadBlocked().catch(() => {});
              after();
            }));
          }
        }
        return out;
      },
      add(field, value) {
        setVal(field === "domain" ? "bl-domain" : "bl-client", value);
        if (typeof loadBlocked === "function") loadBlocked().catch(() => {});
        after();
      },
    },

    settings: {
      label: "Settings",
      list() {
        const value = txt("st-filter");
        return value ? [pill("st.q", "search", value, () => {
          setVal("st-filter", "");
          after();
        })] : [];
      },
      add(field, value) {
        setVal("st-filter", value);
        after();
      },
    },

    // These surfaces have no value filters of their own; the bar exists and stays hidden.
    evidence: { label: "Evidence", list: () => [], add: () => {} },
    host: { label: "Host", list: () => [], add: () => {} },
    health: { label: "Health", list: () => [], add: () => {} },
  };

  function adapterFor(view) {
    const name = view === "identity" ? "assets" : view;
    return VIEWS[name] || null;
  }

  /* ── the bar ──────────────────────────────────────────────────────────────────────────── */
  function render() {
    const host = document.getElementById("filter-bar");
    if (!host) return;
    const view = (typeof CURRENT_VIEW !== "undefined" && CURRENT_VIEW) || "health";
    const adapter = adapterFor(view);
    const items = adapter ? adapter.list() : [];
    host.replaceChildren();
    if (!items.length) {
      host.hidden = true;
      host.dataset.count = "0";
      host.setAttribute("aria-hidden", "true");
      return;
    }
    host.hidden = false;
    host.dataset.count = String(items.length);
    host.setAttribute("aria-hidden", "false");
    host.appendChild(el("span", { class: "filter-bar-label", text: `${adapter.label} filters` }));
    for (const item of items) {
      const b = el("button", {
        class: "bubble filter",
        attrs: { type: "button", "aria-pressed": "true",
                 // NAMED, NOT HOVER-ONLY. A `title` here was canon debt: on touch there is no
                 // hover, so the only statement that this pill removes itself vanished. The
                 // aria-label carries that verb to every reader, pointer or not.
                 "aria-label": `remove filter ${item.label}`,
                 "data-filter-key": item.key,
                 "data-filter-value": item.value || "" },
      }, [
        el("span", { text: item.label }),
        el("span", { class: "bubble-x", text: "\u00d7", attrs: { "aria-hidden": "true" } }),
      ]);
      b.addEventListener("click", (ev) => {
        ev.stopPropagation();
        item.remove();
      });
      host.appendChild(b);
    }
    host.appendChild(el("button", {
      class: "bubble filter filter-clear",
      attrs: { type: "button", "aria-pressed": "false" },
      text: "clear all",
      on: { click: () => { for (const item of items) item.remove(); } },
    }));
  }

  function add(field, value, label) {
    const view = (typeof CURRENT_VIEW !== "undefined" && CURRENT_VIEW) || "";
    const adapter = adapterFor(view);
    if (!adapter || !adapter.add) return false;
    if (value === undefined || value === null || String(value).trim() === "") return false;
    adapter.add(field, String(value).trim(), label);
    render();
    return true;
  }

  /* ── value cells: click a VALUE, never both verbs ─────────────────────────────────────── */
  function tagCell(cell, field) {
    if (!cell || cell.dataset.filterField) return;
    const value = String(cell.textContent || "").trim();
    if (!value || value === "—") return;
    cell.dataset.filterField = field;
    cell.dataset.filterValue = value;
    if (!cell.getAttribute("role")) cell.setAttribute("role", "button");
    cell.setAttribute("tabindex", "0");
    if (!cell.classList.contains("dcell")) cell.classList.add("value-cell");
    // NEVER REPLACE A TITLE THE RENDERER WROTE. A mode cell's title explains the declared-vs-
    // reported disagreement; "filter by siphon" would erase the explanation the operator needs.
    if (!cell.getAttribute("title")) cell.setAttribute("title", `filter by ${value}`);
    if (!cell.getAttribute("aria-label")) cell.setAttribute("aria-label", `filter by ${value}`);
  }

  // Columns are named by position because the renderers build rows positionally. Only value
  // columns are listed; action/checkbox columns are deliberately absent so a row keeps its verb.
  const TABLES = {
    "nw-hosts-table": { 0: "q" },
    "nw-table": { 0: "q", 1: "q" },
    "anomalies-table": { 6: "severity", 7: "model", 9: "feature" },
    "nz-feed": { 4: "q", 5: "segment" },
    "as-table": { 0: "q" },
    "dn-rows": { 1: "client", 2: "domain", 3: "qtype", 4: "rcode" },
    "nf-detail-table": { 0: "src", 1: "dst", 2: "dport" },
    "zk-hosts-table": { 0: "host" },
    "wl-table": { 1: "state" },
    "sl2-rules": { 2: "gate" },
    "audit-table": { 1: "action", 2: "target" },
    "md-table": { 0: "host" },
  };

  function markTable(tableId) {
    const spec = TABLES[tableId];
    const table = document.getElementById(tableId);
    if (!spec || !table) return;
    for (const row of table.querySelectorAll("tbody > tr")) {
      // A NIC line under a sensor is part of the fleet table's markup but not one of its data
      // rows; its cells carry their own explanations (declared vs reported), so the value-cell
      // marker must not touch them.
      if (row.classList.contains("wl-nic-row") || row.classList.contains("wl-colhead")) continue;
      const cells = row.querySelectorAll(":scope > td");
      for (const [index, field] of Object.entries(spec)) {
        tagCell(cells[Number(index)], field);
      }
    }
  }

  function markAll() {
    for (const id of Object.keys(TABLES)) markTable(id);
  }

  function installObservers() {
    for (const id of Object.keys(TABLES)) {
      const table = document.getElementById(id);
      const tbody = table && table.querySelector("tbody");
      if (!tbody) continue;
      new MutationObserver(() => markTable(id)).observe(tbody, { childList: true });
    }
  }

  document.addEventListener("click", (ev) => {
    // A .dcell INSIDE a tagged cell has its own, more specific verb. The anomalies row's
    // detector pieces are the reference: tagging their column with the full model string
    // would make "LOF" filter by "Isolation Forest, LOF" and shadow the piece's handler.
    if (ev.target && ev.target.closest && ev.target.closest(".dcell")) return;
    const cell = ev.target && ev.target.closest
      ? ev.target.closest("[data-filter-field]") : null;
    if (!cell) return;
    // CAPTURE, SO THE ROW NEVER ALSO OPENS. This listener is registered with capture=true
    // below; stopPropagation here prevents the row's bubble handler from firing after us.
    ev.preventDefault();
    ev.stopPropagation();
    add(cell.dataset.filterField, cell.dataset.filterValue);
  }, true);

  document.addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter" && ev.key !== " ") return;
    if (ev.target && ev.target.closest && ev.target.closest(".dcell")) return;
    const cell = ev.target && ev.target.closest
      ? ev.target.closest("[data-filter-field]") : null;
    if (!cell) return;
    ev.preventDefault();
    ev.stopPropagation();
    add(cell.dataset.filterField, cell.dataset.filterValue);
  }, true);

  document.addEventListener("DOMContentLoaded", () => {
    installObservers();
    markAll();
    render();
  });

  window.FILTER_BAR = { render, add, markAll, VIEWS, TABLES };
})();
