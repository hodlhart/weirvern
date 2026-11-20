/* Assets (inventory) and Network (connection graph).
 *
 * WHY A THIRD SCRIPT. `app.js` owns the original views and the shared helpers; `soc.js` owns
 * the traffic-shape views. These two are a third kind of question -- "which hosts EXIST" and
 * "how are they CONNECTED" -- and they need a force layout that neither of the others has.
 * Keeping them separate means the graph code can be read on its own, and a bug in the layout
 * cannot take the anomaly table down with it.
 *
 * EVERYTHING IS HAND-ROLLED SVG, for the reason stated at the top of app.js: the GUI is
 * deliberately dependency-free because it has to work on an isolated sensor network, and a
 * charting library fetched from a CDN is a chart that does not render there.
 *
 * BOTH VIEWS STATE WHAT IS ABSENT. Every panel either draws real data or says in words what is
 * missing and why. A short asset list and a failed query look identical on screen otherwise --
 * and this codebase has shipped that bug more than once.
 */

const ASSET_API = {
  assets: (hours) => `/api/assets?hours=${hours}`,
  assetChanges: (hours) => `/api/asset-changes?hours=${hours}`,
  graph: (hours, hosts) =>
    `/api/graph?hours=${hours}` +
    (hosts && hosts.length ? hosts.map((h) => `&host=${encodeURIComponent(h)}`).join("") : ""),
  networkHost: (addr, hours) =>
    `/api/network/host?addr=${encodeURIComponent(addr)}&hours=${hours}`,
  zeeklog: (log, hours, filters = "") => `/api/zeeklog?log=${encodeURIComponent(log)}&hours=${hours}${filters}`,
  flows: (params, hours) => `/api/flows?hours=${hours}` +
    (params.port !== undefined ? `&port=${params.port}` : "") +
    (params.proto !== undefined ? `&proto=${params.proto}` : "") +
    (params.src ? `&src=${encodeURIComponent(params.src)}` : "") +
    (params.dst ? `&dst=${encodeURIComponent(params.dst)}` : ""),
};

/* State kept in one place: the hosts the operator has chosen to track, and the raw payload so
 * a re-render (a sort, a filter keystroke) does not refetch. Re-querying on every keystroke
 * would put a ClickHouse aggregate behind a text input. */
const ASSETS_STATE = {
  hours: 24,
  inventory: null,   // the /api/assets payload
  changes: null,     // the /api/asset-changes payload
  graph: null,       // the /api/graph payload
  tracked: [],       // addresses the operator selected on the Network view
  identity: {},      // address/name -> the identity verdict, for the inventory column
  identityError: "", // why the identity lookup could not fill that column
  sort: "anomalies",
  search: "",
  svc: "",          // US-7: the service facet filter (click a chip; filters in place)
  trackedOnly: false,  // US-7: the graph filter -- only the hosts the operator tracks
  status: "all",      // All / Blocked / Alerted -- a real filter over the graph payload
  rippleFilter: "all",  // All / Any ripple / High+ -- narrows the graph and both tables together
  family: "all",     // the ripple FAMILY filter; composes with rippleFilter
  subnet: "",        // subnet/CIDR filter over host addresses
  query: "",         // free-text host/name filter
  sortHosts: "interest",  // "interest" (band then bytes) or "busy" (bytes)
  minEdges: 1,
  showNames: false,
  // Pagination for the inventory. 15 per page by default (the user's number): a segment with
  // 245 hosts is unreadable as one scroll, and a table you have to scroll is a table you skim
  // rather than read.
  page: 1,
  pageSize: 25,
};

/* getJSON lives in app.js -- ONE definition for the whole page. The duplicate that used to
 * sit here silently overrode app.js's version for every call site (scripts share one scope,
 * later declaration wins), so the effective error semantics depended on load order. */

/* ── Assets: the inventory ─────────────────────────────────────────────────── */

/** Queue a manual Nmap scan. The scanner owns execution; this only files the request.
 *
 *  THE SHEET IS THE FEEDBACK (operator, 2026-11-20). A queued job used to leave the button on
 *  "Queued" and nothing else: no state, no elapsed time, no findings. The POST's answer is the
 *  job id, so the sheet opens on that id and polls the queue row the server just wrote. */
function requestScan(ip, btn) {
  if (!btn || btn.disabled) return;
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Queueing…";
  btn.setAttribute("aria-label", `queueing a manual scan of ${ip}`);
  fetch("/api/scan-jobs", {
    method: "POST",
    headers: requestHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ ip }),
  })
    .then(async (response) => {
      const data = await response.json().catch(() => ({}));
      if (!response.ok || data.ok !== true) {
        throw new Error(data.error || `the request was refused (${response.status})`);
      }
      return data;
    })
    .then((data) => {
      btn.disabled = false;
      btn.textContent = original;
      btn.setAttribute("aria-label", `open the running scan of ${ip}`);
      if (typeof openScanSheet === "function" && data.job_id) {
        openScanSheet(data.job_id, { ip });
      }
    })
    .catch((err) => {
      btn.disabled = false;
      btn.textContent = original;
      btn.setAttribute("aria-label", `scan request failed: ${err.message}`);
      btn.classList.add("bad");
    });
}

function loadAssets() {
  if (typeof scheduleURLSync === "function") scheduleURLSync();
  const hours = trHours();  // the global time control is the range (one control, every view)
  // The ledger is its own endpoint and must not wait behind a slow inventory query. Kick it
  // off here; renderAssetChanges owns its loading and unavailable states.
  loadAssetChanges(hours);
  // THE INVENTORY CARRIES IDENTITY NOW (operator, 2026-10-19). Fetch the verdicts in parallel
  // with the inventory, then fold them by address; a failed identity read leaves the column as
  // "—" and says why, never as a guessed label.
  return Promise.all([
    getJSON(ASSET_API.assets(hours)),
    // Identity is a current snapshot; the inventory's window does not filter it (issue #63).
    getJSON("/api/identity")
      .catch((err) => ({ available: false, hosts: [], reason: err.message })),
  ])
    .then(([d, ids]) => {
      ASSETS_STATE.inventory = d;
      ASSETS_STATE.identity = indexIdentity(ids);
      ASSETS_STATE.identityError = ids && ids.available === false
        ? (ids.reason || "the identity lookup did not run") : "";
      renderAssets();
    })
    .catch((err) => {
      ASSETS_STATE.inventory = {
        available: false, hosts: [], reason: err.message,
      };
      renderAssets();
    });
}

/** Sort + filter + render the inventory, from the cached payload. */
/** US-7: the service facet -- one chip per service the inventory saw, with its host count.
 *  A chip TOGGLES: click it to filter, click it again to stop. It wears aria-pressed while it
 *  holds the filter, and the CSS gives pressed chips a checkmark (never colour alone). */
function renderAssetFacets(all) {
  const box = document.getElementById("as-facets");
  if (!box) return;
  box.replaceChildren();
  const counts = new Map();
  for (const h of all) {
    for (const s of (h.services || [])) {
      const key = String(s || "").trim();
      if (key) counts.set(key, (counts.get(key) || 0) + 1);
    }
  }
  if (!counts.size) return;
  const top = [...counts.entries()]
    .sort((a, b) => (b[1] - a[1]) || a[0].localeCompare(b[0]))
    .slice(0, 10);
  for (const [svc, n] of top) {
    const on = ASSETS_STATE.svc.toLowerCase() === svc.toLowerCase();
    const chip = el("button", {
      class: "bubble filter", text: `${svc} \u00b7 ${n}`,
      attrs: { type: "button", "aria-pressed": on ? "true" : "false",
               title: on ? `stop filtering by ${svc}` : `show only hosts speaking ${svc}` },
    });
    chip.addEventListener("click", () => {
      ASSETS_STATE.svc = on ? "" : svc;
      ASSETS_STATE.page = 1;
      renderAssets();
      // US-7: the filter rides the URL (so the current link and a reload keep it).
      if (typeof scheduleURLSync === "function") scheduleURLSync();
    });
    box.appendChild(chip);
  }
}

/** The inventory's first questions: how many monitored hosts, how many are active now, how many
 *  carry an anomaly, and how many have findings. The set is the inventory's monitored set --
 *  external peers are not assets and are never counted here. */
function renderAssetStats(all, payload = {}) {
  const box = document.getElementById("as-stats");
  if (!box) return;
  const now = Date.now();
  const active = all.filter((h) => h.last_seen && (now - Date.parse(h.last_seen)) < 3600e3).length;
  const anomalies = all.filter((h) => Number(h.anomalies) > 0).length;
  // A finding is an exposure observation, not a vulnerability proof. Count only the bands
  // that an operator would triage; "clear" and "not scanned" are not findings.
  const exposed = all.filter((h) => h.scan &&
    ["critical", "high", "medium", "low"].includes(String(h.scan.exposure || ""))).length;
  const scanKnown = payload.scan_available !== false && all.some((h) => h.scan);
  const cells = [["monitored hosts", String(all.length)], ["active (1h)", String(active)],
                 ["with anomalies", String(anomalies)],
                 ["with findings", scanKnown ? String(exposed) : "—"]];
  box.replaceChildren(...cells.map(([k, v]) => el("div", { class: "stat" }, [
    el("div", { class: "k", text: k }), el("div", { class: "v", text: v }),
  ])));
}

/** Fold identity verdicts by every key an asset may be indexed under. */
function indexIdentity(payload) {
  const out = {};
  for (const h of (payload && payload.hosts) || []) {
    for (const key of [h.host, h.hostname, ...(h.aliases || [])]) {
      const k = String(key || "").trim().toLowerCase();
      if (k) out[k] = h;
    }
  }
  return out;
}

function identityForAsset(h) {
  return ASSETS_STATE.identity[String(h.addr || "").trim().toLowerCase()]
    || ASSETS_STATE.identity[String(h.name || "").trim().toLowerCase()]
    || null;
}

function renderAssets() {
  const tbody = document.querySelector("#as-table tbody");
  const note = document.getElementById("as-note");
  const summary = document.getElementById("as-summary");
  if (!tbody) return;

  const d = ASSETS_STATE.inventory || {};
  note.replaceChildren();

  if (d.available === false) {
    summary.textContent = "";
    tbody.replaceChildren();
    note.appendChild(el("p", { class: "muted", text: `Cannot list assets: ${d.reason}.` }));
    return;
  }

  const everyHost = d.hosts || [];
  // THE INVENTORY IS MONITORED-ONLY, BY THE SERVER'S OWN RULE. There is no external set to
  // switch to: a peer outside the monitored networks is not an asset we are responsible for.
  // The old client-side scope select was filtering a payload the server had already filtered,
  // and its "external" option could only ever show an empty list.
  const all = everyHost;
  // Search matches the address, the reverse-DNS name, or a service -- an analyst looking for
  // "everything that spoke smb" has a service name, not an address.
  const q = ASSETS_STATE.search.trim().toLowerCase();
  const searched = q
    ? all.filter((h) =>
        h.addr.toLowerCase().includes(q) ||
        (h.name || "").toLowerCase().includes(q) ||
        (h.services || []).some((s) => s.toLowerCase().includes(q)))
    : all;
  // US-7: the service facet is an EXACT service, not a substring -- clicking the "dns" chip must
  // show the hosts that speak dns, not every host whose service name contains "dn".
  const rows = ASSETS_STATE.svc
    ? searched.filter((h) => (h.services || [])
        .some((s) => s.toLowerCase() === ASSETS_STATE.svc.toLowerCase()))
    : searched;

  const sorters = {
    anomalies: (a, b) => (b.anomalies - a.anomalies) || (b.bytes - a.bytes),
    bytes: (a, b) => b.bytes - a.bytes,
    flows: (a, b) => b.flows - a.flows,
    // NUMERIC, not lexicographic. `localeCompare` puts "…​.10" before "…​.2" because it compares
    // character by character, and an address column that reads 1, 10, 11, 2, 20 looks broken to
    // anyone scanning it. IPv4 is compared octet-by-octet; anything else (a hostname, an IPv6
    // address) falls back to the string comparison, which is the best available ordering.
    addr: (a, b) => compareAddr(a.addr, b.addr),
    name: (a, b) => (a.name || "~").localeCompare(b.name || "~"),
  };
  rows.sort(sorters[ASSETS_STATE.sort] || sorters.anomalies);

  // PAGINATED, because a segment with 245 hosts is unreadable as one scroll and a table you
  // scroll is a table you skim. The page is clamped to the real range: a filter can shrink the
  // result below the current page, and leaving the page number where it was would render an
  // empty table with no explanation.
  const size = ASSETS_STATE.pageSize;
  const pages = Math.max(1, Math.ceil(rows.length / size));
  if (ASSETS_STATE.page > pages) ASSETS_STATE.page = pages;
  if (ASSETS_STATE.page < 1) ASSETS_STATE.page = 1;
  const from = (ASSETS_STATE.page - 1) * size;
  const pageRows = rows.slice(from, from + size);

  renderPager("as-pager", rows.length, ASSETS_STATE.page, pages, (next) => {
    ASSETS_STATE.page = next;
    renderAssets();
  });

  const range = rows.length
    ? ` (showing ${from + 1}\u2013${Math.min(from + size, rows.length)})`
    : "";
  // US-7: "showing X of Y" for EVERY filter combination -- the count and the reasons travel
  // together, so a short list always says what made it short.
  const why = [];
  if (q) why.push(`matching “${ASSETS_STATE.search}”`);
  if (ASSETS_STATE.svc) why.push(`with service ${ASSETS_STATE.svc}`);
  summary.textContent = (why.length
    ? `${rows.length} of ${all.length} monitored hosts ${why.join(" and ")}`
    : `${all.length} monitored hosts in the last ${d.hours}h`) + range;
  renderAssetStats(all, d);

  // The facet itself: what services this inventory actually saw, most common first.
  renderAssetFacets(all);

  // The unreadable sources are named, because a short list must never be mistaken for a
  // quiet network.
  if ((d.unreadable || []).length) {
    note.appendChild(el("p", {
      class: "muted",
      text: `Not counted: ${d.unreadable.join(", ")} could not be read. Hosts that appear only ` +
            `in those logs are missing from this list.`,
    }));
  }
  if ((d.sources_failed || []).length) {
    note.appendChild(el("p", {
      class: "muted",
      text: `Some figures are incomplete: the ${d.sources_failed.join(", ")} query did not run.`,
    }));
  }
  if (ASSETS_STATE.identityError) {
    note.appendChild(el("p", {
      class: "muted",
      text: `Identity is unavailable: ${ASSETS_STATE.identityError}. The Identity column is blank; ` +
            "the asset rows are still complete.",
    }));
  }
  if ((d.scan_sources_failed || []).length) {
    note.appendChild(el("p", {
      class: "muted",
      text: `Scanned exposure is incomplete: the ${d.scan_sources_failed.join(", ")} read failed; ` +
            "those cells say unknown, not clear.",
    }));
  }

  tbody.replaceChildren();
  if (!rows.length) {
    tbody.replaceChildren(el("tr", {}, [emptyStateCell(13, {
      state: q ? "filtered" : "none",
      message: q ? `No host matches “${ASSETS_STATE.search}”.`
                : "No host has been seen in this window.",
      filters: q ? [`search = ${ASSETS_STATE.search}`] : [],
    })]));
    return;
  }

  for (const h of pageRows) {
    const tr = el("tr", { class: "clickable" }, [
      el("td", { class: "link", text: h.addr, title: `drill into ${h.addr}` }),
      el("td", { class: "muted" }, [
        el("span", { text: h.name || "—" }),
        (h.first_seen && (Date.now() - Date.parse(h.first_seen)) < (Number(d.hours) || 24) * 3600e3)
          ? el("span", { class: "bubble state muted", text: " new",
                         attrs: { title: `first seen ${fmtTime(h.first_seen)}` } })
          : null,
      ]),
      (() => {
        const ident = identityForAsset(h);
        const cell = el("td", { class: "muted", text: ident ? (ident.os_label || ident.os || "unknown") : "—" });
        if (ident) {
          cell.classList.add("dcell");
          cell.title = "open the identity evidence";
          cell.addEventListener("click", (ev) => {
            ev.stopPropagation();
            if (typeof showIdentityDetail === "function") showIdentityDetail(ident);
          });
        }
        return cell;
      })(),
      el("td", { class: "muted", text: (h.role || "unknown"),
                 attrs: { title: h.role_source ? `role source: ${h.role_source}` : "no role proposal recorded" } }),
      el("td", { class: "mono", text: fmtBytes(h.bytes) }),
      el("td", {
        class: "mono",
        // The direction split is unavailable if the raw-flows query failed; showing "0 / 0"
        // would claim a measurement that was never made.
        text: (h.bytes_out === undefined && h.bytes_in === undefined)
          ? "—"
          : `${fmtBytes(h.bytes_out)} / ${fmtBytes(h.bytes_in)}`,
      }),
      el("td", { class: "mono", text: String(h.flows) }),
      el("td", { class: "mono", text: String(h.dst_count) }),
      el("td", { class: "muted", text: (h.services || []).join(", ") || "—" }),
      el("td", {
        class: h.anomalies ? "mono" : "mono muted",
        text: h.anomalies ? String(h.anomalies) : "0",
      }),
      el("td", { class: "mono muted", text: fmtTime(h.last_seen) }),
      (() => {
        const scan = h.scan || null;
        const cell = el("td");
        if (!scan) {
          cell.className = "muted";
          cell.textContent = "—";
          cell.title = "scanner status is not attached to this row";
          return cell;
        }
        const band = String(scan.exposure || "unknown");
        const cls = ["critical", "high"].includes(band) ? "bad"
          : band === "medium" ? "warn" : "muted";
        const total = scan.findings && Number(scan.findings.total || 0);
        const chip = el("span", {
          class: `bubble state ${cls}`,
          text: total ? `${band} · ${total}` : band,
        });
        cell.appendChild(chip);
        cell.classList.add("dcell");
        cell.addEventListener("click", (ev) => {
          ev.stopPropagation();
          if (typeof openFindings === "function") openFindings(h.addr);
        });
        const bits = [];
        if (scan.state) bits.push(`scan ${scan.state}`);
        if (scan.services !== null && scan.services !== undefined) {
          bits.push(`${scan.services} service${Number(scan.services) === 1 ? "" : "s"}`);
        }
        if (scan.last_scan) bits.push(`last ${fmtTime(scan.last_scan)}`);
        if (scan.error) bits.push(`error: ${scan.error}`);
        cell.title = bits.concat(["open recorded findings"]).join(" · ");
        return cell;
      })(),
      (() => {
        const btn = el("button", {
          class: "scan-now", text: "Scan now",
          attrs: { type: "button", title: `queue a manual Nmap scan of ${h.addr}` },
        });
        btn.addEventListener("click", (ev) => {
          ev.stopPropagation();
          requestScan(h.addr, btn);
        });
        return el("td", {}, [btn]);
      })(),
    ]);
    tr.addEventListener("click", (ev) => {
      // Shift-click tracks instead of drilling, so the inventory feeds the graph without a
      // round trip through the Network tab's own controls.
      if (ev.shiftKey) { ev.preventDefault(); toggleTracked(h.addr); return; }
      openHost(h.addr);
    });
    tr.title = "click to drill down · shift-click to track on the Network graph";
    tbody.appendChild(tr);
  }

  // The range is stated by the pager, but the summary line repeats it because it is the line an
  // analyst reads first -- and a paged table that does not say "of 245" is the same
  // silent-truncation problem as the graph's edge cap.

  // Feed the drill-down datalist, so typing an address is a suggestion not a memory test.
  const dl = document.getElementById("known-hosts");
  if (dl) {
    dl.replaceChildren(...all.slice(0, 300).map((h) =>
      el("option", { attrs: { value: h.addr, label: h.name || h.addr } })));
  }
}

/** Page controls for a long table: prev/next arrows, a page indicator, and the range.
 *
 * WHY ARROWS RATHER THAN A SCROLL. The inventory reached 245 hosts on one page, which is a
 * scroll rather than a table -- you skim it and lose your place. Pages of 15 give a stable
 * viewport and a bounded number of rows to read at once.
 *
 * THE RANGE IS ALWAYS STATED ("showing 16-30 of 245"). A paged list that shows only "page 2 of
 * 17" makes the total invisible, which is the same silent-truncation problem as the connection
 * graph's edge cap: the reader cannot tell a complete list from a partial one.
 *
 * The arrows are DISABLED at the ends rather than hidden, so the control does not reflow and
 * the reader can see that they are at the boundary.
 */
/** Compare two addresses numerically when both are IPv4, else as strings.
 *
 * An asset inventory is scanned, and "…​.10" sorting before "…​.2" makes the column unreadable.
 * IPv6 and hostnames are left to string comparison rather than half-parsed into something wrong.
 */
function compareAddr(a, b) {
  const octets = (s) => {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s || ""));
    return m ? m.slice(1).map(Number) : null;
  };
  const x = octets(a), y = octets(b);
  if (x && y) {
    for (let i = 0; i < 4; i++) if (x[i] !== y[i]) return x[i] - y[i];
    return 0;
  }
  return String(a || "").localeCompare(String(b || ""));
}

/* ── THE UNIVERSAL PAGER ────────────────────────────────────────────────────────────────────
 * Operator (2026-11-20): "connection details and edges as a table needs previous and next
 * buttons to reduce scrolling. any table that is long needs the same, make previous and next
 * buttons universal in the whole project."
 *
 * ONE page size, ONE control, ONE count grammar. `PAGER_PAGE_SIZE` is the console's page size;
 * a table that needs a different number has to change it here, so two tables cannot disagree
 * about what "rows 1-25" means. `paginateTable` is wired ONCE per table and observes the tbody,
 * so any renderer -- including ones written later -- is paged without a second implementation.
 *
 * COUNT HONESTY. `serverTotal` is the payload's own total, which can exceed the rows the server
 * was willing to send (`truncated`). In that case the line says "first N of M (server cap)" and
 * never implies M is available by paging: only the rows that exist can be paged.
 */
const PAGER_PAGE_SIZE = 25;
const TABLE_PAGERS = Object.create(null);

function renderPager(hostId, total, page, pages, onGo, size = PAGER_PAGE_SIZE, opts = {}) {
  const host = document.getElementById(hostId);
  if (!host) return;
  host.replaceChildren();
  const label = opts.label || "this table";
  const truncated = Boolean(opts.truncated && Number(opts.serverTotal) > Number(total));
  if (total === 0 && !truncated) return;
  // A one-page table keeps its range line when the payload was capped -- that sentence is the
  // only place the operator learns the server held more. Otherwise a single page is furniture.
  if (pages <= 1 && !truncated) return;

  const first = total ? (page - 1) * size + 1 : 0;
  const last = Math.min(page * size, total);
  const range = truncated
    ? `first ${last} of ${Number(opts.serverTotal).toLocaleString()} (server cap)`
    : `rows ${first}\u2013${last} of ${Number(total).toLocaleString()}`;

  const btn = (text, target, disabled, aria) => {
    const b = el("button", { class: "pager-btn", text, attrs: { type: "button", "aria-label": aria } });
    b.disabled = !!disabled;
    if (!disabled) b.addEventListener("click", () => onGo(target));
    return b;
  };

  host.appendChild(btn("\u2039 Previous", page - 1, page <= 1, `previous page of ${label}`));
  host.appendChild(el("span", {
    class: "pager-info",
    text: `page ${page} of ${pages}   \u00b7   ${range}`,
  }));
  host.appendChild(btn("Next \u203a", page + 1, page >= pages, `next page of ${label}`));

  // Jump-to-first/last only earn their space when there are enough pages to make them useful.
  if (pages > 3) {
    host.appendChild(btn("\u00ab first", 1, page <= 1, `first page of ${label}`));
    host.appendChild(btn("last \u00bb", pages, page >= pages, `last page of ${label}`));
  }
}

/** The pager's view of a table: how many rows it held on the last render, and its page. */
function _tablePageState(tableId, rows) {
  const sig = `${rows.length}|${rows.length ? rows[0].textContent : ""}|` +
    `${rows.length ? rows[rows.length - 1].textContent : ""}`;
  const st = TABLE_PAGERS[tableId] || (TABLE_PAGERS[tableId] = { sig: "", page: 1, total: null,
                                                                 truncated: false });
  // FILTER/SORT/RENDER CHANGED THE ROW SET -> page 1. An identical re-render (a refresh within
  // the same filter) keeps the page, which is the operator's "survive a refresh" rule.
  if (st.sig !== sig) { st.sig = sig; st.page = 1; }
  return st;
}

function paginateTable(tableId) {
  const table = document.getElementById(tableId);
  const tbody = table && table.querySelector("tbody");
  const host = document.getElementById(`${tableId}-pager`);
  if (!tbody || !host) return;
  const all = [...tbody.querySelectorAll(":scope > tr")];
  // An empty-state row (`<td colspan=...>`) is a message, not a page of data.
  const placeholder = all.length === 1 && all[0].querySelector("td[colspan]");
  const rows = placeholder ? [] : all;
  const st = _tablePageState(tableId, rows);
  const pages = Math.max(1, Math.ceil(rows.length / PAGER_PAGE_SIZE));
  st.page = Math.min(Math.max(1, Number(st.page) || 1), pages);
  const start = (st.page - 1) * PAGER_PAGE_SIZE;
  rows.forEach((row, i) => { row.hidden = i < start || i >= start + PAGER_PAGE_SIZE; });
  renderPager(host.id, rows.length, st.page, pages, (next) => {
    st.page = Math.min(Math.max(1, Number(next) || 1), pages);
    paginateTable(tableId);
  }, PAGER_PAGE_SIZE, {
    label: (TABLE_PAGERS[tableId] || {}).label || tableId,
    serverTotal: st.total, truncated: st.truncated,
  });
}

/** Register a table once; every later render of its tbody is paged automatically. */
function wireTablePager(tableId, label) {
  const table = document.getElementById(tableId);
  const tbody = table && table.querySelector("tbody");
  if (!tbody) return;
  if (!TABLE_PAGERS[tableId]) TABLE_PAGERS[tableId] = { sig: "", page: 1, total: null, truncated: false };
  TABLE_PAGERS[tableId].label = label || tableId;
  if (tbody.dataset.pagerWired === "1") return;
  tbody.dataset.pagerWired = "1";
  new MutationObserver(() => paginateTable(tableId)).observe(tbody, { childList: true });
  paginateTable(tableId);
}

/** The payload's own total, for the "first N of M (server cap)" line. */
function setTablePagerTotal(tableId, total, truncated) {
  if (!TABLE_PAGERS[tableId]) return;
  TABLE_PAGERS[tableId].total = Number(total) || null;
  TABLE_PAGERS[tableId].truncated = Boolean(truncated);
  paginateTable(tableId);
}

/* ── Network: the connection graph ─────────────────────────────────────────── */

function loadNetwork() {
  if (typeof scheduleURLSync === "function") scheduleURLSync();
  const hosts = ASSETS_STATE.tracked;
  return getJSON(ASSET_API.graph(trHours(), hosts))
    .then((d) => {
      ASSETS_STATE.graph = d;
      renderNetwork();
    })
    .catch((err) => {
      ASSETS_STATE.graph = { available: false, nodes: [], edges: [], reason: err.message };
      renderNetwork();
    });
}

function toggleTracked(addr) {
  const i = ASSETS_STATE.tracked.indexOf(addr);
  if (i >= 0) ASSETS_STATE.tracked.splice(i, 1);
  else if (ASSETS_STATE.tracked.length < 64) ASSETS_STATE.tracked.push(addr);
  renderChips();
  loadNetwork();
}

function renderChips() {
  const box = document.getElementById("nw-selected");
  if (!box) return;
  box.replaceChildren();
  if (!ASSETS_STATE.tracked.length) {
    box.appendChild(el("span", {
      class: "muted",
      text: "No hosts selected — showing every connection. Click a node or a bar to track specific hosts.",
    }));
    return;
  }
  box.appendChild(el("span", { class: "muted", text: "Tracking:" }));
  for (const addr of ASSETS_STATE.tracked) {
    // US-7: this chip HOLDS a filter (the host is tracked), so it says so: aria-pressed, and
    // the grammar's checkmark follows from the attribute. Clicking releases it.
    const chip = el("span", { class: "bubble filter", title: "click to stop tracking this host",
                              attrs: { "aria-pressed": "true" } }, [
      el("span", { text: addr }),
      el("span", { class: "x", text: "×" }),
    ]);
    chip.addEventListener("click", () => toggleTracked(addr));
    box.appendChild(chip);
  }
}

/* ── Ripple presence on the Network view ─────────────────────────────────────
 *
 * THE BANDS COME FROM THE SERVER. `/api/graph` carries `ripples` (the same rows
 * `/api/ripples` grouped) and `severity_bands`; `rippleBand()` in app.js resolves a row's
 * band from its server-computed `severity` (or, for an older payload, the shipped table).
 * Nothing here restates a threshold: a second mapping would drift from the Alerts tab.
 */
const NW_RIPPLE_RANK = { low: 1, medium: 2, high: 3 };

function networkRipples() {
  return ((ASSETS_STATE.graph || {}).ripples) || [];
}

function networkRipple(host) {
  const addr = String(host || "");
  if (!addr) return null;
  return networkRipples().find((r) => String(r.host || "") === addr) || null;
}

/* ── THE RIPPLE FILTER (operator, 2026-11-20: "for network i need to be able to filter by
 * ripples"). The chips already annotate; this narrows. One state value drives the graph, the
 * connection-detail table and the edge table, so the three surfaces cannot disagree. */
const NW_RIPPLE_MODES = ["all", "any", "high"];

function nwRippleMode() {
  const mode = String(ASSETS_STATE.rippleFilter || "all").toLowerCase();
  return NW_RIPPLE_MODES.includes(mode) ? mode : "all";
}

function nwRippleModeLabel(mode) {
  const m = mode || nwRippleMode();
  return m === "high" ? "high and above" : (m === "any" ? "hosts with ripples" : "all hosts");
}

/** Does this host carry a ripple that survives the active filter? */
function nwRippleMatches(host) {
  const mode = nwRippleMode();
  if (mode === "all") return true;
  const row = networkRipple(host);
  if (!row) return false;
  if (mode === "high") {
    const bands = (ASSETS_STATE.graph || {}).severity_bands;
    return rippleBand(row, bands) === "high";
  }
  return true;
}

/** An edge survives when at least one endpoint is a matched host -- the filter's own wording:
 *  "any edge whose endpoint survives". */
function nwEdgeMatches(edge, matchedIds) {
  if (nwRippleMode() === "all") return true;
  const ids = matchedIds || nwRippleMatchedIds();
  return ids.has(String(edge && edge.source)) || ids.has(String(edge && edge.target));
}

function nwRippleMatchedIds(nodes) {
  const pool = nodes || ((ASSETS_STATE.graph || {}).nodes || []);
  return new Set(pool.filter((n) => nwRippleMatches(n.id)).map((n) => String(n.id)));
}

function nwSetRippleFilter(mode) {
  ASSETS_STATE.rippleFilter = NW_RIPPLE_MODES.includes(mode) ? mode : "all";
  for (const btn of document.querySelectorAll("#nw-ripple [data-nw-ripple]")) {
    btn.setAttribute("aria-pressed", btn.dataset.nwRipple === ASSETS_STATE.rippleFilter
      ? "true" : "false");
  }
  nwClearDetail();
  renderNetwork();
}

/** The detail panel belongs to the previous filter's selection once the filter changes. */
function nwClearDetail() {
  const host = document.getElementById("nw-detail");
  const table = document.querySelector("#nw-detail-table tbody");
  const title = document.getElementById("nw-detail-title");
  const note = document.getElementById("nw-detail-note");
  if (host) host.replaceChildren();
  if (table) table.replaceChildren();
  if (title) title.textContent = "click a line or a dot";
  if (note) note.textContent = "";
}

/** The ripple behind an edge: the HIGHER band when both endpoints have one. */
function networkEdgeRipple(edge) {
  const a = networkRipple(edge && edge.source);
  const b = networkRipple(edge && edge.target);
  if (!a) return b;
  if (!b) return a;
  const bands = (ASSETS_STATE.graph || {}).severity_bands;
  const ra = NW_RIPPLE_RANK[rippleBand(a, bands)] || 0;
  const rb = NW_RIPPLE_RANK[rippleBand(b, bands)] || 0;
  return rb > ra ? b : a;
}

/** A ripple chip, or an EMPTY cell when the host has no ripple (never a zero chip). */
function networkRippleCell(row) {
  const cell = el("td", { class: "nw-ripple-cell" });
  if (!row) return cell;
  const bands = (ASSETS_STATE.graph || {}).severity_bands;
  const band = rippleBand(row, bands);
  const families = (row.families || []).join(" / ") || "no family named";
  const chip = el("span", {
    class: "bubble state nw-ripple-bubble clickable sev-" + band,
    text: sevText(band),
    attrs: {
      role: "button", tabindex: "0",
      "aria-label": `open the ripple evidence for ${row.host}`,
    },
  });
  chip.setAttribute("title", `ripple on ${row.host}: score ${Number(row.score || 0).toFixed(2)} ` +
    `(${families}) — ${band}`);
  const open = (ev) => { ev.stopPropagation(); openRippleSheet(row, chip); };
  chip.addEventListener("click", open);
  chip.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); open(ev); }
  });
  cell.appendChild(chip);
  return cell;
}

function renderNetworkRippleLine(nodes, d, baseNodes) {
  const line = document.getElementById("nw-ripple-line");
  if (!line) return;
  line.replaceChildren();
  if (!d || d.available === false) {
    line.appendChild(el("span", { text: "Ripple presence is unavailable because the graph did not load." }));
    return;
  }
  if (d.ripple_available === false) {
    line.appendChild(el("span", {
      text: `Ripple presence could not be read: ${d.ripple_reason || "the ripple read failed"} — ` +
        "that is not the same as no host rippling.",
    }));
    return;
  }
  const hours = d.ripple_window_hours || d.hours || ASSETS_STATE.hours;
  const rows = d.ripples || [];
  const pool = baseNodes || nodes || [];
  const inView = pool.filter((n) => networkRipple(n.id));
  const mode = nwRippleMode();
  const btn = el("button", {
    class: "rp-link", text: "open Alerts",
    attrs: { type: "button" },
  });
  btn.setAttribute("title", "open the Alerts tab on this same window");
  btn.addEventListener("click", () => showView("anomalies"));
  // THE COVERAGE IS PART OF THE CLAIM. Ripple evidence on this deployment began on
  // 2026-11-19 -- a 7d request holds ~1 day of evidence. Saying "0 ripples" without that
  // sentence would read as a quiet week.
  let covNote = "";
  const cov = d.ripple_coverage || {};
  if (cov.available && cov.from) {
    const span = (new Date(cov.to) - new Date(cov.from)) / 36e5;
    if (Number.isFinite(span) && span + 0.5 < Number(hours)) {
      covNote = ` Ripple evidence covers ${fmtTime(cov.from)} → ${fmtTime(cov.to)} `
        + `(${Math.max(1, Math.round(span))}h of ${hours}h).`;
    }
  } else if (cov.available === false) {
    covNote = ` Ripple coverage unknown: ${cov.reason || "not read"}.`;
  }
  // THE SENTENCE RESTATES THE ACTIVE FILTER. "3 of 19 hosts have ripples — showing 3" is the
  // count of what is on screen, not a count of the payload the reader cannot see.
  let text;
  if (!rows.length) {
    text = `0 hosts in view have a ripple in this ${hours}h window — no host met the ripple bar.`
      + covNote;
  } else if (mode !== "all") {
    const highOnly = mode === "high";
    const matched = nwRippleMatchedIds(pool);
    text = `${matched.size} of ${pool.length} host${pool.length === 1 ? "" : "s"} have `
      + `${highOnly ? "high-band " : ""}ripples in this ${hours}h window — showing `
      + `${matched.size}.` + covNote;
  } else {
    text = `${inView.length} of ${pool.length} host${pool.length === 1 ? "" : "s"} in view have `
      + `${rows.length} ripple${rows.length === 1 ? "" : "s"} in this ${hours}h window.` + covNote;
  }
  line.append(el("span", { text }), el("span", { text: " " }), btn);
}

const NW_FAMILIES = ["flow", "conn", "dns", "tls", "http", "ssh", "notice"];

function nwFamilyMode() {
  const mode = String(ASSETS_STATE.family || "all").toLowerCase();
  return NW_FAMILIES.includes(mode) ? mode : "all";
}

function nwSetFamilyFilter(mode) {
  ASSETS_STATE.family = NW_FAMILIES.includes(mode) ? mode : "all";
  for (const btn of document.querySelectorAll("#nw-family [data-nw-family]")) {
    btn.setAttribute("aria-pressed", btn.dataset.nwFamily === ASSETS_STATE.family
      ? "true" : "false");
  }
  nwClearDetail();
  renderNetwork();
}

/* ── SUBNET AND TEXT FILTERS ────────────────────────────────────────────────────────────────
 * Both are filters over the graph payload (the map's drawn population). They compose with the
 * ripple and family filters: a host must pass every active reading. An INVALID subnet is not
 * applied and is NAMED in the caption -- a typo must not empty the map and blame the network.
 */
function nwSubnetMatcher(raw) {
  const text = String(raw || "").trim();
  if (!text) return { active: false, test: () => true, note: "" };
  const m = text.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
  if (m) {
    const parts = m[1].split(".").map(Number);
    const bits = m[2] === undefined ? 32 : Number(m[2]);
    if (parts.some((p) => p < 0 || p > 255) || bits < 0 || bits > 32) {
      return { active: false, test: () => true,
               note: `subnet "${text}" is not a valid CIDR — not applied` };
    }
    const ipv4ToInt = (ip) => ip.split(".").reduce((n, p) => ((n << 8) + Number(p)) >>> 0, 0) >>> 0;
    const base = ipv4ToInt(m[1]);
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const test = (addr) => {
      if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(addr || ""))) return false;
      return ((ipv4ToInt(String(addr)) & mask) >>> 0) === ((base & mask) >>> 0);
    };
    return { active: true, test, note: "" };
  }
  if (text.includes(":")) {
    // IPv6: a plain prefix is supported; a CIDR is matched as its address prefix and SAID SO.
    const prefix = text.replace(/\/.*$/, "").toLowerCase();
    return {
      active: true,
      test: (addr) => String(addr || "").toLowerCase().startsWith(prefix),
      note: text.includes("/") ? `IPv6 CIDR "${text}" is matched as a prefix` : "",
    };
  }
  return { active: false, test: () => true,
           note: `subnet "${text}" is not a CIDR — not applied` };
}

function nwExtraMatch(node, matcher) {
  if (!node) return false;
  const family = nwFamilyMode();
  if (family !== "all" && !(node.ripple_families || []).includes(family)) return false;
  if (matcher && matcher.active && !matcher.test(node.id)) return false;
  const q = String(ASSETS_STATE.query || "").trim().toLowerCase();
  if (q) {
    const hay = `${node.id || ""} ${node.name || ""}`.toLowerCase();
    if (hay.indexOf(q) === -1) return false;
  }
  return true;
}

function nwExtraActive(matcher) {
  return nwFamilyMode() !== "all" || Boolean(matcher && matcher.active)
    || Boolean(String(ASSETS_STATE.query || "").trim());
}

function nwExtraNames(matcher) {
  const out = [];
  if (nwFamilyMode() !== "all") out.push(`family ${nwFamilyMode()}`);
  if (matcher && matcher.active) out.push(`subnet ${String(ASSETS_STATE.subnet || "").trim()}`);
  const q = String(ASSETS_STATE.query || "").trim();
  if (q) out.push(`text "${q}"`);
  return out;
}

const NW_BAND_RANK = { low: 1, medium: 2, high: 3, critical: 4 };

function nwWorstBand(node) {
  const a = String((node && node.ripple_worst) || "").toLowerCase();
  const b = String((node && node.model_worst) || "").toLowerCase();
  return (NW_BAND_RANK[b] || 0) > (NW_BAND_RANK[a] || 0) ? b : a;
}

/* ── HOST-TABLE ORDER: intelligence first, volume second ───────────────────────────────────
 * The operator asked for a "most interesting" order, not another busiest list. The arithmetic
 * is one line and it is printed under the table: sort by the worst band the host carries
 * (critical > high > medium > low > none), then by bytes in the window. Band DOMINATES; bytes
 * only break ties inside a band. A critical host with 1 MB therefore outranks a quiet host
 * with 10 GB, which is the whole point of a worklist.
 */
function nwInterestKey(node) {
  return [NW_BAND_RANK[nwWorstBand(node)] || 0, Number(node.bytes || 0),
          Number(node.degree || 0)];
}

function nwSortHosts(nodes) {
  const list = nodes.slice();
  if (String(ASSETS_STATE.sortHosts || "interest") === "busy") {
    list.sort((a, b) => (Number(b.bytes || 0) - Number(a.bytes || 0)) ||
      (Number(b.degree || 0) - Number(a.degree || 0)) || String(a.id).localeCompare(String(b.id)));
    return list;
  }
  list.sort((a, b) => {
    const ka = nwInterestKey(a), kb = nwInterestKey(b);
    return (kb[0] - ka[0]) || (kb[1] - ka[1]) || (kb[2] - ka[2])
      || String(a.id).localeCompare(String(b.id));
  });
  return list;
}

/** One host's signal counts as a compact chip, or a dash when the source is unavailable.
 *
 * `blank` is for the EDGE table: an edge has two cells side by side, and a dash in each of them
 * on every quiet conversation is noise that reads as a value. There, "nothing" is an empty cell;
 * in the host table a dash distinguishes "measured, nothing found" from an empty column.
 */
function nwSignalChip(node, d, opts) {
  const cell = el("td", { class: "nw-sig-cell" });
  const blank = Boolean(opts && opts.blank);
  if (!node) return cell;
  const rippleAvailable = d && d.ripple_available !== false;
  const modelAvailable = d && d.status_available !== false;
  const rn = Number(node.ripple_count || 0);
  const mn = Number(node.anomaly_count || 0);
  const band = nwWorstBand(node);
  if (!rippleAvailable && !modelAvailable) {
    if (!blank) cell.appendChild(el("span", { class: "muted", text: "—" }));
    cell.setAttribute("title", "ripple and model reads are unavailable for this window");
    return cell;
  }
  if (!rn && !mn) {
    if (!blank) cell.appendChild(el("span", { class: "muted", text: "—" }));
    cell.setAttribute("title", "no ripple and no model detection on this host in this window");
    return cell;
  }
  const text = `${rippleAvailable ? rn : "?"}r · ${modelAvailable ? mn : "?"}m`;
  const chip = el("span", {
    class: "bubble state nw-sig" + (band ? " sev-" + band : ""),
    text,
    attrs: { "aria-label": `${node.id}: ${rn} ripple windows, ${mn} model detections` },
  });
  chip.setAttribute("title", `${node.id}: ${rn} ripple window(s), ${mn} model detection(s)` +
    (band ? ` — worst band ${band}` : ""));
  // A CHIP IS A DOOR: it opens the host sheet, where the ripple sentences and the model rows
  // live. stopPropagation keeps the edge row's own tracking click out of it.
  chip.addEventListener("click", (ev) => {
    ev.stopPropagation();
    if (typeof openNetworkHost === "function") openNetworkHost(node);
  });
  cell.appendChild(chip);
  return cell;
}

function nwWorstCell(node) {
  const cell = el("td", { class: "nw-worst-cell" });
  const band = nwWorstBand(node);
  if (!band) {
    cell.appendChild(el("span", { class: "muted", text: "—" }));
    return cell;
  }
  const chip = el("span", { class: "bubble state sev-" + band, text: sevText(band) });
  chip.setAttribute("title", `worst band on ${node.id} in this window: ${band}`);
  cell.appendChild(chip);
  return cell;
}

function renderNetworkHosts(nodes, d, opts = {}) {
  const table = document.querySelector("#nw-hosts-table tbody");
  const caption = document.getElementById("nw-hosts-caption");
  const note = document.getElementById("nw-hosts-note");
  if (!table) return;
  table.replaceChildren();
  const hours = Number(d && (d.hours || ASSETS_STATE.hours)) || 24;
  // A FAILED GRAPH READ IS NOT A FILTERED HOST LIST. The screenshot audit caught this one:
  // blocking /api/graph left the edges table saying "Could not read" while this one said
  // "Nothing matches" in amber, implying the operator's filters had emptied it.
  if (opts.failure) {
    if (caption) caption.textContent = "host list unavailable";
    if (note) note.textContent = "";
    emptyRow(table, 7, opts.failure, null, { state: "failed" });
    return;
  }
  const ordered = nwSortHosts(nodes || []);
  if (caption) {
    caption.textContent = `${ordered.length} host${ordered.length === 1 ? "" : "s"} · ${hours}h window`;
  }
  if (note) {
    note.textContent = ASSETS_STATE.sortHosts === "busy"
      ? `Ordered by bytes in this ${hours}h window; peers are distinct hosts in the loaded map.`
      : `Ordered by worst band first (critical → high → medium → low → none), then bytes in this ` +
        `${hours}h window — band dominates, traffic breaks ties.`;
  }
  if (!ordered.length) {
    emptyRow(table, 7, `No host matches the active filters in this ${hours}h window. ` +
      "Clear a filter to widen the map.", null,
      { state: "filtered", filters: activeFilterLabels("network") });
    return;
  }
  for (const n of ordered) {
    const row = el("tr", { class: "clickable" }, [
      el("td", { class: "mono link", text: n.id }),
      el("td", { class: "nw-h-name", text: n.name || "—" }),
      el("td", { class: "mono", text: d.ripple_available === false ? "—"
        : String(Number(n.ripple_count || 0)) }),
      el("td", { class: "mono", text: d.status_available === false ? "—"
        : String(Number(n.anomaly_count || 0)) }),
      nwWorstCell(n),
      el("td", { class: "mono nw-h-bytes", text: fmtBytes(n.bytes || 0) }),
      el("td", { class: "mono nw-h-peers", text: String(Number(n.degree || 0)) }),
    ]);
    row.setAttribute("title", `open why ${n.id} is interesting`);
    row.addEventListener("click", () => openNetworkHost(n));
    table.appendChild(row);
  }
}

function renderNetwork() {
  const host = document.getElementById("nw-graph");
  const caption = document.getElementById("nw-caption");
  const table = document.querySelector("#nw-table tbody");
  const d = ASSETS_STATE.graph || {};
  if (!host) return;

  renderChips();
  host.replaceChildren();
  table.replaceChildren();

  if (d.available === false) {
    // A FAILED GRAPH READ IS NOT AN EMPTY NETWORK. This branch used to print the same
    // "No edges to show." as a genuinely quiet window, which is precisely how the Alerts
    // tab could list hosts while this table looked calm.
    caption.textContent = `The connection graph could not be read: ${d.reason || "no reason was reported"}.`;
    host.appendChild(chartEmpty(`Cannot draw the graph: ${d.reason}.`, "failed"));
    renderNetworkRippleLine([], d);
    renderNetworkHosts([], d, {
      failure: `The connection graph could not be read: ${d.reason || "no reason was reported"}. `
        + "The host list is part of that read.",
    });
    emptyRow(table, 7, "The graph read failed — no edges were read.", null, { state: "failed" });
    return;
  }

  // The window the graph covers. Every sibling view states this; leaving it blank made the
  // heading read as a panel that had failed to load.
  const win = document.getElementById("nw-window");
  if (win) {
    const h = d.hours || ASSETS_STATE.hours;
    // A GRAPH DRAWN OVER A NARROWER WINDOW SAYS SO. The server reports the window it could afford
    // (`hours`) beside the one that was asked for (`narrowed_from`); the pair is printed because a
    // 24h request that silently drew 1h would misreport how far back the map reaches.
    const narrowed = d.narrowed_from
      ? ` (the ${d.narrowed_from}h aggregate did not finish, showing the last ${h}h)` : "";
    win.textContent = `${h}h window` + narrowed
      + (d.truncated ? `, ${d.total_edges} total connections` : "");
  }

  const nodes0 = d.nodes || [];
  const allEdges = d.edges || [];
  // US-7: TRACKED ONLY. The graph holds every host the weirlings saw; this chip narrows it to
  // the ones the operator chose to follow (and the edges between them), so a busy map can be
  // read as a worklist.
  const trackedSet = new Set(ASSETS_STATE.tracked || []);
  let nodes = ASSETS_STATE.trackedOnly
    ? nodes0.filter((n) => trackedSet.has(n.id)) : nodes0;
  let edgesPool = ASSETS_STATE.trackedOnly
    ? allEdges.filter((e) => trackedSet.has(e.source) && trackedSet.has(e.target)) : allEdges;
  const status = ["all", "blocked", "alerted"].includes(ASSETS_STATE.status)
    ? ASSETS_STATE.status : "all";
  for (const btn of document.querySelectorAll("#nw-status [data-nw-status]")) {
    btn.setAttribute("aria-pressed", btn.dataset.nwStatus === status ? "true" : "false");
  }
  // STATUS IS A FILTER OVER THE SAME PAYLOAD, never a second query. A status host brings its
  // direct peers along as context; the peers stay blue so the flagged host is the thing the eye
  // lands on. If the status sources could not be read, do not draw a normal-looking map and do
  // not turn the missing source into "no blocked hosts".
  let statusMatches = [];
  if (status !== "all") {
    if (d.status_available === false) {
      caption.textContent = `Host status is unavailable: ${d.status_reason || "the source could not be read"}.`;
      host.appendChild(chartEmpty("The graph can still be read under All; blocked and alerted status could not be computed.", "failed"));
      renderNetworkRippleLine(nodes, d);
      renderNetworkHosts([], d, {
        failure: "Host status is unavailable, so the host list cannot be filtered by "
          + "blocked/alerted. Use All to see the map.",
      });
      emptyRow(table, 7, "Host status is unavailable; no edges are listed under this filter.", null,
      { state: "failed" });
      return;
    }
    statusMatches = nodes.filter((n) => n.status === status);
    if (!statusMatches.length) {
      const label = status === "blocked" ? "blocked" : "alerted";
      caption.textContent = `No ${label} hosts in this window.`;
      host.appendChild(chartEmpty(`No host has a live block rule` +
        (status === "alerted" ? " or an anomaly window" : "") + ` in this range. Use All to see the map.`));
      renderNetworkRippleLine(statusMatches, d);
      renderNetworkHosts([], d);
      emptyRow(table, 7, `No ${label} hosts to draw.`, null,
      { state: "filtered", filters: [`status = ${label}`] });
      return;
    }
    const matchIds = new Set(statusMatches.map((n) => n.id));
    const visible = new Set(matchIds);
    for (const e of edgesPool) {
      if (matchIds.has(e.source) || matchIds.has(e.target)) {
        visible.add(e.source);
        visible.add(e.target);
      }
    }
    nodes = nodes.filter((n) => visible.has(n.id));
    edgesPool = edgesPool.filter((e) => matchIds.has(e.source) || matchIds.has(e.target));
  }
  // ── THE RIPPLE FILTER NARROWS ALL THREE SURFACES ──────────────────────────────────────────
  // Applied after the status/tracked filters so the controls compose, and before `edges` is
  // computed so the graph, the detail panel (its own reader of graph.edges) and #nw-table all
  // see the same surviving set. Peers of a matched host stay on the map as context, exactly as
  // the status filter keeps peers; the count line names the matched hosts, not the peers.
  const rippleMode = nwRippleMode();
  const rippleBase = [...nodes];
  const rippleMatched = nwRippleMatchedIds(rippleBase);
  if (rippleMode !== "all") {
    const context = new Set(rippleMatched);
    for (const e of edgesPool) {
      if (rippleMatched.has(String(e.source)) || rippleMatched.has(String(e.target))) {
        context.add(String(e.source));
        context.add(String(e.target));
      }
    }
    nodes = nodes.filter((n) => context.has(String(n.id)));
    edgesPool = edgesPool.filter((e) => nwEdgeMatches(e, rippleMatched));
  }
  // ── THE COMPOSABLE FILTERS: FAMILY, SUBNET, TEXT ──────────────────────────────────────────
  // Applied after the ripple filter so a host must pass EVERY active reading. `matched` starts
  // from the ripple filter's matched set (or every host when it is off) and narrows further.
  // Peers of a matched host stay as context, exactly like the status/ripple filters, so a
  // flagged host is never drawn alone.
  const subnetMatcher = nwSubnetMatcher(ASSETS_STATE.subnet);
  const extraActive = nwExtraActive(subnetMatcher);
  let matched = rippleMatched;
  if (extraActive) {
    matched = new Set([...matched].filter((id) => {
      const node = rippleBase.find((n) => String(n.id) === String(id));
      return node ? nwExtraMatch(node, subnetMatcher) : false;
    }));
    const context = new Set(matched);
    for (const e of edgesPool) {
      if (matched.has(String(e.source)) || matched.has(String(e.target))) {
        context.add(String(e.source));
        context.add(String(e.target));
      }
    }
    nodes = nodes.filter((n) => context.has(String(n.id)));
    edgesPool = edgesPool.filter((e) => matched.has(String(e.source))
      || matched.has(String(e.target)));
  }
  const edges = edgesPool.filter((e) => e.flows >= ASSETS_STATE.minEdges);
  const matchedNodes = rippleBase.filter((n) => matched.has(String(n.id)));
  // A FILTER THAT MATCHES NOTHING NAMES ITSELF AND THE WAY OUT. This is not "No edges to show":
  // the network may be busy; the active filter is what emptied the view.
  if (rippleMode !== "all" && !rippleMatched.size) {
    const label = nwRippleModeLabel(rippleMode);
    caption.textContent = `No host has ${rippleMode === "high" ? "a high-band ripple" : "a ripple"} `
      + `in this ${d.hours || ASSETS_STATE.hours}h window \u2014 the "${label}" filter is on. `
      + `Clear it (All) to see ${rippleBase.length} host${rippleBase.length === 1 ? "" : "s"}.`;
    host.appendChild(chartEmpty(`The "${label}" ripple filter matches no host in this window. `
      + `Choose All to restore the full map.`));
    renderNetworkRippleLine([], d, rippleBase);
    renderNetworkHosts([], d);
    emptyRow(table, 7, `No connections under the "${label}" ripple filter. Choose All to clear it.`, null,
      { state: "filtered", filters: [`ripple = ${label}`] });
    return;
  }
  if (rippleMode !== "all" && rippleMatched.size && !edges.length) {
    const label = nwRippleModeLabel(rippleMode);
    caption.textContent = `showing ${rippleMatched.size} of ${rippleBase.length} hosts with `
      + `${rippleMode === "high" ? "high-band " : ""}ripples \u00b7 no connections above `
      + `${ASSETS_STATE.minEdges} flow${ASSETS_STATE.minEdges === 1 ? "" : "s"} under this filter.`;
    host.appendChild(chartEmpty(`The "${label}" filter matched ${rippleMatched.size} host`
      + `${rippleMatched.size === 1 ? "" : "s"}, but none has a drawn connection above the flows `
      + `filter. Lower it or choose All.`));
    renderNetworkRippleLine(nodes, d, rippleBase);
    renderNetworkHosts(rippleBase.filter((n) => rippleMatched.has(String(n.id))), d);
    emptyRow(table, 7, `No connections among the hosts matched by the "${label}" filter.`, null,
      { state: "filtered", filters: [`ripple = ${label}`, `flows ≥ ${ASSETS_STATE.minEdges}`] });
    return;
  }
  // THE COMPOSABLE FILTERS EMPTY STATE NAMES THEM AND THE WAY OUT. A family that no host
  // carries, a subnet that holds nothing, a text fragment that matches nothing -- each is a
  // fact about the FILTER, not about the network, and says so with the count it started from.
  if (extraActive && !matched.size) {
    const names = nwExtraNames(subnetMatcher);
    caption.textContent = `No host matches ${names.join(" + ")} in this `
      + `${d.hours || ASSETS_STATE.hours}h window. The map holds `
      + `${rippleBase.length} host${rippleBase.length === 1 ? "" : "s"} before this filter.`;
    host.appendChild(chartEmpty(`No host matches ${names.join(" + ")} in this window. `
      + `Clear the filter to see ${rippleBase.length} host${rippleBase.length === 1 ? "" : "s"}.`));
    renderNetworkRippleLine([], d, rippleBase);
    emptyRow(table, 7, `No connections under ${names.join(" + ")}.`, null,
      { state: "filtered", filters: names });
    renderNetworkHosts([], d);
    return;
  }
  // A status host with no drawn connection is still a finding: show the filter's own count
  // rather than the generic "no traffic" sentence.
  if (status !== "all" && nodes.length && !edges.length) {
    const label = status === "blocked" ? "blocked" : "alerted";
    caption.textContent = `${statusMatches.length} ${label} host${statusMatches.length === 1 ? "" : "s"} ` +
      `in this window, no connections above ${ASSETS_STATE.minEdges} flow${ASSETS_STATE.minEdges === 1 ? "" : "s"}.`;
    host.appendChild(chartEmpty(`The ${label} host${statusMatches.length === 1 ? " has" : "s have"} no drawn ` +
      `connection above the flows filter. Lower the filter or use All.`));
    renderNetworkRippleLine(nodes, d);
    renderNetworkHosts(statusMatches, d);
    emptyRow(table, 7, `No connections for the ${label} host${statusMatches.length === 1 ? "" : "s"}.`, null,
      { state: "filtered", filters: [`status = ${label}`, `flows ≥ ${ASSETS_STATE.minEdges}`] });
    return;
  }
  // A filter that hides everything must say so -- the tracked-only chip with nothing tracked is
  // the operator's own empty set, not a quiet network.
  const trackedEmpty = ASSETS_STATE.trackedOnly && nodes0.length > 0 && nodes.length === 0;
  if (trackedEmpty) {
    caption.textContent = `${nodes0.length} hosts in this window, none tracked yet \u2014 `
      + "click a dot or a row to track one.";
    host.appendChild(chartEmpty("The tracked-only filter is on and no host is tracked."));
    renderNetworkRippleLine(nodes, d);
    renderNetworkHosts([], d);
    emptyRow(table, 7, "No tracked hosts to draw.", null,
      { state: "filtered", filters: ["tracked only"] });
    return;
  }
  if (!nodes.length || !edges.length) {
    if (ASSETS_STATE.trackedOnly && nodes.length) {
      caption.textContent = `showing ${nodes.length} of ${nodes0.length} hosts \u00b7 `
        + `no connections among them in the last ${d.hours || ASSETS_STATE.hours}h.`;
      host.appendChild(chartEmpty("The tracked hosts did not talk to each other in this "
        + "window. Track more hosts, widen the window, or turn the filter off."));
      renderNetworkRippleLine(nodes, d);
      renderNetworkHosts(nodes, d);
      emptyRow(table, 7, "No connections among the tracked hosts.", null,
      { state: "filtered", filters: ["tracked only"] });
      return;
    }
    // THREE states, not two (review round 2026-10-15). This branch used to collapse "the
    // filter removed every edge" into "No host-to-host traffic was recorded" -- a panel
    // HIDING data it held, while blaming the network for the absence. The filtered case
    // now names the filter and its count; the quiet case keeps its old wording (the jsdom
    // harness pins it, and it was correct for what it described).
    const hidden = nodes.length ? allEdges.length : 0;
    caption.textContent = hidden
      ? `${hidden} connection${hidden === 1 ? "" : "s"} below the flows filter (${ASSETS_STATE.minEdges}+ flows), in the last ${d.hours || ASSETS_STATE.hours}h.`
      : ASSETS_STATE.tracked.length
        ? `No connections among the tracked hosts in the last ${d.hours || ASSETS_STATE.hours}h.`
        : `No host-to-host traffic in the last ${d.hours || ASSETS_STATE.hours}h.`;
    host.appendChild(chartEmpty(
      hidden
        ? `The flows filter is hiding ${hidden} connection${hidden === 1 ? "" : "s"} (fewer than ${ASSETS_STATE.minEdges} flows each). Lower the filter to see them.`
        : ASSETS_STATE.tracked.length
          ? "These hosts did not talk to each other in this window. Widen the window or clear the selection."
          : "No host-to-host traffic was recorded. Broadcast and self-directed traffic is excluded."));
    emptyRow(table, 7,
      hidden ? "No edges above the flows filter." : "No edges to show.", null,
      { state: hidden ? "filtered" : "none",
        filters: hidden ? [`flows ≥ ${ASSETS_STATE.minEdges}`] : [] });
    renderNetworkRippleLine(nodes, d);
    renderNetworkHosts(nodes.length ? matchedNodes : [], d);
    return;
  }

  // The caption reports what was actually drawn, and says so when the edge cap truncated the
  // set -- a graph silently missing hosts looks complete. EVERY COUNT NAMES ITS WINDOW.
  const bits = [`${d.hours || ASSETS_STATE.hours}h window`];
  if (status !== "all") {
    const label = status === "blocked" ? "blocked" : "alerted";
    const peers = Math.max(0, nodes.length - statusMatches.length);
    bits.push(`showing ${statusMatches.length} ${label} host${statusMatches.length === 1 ? "" : "s"}` +
      (peers ? ` and ${peers} peer${peers === 1 ? "" : "s"}` : ""));
  }
  // THE DENOMINATOR IS THE POPULATION THE FILTER CHOSE FROM. With tracked-only on, `nodes` (and
  // therefore `rippleBase`) has already been narrowed, and "2 of 2" would hide the host the chip
  // removed. The operator's question is how much is NOT shown.
  const population = ASSETS_STATE.trackedOnly ? nodes0.length : rippleBase.length;
  bits.push(`showing ${matched.size} of ${population} hosts`);
  if (rippleMode !== "all") {
    bits.push(`ripples: ${nwRippleModeLabel(rippleMode)}`);
  }
  if (extraActive) bits.push(nwExtraNames(subnetMatcher).join(" + "));
  if (subnetMatcher.note) bits.push(subnetMatcher.note);
  bits.push(`${edges.length} connections`);
  if (ASSETS_STATE.tracked.length) bits.push(`filtered to ${ASSETS_STATE.tracked.length} tracked`);
  if (d.truncated) bits.push(`of ${d.total_edges} total connections (capped at ${allEdges.length})`);
  if (status === "all" && d.status_available === false) {
    bits.push(`host status unavailable: ${d.status_reason || "source could not be read"}`);
  }
  // THE RETENTION IS PART OF THE WINDOW. A 7d request against 3.3 days of raw flows is a 3.3d
  // map labelled 7d unless the coverage is printed; this is the sentence that stops that.
  const cov = d.coverage || {};
  if (cov.available && cov.from) {
    const heldH = (new Date(cov.to) - new Date(cov.from)) / 36e5;
    const askedH = Number(d.hours || ASSETS_STATE.hours) || 24;
    if (Number.isFinite(heldH) && heldH + 0.5 < askedH) {
      bits.push(`flows held from ${fmtTime(cov.from)} (${Math.max(1, Math.round(heldH))}h of ${askedH}h)`);
    }
  } else if (cov.available === false) {
    bits.push(`flows coverage unknown: ${cov.reason || "not read"}`);
  }
  caption.textContent = bits.join(" · ");

  renderNetworkRippleLine(nodes, d, rippleBase);
  drawGraph(host, nodes, edges, d.truncated);

  // The busiest edges, clickable to track either endpoint.
  renderBars("nw-edges", {
    available: true, points: edges.slice(0, 12).map((e) => ({
      label: `${e.source} → ${e.target}`, value: e.bytes, edge: e,
    })),
  }, {
    onClick: (r) => { toggleTracked(r.edge.source); },
    colour: () => "var(--series-1)",
    format: (v) => fmtBytes(v),
    title: (r) => `track ${r.edge.source}`,
  });

  // Most connected hosts, clickable to track.
  renderBars("nw-nodes", {
    available: true, points: matchedNodes.slice(0, 12).map((n) => ({
      label: n.name || n.id, value: n.degree, node: n,
    })),
  }, {
    onClick: (r) => toggleTracked(r.node.id),
    colour: (r) => (ASSETS_STATE.tracked.includes(r.node.id) ? "var(--series-2)" : "var(--series-6)"),
    format: (v) => `${v} peers`,
    title: (r) => (ASSETS_STATE.tracked.includes(r.node.id)
      ? `stop tracking ${r.node.id}` : `track ${r.node.id}`),
  });

  // THE HOST TABLE: the map's population as a worklist. It shows the MATCHED hosts, never the
  // context peers the map keeps so a flagged host is not drawn alone.
  renderNetworkHosts(matchedNodes, d);

  const nodeById = new Map((d.nodes || []).map((n) => [String(n.id), n]));
  // The pager states the payload's own cap ("first 200 of 1,240") beside the page range.
  if (typeof setTablePagerTotal === "function") {
    setTablePagerTotal("nw-table", d.total_edges, d.truncated);
  }
  for (const e of edges.slice(0, 200)) {
    const tr = el("tr", {}, [
      el("td", { class: "link mono", text: e.source }),
      el("td", { class: "link mono", text: e.target }),
      nwSignalChip(nodeById.get(String(e.source)), d, { blank: true }),
      nwSignalChip(nodeById.get(String(e.target)), d, { blank: true }),
      el("td", { class: "mono", text: fmtBytes(e.bytes) }),
      el("td", { class: "mono", text: String(e.flows) }),
      el("td", {}, [el("span", { class: "muted", text: "track →" })]),
    ]);
    tr.addEventListener("click", () => toggleTracked(e.source));
    tr.title = `track ${e.source}`;
    table.appendChild(tr);
  }
}

/** The layout's physics, in fixed numbers -- no random source anywhere: same data, same map.
 *
 * WHY THIS IS A FORCE LAYOUT NOW, and how each objection that kept the old view a fixed
 * circle is answered rather than ignored:
 *
 *   1. "It settles to a different picture on every load; two people cannot compare screens."
 *      The solver below has NO randomness and a FIXED tick count. The start positions are the
 *      old degree-ordered circle, every step is deterministic arithmetic, so one window of
 *      data always settles to the same map -- what animates is the path to it, never the map.
 *   2. "It has no fixed cost: hundreds of iterations per frame." The solve runs ONCE per
 *      render, and then the picture is frozen; a drag re-runs a bounded warm start, and
 *      nothing iterates per frame once the map has settled. The bound is per RENDER, not
 *      per node count: the repulsion loop visits every pair, so cost scales with
 *      nodes² × ticks. The measured 12 ms is the demo graph (20 nodes / 63 edges); the
 *      payload's 400-edge cap puts the worst case (~800 nodes) at roughly 800x the demo's
 *      pair evaluations -- seconds, not milliseconds. That class is fine to accept (the
 *      solve still completes and freezes), but it is NOT covered by the 12 ms number.
 *   3. "There is no structure for a force layout to uncover." That was true of edges alone --
 *      and it stopped being true when the ingest started carrying IP TTL. A host's observed
 *      TTL is its hop distance from the sensor, and the radial pull below turns that into
 *      distance rings: same-segment hosts inside, routed hosts outside. Where an export does
 *      not carry TTL the rings are simply absent and the links alone shape the map.
 */
const FORCE = {
  ticks: 320,       // fixed: the final map must not depend on how long a browser waited
  repel: 5000,      // pairwise push, 1/d^2 falloff
  repelCut: 360,    // beyond this two nodes do not feel each other -- bounds the FORCE, not
                    // the loop: the pairwise distance test still runs for every pair (above)
  linkDist: 112,    // the spring length an edge wants
  linkK: 0.045,     // spring stiffness
  centerK: 0.005,   // gently pulls islands back toward the middle
  ringK: 0.12,      // pull toward the host's hop ring (only where TTL was measured) --
                    // measured on the demo dataset: at gentler values (0.02-0.05) the springs
                    // through the shared servers smear the two classes together and the
                    // structure stops being readable; at 0.12 the classes hold apart
  ringBase: 74,     // the same-segment ring's radius; deeper classes step outward
  ringMax: 178,     // the outermost ring stays inside the frame at any hop count
  damp: 0.85,
  maxSpeed: 14,
  // The circle/label footprint, not a decorative margin: the largest node radius is 14 and a
  // label sits 18 above it. A clamp of 8 put the circle on the frame and clipped the label.
  nodeEdge: 34,
  animateMs: 750,
};

/** Which hop classes exist, and how far apart their rings sit (visual cap: class 3).
 *
 * Only nodes with a MEASURED reading count -- `hops` is absent, not zero, for hosts whose
 * records carried no TTL, and those hosts float on the links alone. */
function ringPlan(nodes) {
  const classes = new Set();
  for (const n of nodes) {
    if (n.hops === null || n.hops === undefined) continue;
    classes.add(Math.min(3, Math.max(0, Number(n.hops) || 0)));
  }
  const list = [...classes].sort((a, b) => a - b);
  const maxH = list.length ? list[list.length - 1] : 0;
  return { classes: list, dr: maxH > 0 ? (FORCE.ringMax - FORCE.ringBase) / maxH : 0 };
}

/** The positions the graph settles to -- pure and deterministic: same data in, same map out.
 *
 * Returns {start, end, rings}: `start` is the degree-ordered circle the view used to draw at
 * (the settle animation's first frame), `end` the settled map it freezes at. `warmStart`
 * (a Map of id -> {x, y}) continues from a dragged arrangement instead of the circle and
 * keeps the previous scale, so a hand-arranged map never jumps between sizes; it is used
 * only by the re-settle after a drag. `pinned` (a Set of ids) holds those hosts at their
 * DROPPED positions while the rest of the map re-arranges -- the pin belongs in the solver,
 * not in the drawing: the springs would otherwise drag the host straight back and the
 * gesture would read as having done nothing. Only Re-settle clears the pins.
 */
function computeLayout(nodes, edges, box, warmStart, pinned) {
  const n = nodes.length;
  const cx = box.cx, cy = box.cy;
  const radius = Math.min(box.w, box.h) / 2 - FORCE.nodeEdge;

  const ordered = nodes.slice().sort((a, b) => (b.degree || 0) - (a.degree || 0));
  const start = new Map();
  ordered.forEach((nd, i) => {
    const from = warmStart && warmStart.get(nd.id);
    if (from) {
      start.set(nd.id, { x: from.x, y: from.y });
    } else {
      const angle = (i / Math.max(1, ordered.length)) * Math.PI * 2 - Math.PI / 2;
      start.set(nd.id, { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) });
    }
  });

  const idx = new Map(ordered.map((nd, i) => [nd.id, i]));
  const xs = ordered.map((nd) => start.get(nd.id).x);
  const ys = ordered.map((nd) => start.get(nd.id).y);
  const vx = ordered.map(() => 0);
  const vy = ordered.map(() => 0);
  const ring = ringPlan(ordered);
  const classOf = ordered.map((nd) => {
    if (nd.hops === null || nd.hops === undefined) return null;
    return Math.min(3, Math.max(0, Number(nd.hops) || 0));
  });

  const maxBytes = Math.max(1, ...ordered.map((nd) => nd.bytes || 0));
  const links = [];
  for (const e of edges) {
    const a = idx.get(e.source), b = idx.get(e.target);
    if (a === undefined || b === undefined || a === b) continue;
    // Heavier observed pairs sit closer (log-normalised), so the tightest knots on the map
    // read as the busiest relationships.
    const w = Math.min(1, Math.log10(1 + (e.bytes || 0)) / Math.log10(1 + maxBytes ** 2));
    links.push({ a: a, b: b, len: FORCE.linkDist + 52 * (1 - w) });
  }

  const ticks = n > 300 ? 150 : n > 150 ? 220 : FORCE.ticks;
  const cut2 = FORCE.repelCut * FORCE.repelCut;
  for (let t = 0; t < ticks; t++) {
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const dx = xs[i] - xs[j], dy = ys[i] - ys[j];
        const d2 = dx * dx + dy * dy;
        if (d2 > cut2 || d2 < 1e-6) continue;
        const d = Math.sqrt(d2);
        const f = FORCE.repel / d2;
        const fx = (f * dx) / d, fy = (f * dy) / d;
        vx[i] += fx; vy[i] += fy;
        vx[j] -= fx; vy[j] -= fy;
      }
    }
    for (const L of links) {
      const dx = xs[L.b] - xs[L.a], dy = ys[L.b] - ys[L.a];
      const d = Math.hypot(dx, dy) || 1e-6;
      const f = FORCE.linkK * (d - L.len);
      const fx = (f * dx) / d, fy = (f * dy) / d;
      vx[L.a] += fx; vy[L.a] += fy;
      vx[L.b] -= fx; vy[L.b] -= fy;
    }
    for (let i = 0; i < n; i++) {
      if (pinned && pinned.has(ordered[i].id)) {
        // A host the operator dragged holds exactly where it was dropped; the rest of the
        // map settles AROUND it (see the pinned note in the docstring).
        xs[i] = start.get(ordered[i].id).x;
        ys[i] = start.get(ordered[i].id).y;
        vx[i] = 0; vy[i] = 0;
        continue;
      }
      vx[i] += (cx - xs[i]) * FORCE.centerK;
      vy[i] += (cy - ys[i]) * FORCE.centerK;
      if (classOf[i] !== null) {
        const target = FORCE.ringBase + ring.dr * classOf[i];
        const rx = xs[i] - cx, ry = ys[i] - cy;
        const rd = Math.hypot(rx, ry);
        if (rd > 1e-6) {
          const pull = (FORCE.ringK * (rd - target)) / rd;
          vx[i] -= rx * pull; vy[i] -= ry * pull;
        }
      }
      vx[i] *= FORCE.damp; vy[i] *= FORCE.damp;
      const sp = Math.hypot(vx[i], vy[i]);
      if (sp > FORCE.maxSpeed) { vx[i] *= FORCE.maxSpeed / sp; vy[i] *= FORCE.maxSpeed / sp; }
      xs[i] += vx[i]; ys[i] += vy[i];
    }
  }

  // Recentre the settled mass on the frame, when this is a fresh layout: the forces pull
  // toward the middle, but an asymmetric link structure (all spokes through a few hubs)
  // leaves the cloud visibly off to one side, and an off-centre map reads as a fault. A
  // warm start skips this -- it would fight the operator's own arrangement.
  if (!warmStart && n) {
    // CENTRE THE BOUNDING BOX, NOT THE MEAN. A few heavy hubs pull the mean to their side,
    // leaving a third of the panel empty on the other side; the box is what the eye reads.
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    for (let i = 0; i < n; i++) {
      minX = Math.min(minX, xs[i]); maxX = Math.max(maxX, xs[i]);
      minY = Math.min(minY, ys[i]); maxY = Math.max(maxY, ys[i]);
    }
    const shiftX = cx - (minX + maxX) / 2;
    const shiftY = cy - (minY + maxY) / 2;
    for (let i = 0; i < n; i++) { xs[i] += shiftX; ys[i] += shiftY; }
  }

  // Fit the settle into the frame by SCALING (never distorting), using the 95th-percentile
  // radius so one drifting node cannot shrink the whole picture. A warm start keeps the
  // previous scale so a dragged map does not jump between sizes.
  // THE FRAME IS AN ELLIPSE, NOT A SQUARE. A square clamp puts every outer host on one of
  // four walls, which is exactly the "everything sits along the edge" picture the operator
  // rejected. Scale to the widest normalised radial and clamp to an ellipse with the same
  // 34px node/label margin; the cloud uses the full tile without drawing a rectangle.
  const rx = Math.max(1, box.w / 2 - FORCE.nodeEdge);
  const ry = Math.max(1, box.h / 2 - FORCE.nodeEdge);
  let maxNx = 0, maxNy = 0;
  for (let i = 0; i < n; i++) {
    maxNx = Math.max(maxNx, Math.abs(xs[i] - cx) / rx);
    maxNy = Math.max(maxNy, Math.abs(ys[i] - cy) / ry);
  }
  // STRETCH X AND Y SEPARATELY. A circular force cloud fitted into a wide tile leaves half
  // the panel empty; one shared scale cannot use the width and the height at once. The two
  // axes are normalized independently, with the cap stopping a sparse graph from becoming a
  // letterbox smear.
  const sx = warmStart ? 1 : Math.min(1.35, Math.max(0.55, 0.94 / Math.max(1e-9, maxNx)));
  const sy = warmStart ? 1 : Math.min(1.35, Math.max(0.55, 0.94 / Math.max(1e-9, maxNy)));
  const end = new Map();
  ordered.forEach((nd, i) => {
    let dx = (xs[i] - cx) * sx, dy = (ys[i] - cy) * sy;
    const norm = Math.hypot(dx / rx, dy / ry);
    if (norm > 0.97) { dx *= 0.97 / norm; dy *= 0.97 / norm; }
    end.set(nd.id, { x: cx + dx, y: cy + dy });
  });
  // Rings are drawn only when TTL produced more than one class: a single circle around
  // everything would read as a frame, not a measurement. Each circle sits at the radius its
  // class ACTUALLY settled at (the mean), not at the nominal target -- a circle drawn at
  // the target while the cluster settles elsewhere is a diagram of an intention.
  const rings = [];
  if (ring.classes.length > 1) {
    for (const h of ring.classes) {
      let sum = 0, cnt = 0, capped = false;
      ordered.forEach((nd, i) => {
        if (classOf[i] !== h) return;
        const p = end.get(nd.id);
        sum += Math.hypot(p.x - cx, p.y - cy);
        cnt += 1;
        // The geometry caps at class 3; a member further out than that must make the LABEL
        // say so, or the ring prints a capped class as if it were a measured hop count.
        if (Number(nd.hops) > h) capped = true;
      });
      if (cnt) rings.push({ hops: h, radius: sum / cnt, capped: capped });
    }
  }
  return { start: start, end: end, rings: rings };
}

/** The hover card for a host: address, activity, and -- when measured -- where it sits.
 *
 * A hop reading is always shown WITH the TTL it came from: the ring position is a
 * measurement, and a measurement without its evidence is a conclusion. */
function nodeTitle(n) {
  const out = [`${n.name ? n.name + " · " : ""}${n.id}`, `${n.degree} peers`, fmtBytes(n.bytes)];
  if (n.blocked) out.push("blocked by a live block rule");
  if (n.alerted) out.push(`alerted: ${n.anomaly_count || 0} anomaly window${(n.anomaly_count || 0) === 1 ? "" : "s"}`);
  const modelBand = String(n.model_worst || "");
  if (modelBand) out.push(`model detections: ${n.anomaly_count || 0} (worst ${modelBand})`);
  const rip = typeof networkRipple === "function" ? networkRipple(n.id) : null;
  if (rip) {
    const band = rippleBand(rip, (ASSETS_STATE.graph || {}).severity_bands);
    out.push(`ripple: score ${Number(rip.score || 0).toFixed(2)}, ` +
      `${(rip.families || []).join(" / ") || "no family named"} (${band})`);
  }
  const normalized = Number(n.normalized_count || 0);
  if (normalized) {
    out.push(`${normalized} normalized pattern${normalized === 1 ? "" : "s"}`);
  }
  if (n.hops !== null && n.hops !== undefined) {
    out.push(`${n.hops} ${n.hops === 1 ? "hop" : "hops"} from the sensor (ttl ${n.ttl})`);
  }
  return out.join("\n");
}

/** The hover card for one connection: the pair, the volume, and the TTL range when carried. */
function edgeTitle(e) {
  const out = [`${e.source} → ${e.target}`, fmtBytes(e.bytes)];
  if (e.source_status || e.target_status) {
    out.push(`status: source ${e.source_status || "normal"}, destination ${e.target_status || "normal"}`);
  }
  if ((e.ports || []).length) {
    out.push(`port${e.ports.length === 1 ? "" : "s"} ${e.ports.join(", ")}`);
  }
  if (e.ttl_max > 0) {
    out.push(e.ttl_min === e.ttl_max ? `ttl ${e.ttl_max}` : `ttl ${e.ttl_min}–${e.ttl_max}`);
  }
  return out.join("\n");
}

/** Draw the connection graph: a settled force map with hop rings where TTL allows.
 *
 * All the interactions the view already had are unchanged -- clicks open the same detail
 * panels, the tracking selection is the same ClickHouse-side filter. What the map adds: a
 * short settle animation on load, hop-distance rings drawn from the measured TTL, and a
 * drag that carries a host and re-settles its neighbours (the interaction Obsidian's graph
 * is known for, and the reason a map is worth arranging by hand). */
function drawGraph(host, nodes, edges, truncated) {
  // A graph that is only 460px tall clamps its own outer ring against the frame. Give the
  // map a taller, more generously inset canvas; the CSS height matches this viewBox.
  const W = 1000;
  const H = 620;
  const { svg, plot } = chartFrame(W, H, { l: 40, r: 40, t: 40, b: 40 });
  const cx = (plot.l + plot.r) / 2;
  const cy = (plot.t + plot.b) / 2;
  const box = { cx: cx, cy: cy, w: plot.r - plot.l, h: plot.b - plot.t };
  const layout = computeLayout(nodes, edges, box);
  const pos = new Map(layout.start);
  const pinned = new Set();  // hosts the operator has dragged; they hold until Re-settle

  // Faint hop rings under everything; their LABELS are appended after the nodes instead
  // (see below) so a node can never sit on top of the label that explains the ring.
  const ringLabels = [];
  for (const ring of layout.rings) {
    svg.appendChild(svgEl("circle", {
      cx: cx, cy: cy, r: ring.radius.toFixed(1), class: "ring", fill: "none",
    }));
    ringLabels.push({ x: cx, y: (cy - ring.radius + 11).toFixed(1),
                      text: (ring.capped ? "3+" : ring.hops) +
                            (ring.hops === 1 ? " hop" : " hops") });
  }

  // Position writers: one list applied to a Map of id -> {x, y}, so "draw at start", "draw
  // mid-animation" and "draw mid-drag" are the same code path.
  const edgeEls = [];
  const nodeEls = [];
  function applyPositions(cur) {
    for (const ee of edgeEls) {
      const a = cur.get(ee.source), b = cur.get(ee.target);
      if (!a || !b) continue;
      for (const el2 of ee.els) {
        el2.setAttribute("x1", a.x.toFixed(1)); el2.setAttribute("y1", a.y.toFixed(1));
        el2.setAttribute("x2", b.x.toFixed(1)); el2.setAttribute("y2", b.y.toFixed(1));
      }
    }
    for (const ne of nodeEls) {
      const p = cur.get(ne.id);
      if (p) ne.g.setAttribute("transform", `translate(${p.x.toFixed(1)},${p.y.toFixed(1)})`);
    }
  }

  // ── the settle: circle -> map, once, bounded ──────────────────────────────────────────────
  // The FINAL state is applied by `finish` no matter what happens to the frames: a stalled
  // animation frame (a backgrounded tab, a throttled renderer) must cost the ANIMATION, not
  // the map -- and a map silently stuck at the circle would also poison the next drag's warm
  // re-settle, which reads `pos`. The watchdog timer guarantees the settled state; the frames
  // are only how a visible tab watches it get there.
  let animSeq = 0;
  function settleTo(target, ms) {
    const seq = ++animSeq;
    const finish = () => {
      if (seq !== animSeq) return;
      for (const [id, p1] of target) pos.set(id, p1);
      applyPositions(target);
    };
    const reduce = typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const raf = typeof requestAnimationFrame === "function" ? requestAnimationFrame : null;
    if (!raf || reduce || document.hidden) {
      finish();
      return;
    }
    const from = new Map(pos);
    const t0 = performance.now();
    const watchdog = setTimeout(finish, ms + 300);
    function frame(now) {
      if (seq !== animSeq) {
        clearTimeout(watchdog);
        return;  // superseded by a drag or a re-render
      }
      const t = Math.min(1, (now - t0) / ms);
      const e = 1 - Math.pow(1 - t, 3);
      const cur = new Map();
      for (const [id, p1] of target) {
        const p0 = from.get(id) || p1;
        cur.set(id, { x: p0.x + (p1.x - p0.x) * e, y: p0.y + (p1.y - p0.y) * e });
      }
      // `pos` tracks the animation, not just the final state: a pointer that grabs a host
      // mid-flight must drag from where the host VISIBLY is, and a warm re-settle after an
      // interrupted animation must start from the picture on screen, not the start circle.
      for (const [id2, p2] of cur) pos.set(id2, p2);
      applyPositions(cur);
      if (t < 1) {
        raf(frame);
      } else {
        clearTimeout(watchdog);
        finish();
      }
    }
    raf(frame);
  }

  // Drag a node: the node carries its edges live, and on release a bounded warm re-settle
  // lets the springs respond to where the operator put it.
  function wireDrag(g, id) {
    const state = { moved: false };
    g.addEventListener("pointerdown", (ev) => {
      if (ev.button !== undefined && ev.button !== 0) return;
      ev.preventDefault();
      ev.stopPropagation();
      // The in-flight settle animation is NOT cancelled here. A plain click mid-settle is a
      // selection, not an interruption -- and cancelling at PRESS left the map frozen at
      // whatever frame the click caught, for good: measured on the demo map, a click 250 ms
      // into the 750 ms settle froze it 185 px short of the settled picture, and only a
      // re-render ever moved it again. The drag cancels the animation on its first real
      // move instead (see `onMove`), where the gesture has actually taken the map over.
      state.moved = false;
      const rect = typeof svg.getBoundingClientRect === "function" ? svg.getBoundingClientRect() : null;
      const scaleX = rect && rect.width > 0 ? W / rect.width : 1;
      const scaleY = rect && rect.height > 0 ? H / rect.height : 1;
      const toLocal = (e2) => ({
        x: (e2.clientX - (rect ? rect.left : 0)) * scaleX,
        y: (e2.clientY - (rect ? rect.top : 0)) * scaleY,
      });
      const onMove = (e2) => {
        const p = toLocal(e2);
        const cur = pos.get(id);
        if (!cur) return;
        // Drag against the same ellipse: a host can be placed anywhere in the tile, never by
        // clamping to a rectangular wall that the force map then crowds.
        const rx = box.w / 2 - FORCE.nodeEdge, ry = box.h / 2 - FORCE.nodeEdge;
        let dx = p.x - cx, dy = p.y - cy;
        const norm = Math.hypot(dx / rx, dy / ry);
        if (norm > 0.97) { dx *= 0.97 / norm; dy *= 0.97 / norm; }
        const nx = cx + dx, ny = cy + dy;
        if (!state.moved && Math.abs(nx - cur.x) + Math.abs(ny - cur.y) > 2) {
          state.moved = true;
          animSeq++;  // the drag owns the map now; any in-flight settle animation stops
        }
        cur.x = nx; cur.y = ny;
        applyPositions(pos);
      };
      const onUp = () => {
        window.removeEventListener("pointermove", onMove);
        window.removeEventListener("pointerup", onUp);
        window.removeEventListener("pointercancel", onUp);
        if (!state.moved) return;
        pinned.add(id);
        const re = computeLayout(nodes, edges, box, pos, pinned);
        settleTo(re.end, 260);
      };
      window.addEventListener("pointermove", onMove);
      window.addEventListener("pointerup", onUp);
      // A cancelled pointer (OS gesture takeover, a browser action) must end the gesture HERE.
      // Without this listener the move handler stayed armed: after a cancel, the host kept
      // following bare mouse motion and pinned itself wherever the next stray press landed.
      window.addEventListener("pointercancel", onUp);
    });
    return state;
  }

  // Edges first so nodes draw over them.
  const maxEdge = Math.max(1, ...edges.map((e) => e.bytes));
  for (const e of edges) {
    const a = pos.get(e.source);
    const b = pos.get(e.target);
    if (!a || !b) continue;
    // Width is log-scaled: byte volumes span orders of magnitude, and a linear scale makes
    // every edge but the largest a hairline.
    const w = 0.6 + 2.4 * (Math.log10(1 + e.bytes) / Math.log10(1 + maxEdge));
    const involved = ASSETS_STATE.tracked.length === 0 ||
      ASSETS_STATE.tracked.includes(e.source) || ASSETS_STATE.tracked.includes(e.target);
    const shown = involved ? "0.85" : "0.18";
    // A WIDE TRANSPARENT LINE UNDER EACH EDGE IS THE CLICK TARGET. The drawn line is 0.6-3px,
    // which is not a realistic pointer target, so an invisible 12px stroke sits beneath it and
    // carries the click. Without this the edges would be decorative -- and an analyst pointing
    // at a specific connection is exactly the interaction this view is for.
    const hit = svgEl("line", {
      x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: "edge-hit",
      "stroke-width": "12", stroke: "transparent", "pointer-events": "stroke",
    });
    hit.addEventListener("click", (ev) => {
      ev.stopPropagation();
      showEdgeDetail(e);
    });
    hit.appendChild(svgEl("title", {}, edgeTitle(e)));
    svg.appendChild(hit);
    // AN EDGE TOUCHING A FLAGGED HOST WEARS THE SAME COLOUR AS THE HOST. The node is the
    // primary mark; this line is the connection that makes it relevant, and a red host with
    // only grey lines reads as a colouring mistake. Normal edges keep the neutral hairline.
    const edgeColour = e.status === "blocked" ? "var(--bad)"
      : e.status === "alerted" ? "var(--warn)" : "var(--border)";
    const line = svgEl("line", {
      x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: "edge",
      "stroke-width": w.toFixed(2),
      // Inline style, not a presentation attribute: the stylesheet's `.graph .edge` rule would
      // otherwise win and every status edge would render as the neutral border again.
      style: e.status ? `stroke:${edgeColour}` : "",
      opacity: e.status ? "0.82" : shown, "pointer-events": "none",
    });
    svg.appendChild(line);
    edgeEls.push({ source: e.source, target: e.target, els: [hit, line] });
  }

  const maxBytes = Math.max(1, ...nodes.map((n) => n.bytes || 0));
  const ordered = nodes.slice().sort((a, b) => (b.degree || 0) - (a.degree || 0));
  for (const n of ordered) {
    const p = pos.get(n.id);
    const selected = ASSETS_STATE.tracked.includes(n.id);
    const r = 5 + 9 * Math.sqrt((n.bytes || 0) / maxBytes);
    const rip = networkRipple(n.id);
    const rband = rip ? rippleBand(rip, (ASSETS_STATE.graph || {}).severity_bands) : "";
    // A ripple ring is drawn only when the map has a measured band. SOLID, and in a COOL palette
    // reserved for ripples: the fills own the status hues (blocked red, alerted orange, tracked
    // green, observed grey), so a ring must never be orange or yellow or it reads as one of them
    // (operator, 2026-11-20: "you have three icons that are basically orange ... unclassified,
    // alerted and ripple"). Band order still reads: slate -> cyan -> violet, and the band word
    // is in the aria-label/title, so colour is reinforcement rather than the only encoding.
    const rmeasured = Boolean(rip) && Boolean(rband);
    const rclass = ["low", "medium", "high"].includes(rband) ? rband : "unknown";
    const normalizedN = Number(n.normalized_count || 0);
    const g = svgEl("g", {
      class: "node" + (selected ? " selected" : "") + (n.status ? " " + n.status : "") +
        (rmeasured ? " has-ripple rp-sev-" + rclass : "") +
        (normalizedN ? " has-normalized" : ""),
      transform: `translate(${p.x.toFixed(1)},${p.y.toFixed(1)})`,
    });
    // A RIPPLE RING, DRAWN UNDER THE NODE so it reads as a halo, in the SAME band colour the
    // Alerts tab uses. Colour is reinforcement: the title carries score, families and band.
    // SOLID (dash is the unclassified cue); NO RING when the host has no ripple row at all.
    if (rmeasured) {
      g.appendChild(svgEl("circle", {
        r: (r + 3.5).toFixed(1), class: "node-ripple-ring rp-sev-" + rclass,
        fill: "none", "pointer-events": "none",
      }));
    }
    // NORMALIZED IS ITS OWN HALO, not a dimmed node: dimming already means "observed network"
    // on this map, and one appearance cannot carry two facts. The solid outer ring says the
    // host has at least one pattern the operator marked normal; the legend names it. Solid,
    // because dash means unclassified.
    if (normalizedN) {
      g.appendChild(svgEl("circle", {
        r: (r + 7.5).toFixed(1), class: "node-normalized-ring",
        fill: "none", "pointer-events": "none",
      }));
    }
    // STATUS OUTRANKS THE NORMAL/SELECTED FILL. A blocked host must not turn blue just because
    // it is a busy node, and a tracked blocked host keeps its tracked stroke without losing
    // the reason it is red. Normal selected nodes keep the green tracking fill.
    //
    // SCOPE IS A READING, NOT A STATUS: an observed (unmonitored) host is muted. It is NOT
    // drawn on the node: the scope word lives in the host table and the host sheet. An
    // unclassified host renders as an ordinary node -- scope is not one of the graph's two
    // signal layers, and an outline for it stole the ripple ring's colour and shape.
    const observed = n.scope_monitored === false;
    const fill = n.status === "blocked" ? "var(--bad)"
      : n.status === "alerted" ? "var(--warn)"
      : selected ? "var(--ok)"
      : observed ? "var(--dim)" : "var(--accent)";
    const circleStyle = `fill:${fill}`;
    // ON A PHONE THE VISIBLE DOT IS NOT THE TAP TARGET. A host's circle is 5-14px radius; the
    // 44px floor applies to what a finger must hit, so a transparent r=22 circle carries the
    // pointer while the drawn circle keeps its data-scaled size.
    const touch = typeof window.matchMedia === "function"
      && window.matchMedia("(max-width: 720px)").matches;
    if (touch) {
      // The graph is drawn in a 1000-unit viewBox and scaled into the card (0.27-0.35x on a
      // phone), so a 22-UNIT circle is only 12-15 CSS px. 84 units renders at 46 CSS px on the
      // narrowest supported width (320px -> 274px card -> 0.274 scale) and 58px at 390px, so
      // the transparent target clears the 44px floor at both widths instead of only the wider one.
      g.appendChild(svgEl("circle", {
        r: "84", class: "node-hit", fill: "transparent", "pointer-events": "all",
      }));
    }
    g.appendChild(svgEl("circle", {
      r: r.toFixed(1),
      style: circleStyle,
      opacity: selected || n.status ? "1" : (observed ? "0.45" : "0.78"),
    }));
    // Labels only when asked for, or for a selected node: 250 labels in a circle is a smear.
    if (ASSETS_STATE.showNames || selected) {
      g.appendChild(svgEl("text", {
        x: 0, y: -(r + 4), "text-anchor": "middle",
        text: n.name || n.id,
      }));
    }
    g.appendChild(svgEl("title", {}, nodeTitle(n)));
    // THE ACCESSIBLE NAME IS THE HOVER CARD, so a screen reader gets the same score/families
    // the eye gets from the ring; the SVG group is the click target, not a decorative image.
    g.setAttribute("aria-label", nodeTitle(n));
    g.setAttribute("role", "button");
    // CLICK LEADS WITH DATA. It used to toggle tracking only, which the user could not infer
    // from anything on screen -- "i dont understand what clicking down". The detail panel now
    // opens on the host's connections, and tracking is an explicit button inside it.
    const drag = wireDrag(g, n.id);
    g.addEventListener("click", () => {
      if (drag.moved) return;  // a drag is not a click
      showNodeDetail(n);
    });
    nodeEls.push({ id: n.id, g: g });
    svg.appendChild(g);
  }

  host.appendChild(svg);
  // Ring labels ride ON TOP of the map (with a halo in CSS): drawn underneath, the 0-hop
  // label sat behind a node on the settled demo map and read as "hops".
  for (const rl of ringLabels) {
    svg.appendChild(svgEl("text", {
      x: rl.x, y: rl.y, "text-anchor": "middle", class: "ring-label",
    }, rl.text));
  }
  settleTo(layout.end, FORCE.animateMs);

  const legend = document.getElementById("nw-legend");
  if (legend) {
    legend.replaceChildren();
    const legendItems = [
      ["var(--series-1)", `host (size = bytes in this ${(ASSETS_STATE.graph || {}).hours || ASSETS_STATE.hours}h window)`],
      ["var(--series-2)", "tracked"],
      ["var(--bad)", "blocked by a live block rule"],
      ["var(--warn)", "alerted: anomaly in this range"],
      ["edge width", "log of bytes"],
      ["var(--dim)", "observed network (not alertable)"],
      ["solidring", "solid ring = ripples in this window (colour = band: slate low / cyan medium / violet high)"],
      ["noring", "no ring = no ripples measured in this window"],
    ];
    if (layout.rings.length) {
      legendItems.push(["ring", "thin solid ring = hop distance from the sensor (IP TTL)"]);
    }
    if (nodes.some((n) => Number(n.normalized_count || 0) > 0)) {
      legendItems.push(["normalized", "thin outer halo = normalized pattern on this host"]);
    }
    for (const [colour, label] of legendItems) {
      const swatch = colour === "ring"
        ? el("span", { class: "legend-swatch ring" })
        : colour === "outline"
        ? el("span", { class: "legend-swatch outline" })
        : colour === "solidring"
        ? el("span", { class: "legend-swatch solidring" })
        : colour === "noring"
        ? el("span", { class: "legend-swatch noring", text: "∅" })
        : colour === "normalized"
        ? el("span", { class: "legend-swatch normalized" })
        : colour === "none"
        ? el("span", { class: "legend-swatch none" })
        : el("span", {
            class: "legend-swatch",
            attrs: { style: `background:${(colour.startsWith("#") || colour.startsWith("var(")) ? colour : "var(--border)"}` },
          });
      legend.appendChild(el("span", { class: "legend-item" + (colour === "none" ? " muted" : "") }, [
        swatch,
        el("span", { text: label }),
      ]));
    }
    if (truncated) {
      legend.appendChild(el("span", {
        class: "legend-item muted",
        text: "the edge cap was reached — some connections are not drawn",
      }));
    }
  }
}

/** Re-run the layout from its deterministic start, discarding any hand-dragged arrangement.
 *
 * The counterpart to dragging a node somewhere unhelpful: the map returns to the exact
 * picture the data settles to, so there is always a way back to the comparable view. */
function settleGraph() {
  const d = ASSETS_STATE.graph;
  if (!d || d.available === false) return;
  renderNetwork();
}

/* The window the Zeek view is showing. The GLOBAL time control is the range -- the per-view
   hours boxes were removed on the operator's instruction (2026-10-16): one control, every tab. */
function zeekWindow() {
  return trHours();
}

/* ── Network: what a click on the graph actually means ─────────────────────── */

/** The status chip shared by the node and edge details. The word is always present; the colour
 *  is a second encoding, never the only one. */
function statusChip(status) {
  if (status === "blocked") return el("span", { class: "bubble state bad", text: "blocked" });
  if (status === "alerted") return el("span", { class: "bubble state warn", text: "alerted" });
  return null;
}

/** One connection's source and destination, in words and numbers.
 *
 * WHY THIS EXISTS: the user clicked the graph and could not tell what had happened. A node click
 * only toggled a filter, so the click looked inert and the graph looked unreadable -- you could
 * see that two hosts were joined but not what the join WAS.
 *
 * Every line shows the address AND the name, never the name alone: a name is a convenience that
 * can be wrong, shared, or absent, and the address is the fact.
 */
function showEdgeDetail(edge) {
  const host = document.getElementById("nw-detail");
  const table = document.querySelector("#nw-detail-table tbody");
  const title = document.getElementById("nw-detail-title");
  const note = document.getElementById("nw-detail-note");
  if (!host) return;
  host.replaceChildren();
  table.replaceChildren();

  title.textContent = "one connection";
  const ports = (edge.ports || []).length ? edge.ports.join(", ") : "—";
  const srcPorts = (edge.source_ports || []).length ? edge.source_ports.join(", ") : "";
  // The TTL range is the evidence a ring position rests on, so it shows when the records
  // carried the field -- and says nothing when they did not.
  const ttl = edge.ttl_max > 0
    ? ` Observed TTL ${edge.ttl_min === edge.ttl_max ? edge.ttl_max : `${edge.ttl_min}–${edge.ttl_max}`}.`
    : "";
  // THE DIRECTION IS THE DATA'S OWN CLAIM (2026-10-16, after the operator caught this panel
  // showing an outbound HTTPS call backwards: "the source port of overseerr going outbound").
  // `direction` comes from the server's port-based determination -- the initiator is the side
  // whose destination ports are services -- and the note says WHICH CASE this edge is instead
  // of drawing an arrow the flows do not support. The initiator's ephemeral source ports ride
  // the source card, where they belong.
  const dirText = edge.direction === "request/reply"
    ? `opened by the source; ${fmtBytes(edge.bytes_target || 0)} came back`
    : (edge.direction || "");
  note.textContent =
    `${label(edge.source_name, edge.source)} → ${label(edge.target_name, edge.target)}` +
    ` on port${(edge.ports || []).length === 1 ? "" : "s"} ${ports}.` +
    (dirText ? ` ${dirText}.` : "") + ttl;

  // THE STATUS OF BOTH ENDS, ON THE CONNECTION. The map colours the host; this sentence says
  // which end carried the policy/detection fact, so a red line is not a claim about a packet.
  const srcNode = ((ASSETS_STATE.graph && ASSETS_STATE.graph.nodes) || [])
    .find((n) => n.id === edge.source) || {};
  const dstNode = ((ASSETS_STATE.graph && ASSETS_STATE.graph.nodes) || [])
    .find((n) => n.id === edge.target) || {};
  const srcStatus = edge.source_status || srcNode.status || "";
  const dstStatus = edge.target_status || dstNode.status || "";
  const statusBits = [];
  if (srcStatus) statusBits.push(`source ${srcStatus}${srcNode.status_reasons && srcNode.status_reasons.length
    ? ` (${srcNode.status_reasons.join("; ")})` : ""}`);
  if (dstStatus) statusBits.push(`destination ${dstStatus}${dstNode.status_reasons && dstNode.status_reasons.length
    ? ` (${dstNode.status_reasons.join("; ")})` : ""}`);
  if (statusBits.length) {
    const statusRow = el("div", { class: "chips" }, [
      statusChip(srcStatus),
      statusChip(dstStatus),
    ].filter(Boolean));
    statusRow.appendChild(el("span", { class: "muted", text: statusBits.join(" · ") }));
    host.appendChild(statusRow);
  }

  // The pair, as a single prominent row, because "source and destination" is the question.
  host.appendChild(el("div", { class: "pair" }, [
    el("div", { class: "pair-side" }, [
      el("div", { class: "pair-label", text: "source" }),
      el("div", { class: "pair-addr link", text: edge.source,
                  on: { click: () => openHost(edge.source) } }),
      // THE INITIATOR'S EPHEMERAL PORTS BELONG ON THE INITIATOR'S CARD: "overseerr :51334" is
      // the fact the operator was reading for when this panel showed it backwards.
      srcPorts ? el("div", { class: "muted", text: `source ports ${srcPorts}` }) : null,
      edge.source_name ? el("div", { class: "muted", text: edge.source_name }) : null,
    ]),
    el("div", { class: "pair-arrow", text: "→" }),
    el("div", { class: "pair-side" }, [
      el("div", { class: "pair-label", text: "destination" }),
      // The port belongs on the destination card: "host :443" is one fact, and splitting it
      // across a card and a note makes the reader assemble it. Several ports are listed in
      // descending-count order (topK), so a host on many ports reads as a short list.
      el("div", { class: "pair-addr link",
                  text: (edge.ports || []).length === 1
                    ? `${edge.target}:${edge.ports[0]}`
                    : edge.target,
                  on: { click: () => openHost(edge.target) } }),
      (edge.ports || []).length > 1
        ? el("div", { class: "muted", text: `ports ${edge.ports.join(", ")}` })
        : null,
      edge.target_name ? el("div", { class: "muted", text: edge.target_name }) : null,
    ]),
  ]));
  host.appendChild(el("div", { class: "muted", text:
    `${fmtBytes(edge.bytes)} across ${edge.flows} flow${edge.flows === 1 ? "" : "s"}` +
    (edge.reply_seen
      ? ` (${fmtBytes(edge.bytes_source || 0)} opened it, ${fmtBytes(edge.bytes_target || 0)} came back)`
      : "") +
    (edge.first_seen ? ` · first seen ${fmtTime(edge.first_seen)}` : "") +
    (edge.last_seen ? ` · last seen ${fmtTime(edge.last_seen)}` : "") }));

  const tr = el("tr", {}, [
    el("td", { class: "link mono", text: edge.source }),
    el("td", { class: "link mono", text: edge.target }),
    networkRippleCell(networkEdgeRipple(edge)),
    el("td", { class: "mono", text: ports }),
    el("td", { class: "mono", text: fmtBytes(edge.bytes) }),
    el("td", { class: "mono", text: String(edge.flows) }),
    el("td", {}, [el("span", { class: "muted", text: "drill into source →" })]),
  ]);
  tr.addEventListener("click", () => openHost(edge.source));
  table.appendChild(tr);
}

/** Everything one host talked to, from the graph already in memory.
 *
 * NO REFETCH: the graph payload holds every drawn edge, so the answer is filtered locally. A
 * click that runs a query is a click that can be slow, and this view is meant to be explorable.
 */
function showNodeDetail(node) {
  const host = document.getElementById("nw-detail");
  const table = document.querySelector("#nw-detail-table tbody");
  const title = document.getElementById("nw-detail-title");
  const note = document.getElementById("nw-detail-note");
  if (!host) return;
  host.replaceChildren();
  table.replaceChildren();

  // THE DETAIL TABLE OBEYS THE SAME RIPPLE FILTER as the graph and the edge table. A filtered
  // graph with an unfiltered drill-down would show connections the map says are not in view.
  const matched = nwRippleMatchedIds();
  const all = ((ASSETS_STATE.graph && ASSETS_STATE.graph.edges) || [])
    .filter((e) => nwEdgeMatches(e, matched));
  const touching = all.filter((e) => e.source === node.id || e.target === node.id);
  // Sorted so the heaviest conversation is first -- an analyst asking "what does this host
  // talk to" wants the answer ordered by significance, not by query order.
  const outbound = touching.filter((e) => e.source === node.id)
                           .sort((a, b) => b.bytes - a.bytes);
  const inbound = touching.filter((e) => e.target === node.id)
                          .sort((a, b) => b.bytes - a.bytes);

  title.textContent = label(node.name, node.id);
  const dist = (node.hops === null || node.hops === undefined)
    ? ""
    : ` · ${node.hops} ${node.hops === 1 ? "hop" : "hops"} from the sensor (ttl ${node.ttl})`;
  note.replaceChildren(el("span", { text:
    `${node.degree} peer${node.degree === 1 ? "" : "s"} · ${fmtBytes(node.bytes)} · ` +
    `${outbound.length} outbound, ${inbound.length} inbound${dist}` }));

  if (node.status || (node.status_reasons || []).length) {
    const statusRow = el("div", { class: "chips" }, [statusChip(node.status)].filter(Boolean));
    if ((node.status_reasons || []).length) {
      statusRow.appendChild(el("span", { class: "muted", text: node.status_reasons.join(" · ") }));
    }
    host.appendChild(statusRow);
  }

  // Tracking stays available, but as an explicit ACTION inside the panel rather than the thing
  // a click silently did.
  const tracking = ASSETS_STATE.tracked.includes(node.id);
  // US-4: an action button wore the PAGINATION class (a pager arrow's styling on a verb);
  // it wears the standard action shape now.
  const btn = el("button", {
    class: "review-act",
    text: tracking ? "stop tracking this host" : "track only this host's connections",
  });
  btn.addEventListener("click", () => { toggleTracked(node.id); showNodeDetail(node); });
  const open = el("button", { class: "review-act", text: "open host page" });
  open.addEventListener("click", (event) => { event.stopPropagation(); openHost(node.id); });
  // THE GRAPH'S PATH TO THE HOST SHEET. The quick panel answers "what does it talk to";
  // the sheet answers "why is it interesting" (names, in/out traffic, ripples, models).
  const why = el("button", { class: "review-act", text: "why this host is interesting →" });
  why.addEventListener("click", (event) => {
    event.stopPropagation();
    openNetworkHost(node);
  });
  host.appendChild(el("div", { class: "pair-side" }, [
    el("div", { class: "pair-label", text: "host" }),
    el("div", { class: "pair-addr", text: node.id }),
    node.name ? el("div", { class: "muted", text: node.name }) : null,
  ]));
  host.appendChild(el("div", { class: "chips" }, [why, btn, open]));

  if (!touching.length) {
    table.appendChild(el("tr", {}, [emptyStateCell(7, {
      state: "none",
      message: "This host has no drawn connections in the current selection.",
    })]));
    return;
  }

  // Outbound first: "who does this host talk TO" is the usual question, and separating the
  // directions means a server answering everything does not bury its own few outbound flows.
  const rows = [];
  if (outbound.length) {
    rows.push(el("tr", {}, [el("td", {
      class: "muted", attrs: { colspan: "7" }, text: `outbound (${outbound.length})` })]));
    rows.push(...outbound.map(edgeRow));
  }
  if (inbound.length) {
    rows.push(el("tr", {}, [el("td", {
      class: "muted", attrs: { colspan: "7" }, text: `inbound (${inbound.length})` })]));
    rows.push(...inbound.map(edgeRow));
  }
  table.replaceChildren(...rows);
}

/** One edge as a table row: who → who, on which ports, how much. */
function edgeRow(e) {
  const ports = (e.ports || []).length ? e.ports.join(", ") : "—";
  const tr = el("tr", { class: "clickable" }, [
    el("td", { class: "mono", text: e.source }),
    el("td", { class: "mono", text: e.target }),
    networkRippleCell(networkEdgeRipple(e)),
    el("td", { class: "mono", text: ports }),
    el("td", { class: "mono", text: fmtBytes(e.bytes) }),
    el("td", { class: "mono", text: String(e.flows) }),
    el("td", {}, [el("span", { class: "muted", text: "details →" })]),
  ]);
  tr.addEventListener("click", () => showEdgeDetail(e));
  return tr;
}

/** An address with its name in front, when there is one. Never a name INSTEAD of an address. */
function label(name, addr) {
  return name ? `${name} (${addr})` : String(addr || "");
}

/* ── THE NETWORK HOST SHEET ─────────────────────────────────────────────────────────────────
 *
 * THE QUESTION THE TAB COULD NOT ANSWER. A dot, a line and a byte count say a host is PRESENT;
 * they do not say why it is worth opening. This sheet reads one address for the global window
 * and puts the facts in the order an analyst asks them: who is it (names), what did it move
 * (in/out), who did it talk to, what services did it offer/use, what ripples did the engine
 * form (with their own sentences), which model detections corroborate, and whether any pattern
 * has been normalized. Every count names its window.
 */
let NW_HOST = { addr: "", data: null, node: null };

function nwHostSection(title, linkText, onLink, children) {
  const head = el("div", { class: "nw-host-head" }, [el("h3", { text: title })]);
  if (linkText) {
    const link = el("button", { class: "rp-link", text: linkText, attrs: { type: "button" } });
    link.addEventListener("click", onLink);
    head.appendChild(link);
  }
  return el("div", { class: "nw-host-section" }, [head].concat(children || []));
}

function nwHostKv(key, value, title) {
  const v = el("span", { class: "nw-host-v", text: value === "" || value === null
    || value === undefined ? "—" : String(value) });
  if (title) v.setAttribute("title", title);
  return el("div", { class: "nw-host-kv" }, [
    el("span", { class: "nw-host-k", text: key }), v,
  ]);
}

function nwNameLine(names, max) {
  const list = (names || []).filter(Boolean);
  if (!list.length) return "—";
  const shown = list.slice(0, max || 8);
  return shown.join(", ") + (list.length > shown.length ? ` +${list.length - shown.length} more` : "");
}

function nwOpenAlertsFor(addr) {
  AN_FILTERS.host = addr;
  AN_FILTERS.severity = "";
  AN_FILTERS.model = "";
  AN_FILTERS.feature = "";
  showView("anomalies");
}

function nwOpenFlowsFor(addr) {
  const box = document.getElementById("dc-addr");
  if (box) box.value = addr;
  showView("discover");
}

function nwHostWindowText(data) {
  const w = (data && data.window) || {};
  const hours = Number(w.hours || trHours()) || 24;
  const range = w.since && w.until ? `${fmtTime(w.since)} → ${fmtTime(w.until)}` : "";
  return `${hours}h window${range ? " · " + range : ""} · owned by the header time control`;
}

/** Whether a source's coverage reaches back to the window's start. */
function nwCovered(coverage, data) {
  const c = coverage || {};
  const since = Date.parse(((data && data.window) || {}).since || "");
  const from = Date.parse(c.from || "");
  return Boolean(c.from) && Number.isFinite(since) && Number.isFinite(from) && from <= since;
}

function nwTrafficLine(block, label, data, coverage) {
  if (!block) {
    if (nwCovered(coverage, data)) {
      return el("div", { class: "nw-host-stat" }, [
        el("span", { class: "nw-host-stat-label", text: label }),
        el("span", { text: "0 B · 0 packets · 0 flows (measured: no row in this window)" }),
      ]);
    }
    return el("div", { class: "nw-host-stat" }, [
      el("span", { class: "nw-host-stat-label", text: label }),
      el("span", { class: "muted", text: `not measured${coverage && coverage.from
        ? ` — this source starts ${fmtTime(coverage.from)}` : ""}` }),
    ]);
  }
  return el("div", { class: "nw-host-stat" }, [
    el("span", { class: "nw-host-stat-label", text: label }),
    el("span", { text: `${fmtBytes(block.bytes)} · ${Number(block.packets || 0).toLocaleString()} `
      + `packets · ${Number(block.flows || 0).toLocaleString()} flows · `
      + `${Number(block.peers || 0).toLocaleString()} peers` }),
  ]);
}

function nwRenderHostSheet(data, node) {
  const body = document.getElementById("nw-host-body");
  const note = document.getElementById("nw-host-note");
  if (!body) return;
  body.replaceChildren();
  const hours = Number((data.window || {}).hours || trHours()) || 24;
  const addr = data.addr || (node && node.id) || "";
  if (note) note.textContent = nwHostWindowText(data);
  if (data.available === false) {
    body.appendChild(el("p", { class: "nw-host-empty", text:
      `This host could not be read: ${data.reason || "no reason was reported"}.` }));
    return;
  }
  const ident = data.identity || {};
  const traffic = data.traffic || {};
  const coverage = data.coverage || {};
  const tls = data.tls || {};
  const dns = data.dns || {};
  const models = data.models || {};
  const ripples = data.ripples || {};
  const normalized = data.normalized || {};

  // ── identity and names ──────────────────────────────────────────────────────────────
  const idChildren = [];
  if (ident.available === false) {
    idChildren.push(el("p", { class: "nw-host-empty", text:
      `Identity could not be read: ${ident.reason || "the read failed"}. That is not the same as a host with no name.` }));
  } else {
    idChildren.push(nwHostKv("PTR", ident.ptr || "—", "reverse DNS, resolved at read time"));
    idChildren.push(nwHostKv("DNS names", nwNameLine(ident.hostnames, 10),
      "names this host was seen asking for or holding, from the identity table"));
    const netbios = (ident.netbios || []).map((n) => n.name + (n.domain ? ` (${n.domain})` : ""));
    const dhcp = (ident.dhcp_names || []).map((n) => n.name);
    idChildren.push(nwHostKv("NetBIOS", netbios.length ? netbios.join(", ") : "—",
      "NTLM client hostnames in this window"));
    idChildren.push(nwHostKv("DHCP name", dhcp.length ? dhcp.join(", ") : "—",
      "DHCP option-12 names in this window"));
    idChildren.push(nwHostKv("TLS SNI", nwNameLine((tls.names || []).map((n) => n.name), 8),
      `server names in this ${hours}h window`));
    idChildren.push(nwHostKv("JA4", `${Number(tls.ja4_count || 0)} fingerprints in this ${hours}h window`));
    idChildren.push(nwHostKv("MAC", ident.mac || "—"));
    idChildren.push(nwHostKv("OS", ident.os || "—"));
    if (ident.role) idChildren.push(nwHostKv("Role", `${ident.role}${ident.role_scope ? " · " + ident.role_scope : ""}`));
    idChildren.push(nwHostKv("First seen", ident.first_seen
      ? `${fmtTime(ident.first_seen)} (${ident.first_seen_basis || "retained flow window"})`
      : (ident.first_seen_basis === "read failed" ? "not read" : "not measured")));
    idChildren.push(nwHostKv("Last seen", ident.last_seen ? fmtTime(ident.last_seen) : "—"));
  }
  body.appendChild(nwHostSection("Identity and names", "Flows →", () => nwOpenFlowsFor(addr), idChildren));

  // ── traffic ─────────────────────────────────────────────────────────────────────────
  const inCov = coverage.flows_window_endpoint || {};
  const trafficChildren = [
    nwTrafficLine(traffic.in, "in", data, inCov),
    nwTrafficLine(traffic.out, "out", data, inCov),
  ];
  if (traffic.outbound_flows && !traffic.out) {
    trafficChildren.push(nwTrafficLine(traffic.outbound_flows, "out (longer-retained flow table)", data, coverage.flows_window || {}));
  }
  if (inCov.from && !nwCovered(inCov, data)) {
    trafficChildren.push(el("p", { class: "nw-host-note-line", text:
      `In/out bytes are measured only from ${fmtTime(inCov.from)} — less than the ${hours}h window. `
      + `Outbound totals come from flows_window and reach further back.` }));
  }
  if (traffic.available === false) {
    trafficChildren.push(el("p", { class: "nw-host-empty", text:
      `Traffic could not be read: ${traffic.reason || "the read failed"}.` }));
  }
  body.appendChild(nwHostSection(`Traffic in this ${hours}h window`, "Flows →",
    () => nwOpenFlowsFor(addr), trafficChildren));

  // ── peers ───────────────────────────────────────────────────────────────────────────
  const peerRows = (data.peers || {}).rows || [];
  const peerChildren = [];
  if ((data.peers || {}).available === false) {
    peerChildren.push(el("p", { class: "nw-host-empty", text:
      `Peer records could not be read: ${data.peers.reason || "the read failed"}.` }));
  } else if (!peerRows.length) {
    peerChildren.push(el("p", { class: "nw-host-empty", text:
      `No Zeek connection records for this host in this ${hours}h window. That is an empty log, not zero traffic.` }));
  } else {
    const t = el("table", { class: "nw-host-table" });
    t.appendChild(el("thead", {}, [el("tr", {}, [
      el("th", { text: "Peer" }), el("th", { text: "Out" }), el("th", { text: "In" }),
      el("th", { text: "Conns" }),
    ])]));
    const tb = el("tbody");
    for (const r of peerRows) {
      const tr = el("tr", { class: "clickable" }, [
        el("td", { class: "mono link", text: r.peer }),
        el("td", { class: "mono", text: fmtBytes(r.out_bytes || 0) }),
        el("td", { class: "mono", text: fmtBytes(r.in_bytes || 0) }),
        el("td", { class: "mono", text: String(Number(r.out_conns || 0) + Number(r.in_conns || 0)) }),
      ]);
      tr.addEventListener("click", () => openNetworkHost({ id: r.peer, name: "", bytes: 0 }));
      tb.appendChild(tr);
    }
    t.appendChild(tb);
    peerChildren.push(t);
  }
  body.appendChild(nwHostSection("Top peers in this window", "", null, peerChildren));

  // ── services / ports ───────────────────────────────────────────────────────────────
  const svc = data.services || {};
  const svcChildren = [];
  if (svc.available === false) {
    svcChildren.push(el("p", { class: "nw-host-empty", text:
      `Services could not be read: ${svc.reason || "the read failed"}.` }));
  } else {
    const chips = el("div", { class: "chips" });
    for (const s of svc.services || []) {
      chips.appendChild(el("span", { class: "bubble state", text: `${s.service} ${Number(s.conns).toLocaleString()}` }));
    }
    if (!(svc.services || []).length) chips.appendChild(el("span", { class: "muted", text: "no service label in this window" }));
    svcChildren.push(el("div", { class: "nw-host-kv" }, [
      el("span", { class: "nw-host-k", text: "services" }), chips]));
    svcChildren.push(nwHostKv("listening (inbound)",
      (svc.listening_ports || []).map((p) => `${p.port}/${p.proto} ×${p.conns}`).join(", ") || "—",
      "destination ports on this host — what it offers"));
    svcChildren.push(nwHostKv("used (outbound)",
      (svc.used_ports || []).map((p) => `${p.port}/${p.proto} ×${p.conns}`).join(", ") || "—",
      "destination ports this host dialled — what it consumes"));
  }
  body.appendChild(nwHostSection("Services and ports", "Flows →", () => nwOpenFlowsFor(addr), svcChildren));

  // ── DNS and TLS ────────────────────────────────────────────────────────────────────
  const dnsChildren = [];
  if (dns.available === false) {
    dnsChildren.push(el("p", { class: "nw-host-empty", text:
      `DNS queries could not be read: ${dns.reason || "the read failed"}.` }));
  } else if (!(dns.queries || []).length) {
    dnsChildren.push(el("p", { class: "nw-host-empty", text:
      `No DNS query from this host in this ${hours}h window.` }));
  } else {
    dnsChildren.push(nwHostKv("asked", (dns.queries || []).map((q) => `${q.name} (qtype ${q.qtype}, ${q.asks})`).join(", ")));
  }
  if (tls.available === false) {
    dnsChildren.push(el("p", { class: "nw-host-empty", text:
      `TLS names could not be read: ${tls.reason || "the read failed"}.` }));
  } else if (!(tls.names || []).length) {
    dnsChildren.push(el("p", { class: "nw-host-empty", text:
      `No TLS session with a server name from this host in this ${hours}h window.` }));
  } else {
    dnsChildren.push(nwHostKv("TLS names", (tls.names || []).map((n) => `${n.name} ×${n.sessions}`).join(", ")));
  }
  body.appendChild(nwHostSection("DNS and TLS", "Flows →", () => nwOpenFlowsFor(addr), dnsChildren));

  // ── ripples ────────────────────────────────────────────────────────────────────────
  const ripChildren = [];
  if (ripples.available === false) {
    ripChildren.push(el("p", { class: "nw-host-empty", text:
      `Ripple presence could not be read: ${ripples.reason || "the read failed"}. That is not the same as no ripple.` }));
  } else if (!(ripples.rows || []).length) {
    ripChildren.push(el("p", { class: "nw-host-empty", text:
      `No ripple on this host in this ${Number(ripples.window_hours || hours)}h window.` }));
  } else {
    ripChildren.push(el("p", { class: "nw-host-kv" }, [
      el("span", { class: "nw-host-k", text: "worst" }),
      el("span", { class: "bubble state sev-" + (ripples.worst || "low"), text: sevText(ripples.worst || "low") }),
      el("span", { class: "muted", text: `${ripples.count} ripple window${ripples.count === 1 ? "" : "s"} in ${Number(ripples.window_hours || hours)}h` }),
    ]));
    for (const r of ripples.rows) {
      const row = el("div", { class: "nw-host-ripple" }, [
        el("div", { class: "nw-host-ripple-head" }, [
          el("span", { class: "bubble state sev-" + (r.severity || "low"), text: sevText(r.severity || "low") }),
          el("span", { class: "muted", text: `score ${Number(r.score || 0).toFixed(2)}` }),
          el("span", { class: "muted", text: fmtTime(r.window_start) }),
        ]),
        el("p", { class: "nw-host-ripple-sentence", text: r.explanation || "No sentence was carried." }),
      ]);
      // A ROW THAT OPENS IS A CONTROL. The CSS gives it a pointer and a 44px target; without a
      // role and a key handler the ripple sentence would be mouse-only, which the row-opener
      // audit counts as looks-clickable-but-is-not.
      row.setAttribute("role", "button");
      row.setAttribute("tabindex", "0");
      row.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " " || ev.key === "Spacebar") {
          ev.preventDefault();
          row.click();
        }
      });
      row.addEventListener("click", () => {
        closeSheet(document.getElementById("nw-host-card"));
        openRippleSheet(r, row);
      });
      ripChildren.push(row);
    }
  }
  body.appendChild(nwHostSection("Ripples", "Alerts →", () => nwOpenAlertsFor(addr), ripChildren));

  // ── model detections ───────────────────────────────────────────────────────────────
  const modelChildren = [];
  if (models.available === false) {
    modelChildren.push(el("p", { class: "nw-host-empty", text:
      `Model detections could not be read: ${models.reason || "the read failed"}.` }));
  } else if (!(models.rows || []).length) {
    modelChildren.push(el("p", { class: "nw-host-empty", text:
      `No model detection on this host in this ${hours}h window.` }));
  } else {
    modelChildren.push(el("p", { class: "nw-host-kv" }, [
      el("span", { class: "nw-host-k", text: "worst" }),
      el("span", { class: "bubble state sev-" + (models.worst || "low"), text: sevText(models.worst || "low") }),
      el("span", { class: "muted", text: `${models.count} detection${models.count === 1 ? "" : "s"} in this ${hours}h window` }),
    ]));
    const t = el("table", { class: "nw-host-table" });
    t.appendChild(el("thead", {}, [el("tr", {}, [
      el("th", { text: "Window" }), el("th", { text: "Band" }), el("th", { text: "Score" }),
      el("th", { text: "Models" }),
    ])]));
    const tb = el("tbody");
    for (const m of models.rows) {
      const tr = el("tr", { class: "clickable" }, [
        el("td", { class: "mono", text: fmtTime(m.window_start) }),
        el("td", {}, [el("span", { class: "bubble state sev-" + (m.severity || "low"), text: sevText(m.severity || "low") })]),
        el("td", { class: "mono", text: Number(m.score || 0).toFixed(2) }),
        el("td", { text: m.models || "—" }),
      ]);
      tr.addEventListener("click", () => nwOpenAlertsFor(addr));
      tb.appendChild(tr);
    }
    t.appendChild(tb);
    modelChildren.push(t);
  }
  body.appendChild(nwHostSection("Model detections", "Alerts →", () => nwOpenAlertsFor(addr), modelChildren));

  // ── normalized patterns ────────────────────────────────────────────────────────────
  const normChildren = [];
  if (normalized.available === false) {
    normChildren.push(el("p", { class: "nw-host-empty", text:
      `The normalization state could not be read: ${normalized.reason || "the read failed"}.` }));
  } else if (!Number(normalized.count || 0)) {
    normChildren.push(el("p", { class: "nw-host-empty", text:
      `0 patterns normalized on this host (measured). Normalizing adds a pattern to the host's `
      + `baseline; it is not a mute.` }));
  } else {
    for (const n of normalized.rows || []) {
      normChildren.push(el("div", { class: "nw-host-kv" }, [
        el("span", { class: "nw-host-k", text: `${n.channel}` }),
        el("span", { class: "nw-host-v", text: `${n.value} · ${n.family} · ${fmtTime(n.created_at)}` }),
      ]));
    }
  }
  body.appendChild(nwHostSection("Normalized patterns", "", null, normChildren));

  const errs = Object.keys(data.errors || {});
  if (errs.length) {
    body.appendChild(el("p", { class: "nw-host-note-line", text:
      `Sections that could not be read: ${errs.join(", ")}.` }));
  }
}

function openNetworkHost(node) {
  const card = document.getElementById("nw-host-card");
  if (!card || !node) return;
  const addr = String(node.id || node.addr || "");
  if (!addr) return;
  NW_HOST = { addr, data: null, node };
  const title = document.getElementById("nw-host-title");
  const sub = document.getElementById("nw-host-addr");
  if (title) title.textContent = node.name ? `${node.name}` : addr;
  if (sub) sub.textContent = node.name ? `· ${addr}` : "";
  const note = document.getElementById("nw-host-note");
  if (note) note.textContent = `Reading this host for the ${trHours()}h window…`;
  const body = document.getElementById("nw-host-body");
  if (body) body.replaceChildren(el("p", { class: "muted", text: "Loading…" }));
  if (typeof openSheet === "function") {
    openSheet(card, { scrimId: "nw-host-scrim", initialFocus: "nw-host-close" });
  } else {
    card.classList.remove("hidden");
  }
  getJSON(ASSET_API.networkHost(addr, trHours()))
    .then((data) => { NW_HOST.data = data; nwRenderHostSheet(data, node); })
    .catch((err) => {
      if (note) note.textContent = `This host could not be read: ${err.message}`;
      if (body) body.replaceChildren(el("p", { class: "nw-host-empty", text:
        `The host sheet read failed: ${err.message}.` }));
    });
}

/** Bind the sheet's fixed controls once. The view's own controls are wired in app.js. */
function nwWireHostSheet() {
  const card = document.getElementById("nw-host-card");
  if (!card) return;
  if (typeof wireSheet === "function") {
    wireSheet(card, { scrimId: "nw-host-scrim" });
  }
  const close = () => closeSheet(card);
  for (const id of ["nw-host-close", "nw-host-cancel"]) {
    const btn = document.getElementById(id);
    if (btn) btn.addEventListener("click", close);
  }
  const alerts = document.getElementById("nw-host-alerts");
  if (alerts) alerts.addEventListener("click", () => nwOpenAlertsFor(NW_HOST.addr));
  const flows = document.getElementById("nw-host-flows");
  if (flows) flows.addEventListener("click", () => nwOpenFlowsFor(NW_HOST.addr));
  const page = document.getElementById("nw-host-page");
  if (page) page.addEventListener("click", () => {
    closeSheet(card);
    openHost(NW_HOST.addr);
  });
}

/* ── Netflow: the port/protocol drill-down ─────────────────────────────────── */

/* "Top ports" answers which ports carry the most bytes and stops there; the next question is
 * always which hosts and to where. This is the way in from both the protocol and the port
 * charts. `params` carries whichever filter was clicked -- a port, a protocol, or both. */
function loadFlowDetail(params) {
  const host = document.getElementById("nf-detail");
  const table = document.querySelector("#nf-detail-table tbody");
  const title = document.getElementById("nf-detail-title");
  const note = document.getElementById("nf-detail-note");
  if (!host) return Promise.resolve();
  // THE CHIPS RIDE ALONG (issue #31): the view's click-to-filter chips and this table used to
  // answer different questions -- a host chip narrowed the charts while the table below kept
  // whatever the last bar showed, with no sign they had parted ways. The chips are merged
  // onto the drill ONCE per fetch; a chip the request cannot express is NAMED in the note
  // rather than silently dropped.
  const base = params;
  const merged = (typeof nfDetailWithChips === "function")
    ? nfDetailWithChips(params) : { params, unapplied: [] };
  params = merged.params;
  const chipNote = merged.unapplied.length
    ? ` Active chip(s) this table cannot apply: ${merged.unapplied.join(", ")}.` : "";
  title.textContent = params.name || "flow detail";
  // THE WINDOW IS SAID OUT LOUD, and it is the GLOBAL one. This table used to read
  // ASSETS_STATE.hours, which nothing updated after the per-view time boxes were removed --
  // so the drill fetched a stale fixed 24h, ignored the operator's range, and (because it is
  // only re-fetched on a bar click) kept rendering whatever it last loaded. Measured by the
  // operator: with "last 15 minutes" selected the table still showed rows from hours earlier.
  ASSETS_STATE.detailParams = base;  // the bar's own drill; the chips attach at fetch time
  note.textContent = `Host-to-host pairs behind this bar, busiest first \u00b7 ${trLabel().toLowerCase()}.` + chipNote;
  host.replaceChildren();
  table.replaceChildren();

  const url = (typeof ASSET_API !== "undefined" && ASSET_API.flows)
    ? ASSET_API.flows(params, trHours())
    : `/api/flows?hours=${trHours()}` +
      (params.port !== undefined ? `&port=${params.port}` : "") +
      (params.proto !== undefined ? `&proto=${params.proto}` : "") +
      (params.src ? `&src=${encodeURIComponent(params.src)}` : "") +
      (params.dst ? `&dst=${encodeURIComponent(params.dst)}` : "");

  return getJSON(url)
    .then((d) => {
      if (d.available === false) {
        host.appendChild(chartEmpty(`Cannot read the flows: ${d.reason}.`, "failed"));
        emptyRow(table, 6, "Nothing to show — the flows read failed.", null, { state: "failed" });
        return;
      }
      const rows = d.points || [];
      if (!rows.length) {
        host.appendChild(chartEmpty("No flows matched in this window."));
        emptyRow(table, 6, "No rows.");
        return;
      }
      // Say when the list is capped: a truncated list that does not mention it looks complete.
      // AND SAY WHICH WINDOW: this line is what an operator reads to know whether the table
      // follows the range in the header -- the question that exposed a stale-window bug.
      const windowLabel = ` \u00b7 ${trLabel().toLowerCase()}`;
      if (d.truncated) {
        note.textContent =
          `Showing the ${rows.length} busiest of ${d.total_pairs} host pairs ` +
          `(${d.total_flows} flows total)${windowLabel}.` + chipNote;
      } else {
        note.textContent = `${rows.length} host pair(s), ${d.total_flows} flows${windowLabel}.` + chipNote;
      }
      renderBars("nf-detail", {
        available: true,
        points: rows.map((r) => ({
          label: `${r.src_addr} → ${r.dst_addr}`, value: r.bytes, row: r,
        })),
      }, {
        onClick: (r) => openHost(r.row.src_addr),
        format: (v) => fmtBytes(v),
        colour: () => "var(--series-1)",
        title: (r) => `drill into ${r.row.src_addr}`,
      });
      table.replaceChildren(...rows.map((r) => {
        const tr = el("tr", { class: "clickable" }, [
          el("td", { class: "link mono", text: r.src_addr }),
          el("td", { class: "mono", text: r.dst_addr }),
          el("td", { class: "mono", text: String(r.dst_port) }),
          el("td", { class: "mono", text: fmtBytes(r.bytes) }),
          el("td", { class: "mono", text: String(r.flows) }),
          el("td", {}, [el("span", { class: "muted", text: "drill down →" })]),
        ]);
        tr.addEventListener("click", () => openHost(r.src_addr));
        return tr;
      }));
    })
    .catch((err) => {
      host.appendChild(chartEmpty(`Cannot read the flows: ${err.message}.`, "failed"));
      emptyRow(table, 6, "Nothing to show — the flows read failed.", null, { state: "failed" });
    });
}

/* ── Zeek: the per-log drill-down ──────────────────────────────────────────── */

function loadZeekLog(log) {
  const host = document.getElementById("zk-hosts");
  const table = document.querySelector("#zk-hosts-table tbody");
  const title = document.getElementById("zk-drill-title");
  const note = document.getElementById("zk-drill-note");
  if (!host) return;
  title.textContent = `${log}.log`;
  note.textContent = `Hosts appearing in ${log}.log over the selected window.`;
  host.replaceChildren();
  table.replaceChildren();

  // The Zeek view has its OWN window selector (zk-hours), and the drill-down must use the same
  // window as the bars that were clicked. Reading ASSETS_STATE.hours here would silently
  // drill into a different period than the chart above it, which is the sort of mismatch that
  // reads as "the numbers are wrong".
  const filters = typeof zkQuery === "function" ? zkQuery() : "";
  return getJSON(ASSET_API.zeeklog(log, zeekWindow(), filters))
    .then((d) => {
      if (d.available === false) {
        host.appendChild(chartEmpty(`Cannot read ${log}.log: ${d.reason}.`, "failed"));
        emptyRow(table, 3, "Nothing to show — the log read failed.", null, { state: "failed" });
        return;
      }
      const rows = d.points || [];
      if (!rows.length) {
        // "the log is empty" and "the query failed" are different facts and are stated
        // differently -- the distinction the Zeek view exists to keep.
        host.appendChild(chartEmpty(
          `${log}.log has no rows in this window. That is an empty log, not a failed query.`));
        emptyRow(table, 3, "No rows.");
        return;
      }
      renderBars("zk-hosts", {
        available: true, points: rows.map((r) => ({ label: r.addr, value: r.n, addr: r.addr })),
      }, {
        onClick: (r) => openHost(r.addr),
        format: (v) => String(v),
        title: (r) => `drill into ${r.addr}`,
      });
      table.replaceChildren(...rows.map((r) => {
        // The NAME when one exists, with the address beside it -- same rule as every other
        // host list (the IP is the fact; the name is the convenience, never a replacement).
        const tr = el("tr", { class: "clickable" }, [
          el("td", { class: "link mono", text: r.name ? `${r.name} (${r.addr})` : r.addr }),
          el("td", { class: "mono", text: String(r.n) }),
          el("td", {}, [el("span", { class: "muted", text: "drill down →" })]),
        ]);
        tr.addEventListener("click", () => openHost(r.addr));
        return tr;
      }));
    })
    .catch((err) => {
      host.appendChild(chartEmpty(`Cannot read ${log}.log: ${err.message}.`, "failed"));
      emptyRow(table, 3, "Nothing to show — the log read failed.", null, { state: "failed" });
    });
}


/* ── Asset changes: the Nmap ledger ────────────────────────────────────────── */

function loadAssetChanges(hours) {
  return getJSON(ASSET_API.assetChanges(hours))
    .then((d) => { ASSETS_STATE.changes = d; renderAssetChanges(); })
    .catch((err) => {
      ASSETS_STATE.changes = { available: false, changes: [], reason: err.message };
      renderAssetChanges();
    });
}

function renderAssetChanges() {
  const tbody = document.querySelector("#ac-table tbody");
  const summary = document.getElementById("ac-summary");
  const note = document.getElementById("ac-note");
  const empty = document.getElementById("ac-empty");
  const coverage = document.getElementById("ac-coverage");
  if (!tbody || !summary || !note || !empty || !coverage) return;

  const d = ASSETS_STATE.changes || {};
  tbody.replaceChildren();
  note.replaceChildren();
  empty.replaceChildren();
  coverage.textContent = "";
  if (!d.available) {
    summary.textContent = "unavailable";
    note.appendChild(el("p", { class: "warn", text:
      `The change ledger could not be read: ${d.reason || "unknown error"}.` }));
    return;
  }

  const rows = d.changes || [];
  const cov = d.coverage || {};
  if (cov.available) {
    const scanAge = cov.last_scan
      ? fmtAge(Math.max(0, (Date.now() - Date.parse(cov.last_scan)) / 1000)) + " ago"
      : "never";
    // ── THE PERCENTAGE IS OF THE MONITORED NETWORK, NOT OF EVERY ADDRESS (operator, 2026-11-12) ──
    //
    // The old line read "Coverage: scanned/assets assets scanned" with `assets` counting every row
    // in the registry, internet peers included, so the number fell as the box saw more of the
    // world and answered nothing anyone asked. The question is "have we scanned the network we said
    // we were watching", and that needs the monitored population as the denominator.
    //
    // The basis is STATED, because the same number means different things in the three cases: an
    // upgrade with nothing declared (legacy, everything counts), a declaration set with no
    // monitored scope (an explicit no-monitoring configuration), and the normal case.
    const scope = cov.in_scope === undefined ? cov.assets : cov.in_scope;
    const scopeHits = cov.in_scope_scanned === undefined ? cov.scanned : cov.in_scope_scanned;
    const basis = String(cov.basis || "all");
    const pct = scope > 0 ? Math.round((scopeHits / scope) * 100) : 0;
    const coverageOf = basis === "monitored"
      ? `${scopeHits}/${scope} monitored hosts scanned (${pct}%)`
      : (basis === "none"
        ? "no monitored scope is declared, so scanner coverage has no denominator"
        : `${scopeHits}/${scope} hosts scanned (${pct}%); no network scopes are declared yet, so ` +
          "this counts every address in the registry");
    coverage.textContent = `Coverage: ${coverageOf}; ` +
      `${cov.observations} observations across ${cov.observed_assets} hosts in this window; ` +
      `last scan ${scanAge}.`;
  } else {
    coverage.textContent = `Coverage unavailable: ` +
      `${cov.reason || "the scanner did not report a baseline"}.`;
  }
  summary.textContent = rows.length
    ? `${rows.length} in the window`
    : "none in the window";
  if (!rows.length) {
    empty.replaceChildren(emptyState({
      state: "none",
      message: "No service changes between successful scans in this window. " +
        "A change appears only when two scans disagree; a failed scan is not a change.",
    }));
    return;
  }

  const bandClass = { expected: "ok", watch: "warn", suspicious: "bad", high: "bad" };
  for (const c of rows) {
    const when = c.last_seen ? new Date(c.last_seen) : null;
    const age = when && !Number.isNaN(when.getTime())
      ? fmtAge(Math.max(0, (Date.now() - when.getTime()) / 1000)) + " ago"
      : "unknown";
    const change = `${String(c.kind || "change").replaceAll("_", " ")} ${c.protocol}/${c.port}`;
    const posture = c.posture || {};
    const band = posture.band || "unscored";
    const reasons = (posture.reasons || []).join(" ");
    const chip = el("span", {
      class: `bubble state ${bandClass[band] || "muted"}`,
      text: band === "unscored" ? "unscored" : `${band} ${Number(posture.score || 0).toFixed(2)}`,
      attrs: reasons ? { title: reasons } : {},
    });
    tbody.appendChild(el("tr", {}, [
      el("td", { text: age }),
      el("td", {}, [el("span", { class: "mono", text: c.ip || c.asset_key || "—" })]),
      el("td", { text: change }),
      el("td", { class: "muted", text: c.old_value || "—" }),
      el("td", { text: c.new_value || "—" }),
      el("td", { class: "muted", text: c.confidence || "—" }),
      el("td", {}, [chip]),
    ]));
  }
}
