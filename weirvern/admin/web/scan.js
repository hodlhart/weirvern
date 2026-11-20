/* THE SCAN SHEET: watching one manual scan from queued to its recorded findings.
 *
 * WHY THIS EXISTS. Pressing "Scan now" filed a request and then said nothing: the operator had
 * no way to tell a queued job from one the scanner had claimed, no elapsed time, and no place
 * where a finding appeared as the scan recorded it. The queue already carries the truth -- a row
 * keyed by job_id, written again on every state change -- so this file reads that row and says
 * only what it says.
 *
 * HONEST PROGRESS. `weirvern.scan_jobs` has no phase and no percentage: states are queued,
 * claimed, done and error. So the sheet never draws a bar or a percentage. It shows the state,
 * the timestamps, elapsed time derived from those timestamps, and the findings the scanner has
 * recorded for the host since the job was queued. The sentence saying so is in the sheet, not
 * just in a comment.
 *
 * ONE DETAIL SURFACE (docs/design/sheets.md): this is a sheet, built by sheets.js -- one scrim,
 * one Escape, focus returns to the control that opened it.
 */

const SCAN_STATE = {
  jobId: "",
  ip: "",
  job: null,
  findings: [],
  findingsState: "waiting",   // waiting | ok | failed
  findingsReason: "",
  missingPolls: 0,
  timedOut: "",
  pollTimer: null,
  tickTimer: null,
  inFlight: false,
  renderedKey: "",
};

const SCAN_POLL_MS = 2500;                 // bounded: one read per 2.5s while the sheet is open
const SCAN_QUEUED_TIMEOUT_MS = 30 * 60 * 1000;   // nobody claimed it in half an hour
const SCAN_RUNNING_TIMEOUT_MS = 20 * 60 * 1000;  // the scanner lease is 15 minutes

const SCAN_WORDS = {
  queued: "Queued",
  claimed: "Running",
  done: "Done",
  error: "Failed",
};

function scanMs(value) {
  const s = String(value || "").trim();
  if (!s) return NaN;
  const hasZone = /([zZ]|[+-]\d\d:?\d\d)$/.test(s);
  const iso = s.indexOf("T") >= 0 ? s : s.replace(" ", "T");
  const ms = Date.parse(hasZone ? iso : iso + "Z");
  return Number.isFinite(ms) ? ms : NaN;
}

function scanClock(ms) {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h) return `${h}h${String(m).padStart(2, "0")}m`;
  if (m) return `${m}m${String(s).padStart(2, "0")}s`;
  return `${s}s`;
}

/** The state word the operator reads. `timedOut` is a client-side fact about the queue, and it
 *  never replaces a terminal state the server recorded. */
function scanWord(job) {
  if (!job) return "Reading the queue…";
  if (job.state === "error") return "Failed";
  if (job.state === "done") return "Done";
  if (SCAN_STATE.timedOut) return "Timed out";
  return SCAN_WORDS[job.state] || `State ${job.state || "unknown"}`;
}

function scanElapsed(job) {
  if (!job) return { label: "elapsed", text: "—" };
  const requested = scanMs(job.requested_at);
  const started = scanMs(job.started_at);
  const finished = scanMs(job.finished_at);
  if (job.state === "queued") {
    return { label: "waiting", text: scanClock(Date.now() - requested) };
  }
  if (job.state === "claimed") {
    const from = Number.isFinite(started) ? started : requested;
    return { label: "running", text: scanClock(Date.now() - from) };
  }
  const from = Number.isFinite(started) ? started : requested;
  const to = Number.isFinite(finished) ? finished : Date.now();
  return { label: job.state === "error" ? "failed after" : "finished in", text: scanClock(to - from) };
}

/** One raw read, deliberately outside getJSON's 8s cache: a poll that returns a cached row is
 *  not a poll, and the sheet would sit on "running" after the job had finished. */
async function scanGet(url) {
  const res = await window.fetch(url, { headers: requestHeaders(), cache: "no-store" });
  const body = await res.json().catch(() => null);
  if (!res.ok) throw new Error((body && body.error) || `${res.status} ${res.statusText}`.trim());
  return body || {};
}

function scanSheetEls() {
  return {
    card: document.getElementById("scan-sheet"),
    subject: document.getElementById("scan-subject"),
    stateLine: document.getElementById("scan-state-line"),
    body: document.getElementById("scan-body"),
    retry: document.getElementById("scan-retry"),
    check: document.getElementById("scan-check"),
    findings: document.getElementById("scan-findings"),
    close: document.getElementById("scan-close"),
    cancel: document.getElementById("scan-cancel"),
  };
}

function scanURLSync() {
  if (typeof scheduleURLSync === "function") scheduleURLSync();
}

/** Open the sheet for one job id. `ip` is a hint from the POST that created it; the queue row is
 *  the authority and supplies its own address. */
function openScanSheet(jobId, opts = {}) {
  const id = String(jobId || "").trim();
  if (!id) return;
  const els = scanSheetEls();
  if (!els.card) return;
  if (SCAN_STATE.jobId && SCAN_STATE.jobId !== id) scanStopTimers();
  SCAN_STATE.jobId = id;
  SCAN_STATE.ip = String(opts.ip || SCAN_STATE.ip || "").trim();
  SCAN_STATE.job = null;
  SCAN_STATE.findings = [];
  SCAN_STATE.findingsState = "waiting";
  SCAN_STATE.findingsReason = "";
  SCAN_STATE.missingPolls = 0;
  SCAN_STATE.timedOut = "";
  SCAN_STATE.renderedKey = "";
  els.card.dataset.jobId = id;
  if (els.subject) els.subject.textContent = SCAN_STATE.ip || "";
  if (els.stateLine) els.stateLine.textContent = "Reading the queue…";
  scanRenderBody();
  openSheet(els.card, { initialFocus: "scan-close" });
  scanURLSync();
  scanPollOnce();
  scanStartTimers();
}

function scanStopTimers() {
  if (SCAN_STATE.pollTimer) { clearTimeout(SCAN_STATE.pollTimer); SCAN_STATE.pollTimer = null; }
  if (SCAN_STATE.tickTimer) { clearInterval(SCAN_STATE.tickTimer); SCAN_STATE.tickTimer = null; }
  SCAN_STATE.inFlight = false;
}

function scanStartTimers() {
  if (SCAN_STATE.tickTimer) clearInterval(SCAN_STATE.tickTimer);
  // The elapsed clock ticks once a second; the queue is read every 2.5s. Both stop at terminal.
  SCAN_STATE.tickTimer = setInterval(() => scanTick(), 1000);
}

function closeScanSheet() {
  const els = scanSheetEls();
  scanStopTimers();
  SCAN_STATE.jobId = "";
  SCAN_STATE.job = null;
  SCAN_STATE.ip = "";
  SCAN_STATE.renderedKey = "";
  if (els.card) {
    delete els.card.dataset.jobId;
    closeSheet(els.card);
  }
  scanURLSync();
}

function scanTerminal(job) {
  return Boolean(job) && (job.state === "done" || job.state === "error");
}

function scanTimedOut(job) {
  if (!job || scanTerminal(job)) return "";
  const requested = scanMs(job.requested_at);
  const started = scanMs(job.started_at);
  if (job.state === "queued" && Number.isFinite(requested)
      && Date.now() - requested > SCAN_QUEUED_TIMEOUT_MS) {
    return `No scanner has claimed this job in ${scanClock(Date.now() - requested)}. `
      + "The queue is readable, so this is a timeout in the scanner, not a lost request.";
  }
  if (job.state === "claimed" && Number.isFinite(started)
      && Date.now() - started > SCAN_RUNNING_TIMEOUT_MS) {
    return `The scanner claimed this job ${scanClock(Date.now() - started)} ago and has written `
      + "no result. Its 15-minute lease has run out, so another scanner may claim it again.";
  }
  return "";
}

async function scanPollOnce() {
  if (!SCAN_STATE.jobId || SCAN_STATE.inFlight) return;
  SCAN_STATE.inFlight = true;
  try {
    const q = await scanGet(`/api/scan-jobs?job=${encodeURIComponent(SCAN_STATE.jobId)}`);
    if (q.available === false) {
      SCAN_STATE.findingsState = "failed";
      SCAN_STATE.findingsReason = q.reason || "the scan-job table is not readable";
      scanRenderBody();
      scanScheduleNext();
      return;
    }
    const job = (q.jobs || [])[0] || null;
    if (!job) {
      // A JUST-CREATED ROW CAN BE A MOMENT BEHIND. Counting misses keeps that honest: the first
      // few say "reading", six say the queue no longer lists it.
      SCAN_STATE.missingPolls += 1;
      scanRenderBody();
      scanScheduleNext();
      return;
    }
    SCAN_STATE.missingPolls = 0;
    const previous = SCAN_STATE.job;
    SCAN_STATE.job = job;
    if (!SCAN_STATE.ip && job.ip) SCAN_STATE.ip = String(job.ip);
    SCAN_STATE.timedOut = scanTimedOut(job);
    await scanLoadFindings(job);
    scanRenderBody();
    if (previous && previous.state !== job.state) scanURLSync();
    if (scanTerminal(job) || SCAN_STATE.timedOut) {
      scanStopTimers();
      if (SCAN_STATE.tickTimer) { clearInterval(SCAN_STATE.tickTimer); SCAN_STATE.tickTimer = null; }
      return;
    }
    scanScheduleNext();
  } catch (err) {
    SCAN_STATE.findingsState = "failed";
    SCAN_STATE.findingsReason = err && err.message ? err.message : String(err);
    scanRenderBody();
    scanScheduleNext();
  } finally {
    SCAN_STATE.inFlight = false;
  }
}

function scanScheduleNext() {
  if (SCAN_STATE.pollTimer) clearTimeout(SCAN_STATE.pollTimer);
  if (!SCAN_STATE.jobId) return;
  SCAN_STATE.pollTimer = setTimeout(() => { scanPollOnce(); }, SCAN_POLL_MS);
}

async function scanLoadFindings(job) {
  const ip = String(job.ip || SCAN_STATE.ip || "").trim();
  if (!ip) { SCAN_STATE.findingsState = "waiting"; return; }
  try {
    const d = await scanGet(`/api/findings?ip=${encodeURIComponent(ip)}`);
    if (d.available === false) {
      SCAN_STATE.findingsState = "failed";
      SCAN_STATE.findingsReason = d.reason || "the findings table could not be read";
      SCAN_STATE.findings = [];
      return;
    }
    const since = scanMs(job.requested_at);
    const rows = d.findings || [];
    SCAN_STATE.findings = Number.isFinite(since)
      ? rows.filter((f) => {
          const seen = scanMs(f.last_seen);
          return !Number.isFinite(seen) || seen >= since;
        })
      : rows;
    SCAN_STATE.findingsState = "ok";
    SCAN_STATE.findingsReason = "";
  } catch (err) {
    SCAN_STATE.findingsState = "failed";
    SCAN_STATE.findingsReason = err && err.message ? err.message : String(err);
  }
}

function scanTick() {
  const job = SCAN_STATE.job;
  if (!job || !SCAN_STATE.jobId) return;
  const node = document.getElementById("scan-elapsed");
  if (!node) return;
  const e = scanElapsed(job);
  // The LABEL is already the <dt> beside this value ("running", "waiting", "finished in").
  // Repeating it here read as "waiting waiting 3m" in the live console.
  node.textContent = e.text;
}

function scanFact(dl, key, value, cls) {
  dl.appendChild(el("dt", { text: key }));
  const dd = el("dd", { class: cls || "", text: value === undefined || value === null || value === "" ? "—" : String(value) });
  dl.appendChild(dd);
  return dd;
}

function scanRenderBody() {
  const els = scanSheetEls();
  if (!els.body) return;
  const job = SCAN_STATE.job;
  const missing = !job && SCAN_STATE.missingPolls >= 6;
  const word = missing ? "Not in the queue" : scanWord(job);
  if (els.stateLine) {
    // THE RAW QUEUE WORD IS SHOWN ONLY WHEN IT DIFFERS from the word the operator reads
    // (claimed -> Running, error -> Failed). "Queued · queue says queued" was noise.
    const differs = job && job.state && job.state.toLowerCase() !== word.toLowerCase();
    const raw = differs ? ` · queue says ${job.state}` : "";
    els.stateLine.textContent = word + raw;
    els.stateLine.className = "scan-state-line" + (job && job.state === "error" ? " bad" : "");
  }
  if (els.subject) els.subject.textContent = SCAN_STATE.ip || (job && job.ip) || "";

  const key = JSON.stringify([
    SCAN_STATE.jobId, job && job.state, job && job.finished_at, job && job.error,
    SCAN_STATE.timedOut, SCAN_STATE.findingsState, SCAN_STATE.findings.length,
    SCAN_STATE.findingsReason, SCAN_STATE.missingPolls >= 6,
  ]);
  if (key === SCAN_STATE.renderedKey) return;
  SCAN_STATE.renderedKey = key;

  els.body.replaceChildren();

  const dl = el("dl", { class: "scan-facts" });
  scanFact(dl, "target", (job && job.ip) || SCAN_STATE.ip || "unknown address");
  scanFact(dl, "state", word);
  if (job) {
    scanFact(dl, "queued", job.requested_at ? fmtTime(job.requested_at) : "not recorded");
    scanFact(dl, "started", job.started_at ? fmtTime(job.started_at) : "not yet claimed");
    scanFact(dl, "finished", job.finished_at ? fmtTime(job.finished_at) : "not yet");
    const elapsed = scanElapsed(job);
    const dd = scanFact(dl, elapsed.label, elapsed.text);
    dd.id = "scan-elapsed";
    scanFact(dl, "scanner", job.lease_owner || "no scanner has claimed it");
    scanFact(dl, "requested by", job.requested_by || "unknown");
    scanFact(dl, "scanner evidence",
      job.error ? `error: ${job.error}`
        : job.result ? job.result
          : "nothing recorded yet — the scanner writes its result when it finishes");
  }
  els.body.appendChild(dl);

  // THE HONESTY LINE. The queue has no phase and no percentage; saying that is part of the
  // reading, not a disclaimer bolted on.
  els.body.appendChild(el("p", {
    class: "muted scan-honest",
    text: "The queue records state, not percentage: queued, running (claimed), done or failed. "
      + "Elapsed time and recorded findings are the only progress it can prove, so there is "
      + "no progress bar and no percentage here.",
  }));

  if (SCAN_STATE.timedOut) {
    els.body.appendChild(el("p", { class: "warn", text: SCAN_STATE.timedOut }));
  }
  if (missing) {
    els.body.appendChild(el("p", {
      class: "warn",
      text: "The queue no longer lists this job id. It may have been pruned; the recent list "
        + "below the scanner card is the surviving record.",
    }));
  }
  if (job && job.state === "error") {
    els.body.appendChild(el("p", {
      class: "bad",
      text: `The scan failed: ${job.error || "the scanner recorded no reason"}. `
        + "Retry queues the same host again; nothing about the failure is hidden.",
    }));
  }

  els.body.appendChild(el("h3", { class: "scan-findings-title", text: "Findings recorded by this scan" }));
  // THE COUNT IS PART OF THE TERMINAL ANSWER, not only the list. "Done" without a number
  // leaves the operator to count rows; zero is a measurement and is stated as one.
  if (SCAN_STATE.findingsState === "ok") {
    const n = SCAN_STATE.findings.length;
    els.body.appendChild(el("p", {
      class: "scan-findings-count",
      text: `${n} finding${n === 1 ? "" : "s"} recorded on or after this job was queued.`,
    }));
  }
  if (SCAN_STATE.findingsState === "failed") {
    els.body.appendChild(el("p", {
      class: "warn",
      text: `Findings could not be read: ${SCAN_STATE.findingsReason}. This is a failed read, `
        + "not a clean host.",
    }));
  } else if (SCAN_STATE.findingsState === "waiting") {
    els.body.appendChild(el("p", { class: "muted", text: "Waiting for the queue to name the address." }));
  } else if (!SCAN_STATE.findings.length) {
    els.body.appendChild(el("p", {
      class: "muted",
      text: job && job.state === "done"
        ? "No finding was recorded on or after this job was queued. A clear scan is not proof "
          + "the host is patched; it is the absence of a recorded finding."
        : "No finding recorded since this job was queued yet. Findings appear here as the "
          + "scanner records them.",
    }));
  } else {
    const list = el("ul", { class: "scan-findings-list" });
    for (const f of SCAN_STATE.findings.slice(0, 12)) {
      list.appendChild(el("li", { class: "scan-finding" }, [
        el("span", { class: `bubble state sev-${String(f.severity || "low").toLowerCase()}`,
          text: String(f.severity || "unknown") }),
        el("span", { class: "scan-finding-name", text: f.name || f.template_id || "unnamed finding" }),
        el("span", { class: "muted mono", text: f.last_seen ? fmtTime(f.last_seen) : "" }),
      ]));
    }
    els.body.appendChild(list);
    if (SCAN_STATE.findings.length > 12) {
      els.body.appendChild(el("p", {
        class: "muted",
        text: `Showing 12 of ${SCAN_STATE.findings.length}. Open the findings drill for the rest.`,
      }));
    }
  }

  if (els.retry) {
    const retryable = Boolean(job) && (job.state === "error" || Boolean(SCAN_STATE.timedOut) || missing);
    els.retry.classList.toggle("hidden", !retryable);
  }
  if (els.findings) {
    const hasIp = Boolean((job && job.ip) || SCAN_STATE.ip);
    els.findings.classList.toggle("hidden", !hasIp);
  }
}

/** Retry is the same POST as the first click: one queue, one route. An active job is not
 *  duplicated -- the server answers `already` with its id, and the sheet opens that one. */
async function scanRetry() {
  const els = scanSheetEls();
  const ip = String((SCAN_STATE.job && SCAN_STATE.job.ip) || SCAN_STATE.ip || "").trim();
  if (!ip) return;
  if (els.retry) { els.retry.disabled = true; els.retry.textContent = "Queueing…"; }
  try {
    const data = await postJSON("/api/scan-jobs", { ip });
    if (els.retry) { els.retry.disabled = false; els.retry.textContent = "Retry this scan"; }
    if (data && data.job_id) openScanSheet(data.job_id, { ip });
  } catch (err) {
    if (els.retry) { els.retry.disabled = false; els.retry.textContent = "Retry this scan"; }
    if (els.stateLine) {
      els.stateLine.textContent = `The retry was refused: ${err && err.message ? err.message : err}`;
      els.stateLine.className = "scan-state-line bad";
    }
  }
}

function scanOpenFindings() {
  const ip = String((SCAN_STATE.job && SCAN_STATE.job.ip) || SCAN_STATE.ip || "").trim();
  if (!ip || typeof openFindings !== "function") return;
  closeScanSheet();
  openFindings(ip);
}

/* ── the queue list: where a running job is found again after the sheet is closed ─────────── */

let SCAN_QUEUE_TIMER = null;

function scanQueueRow(job) {
  const word = SCAN_WORDS[job.state] || job.state || "unknown";
  const button = el("button", {
    class: "scan-queue-row" + (job.state === "error" ? " bad" : ""),
    attrs: { type: "button", "aria-label": `open scan ${job.job_id} for ${job.ip || "unknown address"}` },
  }, [
    el("span", { class: `bubble state scan-state-${job.state || "unknown"}`, text: word }),
    el("span", { class: "mono scan-queue-ip", text: job.ip || "—" }),
    el("span", { class: "muted scan-queue-when", text: job.requested_at ? `queued ${fmtTime(job.requested_at)}` : "" }),
    el("span", { class: "muted scan-queue-evidence", text: job.error ? `error: ${job.error}` : (job.result || "") }),
  ]);
  button.addEventListener("click", () => openScanSheet(job.job_id, { ip: job.ip }));
  return button;
}

async function loadScanQueue() {
  const box = document.getElementById("scan-queue");
  const note = document.getElementById("scan-queue-note");
  if (!box) return;
  let d;
  try {
    d = await scanGet("/api/scan-jobs");
  } catch (err) {
    box.replaceChildren(emptyState({
      state: "failed",
      message: `The scan queue could not be read: ${err && err.message ? err.message : err}. `
        + "This is a failed read, not an empty queue.",
    }));
    if (note) note.textContent = "";
    return;
  }
  if (d.available === false) {
    box.replaceChildren(emptyState({
      state: "failed",
      message: `${d.reason || "The scan-job table is not readable"}. `
        + "This is a failed read, not an empty queue.",
    }));
    if (note) note.textContent = "";
    return;
  }
  const jobs = d.jobs || [];
  if (!jobs.length) {
    box.replaceChildren(emptyState({
      state: "none",
      message: "No manual scan has been queued. \"Scan now\" on a host files one.",
    }));
    if (note) note.textContent = `${jobs.length} recent job${jobs.length === 1 ? "" : "s"}`;
    return;
  }
  box.replaceChildren(...jobs.slice(0, 6).map(scanQueueRow));
  if (note) {
    const active = jobs.filter((j) => j.state === "queued" || j.state === "claimed").length;
    note.textContent = `${jobs.length} recent job${jobs.length === 1 ? "" : "s"}`
      + (active ? ` · ${active} still active` : " · none active");
  }
  // A RUNNING JOB STAYS DISCOVERABLE. While any job is active the list refreshes on a bounded
  // interval; when every job is terminal it stops, so a quiet console makes no requests.
  if (SCAN_QUEUE_TIMER) { clearTimeout(SCAN_QUEUE_TIMER); SCAN_QUEUE_TIMER = null; }
  if (jobs.some((j) => j.state === "queued" || j.state === "claimed")) {
    SCAN_QUEUE_TIMER = setTimeout(() => { loadScanQueue().catch(() => {}); }, 5000);
  }
}

// ONE WIRING PASS, after the markup is parsed. `onClose` is the sheet standard's own hook, so
// Close, Escape and the scrim all stop the poll and drop the URL key through one path.
document.addEventListener("DOMContentLoaded", () => {
  const els = scanSheetEls();
  if (els.card) {
    wireSheet(els.card, {
      onClose: () => {
        scanStopTimers();
        SCAN_STATE.jobId = "";
        SCAN_STATE.job = null;
        SCAN_STATE.ip = "";
        SCAN_STATE.renderedKey = "";
        if (els.card) delete els.card.dataset.jobId;
        scanURLSync();
      },
    });
  }
  if (els.cancel) els.cancel.addEventListener("click", () => closeScanSheet());
  if (els.retry) els.retry.addEventListener("click", () => { scanRetry(); });
  if (els.check) els.check.addEventListener("click", () => { scanPollOnce(); });
  if (els.findings) els.findings.addEventListener("click", () => scanOpenFindings());
});
