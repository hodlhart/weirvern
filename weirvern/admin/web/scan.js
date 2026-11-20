/* THE SCAN SHEET: watching one manual scan from queued to its recorded result.
 *
 * WHY THIS EXISTS. Pressing "Scan now" filed a request and then said nothing: the operator had
 * no way to tell a queued job from one a weirling had claimed, no elapsed time, and no place
 * where the outcome appeared. The queue already carries the truth -- a row keyed by job_id,
 * written again on every state change -- so this file reads that row and says only what it says.
 *
 * HONEST PROGRESS. `weirvern.scan_jobs` has no phase and no percentage: states are queued,
 * claimed, done and error, and the console derives `abandoned`/`stale` from the lease and the
 * claim. So the sheet never draws a bar or a percentage. It shows the state, the timestamps,
 * elapsed time derived from those timestamps, the measured services the weirling recorded, and
 * the server's own sentence when nothing will claim the job.
 *
 * ONE DETAIL SURFACE (docs/design/sheets.md): this is a sheet, built by sheets.js -- one scrim,
 * one Escape, focus returns to the control that opened it.
 */

const SCAN_STATE = {
  jobId: "",
  ip: "",
  job: null,
  missingPolls: 0,
  timedOut: "",
  pollTimer: null,
  tickTimer: null,
  inFlight: false,
  renderedKey: "",
  renderNote: "",
  receipt: "",
  cancelling: false,
};

/* THE FLEET'S CAPABILITY, NOT A SETTING. Who can scan is measured by each weirling's own agent
 * and reported to the hub; the button and the refusal read the same answer. `loaded` starts
 * false so a control built before the read is disabled with "checking", never enabled on hope. */
const SCAN_READY = {
  loaded: false,
  available: true,
  enabled: false,
  sentence: "",
  reason_unavailable: "",
  docs_url: "",
  ip: "",
  error: "",
};

const SCAN_POLL_MS = 2500;                 // bounded: one read per 2.5s while the sheet is open
const SCAN_QUEUED_TIMEOUT_MS = 30 * 60 * 1000;   // nobody claimed it in half an hour
const SCAN_RUNNING_TIMEOUT_MS = 20 * 60 * 1000;  // the scanner lease is 15 minutes

const SCAN_WORDS = {
  queued: "Queued",
  claimed: "Running",
  done: "Done",
  error: "Failed",
  cancelled: "Cancelled",
  abandoned: "Abandoned",
  stale: "Stale",
};

/** Read the fleet's scan capability for one target (or the fleet as a whole).
 *
 *  A FAILED READ IS NOT "NOBODY CAN SCAN": it leaves `enabled` true and carries the error, so a
 *  transient database failure cannot disable a control that would have worked. The POST still
 *  checks the same facts server-side and refuses with a sentence if it disagrees. */
async function loadScanReadiness(ip) {
  const target = String(ip || "").trim();
  if (SCAN_READY.loaded && SCAN_READY.ip === target) return SCAN_READY;
  const qs = target ? `?ip=${encodeURIComponent(target)}` : "";
  try {
    const d = await getJSON(`/api/scan-readiness${qs}`);
    Object.assign(SCAN_READY, {
      loaded: true, ip: target,
      available: d.available !== false,
      enabled: d.available === false ? true : d.enabled === true,
      sentence: String(d.sentence || ""),
      reason_unavailable: String(d.reason_unavailable || (d.available === false ? d.reason : "") || ""),
      docs_url: String(d.docs_url || ""),
      error: d.available === false ? String(d.reason || "readiness could not be read") : "",
    });
  } catch (err) {
    Object.assign(SCAN_READY, {
      loaded: true, ip: target, available: false, enabled: true,
      sentence: "", reason_unavailable: "", docs_url: "",
      error: `scanner readiness could not be read: ${err && err.message ? err.message : err}`,
    });
  }
  return SCAN_READY;
}

/** Make ONE control honest about whether a scan can run, with the reason in text BESIDE it.
 *
 *  `note` is a real element, not a tooltip: a disabled button with only a `title` is a mystery
 *  to a keyboard or touch user. When readiness has not landed the control stays disabled and
 *  says it is checking, so there is never a moment where it invites a click it cannot honour. */
function scanApplyButton(btn, note, ip) {
  if (!btn) return;
  const st = SCAN_READY;
  const pending = !st.loaded || (st.ip !== String(ip || "").trim() && Boolean(ip));
  btn.disabled = pending ? true : !st.enabled;
  if (note) {
    let text = "";
    if (pending) text = "checking whether a weirling can scan this host…";
    else if (!st.enabled) text = st.reason_unavailable || "no weirling can scan";
    else if (st.error) text = st.error;
    note.textContent = text;
    note.classList.toggle("hidden", !text);
    if (text && note.id) btn.setAttribute("aria-describedby", note.id);
  }
  if (!btn.disabled) btn.removeAttribute("aria-describedby");
}

/** The ready-to-use wiring: apply the cached answer, and re-apply when a read lands. */
function scanGate(btn, note, ip) {
  scanApplyButton(btn, note, ip);
  const target = String(ip || "").trim();
  if (!SCAN_READY.loaded || (target && SCAN_READY.ip !== target)) {
    loadScanReadiness(target).then(() => scanApplyButton(btn, note, ip)).catch(() => {});
  }
}


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

/** The state word the operator reads. The SERVER'S derived state wins over the raw column:
 *  a queued row past its lease is Abandoned, not "Queued" forever. `timedOut` is a client-side
 *  fact about the queue, and it never replaces a terminal state the server recorded. */
function scanWord(job) {
  if (!job) return "Reading the queue…";
  if (job.derived_state === "abandoned") return "Abandoned";
  if (job.derived_state === "stale") return "Stale";
  if (job.state === "error") return "Failed";
  if (job.state === "done") return "Done";
  if (job.state === "cancelled") return "Cancelled";
  if (SCAN_STATE.timedOut) return "Timed out";
  return SCAN_WORDS[job.state] || `State ${job.state || "unknown"}`;
}

function scanElapsed(job) {
  if (!job) return { label: "elapsed", text: "—" };
  const requested = scanMs(job.requested_at);
  const started = scanMs(job.started_at);
  const finished = scanMs(job.finished_at);
  if (job.state === "queued" || job.state === "cancelled") {
    const to = Number.isFinite(finished) ? finished : Date.now();
    return { label: job.state === "cancelled" ? "cancelled after" : "waiting",
             text: scanClock(to - requested) };
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

/** DELETE with a JSON body. A 202 is a SUCCESS here (the running job was asked to stop), so
 *  only a non-2xx throws; the caller reads `removed` to tell the two successes apart. */
async function scanDelete(url, body) {
  const res = await window.fetch(url, {
    method: "DELETE",
    headers: Object.assign({}, requestHeaders(), { "Content-Type": "application/json" }),
    body: JSON.stringify(body || {}),
    cache: "no-store",
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error((data && data.error) || `the cancel was refused (${res.status})`);
  }
  return data || {};
}

function scanSheetEls() {
  return {
    card: document.getElementById("scan-sheet"),
    subject: document.getElementById("scan-subject"),
    stateLine: document.getElementById("scan-state-line"),
    body: document.getElementById("scan-body"),
    retry: document.getElementById("scan-retry"),
    check: document.getElementById("scan-check"),
    cancelJob: document.getElementById("scan-cancel-job"),
    cancelForm: document.getElementById("scan-cancel-form"),
    cancelReason: document.getElementById("scan-cancel-reason"),
    cancelConfirm: document.getElementById("scan-cancel-confirm"),
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
  SCAN_STATE.missingPolls = 0;
  SCAN_STATE.timedOut = "";
  SCAN_STATE.renderedKey = "";
  SCAN_STATE.cancelling = false;
  SCAN_STATE.receipt = "";
  SCAN_STATE.renderNote = "";
  els.card.dataset.jobId = id;
  if (els.subject) els.subject.textContent = SCAN_STATE.ip || "";
  if (els.stateLine) els.stateLine.textContent = "Reading the queue…";
  scanRenderBody();
  openSheet(els.card, { initialFocus: "scan-close" });
  scanURLSync();
  loadScanReadiness(SCAN_STATE.ip).catch(() => {});
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
  return Boolean(job) && (job.state === "done" || job.state === "error"
                          || job.state === "cancelled");
}

/** Nothing will move this row again: terminal, or the server derived abandoned/stale. */
function scanSettled(job) {
  return scanTerminal(job) || Boolean(job && (job.derived_state === "abandoned"
                                              || job.derived_state === "stale"));
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
      SCAN_STATE.renderNote = q.reason || "the scan-job table is not readable";
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
    scanRenderBody();
    if (previous && previous.state !== job.state) scanURLSync();
    if (scanSettled(job) || SCAN_STATE.timedOut) {
      scanStopTimers();
      if (SCAN_STATE.tickTimer) { clearInterval(SCAN_STATE.tickTimer); SCAN_STATE.tickTimer = null; }
      return;
    }
    scanScheduleNext();
  } catch (err) {
    SCAN_STATE.renderNote = err && err.message ? err.message : String(err);
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
    const bad = Boolean((job && job.state === "error") || (job && job.derived_state === "abandoned"));
    els.stateLine.className = "scan-state-line" + (bad ? " bad" : "");
  }
  if (els.subject) els.subject.textContent = SCAN_STATE.ip || (job && job.ip) || "";

  const key = JSON.stringify([
    SCAN_STATE.jobId, job && job.state, job && job.derived_state,
    job && job.state_reason, job && job.finished_at, job && job.error,
    SCAN_STATE.timedOut, SCAN_STATE.missingPolls >= 6, SCAN_STATE.cancelling,
    SCAN_READY.loaded, SCAN_READY.enabled, SCAN_READY.reason_unavailable,
    SCAN_STATE.renderNote, SCAN_STATE.receipt,
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
    scanFact(dl, "claimer", job.lease_owner || "no weirling has claimed it");
    scanFact(dl, "requested by", job.requested_by || "unknown");
    scanFact(dl, "scanner evidence",
      job.error ? `error: ${job.error}`
        : job.result ? job.result
          : "nothing recorded yet — the weirling writes its result when it finishes");
  }
  els.body.appendChild(dl);

  // THE HONESTY LINE. The queue has no phase and no percentage; saying that is part of the
  // reading, not a disclaimer bolted on.
  els.body.appendChild(el("p", {
    class: "muted scan-honest",
    text: "The queue records state, not percentage: queued, running (claimed), done or failed. "
      + "Elapsed time is the only progress it can prove, so there is no progress bar and no "
      + "percentage here. Nmap measures services and identity facts; it does not prove a host "
      + "is patched.",
  }));

  if (job && job.derived_state === "abandoned") {
    els.body.appendChild(el("p", {
      class: "warn",
      text: `Abandoned: ${job.state_reason || "no weirling has claimed it"}. `
        + "Nothing will run this job; Cancel it to clear it from the queue.",
    }));
  } else if (job && job.derived_state === "stale") {
    els.body.appendChild(el("p", { class: "warn", text: `Stale: ${job.state_reason}` }));
  }
  if (SCAN_STATE.timedOut) {
    els.body.appendChild(el("p", { class: "warn", text: SCAN_STATE.timedOut }));
  }
  if (SCAN_STATE.renderNote) {
    els.body.appendChild(el("p", {
      class: "warn", text: `The queue could not be read: ${SCAN_STATE.renderNote}.`,
    }));
  }
  if (SCAN_STATE.receipt) {
    els.body.appendChild(el("p", { class: "scan-receipt", text: SCAN_STATE.receipt }));
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
      text: `The scan failed: ${job.error || "the weirling recorded no reason"}. `
        + "Retry queues the same host again; nothing about the failure is hidden.",
    }));
  }
  if (!SCAN_READY.loaded) {
    els.body.appendChild(el("p", { class: "muted", text: "Checking whether a weirling can scan this host…" }));
  } else if (!SCAN_READY.enabled) {
    els.body.appendChild(el("p", {
      class: "warn",
      text: `No weirling can scan this host: ${SCAN_READY.reason_unavailable || "no capable weirling"}.`,
    }));
  }

  // THE CANCEL OFFER is only for a row nothing has claimed. A claimed job is refused
  // server-side with its own sentence; offering the button would imply it can be stopped.
  if (els.cancelJob) {
    const cancellable = Boolean(job) && String(job.state) === "queued";
    els.cancelJob.classList.toggle("hidden", !cancellable);
    els.cancelJob.disabled = Boolean(SCAN_STATE.cancelling);
    els.cancelJob.textContent = SCAN_STATE.cancelling ? "Cancelling…" : "Cancel this job";
    els.cancelJob.onclick = () => scanCancelJob();
  }

  if (els.retry) {
    const retryable = Boolean(job) && (job.state === "error" || Boolean(SCAN_STATE.timedOut) || missing);
    els.retry.classList.toggle("hidden", !retryable);
    els.retry.disabled = !SCAN_READY.loaded || !SCAN_READY.enabled;
    els.retry.title = els.retry.disabled
      ? (SCAN_READY.reason_unavailable || "checking whether a weirling can scan")
      : "";
  }
}

/** Reveal the reason field. The server REQUIRES a reason, so the button asks for one before
 *  it can send anything -- the audit trail is the only surviving record of a deleted row. */
function scanCancelJob() {
  const els = scanSheetEls();
  if (!els.cancelForm) return;
  els.cancelForm.classList.remove("hidden");
  if (els.cancelReason) { els.cancelReason.focus(); els.cancelReason.select(); }
}

/** DELETE the queued job, with its reason, and show the receipt the server wrote. */
async function scanConfirmCancel() {
  const els = scanSheetEls();
  const id = String(SCAN_STATE.jobId || "").trim();
  const reason = String((els.cancelReason && els.cancelReason.value) || "").trim();
  if (!id || SCAN_STATE.cancelling) return;
  if (!reason) {
    SCAN_STATE.receipt = "A reason is required to cancel a scan; it is kept in the audit trail.";
    scanRenderBody();
    return;
  }
  SCAN_STATE.cancelling = true;
  SCAN_STATE.receipt = "";
  scanRenderBody();
  try {
    const data = await scanDelete(`/api/scan-jobs/${encodeURIComponent(id)}`, { reason });
    SCAN_STATE.cancelling = false;
    if (data.removed) {
      // THE ROW IS GONE; THE RECEIPT IS THE SERVER'S OWN SENTENCE, not a local claim.
      SCAN_STATE.receipt = String(data.note
        || `removed job ${id}; the cancellation is recorded in the audit trail`);
      SCAN_STATE.job = Object.assign({}, SCAN_STATE.job || {}, {
        state: "cancelled", derived_state: "cancelled", cancelled: true,
      });
      SCAN_STATE.jobId = "";
      SCAN_STATE.missingPolls = 0;
      scanStopTimers();
      scanURLSync();
      if (els.cancelForm) els.cancelForm.classList.add("hidden");
      scanRenderBody();
    } else {
      // 202: the weirling was asked to stop and has not confirmed. The row STAYS.
      SCAN_STATE.receipt = String(data.error
        || "cancellation requested; the weirling has not confirmed");
      scanRenderBody();
      scanScheduleNext();
    }
  } catch (err) {
    SCAN_STATE.cancelling = false;
    SCAN_STATE.renderNote = err && err.message ? err.message : String(err);
    scanRenderBody();
  }
}

/** Retry is the same POST as the first click: one queue, one route. An active job is not
 *  duplicated -- the server answers `already` with its id, and the sheet opens that one. */
async function scanRetry() {
  const els = scanSheetEls();
  const ip = String((SCAN_STATE.job && SCAN_STATE.job.ip) || SCAN_STATE.ip || "").trim();
  if (!ip) return;
  if (!SCAN_READY.loaded || !SCAN_READY.enabled) {
    if (els.stateLine) {
      els.stateLine.textContent = `The retry is refused: ${SCAN_READY.reason_unavailable
        || "no weirling can scan this host"}`;
      els.stateLine.className = "scan-state-line bad";
    }
    return;
  }
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

/* ── the queue list: where a running job is found again after the sheet is closed ─────────── */

let SCAN_QUEUE_TIMER = null;

function scanQueueRow(job) {
  const state = job.derived_state || job.state || "unknown";
  const word = SCAN_WORDS[state] || SCAN_WORDS[job.state] || job.state || "unknown";
  const evidence = job.state_reason
    || (job.error ? `error: ${job.error}` : (job.result || ""));
  const button = el("button", {
    class: "scan-queue-row" + (state === "error" || state === "abandoned" ? " bad" : ""),
    attrs: { type: "button", "aria-label": `open scan ${job.job_id} for ${job.ip || "unknown address"}` },
  }, [
    el("span", { class: `bubble state scan-state-${state}`, text: word }),
    el("span", { class: "mono scan-queue-ip", text: job.ip || "—" }),
    el("span", { class: "muted scan-queue-when", text: job.requested_at ? `queued ${fmtTime(job.requested_at)}` : "" }),
    el("span", { class: "muted scan-queue-evidence", text: evidence }),
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
    const active = jobs.filter((j) => (j.derived_state || j.state) === "queued"
      || (j.derived_state || j.state) === "claimed").length;
    const abandoned = jobs.filter((j) => j.derived_state === "abandoned").length;
    note.textContent = `${jobs.length} recent job${jobs.length === 1 ? "" : "s"}`
      + (active ? ` · ${active} still active` : " · none active")
      + (abandoned ? ` · ${abandoned} abandoned` : "");
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
  if (els.cancelConfirm) els.cancelConfirm.addEventListener("click", () => { scanConfirmCancel(); });
  if (els.cancelReason) els.cancelReason.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") { ev.preventDefault(); scanConfirmCancel(); }
  });
  if (els.retry) els.retry.addEventListener("click", () => { scanRetry(); });
  if (els.check) els.check.addEventListener("click", () => { scanPollOnce(); });
});
