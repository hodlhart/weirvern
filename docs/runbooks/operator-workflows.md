# Operator workflows

Five tasks, each with one click path from a cold load, its evidence, and the state that means
"stop — the screen cannot answer this".

## 1. What happened?

**Path:** open the console → **Anomalies** → read the window and severity tiles → click a row.

**Answers:** host, window, score, severity, models, why-sentence, rule, location.

**Stop state:** the queue says `no anomalies recorded yet` or `no rows` with a reason. That is an
empty read, not a quiet network. Follow the freshness card and the SLO report before believing
silence.

## 2. Is it real?

**Path:** Anomalies row → **Evidence** → the chain (observed → sources → detected → explained →
ruled → done) → raw flows/Zeek/TLS/DNS tables.

**Answers:** the records the model scored, the models and families, the source freshness, the
threshold and the review state.

**Stop state:** a source says `not measured`, `stale`, `failed` or `unknown`; the chain says the
flow read was unavailable. Do not treat the alert as confirmed or as false until the source is
read again.

## 3. What do I do?

**Path:** Evidence → **Block** / **Acknowledge** / **Ignore**; or Anomalies row → the disclosure
verbs. Blocking opens the Sluice rule sheet with the address prefilled and requires the
destructive confirmation and a reason.

**Answers:** the action, its target, its blast radius, the reason and the actor. The receipt says
whether the rule was filed; the write trail keeps the record.

**Stop state:** the verb is absent or disabled with a reason (no live gate, no target, no evidence).
That is a deliberate refusal, not a missing button. File a card if the reason is wrong.

## 4. What changed?

**Path:** **Assets** → an asset row → Findings/scan history; or **Weirlings** → a sensor row →
its plan and last-seen state.

**Answers:** new hosts, new exposures, scanner findings, sensor mode and last contact.

**Stop state:** `not scanned` is not `clean`. A host with no scan says not scanned; a sensor that
never reported says never seen, with its reason.

## 5. Did it work?

**Path:** **Health** → the component probes; **Models** → calibration/staleness; **Sluice** → the
gate state and counters; **Logs** → the write trail.

**Answers:** every probe's state and detail, the gate's armed/degraded/off state, the last write,
and whether a model is stale.

**Stop state:** an absent probe is `unknown`, not green. A disabled feature says off; a missing
metric says not measured.

## Reload and sharing

Every drill writes its view and filters to the URL hash. Reloading reproduces the same view; a
link without evidence says so rather than opening a blank page.
