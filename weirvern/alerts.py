"""Alerting — Pushover transport with rate limiting and full audit.

Design goals (explicitly requested for the production homelab deployment):
  * alerts push to the phone via Pushover
  * per-source cooldown + hourly global cap => no alert storms
  * every decision (sent / suppressed / log-only) written to alert_events
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime

import requests
from clickhouse_connect.driver.client import Client

from weirvern import attack, detector_registry
from weirvern.config import Settings

logger = logging.getLogger(__name__)

PUSHOVER_ENDPOINT = "https://api.pushover.net/1/messages.json"
DEFAULT_SOUND = "siren"

# The per-source cooldown map only has to remember sources within the longest cooldown the
# settings can carry -- hours, not days -- so a day is a generous horizon for eviction. See
# AlertState.prune_hourly (issue #29).
LAST_SENT_MAX_AGE_S = 24 * 3600


@dataclass
class AlertState:
    """In-memory rate-limit state for the worker process."""

    last_sent: dict[str, float] = field(default_factory=dict)
    hourly_events: list[float] = field(default_factory=list)

    def cooldown_remaining(self, src: str, cooldown_s: int, now: float | None = None) -> float:
        now = now or time.time()
        last = self.last_sent.get(src, 0.0)
        return max(0.0, last + cooldown_s - now)

    def prune_hourly(self, now: float | None = None) -> None:
        now = now or time.time()
        cutoff = now - 3600
        self.hourly_events = [t for t in self.hourly_events if t > cutoff]
        # BOUNDED (issue #29): last_sent had no eviction and grew for the process lifetime
        # (a review measured 10k entries). An entry older than LAST_SENT_MAX_AGE_S cannot
        # change any cooldown decision -- every configured cooldown is well under an hour --
        # so it is dropped here, on the same cadence as the hourly list this already rides
        # (prune_hourly runs on every send decision). The map stays bounded by the addresses
        # recently alerted on, not by every address ever seen.
        if self.last_sent:
            stale = now - LAST_SENT_MAX_AGE_S
            self.last_sent = {s: t for s, t in self.last_sent.items() if t > stale}

    def can_send(self, src: str, settings: Settings, now: float | None = None) -> tuple[bool, str]:
        """Return (allowed, reason-if-denied)."""
        now = now or time.time()
        self.prune_hourly(now)
        if self.cooldown_remaining(src, settings.pushover_cooldown_s, now) > 0:
            return False, "cooldown"
        if len(self.hourly_events) >= settings.pushover_max_per_hour:
            return False, "cap"
        return True, ""


def format_message(verdict: dict) -> str:
    """Single-message-per-verdict; compact but complete for Pushover (1024 limit).

    Includes the WHY. An alert that says only "score 0.91" tells an operator
    something is wrong but not what, which is the difference between an alert they
    can act on and one they learn to ignore.
    """
    model_scores = (
        f"IF:{verdict['isolation_forest_score']:.2f} "
        f"GB:{verdict['gradient_boosting_score']:.2f} "
        f"DB:{verdict['dbscan_score']:.2f} "
        f"BL:{verdict['baseline_score']:.2f}"
    )
    lines = [
        f"⚠️ {verdict['severity'].upper()} anomaly — {verdict['src_addr']}",
        f"score {verdict['anomaly_score']:.2f} (agreement {verdict['model_agreement']:.0%})",
        f"models: {model_scores}",
        f"by: {verdict['detected_by_models']}",
        f"window {verdict['window_start']} ({verdict.get('duration_minutes', 5)}min)",
    ]
    # The explanation block. `baseline_comparison` is a prebuilt human sentence;
    # fall back to the structured fields if it is absent, and omit the block
    # entirely rather than print an empty "why:" when there is nothing to say.
    why = verdict.get("baseline_comparison") or ""
    if not why and verdict.get("primary_deviation_feature"):
        why = (f"{verdict['primary_deviation_feature']} at "
               f"z={verdict.get('primary_deviation_zscore', 0.0)}")
    if why:
        lines.append(f"why: {why}")

    # ── ATT&CK technique, when one is supported ────────────────────────────────
    #
    # Placed AFTER the measurements, deliberately. Ordering the technique above them would
    # invite an analyst to read the MITRE ID as the finding and stop -- "T1046" is a
    # classification of the measurements below it, not evidence in its own right.
    #
    # Two cases, and only one of them gets a line:
    #
    #   * matches present   -> the id, name and confidence, preceded by "consistent with". An
    #                          alert is read on a phone, and an unhedged technique name reads
    #                          as a conclusion.
    #   * no matches        -> NOTHING is appended. An explicit "no technique matched" line
    #                          would be noise on every alert that lacks one, and worse, it
    #                          would appear to clear the window. Absence of a mapping is
    #                          absence of a mapping; the alert already says what was measured.
    # PREFER THE MATCH OBJECTS. `attack_techniques` is the JSON form (a list of dicts) written to
    # the database; summarise() needs Match objects. Reading the dicts here raised AttributeError
    # on `.confidence` and took the whole alert with it -- a crash in the formatter lost the alert
    # entirely rather than degrading one line of it. The dict form is converted rather than
    # ignored so an alert stays renderable from a stored row too.
    matches = verdict.get("_attack_matches")
    if matches is None:
        matches = [attack.Match.from_dict(t) for t in (verdict.get("attack_techniques") or [])]
    if matches:
        lines.append(f"ATT&CK: {attack.summarise(matches)}")
    return "\n".join(lines)


def push_alert(verdict: dict, settings: Settings, state: AlertState,
               client: Client | None = None) -> tuple[bool, str]:
    """Send (or suppress) one alert. Returns (delivered, reason)."""
    src = verdict["src_addr"]
    now = time.time()

    # THE QUIET-BY-DEFAULT GATE (BF-12), before every other decision: a detector that has no
    # owner and runbook does not page, and neither does one nobody registered. The finding
    # still landed in the console and this audit row still records the decision -- what is
    # withheld is the interruption, which is the scarce resource.
    allowed_page, quiet_reason = detector_registry.may_page(verdict.get("detected_by_models") or "")
    if not allowed_page:
        _audit(client, verdict, sent=False, reason="quiet", message="")
        return False, "quiet: " + quiet_reason

    allowed, reason = state.can_send(src, settings, now)
    if not allowed:
        _audit(client, verdict, sent=False, reason=reason, message="")
        return False, reason

    message = format_message(verdict)
    delivered = False
    reason = "log-only"
    if settings.pushover_enabled:
        try:
            resp = requests.post(
                PUSHOVER_ENDPOINT,
                data={
                    "token": settings.pushover_api_token,
                    "user": settings.pushover_user_key,
                    "message": message,
                    "title": "Weirvern",
                    "priority": 1,
                    "sound": DEFAULT_SOUND,
                },
                timeout=10,
            )
            if resp.status_code == 200:
                delivered = True
                reason = "sent"
                state.last_sent[src] = now
                state.hourly_events.append(now)
                logger.info("📱 Pushover sent to %s (score %.2f)", src, verdict["anomaly_score"])
            else:
                logger.warning("Pushover error %s: %s", resp.status_code, resp.text[:200])
                reason = "pushover-error"
        except requests.RequestException as exc:
            logger.warning("Pushover request failed: %s", exc)
            reason = "pushover-error"

    _audit(client, verdict, sent=delivered, reason=reason, message=message if delivered else "")
    return delivered, reason


def _audit(client: Client | None, verdict: dict, sent: bool, reason: str, message: str) -> None:
    """Record every alert decision. Never raises (alerting must not crash the loop)."""
    if client is None:
        return
    try:
        client.insert(
            "weirvern.alert_events",
            [[
                datetime.now(), verdict["src_addr"], verdict.get("window_start"),
                verdict.get("severity", "low"), verdict.get("anomaly_score", 0.0),
                message[:1024], int(sent), reason,
            ]],
            column_names=["sent_at", "src_addr", "window_start", "severity", "score", "message", "sent", "reason"],
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("alert_events audit insert failed: %s", exc)
