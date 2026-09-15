"""Weirvern configuration — environment-driven, validated at import time.

Lesson v14–v19: magic numbers were scattered through the detection script and
thresholds changed version over version. All knobs live here, overridable via
environment variables, documented in `.env.example`.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    raw = _clean_env(os.environ.get(name))
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None


def _env_float(name: str, default: float) -> float:
    raw = _clean_env(os.environ.get(name))
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        raise ValueError(f"{name} must be a number, got {raw!r}") from None


def _env_str(name: str, default: str = "") -> str:
    raw = _clean_env(os.environ.get(name))
    return default if raw is None else raw


def _clean_env(raw: str | None) -> str | None:
    """Strip an inline trailing comment and surrounding whitespace.

    The `.env.example` template ships values with trailing comments (e.g.
    `DETECT_INTERVAL_S=300          # sweep cadence`), so a parser that did not
    strip them would fail on its own shipped template — verified failure:
    DETECT_INTERVAL_S parsed as "300          # sweep cadence (seconds)" and
    raised on int().

    A `#` inside quotes is preserved (it is part of the value).
    """
    if raw is None:
        return None
    raw = raw.strip()
    if not raw:
        return raw
    if raw[0] in {'"', "'"}:
        quote = raw[0]
        end = raw.find(quote, 1)
        return (raw[1:end] if end != -1 else raw[1:]).strip()
    marker = raw.find(" #")
    if marker == -1:
        marker = raw.find("\t#")
    if marker != -1:
        raw = raw[:marker]
    return raw.strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _clean_env(os.environ.get(name))
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # ClickHouse
    clickhouse_host: str = field(default_factory=lambda: os.environ.get("CLICKHOUSE_HOST", "clickhouse"))
    clickhouse_port: int = field(default_factory=lambda: _env_int("CLICKHOUSE_PORT", 8123))
    clickhouse_db: str = field(default_factory=lambda: os.environ.get("CLICKHOUSE_DB", "weirvern"))
    clickhouse_user: str = field(default_factory=lambda: os.environ.get("CLICKHOUSE_USER", "default"))
    clickhouse_password: str = field(default_factory=lambda: os.environ.get("CLICKHOUSE_PASSWORD", ""))

    # Detection loop
    detect_interval_s: int = field(default_factory=lambda: _env_int("DETECT_INTERVAL_S", 300))
    retrain_every_h: int = field(default_factory=lambda: _env_int("RETRAIN_EVERY_H", 6))
    retrain_window_h: int = field(default_factory=lambda: _env_int("RETRAIN_WINDOW_H", 72))
    base_threshold: float = field(default_factory=lambda: _env_float("BASE_THRESHOLD", 0.35))
    min_agreement: float = field(default_factory=lambda: _env_float("MIN_AGREEMENT", 0.33))

    # Data input (goflow2 JSONL sink)
    tail_file: str = field(default_factory=lambda: os.environ.get("TAIL_FILE", "/data/flows.jsonl"))

    # Zeek packet-level logs (optional second sensor). Empty = NetFlow only.
    zeek_log_dir: str = field(default_factory=lambda: os.environ.get("ZEEK_LOG_DIR", ""))

    # Alerting
    pushover_enabled: bool = field(default_factory=lambda: _env_bool("PUSHOVER_ENABLED", False))
    pushover_user_key: str = field(default_factory=lambda: os.environ.get("PUSHOVER_USER_KEY", ""))
    pushover_api_token: str = field(default_factory=lambda: os.environ.get("PUSHOVER_API_TOKEN", ""))
    pushover_cooldown_s: int = field(default_factory=lambda: _env_int("PUSHOVER_COOLDOWN_S", 1800))
    pushover_max_per_hour: int = field(default_factory=lambda: _env_int("PUSHOVER_MAX_PER_HOUR", 20))

    # Models
    model_dir: str = field(default_factory=lambda: os.environ.get("MODEL_DIR", "/models"))

    # ------------------------------------------------------------------
    @property
    def http_url(self) -> str:
        return f"http://{self.clickhouse_host}:{self.clickhouse_port}"

    def validate(self) -> None:
        """Fail fast on obviously bad config (lesson: silent misconfig cost weeks)."""
        if not 0.0 < self.base_threshold <= 1.0:
            raise ValueError(f"BASE_THRESHOLD must be in (0, 1], got {self.base_threshold}")
        if not 0.0 < self.min_agreement <= 1.0:
            raise ValueError(f"MIN_AGREEMENT must be in (0, 1], got {self.min_agreement}")
        if self.detect_interval_s < 10:
            raise ValueError("DETECT_INTERVAL_S must be >= 10")
        if self.retrain_every_h < 1:
            raise ValueError("RETRAIN_EVERY_H must be >= 1")
        if self.pushover_enabled and (
            not self.pushover_user_key or not self.pushover_api_token
        ):
            raise ValueError(
                "PUSHOVER_ENABLED=1 requires PUSHOVER_USER_KEY and PUSHOVER_API_TOKEN"
            )

    # ------------------------------------------------------------------
    def model_path(self, kind: str) -> str:
        """Versioned artifact path. Lesson: v14 deployed while v19 sat on disk —
        versioned filenames + persisted state make the *running* version obvious."""
        return str(Path(self.model_dir) / f"{kind}_v1.pkl")


@dataclass(frozen=True)
class ModelConfig:
    """Hyper-parameters for the ensemble, versioned with the code."""

    contamination: float = 0.06
    if_n_samples: int = 80_000
    if_extremes: int = 5_000  # top-N extremes per metric to force into training
    dbscan_eps: float = 0.6
    dbscan_min_samples: int = 5
    dbscan_n_samples: int = 5_000
    gb_max_samples: int = 50_000
    test_size: float = 0.2
    random_state: int = 42
    baseline_min_obs: int = 10

    # Ensemble weights — used only when fusion_mode == "mean" (legacy A/B mode).
    # "max" (default) ignores them; see fuse_scores() for why.
    weight_if: float = 1.0
    weight_gb: float = 0.75
    weight_dbscan: float = 0.65
    weight_baseline: float = 1.3   # when baseline exists
    weight_baseline_missing: float = 0.5

    # "max" = strongest-detector signal (default, recommended);
    # "mean" = legacy weighted average retained for comparison.
    fusion_mode: str = "max"

    # Statistically thin windows (few flows) have unreliable per-window
    # statistics; scores are damped proportionally (see
    # ensemble.detection_confidence_factor for the measured rationale).
    min_flows_for_full_confidence: int = 10
    thin_window_floor: float = 0.35

    # Structural port-scan signature (diversity metrics) — lets a lone strong
    # specialist escalate when the window itself is direct scan evidence.
    port_scan_min_ports: int = 50
    port_scan_min_entropy: float = 4.0

    # ── Agreement gate (see ensemble.detection_sweep) ────────────────────────
    # A detection whose fused score is high (>= 0.6) is allowed a lower agreement
    # bar, because its score already carries the evidence. This margin shapes that
    # relaxation. Both knobs are internal derivations rather than operator
    # tunables, which is why neither is in .env.example.
    #
    # A SUBTRACTIVE margin, not a multiplier: the original hardcoded pair was
    # exactly 0.33 (low score) and 0.25 (high score), i.e. a 0.08 offset. A
    # multiplier of 0.75 against the 0.33 default yields 0.2475, which would have
    # silently shifted every high-scoring detection's agreement bar by 0.0025 on
    # the default path. The offset reproduces the original exactly and still
    # tracks MIN_AGREEMENT upward.
    #
    # min_agreement_margin: subtracted from MIN_AGREEMENT for the high-score tier
    #   (0.08 with the default MIN_AGREEMENT of 0.33 gives exactly 0.25).
    # min_agreement_floor: the subtraction can never push the bar below this, so a
    #   badly chosen MIN_AGREEMENT cannot disable the gate entirely.
    min_agreement_margin: float = 0.08
    min_agreement_floor: float = 0.20

    # Score normalization parameters
    z_activation_k: float = 0.4
    z_activation_shift: float = 2.5

    @property
    def weights(self) -> dict[str, float]:
        """Base weights keyed by detector name (baseline adjusted at runtime)."""
        return {
            "isolation_forest": self.weight_if,
            "gradient_boosting": self.weight_gb,
            "dbscan": self.weight_dbscan,
            "adaptive_baseline": self.weight_baseline,
        }


def get_settings() -> Settings:
    """Validated settings singleton (call once; cheap enough to call per-test)."""
    s = Settings()
    s.validate()
    return s
