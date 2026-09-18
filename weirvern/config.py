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


def _env_mode(name: str, default: str = "loch") -> str:
    """Read the sensor mode, normalised through the mode module.

    Normalised here rather than validated: an unknown value is RETURNED AS TYPED so the
    status output can report exactly what is configured and that it is unrecognised.
    Silently coercing it to "loch" would hide a typo and quietly change the sensor's
    behaviour, which is the opposite of what someone setting this wants.
    """
    raw = _clean_env(os.environ.get(name))
    if raw is None or raw.strip() == "":
        return default
    from weirvern.admin.mode import normalise

    return normalise(raw)


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

    # The capture and management interfaces, by NAME, as the sensor node sees them.
    # Kept in the settings so the running worker can report a mismatch: a capture
    # interface that is also the default route is the configuration that produces a
    # capture full of broadcast noise and nothing else.
    zeek_iface: str = field(default_factory=lambda: os.environ.get("ZEEK_IFACE", ""))
    mgmt_iface: str = field(default_factory=lambda: os.environ.get("MGMT_IFACE", ""))

    # HOW the sensor gets its packets: "loch" (passive promisc/SPAN capture) or "weir"
    # (in-path ARP intercept). Normalised through the mode module so a mechanism word
    # like "intercept" typed into a config file still resolves, and so an unknown value
    # is preserved for reporting rather than silently defaulting to something else.
    #
    # Note this is read, not enforced, here: the mode gates container capabilities and
    # sysctls, which are decided in the manifests. Reading it lets the running worker
    # report the mode and its blast radius in status output.
    sensor_mode: str = field(
        default_factory=lambda: _env_mode("SENSOR_MODE")
    )

    # Weir mode only: comma-separated addresses (or CIDRs) to intercept, or "*" for
    # every host on the capture segment. Empty means nothing is intercepted even if the
    # mode says weir, so enabling the mode cannot by itself divert traffic — the
    # targets are a separate, explicit decision.
    intercept_targets: str = field(
        default_factory=lambda: os.environ.get("INTERCEPT_TARGETS", "")
    )

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


def _load_env_file() -> None:
    """Load a local `.env` into os.environ, WITHOUT overriding real env vars.

    THE BUG THIS FIXES: `weirvern install` GENERATES `.env` from `.env.example`,
    and `config`/`tune` read and write it — but nothing ever loaded it into the
    environment, and every Settings field reads os.environ at construction. So
    `.env` had no effect on any runtime setting: editing CLICKHOUSE_USER or
    PUSHOVER_ENABLED appeared to work and silently did nothing.

    It surfaced on a live box where `.env` said CLICKHOUSE_USER=default while the
    cluster had been reconfigured to a named user, so `weirvern status` reported
    an authentication failure that the `.env` file made impossible to fix.

    Precedence: real environment variables WIN. That ordering matters in
    Kubernetes, where the ConfigMap and Secret are injected as environment
    variables and must not be shadowed by a stale `.env` that happened to be
    copied into the image. This only fills in values that are not already set.

    Deliberately no python-dotenv dependency: the format needed here is
    KEY=value with optional `export`, comments and surrounding quotes, which is a
    dozen lines and avoids adding a runtime dependency to the worker image.
    """
    import os
    from pathlib import Path

    candidates: list[Path] = []
    explicit = os.environ.get("WEIRVERN_ENV_FILE")
    if explicit:
        candidates.append(Path(explicit))
    else:
        # WEIRVERN_HOME, then the current directory. Both are checked because the
        # CLI is often run from the project root while the worker runs from an
        # installed package location.
        home = os.environ.get("WEIRVERN_HOME")
        if home:
            candidates.append(Path(home) / ".env")
        candidates.append(Path.cwd() / ".env")

    for path in candidates:
        try:
            text = path.read_text()
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            continue
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            key, _, value = line.partition("=")
            key = key.strip()
            if not key:
                continue
            # Strip an inline comment, but only when it follows whitespace, so a
            # value like `abc#def` is preserved. .env.example ships
            # `PUSHOVER_ENABLED=0             # 1 = real pushes`, which would
            # otherwise be parsed as a value with the comment attached.
            value = value.strip()
            for quote in ('"', "'"):
                if value.startswith(quote) and value.endswith(quote) and len(value) > 1:
                    value = value[1:-1]
                    break
            else:
                hash_idx = value.find(" #")
                if hash_idx != -1:
                    value = value[:hash_idx].rstrip()
            # Real environment wins -- see the docstring.
            os.environ.setdefault(key, value)
        return  # first readable file wins; do not merge several


def get_settings() -> Settings:
    """Validated settings singleton (call once; cheap enough to call per-test)."""
    _load_env_file()
    s = Settings()
    s.validate()
    return s
