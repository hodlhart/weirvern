"""The pieces a ripple is made of: one host, one channel, one scale, one p-value.

WHY THIS EXISTS. The operator asked to "show all the ml and the pieces of ripples, then the
anomaly page is actually the ripples". This module is the missing middle: the fusion in
`ripple.py` could say whether a handful of shadow models agreed, and `generic_channels.py` could
score one five-minute window per source, but nothing measured a channel against the SAME host's
own trailing history at more than one scale, and nothing stored the measurement so it could be
read back. A ripple is only as good as the evidence under it.

WHAT A RIPPLE IS HERE. A small, statistically significant change in one channel's behaviour for
one host, measured against that host's OWN trailing history. No human labels and no synthetic
ground truth: the baseline is the host's own past. Several pieces of evidence that line up in one
time window on one host are grouped into one `Ripple` by `ripple.group_evidence`; the ripple is
what an operator reads, the evidence is what it is made of.

THE TWO TESTS, AND THE EXPLICIT RULE BETWEEN THEM. The empirical two-sided rank p is the default:
it assumes nothing about the host's distribution. Its floor is 1/(n+1), so only a baseline of at
least 100 non-overlapping windows can express a p below the 0.01 family bar. Below that, a COUNT
channel is measured with a fitted negative binomial (Poisson only when the baseline's variance is
statistically indistinguishable from its mean), and the row records which test produced its
number in `p_method` ('empirical' | 'negbin' | 'poisson' | 'insufficient'). The bar itself is
unchanged: two families at p <= 0.01, or one at p <= 0.001, score >= 3.0, independent families.

WHICH SCALES MAY USE THE TAIL IS A MEASURED DECISION, NOT AN AMBIENT ONE. `TAIL_ENABLED` names
the scales whose held-out false-alarm rate was measured and accepted; every other scale keeps the
empirical rule and reports the fitted tail as disabled with its reason. `tail_supported()` also
requires the statistic to be a count: a byte sum, a ratio and a boolean change are not counts,
and a negative binomial over them would be a category error. Those channels therefore report
'insufficient baseline' below 100 windows rather than a modelled number.

THE SCALES, AND A LOOKBACK DERIVED FROM THE RETENTION IN FORCE. A scale is the length of the
window being measured: 1h, 6h, 24h, 7d. A channel can only be measured at a scale the lookback
can supply a baseline for, and the baseline samples are NON-OVERLAPPING windows of that length.

The lookback is not a constant. `scale_lookback_days()` derives it per scale from the retention
the tables have IN FORCE -- `retention.days_in_force()`, which reads each source table's TTL
back from `system.tables` -- and caps it at what that scale needs:

    scale  1h    6h     24h    7d
    need   5d    26d    103d   721d      (100 windows + 2 spare, for the EMPIRICAL test)
    read   7d    26d    103d   retention (1h keeps the 7-day floor; 7d is capped by retention)

The 100-window requirement above is the empirical test's. A validated fitted tail needs only the
30-window floor plus its spare (2/9/33/231 days), which is why the 7d scale is no longer
structurally unreachable: at 231 days of retention it holds 32 windows, enough to fit -- but only
if this deployment actually has that history. On 2026-11-21 the TTL in force was 107 days and the
oldest Zeek table held 37 days, so 24h had 30 windows at most and 7d held 4: both scales report
'insufficient baseline' rather than a number. Declaring the capability and reporting the measured
shortfall are different acts.

MEASURED ON THE LIVE BOX 2026-11-21: the TTLs in force were 107 days while `retention.derive()`
would have said more. The TTL is what decides which rows still exist, so that is what the ripple
lookback is derived from -- re-deriving on the read path would advertise history the cluster has
not applied yet.

COVERAGE AND SILENCE. A host with four hours of data in a week does not have a week-long
normal. Evidence is emitted only when the baseline holds at least `MIN_BASELINE_SAMPLES`
non-empty windows AND those windows cover at least `MIN_COVERAGE` of the expected buckets. A
channel with too little history produces NO evidence at all -- never p=1.0, which would read as
"measured and quiet". For the same reason a missing CURRENT bucket produces no evidence: this
layer cannot tell a host that stopped talking from a collector that stopped writing, and the
collection layer owns freshness.

WHO THE SUBJECT IS. A ripple is a change in a MONITORED host's behaviour, never in a remote
peer's. Every row is attributed to its monitored endpoint: the source if the source is inside a
monitored CIDR, otherwise the destination. A flow row with no monitored endpoint is dropped.

THE SCHEMA. `flows_window` (schema 050) is keyed on `src_addr` alone, so it can only describe the
SOURCE endpoint of a flow. `flows_window_endpoint` (schema 061) is the parallel table keyed on
(window_start, host_addr, direction): 'out' rows describe a flow's source (the same population as
`flows_window`), 'in' rows describe its destination. That second direction is what lets an inbound
flow be attributed to the internal host that received it, instead of being dropped. The two tables
have the same aggregate-state shapes and the same retention policy. The OUTBOUND channels stay on
`flows_window` -- it holds the same population with a longer retained history -- and the inbound
channels read the new table, with `direction = 'in'` spliced into the same select as the merge.

WHAT THIS IS NOT. 'in' and 'out' are the two ENDS of one flow record, not two flows. A flow between
two monitored hosts appears in both directions because each host's behaviour is a different fact. A
reader that wants the network total picks one direction; a reader that wants a host's traffic reads
both and labels them. Within the ripple layer they are one FAMILY, so inbound volume cannot
corroborate outbound volume -- they are the same measurement seen from opposite ends.

THE FOUR FAMILIES ADDED 2026-11-19, one per new collection pipeline. They are independent of
flow/conn/dns/identity in the sense that matters: each observes something none of those four
can see, so it can CORROBORATE rather than re-count. See `ripple.CHANNEL_FAMILIES`.

  tls    `tls_fingerprint_diversity` (zeek_ssl): distinct (server_name, ja4) pairs per host.
         LIVE COLUMN CHECK: there is no JA3, no JA3S and no issuer column, and `ja4_orig` is
         present but EMPTY on every row (0 of 80,982). `ja4` is populated on 84% and
         `server_name` on 78%. So the channel counts the SNI the client asked for plus the JA4
         fingerprint it offered; "server-name/issuer" is not available and claiming it would be
         a lie about what is measured.
  http   `http_host_diversity` (distinct Host values) and `http_ua_novelty` (a User-Agent this
         host has never sent). Both columns exist (`host` 87% populated, `user_agent` 80%).
  ssh    `ssh_version_change`: the (client, server) banner pair per host, and evidence only
         when that pair differs from the host's previous non-empty window. A boolean/timestamp
         channel, not a rate. Both columns exist (`client` 82%, `server` 99.9%).
  notice `zeek_notice_volume` and `zeek_weird_volume`: Zeek's own findings per host per window.
         Both address columns exist. Measured caveat: 616 of 624 notices in the last seven days
         are `CaptureLoss::*` with `0.0.0.0` at BOTH ends -- they describe the sensor, not a
         host -- and the only host-attributed notice class covers four hours, below the
         thirty-window floor. The channel is declared and correct; at this site it currently
         emits nothing, and that is reported rather than papered over.

THE ACTIVE-INVENTORY FAMILY ADDED 2026-11-21. `service_set_change` reads the scanner's per-scan
history (`asset_service_history`, written once per COMPLETE scan) and compares the newest scan's
service set with the previous one: a port opened, a port closed, or a product/version changed on
the same port. It is its own family because no passive pipeline can see a listener that never
sent a packet. Its comparison unit is the SCAN, not an hour -- see `SERVICE_SPECS` -- because a
scan is episodic and bucketing it by clock time would merge two scans or starve the window. The
p-value is still the host's own history of scan-to-scan changes, under the same 100-window
empirical rule and the same 30-window floor; `change` is not a count, so below 100 it reports
'insufficient' rather than a fitted number.

WHAT WAS REFUSED, AND WHY. Every source below is collected and none of it is channelised.
Adding a channel that re-counts an existing population would repeat the defect this module
already fixed once (`flow_bytes` and `flow_volume` counted as two pieces of evidence).

  zeek_quic         RE-COUNT. QUIC carries TLS 1.3, so its `server_name` is the same egress TLS
                    handshake the tls family already measures, over a different transport.
  zeek_files        RE-COUNT. The transfers are already counted by conn/http volume, and the
                    SMB subset by identity's `smb_file_volume`/`smb_path_diversity`.
  zeek_dhcp         TOO SPARSE AT THIS SITE: 395 rows in seven days (18 clients), and a lease
                    is device management, not traffic the host produced.
  zeek_tunnel       TOO SPARSE: 132 rows in seven days from ONE host, far below the floor.
  zeek_dce_rpc      DARK: 0 rows in seven days. A channel would be permanently unavailable.
  zeek_ldap_search  DARK: 0 rows in seven days, for the same reason.
  zeek_x509         UNATTRIBUTABLE: the table has no `src_addr`, `dst_addr` or `uid` at all, so
                    a certificate cannot be tied to a host without inventing a join.

WHAT THIS DOES NOT DO: it never writes `netflow_anomalies`, never pages, never promotes a model
and never touches the anomaly page. Phase 1 is measurement and a read-only card.
"""
from __future__ import annotations

import math
import statistics
from datetime import UTC, datetime, timedelta
from typing import Any

from weirvern import monitored as monitored_mod
from weirvern import retention as retention_mod
from weirvern import ripple_signatures
from weirvern.asset_changes import detect_service_changes
from weirvern.models import ripple_tail
from weirvern.models.generic_channels import ChannelSpec
from weirvern.models.ripple import (
    DEFAULT_FAMILY_MAX_P,
    EMPIRICAL_MIN_WINDOWS,
    EVIDENCE_SCALE_SECONDS,
    EVIDENCE_SCALES,
    MIN_BASELINE_SAMPLES,
    P_METHOD_EMPIRICAL,
    P_METHOD_INSUFFICIENT,
    PARAMETRIC_METHODS,
    RIPPLE_WINDOW_S,
    ChannelEvidence,
    channel_family,
    empirical_pvalue_two_sided,
    group_evidence,
    min_baseline_samples,
    pvalue_floor,
    severity_bands,
)

MODEL_VERSION = "ripple-evidence-6"

#: The lookback a scale gets when the retention in force cannot be read: the historical 7-day
#: window, which is also the FLOOR of every derived lookback. It is no longer the answer -- see
#: `scale_lookback_days`, which derives the per-scale value from what the tables keep.
LOOKBACK_DAYS = 7

#: Spare baseline windows over the number a scale needs to resolve the family bar. One covers a
#: gap (a host that was silent for a window) and one covers the current bucket's arithmetic at a
#: scale boundary; without them a baseline at exactly 100 windows loses its resolution after a
#: single missing bucket.
LOOKBACK_MARGIN_WINDOWS = 2

#: The finest bucket any channel is measured in. Every scale is a whole number of these, so an
#: additive statistic is queried once and rolled up; only `diversity` needs a query per scale.
STEP_SECONDS = 3600

#: Below thirty baseline windows a rank is not evidence of anything: the smallest p the test
#: can express is 1/(n+1), and a floor that is not below the decision threshold turns the test's
#: resolution into a fake result. Imported from `ripple` so the grouping and the measurement
#: cannot disagree about what "short" means.
#: (The name is re-exported below for callers that read it from this module.)

#: The share of the expected baseline windows that must actually exist. A baseline drawn from a
#: host's three busiest hours in a week is not its normal; it is its busiest hours.
MIN_COVERAGE = 0.5

#: A pass is bounded so a scope mistake cannot turn an hourly job into an unbounded write.
#: The READ is already bounded by the lookback; this caps what one pass can store.
MAX_HOSTS = 200

ADDITIVE_KINDS = frozenset({"count", "sum", "ratio"})

#: The channel kinds a fitted count tail is mathematically valid for. A volume (`count`) and a
#: distinct-value count (`diversity`) are non-negative integer counts, which is what a negative
#: binomial models. A byte `sum`, a `ratio` and a boolean `change` are NOT counts: fitting a
#: count distribution to them is a category error, so they keep the empirical test and, below
#: 100 windows, report 'insufficient baseline' rather than a modelled number. `novelty` is a
#: count of values new in the window, so it is eligible -- and will usually be degenerate (all
#: zeros) on a coarse scale, which the fit reports as insufficient.
TAIL_KINDS = frozenset({"count", "diversity", "novelty"})

#: THE SCALES ALLOWED TO USE THE FITTED TAIL. Populated only for scales whose held-out
#: false-alarm rate was measured and accepted by `scripts/ripple_tail_far.py`; a scale not in
#: this mapping falls back to the empirical rule (and is therefore not usable below 100 windows).
#: The reason is part of the value so a disabled scale can say why in `/api/ripples` and the
#: Models card, rather than silently disappearing.
#:
#: 2026-11-21: 6h RE-MEASURED as history grew. The measurement: 97 six-hour windows at most (the
#: production rule still prefers the fit because 97 < 100), 40 held-out tests across the eight
#: count channels; the raw FAR was 2/40 (5.0%, 95% CI 1.4-16.5%), and on the 35 windows the
#: empirical test calls ordinary (p > 0.05) the tail fired 0 times (0%, 95% CI 0-9.9%). Both
#: fires were windows the rank test already ranked between its floor (p=0.0102) and 0.05 -- a
#: resolution gain, not a manufactured ripple. The 2026-11-20 reading was 1/9 (11.1%); the rate
#: FELL as the sample grew, which is what a calibrated tail should do.
TAIL_ENABLED: dict[str, str] = {
    "6h": "validated 2026-11-21 on live held-out windows (40 tests)",
}

TAIL_DISABLED_REASON: dict[str, str] = {
    "1h": "the empirical test already resolves the bar at 100+ windows",
    "24h": ("30 live windows at most on 2026-11-21 (one host/channel), an empirical p floor of "
            "0.032 and ONE held-out fit; a single sample cannot accept a tail"),
    "7d": "4 live windows on 2026-11-21; 30 are required for a fit (about 210 days of history)",
}

#: THE MEASUREMENT BEHIND `TAIL_ENABLED`, per scale, as data. `scripts/ripple_tail_far.py`
#: produces it; the API and the Models card print it so an enabled scale is never an unexplained
#: switch. `None` means the scale could not be measured on this deployment, which is different
#: from a measured zero. `held_out_windows` is the DENOMINATOR of `far`: one held-out window per
#: (host, channel), which is the largest sample that carries no information from the window it
#: scores.
TAIL_VALIDATION: dict[str, dict[str, Any]] = {
    "6h": {
        "as_of": "2026-11-21",
        "held_out_windows": 40,
        "far": 0.05,
        "far_interval": [0.013820, 0.165042],
        "ordinary_windows": 35,
        "fires_on_ordinary": 0,
        "far_on_ordinary": 0.0,
        "far_on_ordinary_interval": [0.0, 0.098904],
        "method_counts": {"negbin": 34, "poisson": 6},
        "observed_windows_max": 97,
        "p_floor": 0.010204,
        "provisional": False,
        "note": ("both fires were windows the empirical test already ranked between its floor "
                 "(p=0.0102) and 0.05; 0 of 35 ordinary windows fired"),
    },
    "24h": {
        "as_of": "2026-11-21", "held_out_windows": 1, "far": 0.0,
        "far_interval": [0.0, 0.793457], "observed_windows_max": 30,
        "p_floor": 0.032258, "provisional": True,
        "reason": ("30 windows on one host/channel, and one held-out fit; a single sample has a "
                   "95% interval of 0-79%, so it can neither accept nor reject the tail"),
    },
    "7d": {
        "as_of": "2026-11-21", "held_out_windows": 0, "far": None, "far_interval": None,
        "observed_windows_max": 4,
        "reason": "4 windows of history; the 30-window minimum is not met",
        "synthetic_at_14_windows": {
            "far": 0.05, "far_interval": [0.041281, 0.060444],
            "draws": 2000,
            "note": ("negative-binomial draws at the live 6h fit's parameters; measures the "
                     "estimator, not the live deployment"),
        },
    },
}


def tail_supported(scale: str, kind: str) -> bool:
    """Whether a channel of `kind` may use the fitted tail at `scale`.

    Two independent conditions, both explicit: the scale must have been VALIDATED (it is in
    `TAIL_ENABLED`), and the statistic must be a count. A `sum` channel at a validated scale
    still keeps the empirical test, because a negative binomial is not a model of bytes.
    """
    return scale in TAIL_ENABLED and kind in TAIL_KINDS


# ── the channels this deployment can actually hear ──────────────────────────────────────────
#
# Every spec names a REAL table, a real host column and a statistic that table can answer.
# Nothing is declared for a source with no table. The family is one collection pipeline, not one
# channel: `flow_bytes` and `flow_volume` are two units for the SAME flow records, so they share
# a family and can never corroborate each other. See `ripple.CHANNEL_FAMILIES` for the map and
# the reason the other groups are drawn where they are.
#
# `flows_window_endpoint` has ONE row per (window, host, direction): 'out' is the source endpoint
# and 'in' the destination. The three ORIGINAL flow channels stay on `flows_window`, which holds
# the same outbound population with a longer retained history -- moving them to the new table would
# have cut their baseline to the raw-flow retention and silently stopped their evidence. The three
# `flow_in_*` channels are the half that did not exist: a host that only receives traffic now has
# flow evidence instead of nothing.
FLOW_SPECS: tuple[ChannelSpec, ...] = (
    # flows_window is an AggregatingMergeTree. Reading it with plain `count()` would sum partial
    # states as if they were values; the `-Merge` combinators are mandatory.
    ChannelSpec("flow_volume", "flow", "weirvern.flows_window", "src_addr",
                time_column="window_start", kind="count", count_state="flow_count",
                required_columns=("window_start", "src_addr", "flow_count"),
                scales=EVIDENCE_SCALES, retention_days=7),
    ChannelSpec("flow_bytes", "flow", "weirvern.flows_window", "src_addr",
                time_column="window_start", kind="sum", count_state="flow_count",
                sum_state="total_bytes",
                required_columns=("window_start", "src_addr", "total_bytes"),
                scales=EVIDENCE_SCALES, retention_days=7),
    ChannelSpec("flow_dst_diversity", "flow", "weirvern.flows_window", "src_addr",
                time_column="window_start", kind="diversity", count_state="flow_count",
                uniq_state="unique_dst_ips",
                required_columns=("window_start", "src_addr", "unique_dst_ips"),
                scales=EVIDENCE_SCALES, retention_days=7),
    # INBOUND. The subject is the destination endpoint, and the peer counted by the diversity
    # channel is the set of senders. Named `flow_in_*` rather than folded into the channels above:
    # a host's received bytes and sent bytes are different quantities, and one column cannot hold
    # both without becoming their sum (which is neither).
    ChannelSpec("flow_in_volume", "flow", "weirvern.flows_window_endpoint", "host_addr",
                time_column="window_start", kind="count", count_state="flow_count",
                direction="in",
                required_columns=("window_start", "host_addr", "direction", "flow_count"),
                scales=EVIDENCE_SCALES, retention_days=7),
    ChannelSpec("flow_in_bytes", "flow", "weirvern.flows_window_endpoint", "host_addr",
                time_column="window_start", kind="sum", count_state="flow_count",
                sum_state="total_bytes", direction="in",
                required_columns=("window_start", "host_addr", "direction", "total_bytes"),
                scales=EVIDENCE_SCALES, retention_days=7),
    ChannelSpec("flow_in_peer_diversity", "flow", "weirvern.flows_window_endpoint", "host_addr",
                time_column="window_start", kind="diversity", count_state="flow_count",
                uniq_state="unique_peer_ips", direction="in",
                required_columns=("window_start", "host_addr", "direction", "unique_peer_ips"),
                scales=EVIDENCE_SCALES, retention_days=7),
)

CONN_SPECS: tuple[ChannelSpec, ...] = (
    ChannelSpec("conn_volume", "conn", "weirvern.zeek_conn", "src_addr",
                peer_column="dst_addr", required_columns=("ts", "src_addr", "dst_addr"),
                scales=EVIDENCE_SCALES, retention_days=7),
    ChannelSpec("conn_dst_diversity", "conn", "weirvern.zeek_conn", "src_addr",
                "dst_addr", peer_column="dst_addr", kind="diversity",
                required_columns=("ts", "src_addr", "dst_addr"),
                scales=EVIDENCE_SCALES, retention_days=7),
    ChannelSpec("conn_service_diversity", "conn", "weirvern.zeek_conn", "src_addr",
                "service", peer_column="dst_addr", kind="diversity",
                required_columns=("ts", "src_addr", "dst_addr", "service"),
                scales=EVIDENCE_SCALES, retention_days=7),
    ChannelSpec("conn_reset_ratio", "conn", "weirvern.zeek_conn", "src_addr",
                peer_column="dst_addr", kind="ratio",
                predicate="conn_state IN ('RSTO','RSTR','S0','REJ')",
                required_columns=("ts", "src_addr", "dst_addr", "conn_state"),
                scales=EVIDENCE_SCALES, retention_days=7),
)

DNS_SPECS: tuple[ChannelSpec, ...] = (
    ChannelSpec("dns_volume", "dns", "weirvern.zeek_dns", "src_addr",
                peer_column="dst_addr", required_columns=("ts", "src_addr", "dst_addr"),
                scales=EVIDENCE_SCALES, retention_days=7),
    ChannelSpec("dns_query_diversity", "dns", "weirvern.zeek_dns", "src_addr",
                "query", peer_column="dst_addr", kind="diversity",
                required_columns=("ts", "src_addr", "dst_addr", "query"),
                scales=EVIDENCE_SCALES, retention_days=7),
    ChannelSpec("dns_nxdomain_ratio", "dns", "weirvern.zeek_dns", "src_addr",
                peer_column="dst_addr", kind="ratio", predicate="rcode = 3",
                required_columns=("ts", "src_addr", "dst_addr", "rcode"),
                scales=EVIDENCE_SCALES, retention_days=7),
    ChannelSpec("dns_reverse_ratio", "dns", "weirvern.zeek_dns", "src_addr",
                peer_column="dst_addr", kind="ratio", predicate="query LIKE '%in-addr.arpa%'",
                required_columns=("ts", "src_addr", "dst_addr", "query"),
                scales=EVIDENCE_SCALES, retention_days=7),
)

# The identity tables carry `src_addr` as IPv4 and retain 30-90 days, which is why they are the
# only sources that could ever support a longer lookback without a schema change.
IDENTITY_SPECS: tuple[ChannelSpec, ...] = (
    ChannelSpec("kerberos_volume", "identity", "weirvern.zeek_kerberos", "src_addr",
                peer_column="dst_addr", required_columns=("ts", "src_addr", "dst_addr"),
                scales=EVIDENCE_SCALES, retention_days=90),
    ChannelSpec("kerberos_service_diversity", "identity", "weirvern.zeek_kerberos", "src_addr",
                "service", peer_column="dst_addr", kind="diversity",
                required_columns=("ts", "src_addr", "dst_addr", "service"),
                scales=EVIDENCE_SCALES, retention_days=90),
    ChannelSpec("ntlm_volume", "identity", "weirvern.zeek_ntlm", "src_addr",
                peer_column="dst_addr", required_columns=("ts", "src_addr", "dst_addr"),
                scales=EVIDENCE_SCALES, retention_days=60),
    ChannelSpec("ntlm_user_diversity", "identity", "weirvern.zeek_ntlm", "src_addr",
                "username", peer_column="dst_addr", kind="diversity",
                required_columns=("ts", "src_addr", "dst_addr", "username"),
                scales=EVIDENCE_SCALES, retention_days=60),
    ChannelSpec("smb_file_volume", "identity", "weirvern.zeek_smb_files", "src_addr",
                peer_column="dst_addr", required_columns=("ts", "src_addr", "dst_addr"),
                scales=EVIDENCE_SCALES, retention_days=30),
    ChannelSpec("smb_path_diversity", "identity", "weirvern.zeek_smb_files", "src_addr",
                "path", peer_column="dst_addr", kind="diversity",
                required_columns=("ts", "src_addr", "dst_addr", "path"),
                scales=EVIDENCE_SCALES, retention_days=30),
)

# ── the four independent families ───────────────────────────────────────────────────────────
#
# Each observes something the four families above cannot (see `ripple.CHANNEL_FAMILIES`), which
# is the only reason to add it: a second view of the same events is one measurement counted
# twice. The columns below were verified against `system.columns` on the live deployment, and
# the docstring at the top of this module records what was found and what was refused.

TLS_SPECS: tuple[ChannelSpec, ...] = (
    # NO JA3, NO JA3S, NO ISSUER. The live table has `ja4` and `ja4_orig`; `ja4_orig` is empty
    # on all 80,982 rows, so counting it would produce a constant. The channel counts distinct
    # (SNI, JA4) pairs: the name the client asked for plus the fingerprint it offered.
    # `value_filter` keeps a session with neither from becoming one anonymous "distinct" pair
    # that every host carries permanently.
    ChannelSpec("tls_fingerprint_diversity", "tls", "weirvern.zeek_ssl", "src_addr",
                "concat(server_name, '|', ja4)", peer_column="dst_addr", kind="diversity",
                value_filter="server_name != '' OR ja4 != ''",
                required_columns=("ts", "src_addr", "dst_addr", "server_name", "ja4"),
                scales=EVIDENCE_SCALES, retention_days=7),
)

HTTP_SPECS: tuple[ChannelSpec, ...] = (
    # THE COLUMN IS QUALIFIED ON PURPOSE. The subject is aliased `host` in the generated SQL,
    # and ClickHouse substitutes aliases in the SELECT list: `uniqExact(host)` silently counts
    # the subject (always 1) instead of the Host header (measured: 1 vs 2 on a live group).
    # `weirvern.zeek_http.host` is the request header, which is what this channel means.
    ChannelSpec("http_host_diversity", "http", "weirvern.zeek_http", "src_addr",
                "weirvern.zeek_http.host", peer_column="dst_addr", kind="diversity",
                required_columns=("ts", "src_addr", "dst_addr", "host"),
                scales=EVIDENCE_SCALES, retention_days=7),
    # Novelty, not volume: a UA this host has never sent is rare even on a noisy host, while
    # the number of requests is a rate the conn family already sees.
    ChannelSpec("http_ua_novelty", "http", "weirvern.zeek_http", "src_addr",
                "user_agent", peer_column="dst_addr", kind="novelty",
                required_columns=("ts", "src_addr", "dst_addr", "user_agent"),
                scales=EVIDENCE_SCALES, retention_days=7),
)

SSH_SPECS: tuple[ChannelSpec, ...] = (
    # A boolean, not a rate: the value is 1 when this window's banner pair differs from the
    # pair in the host's previous non-empty window, and 0 when it is the same. A host that
    # upgrades its SSH client changes this and nothing in conn, which only counted bytes.
    ChannelSpec("ssh_version_change", "ssh", "weirvern.zeek_ssh", "src_addr",
                "concat(client, '|', server)", peer_column="dst_addr", kind="change",
                required_columns=("ts", "src_addr", "dst_addr", "client", "server"),
                scales=EVIDENCE_SCALES, retention_days=7),
)

NOTICE_SPECS: tuple[ChannelSpec, ...] = (
    # Zeek's own conclusions. Low volume and high signal by construction: the finding has
    # already been made by the sensor's scripts, so this is not another parser of the traffic.
    ChannelSpec("zeek_notice_volume", "notice", "weirvern.zeek_notice", "src_addr",
                peer_column="dst_addr", required_columns=("ts", "src_addr", "dst_addr"),
                scales=EVIDENCE_SCALES, retention_days=7),
    # `weird` is the same pipeline (Zeek's scripts deciding something is anomalous) at a much
    # higher volume, which is why it is one family with `notice` and not a family of its own.
    ChannelSpec("zeek_weird_volume", "notice", "weirvern.zeek_weird", "src_addr",
                peer_column="dst_addr", required_columns=("ts", "src_addr", "dst_addr"),
                scales=EVIDENCE_SCALES, retention_days=7),
)

# ── the ACTIVE INVENTORY pipeline: one more independent view ─────────────────────────────────
#
# THE SCANNER WAS PRODUCING FACT THIS LAYER COULD NOT HEAR. `asset_service_history` records one
# row per open service per COMPLETE scan, keyed by scan_id; the current table is a snapshot (see
# `scanner.record_scan_result`). A service that appears, disappears or changes its product or
# version on a host is not visible to any passive family: flow/conn see bytes, dns sees names,
# tls/http/ssh see protocols the host SPEAKS, and notice sees Zeek's conclusions. None of them
# can report a listener that never sent a packet, which is why `service` is a family of its own
# rather than a view of `conn` or `ssh` -- it is an independent measurement, so it can corroborate.
#
# THE COMPARISON UNIT IS ONE SCAN, NOT ONE HOUR. A scan is episodic (the rescan clock decides
# when), so bucketing it into clock windows would either merge two scans or starve the window.
# The channel therefore compares the NEWEST complete scan's snapshot with the one before it, and
# takes its p-value from the host's own history of scan-to-scan changes. `scale='1h'` is the
# ripple grouping window this evidence lands in, not a claim that the series is hourly; the
# sample count on the row is the number of earlier scan transitions, which is what the empirical
# rank test actually ranks.
#
# A PARTIAL SCAN IS NOT A CLOSED PORT. Only `asset_scans.scan_complete = 1` rows are read; a
# timed-out run's port list never enters the series, so it cannot manufacture a closure. A host
# with one complete scan gets an 'insufficient' row (there is no previous scan to compare with),
# never a zero that would read as "measured, no change".
#
# THE STATISTIC IS A BOOLEAN `change`, the same kind as `ssh_version_change`: 1 when the set
# differs from the previous scan, 0 when it does not. That also makes it ineligible for the fitted
# count tail, so below 100 transitions it reports 'insufficient' under the same rule as every
# other non-count channel rather than inventing a model.
SERVICE_CHANNEL = "service_set_change"

#: How many completed scans of ONE host may enter the baseline. The empirical test needs 100 and
#: resolves p<0.001 at 1,000; 400 bounds the read while giving better than the family bar. A
#: rescan clock faster than one per hour can otherwise turn a 30-day lookback into thousands of
#: rows per host.
SERVICE_SCAN_MAX_BASELINE = 400

#: The widest scan history this channel will read, whatever retention allows. A scan series is
#: not a traffic table: the useful question is "how has THIS host changed recently", and a year
#: of hourly scans would be 8,760 samples per host for no extra resolution below 1e-3.
SERVICE_SCAN_LOOKBACK_CAP_DAYS = 30

SERVICE_SPECS: tuple[ChannelSpec, ...] = (
    ChannelSpec(SERVICE_CHANNEL, "service", "weirvern.asset_service_history", "ip",
                time_column="observed_at", kind="change",
                required_columns=("scan_id", "ip", "port", "protocol", "service", "product",
                                  "version", "observed_at"),
                scales=("1h",), retention_days=7),
)

SPECS: tuple[ChannelSpec, ...] = (
    FLOW_SPECS + CONN_SPECS + DNS_SPECS + IDENTITY_SPECS
    + TLS_SPECS + HTTP_SPECS + SSH_SPECS + NOTICE_SPECS + SERVICE_SPECS
)

# ── which channels a Normalize feed row can be corroborated by ──────────────────────────────
#
# THE LANE RULE USED TO BE A FAMILY LIST, AND IT HID MOST OF ZEEK. `normalize_store` mapped a
# feed row to `{"dns"}` for a DNS row and `{"conn", "flow"}` for everything else. A Zeek session
# is a `zeek_conn` row, so a tls, http, ssh, identity or notice ripple for the SAME host in the
# SAME hour was visible on the Ripples page and invisible on the row -- and a host observed only
# through the Zeek lane (no NetFlow row) could never show what Zeek itself had measured. On the
# live box that withheld 211 tls rows (9 hosts), 134 http rows (4), 42 ssh rows (1) and 399
# notice rows (10) from the Zeek lane.
#
# THE TABLE NAMES THE LANE, THE SPEC NAMES THE CHANNEL. A feed lane is a COLLECTION PIPELINE: the
# tables its collector writes. `feed_lane_channels()` then asks every ChannelSpec whether its OWN
# table belongs to that lane, and whether that table has the columns it requires (the live
# `availability()` reply). There is no second family list to drift: adding a channel on a Zeek
# table makes it evaluable from a Zeek row, and a channel whose table lacks a required column is
# not offered at all -- its evidence is 'insufficient', never a zero that reads as measured.
#
# FLOW STAYS IN THE ZEEK LANE. A `zeek_conn` session and a `flows_window` row describe the same
# connection population through two collectors; the join already paired them, and removing it
# would narrow the lane while widening the rest.
#
# DNS IS ITS OWN ROW LANE, NOT ITS OWN COLLECTOR. `zeek_dns` is written by the same Zeek
# pipeline, so a Zeek session row can be corroborated by the DNS evidence that pipeline produced
# for the same host in the same hour -- "every channel whose required columns exist". What does
# NOT change is the other direction: a DNS ROW still matches only DNS channels (a DNS ripple is
# not evidence for a flow row, the operator's existing rule), and a FLOW row still matches only
# flow+conn, because NetFlow never saw a name. `asset_service_history` is the scanner's pipeline,
# not a feed lane, so `service_set_change` is not offered on any feed row.
FEED_LANE_TABLES: dict[str, tuple[str, ...]] = {
    "flow": ("weirvern.flows_window", "weirvern.flows_window_endpoint", "weirvern.zeek_conn"),
    "dns": ("weirvern.zeek_dns",),
    "zeek": (
        "weirvern.flows_window", "weirvern.flows_window_endpoint",
        "weirvern.zeek_conn", "weirvern.zeek_dns", "weirvern.zeek_ssl", "weirvern.zeek_http",
        "weirvern.zeek_ssh", "weirvern.zeek_kerberos", "weirvern.zeek_ntlm",
        "weirvern.zeek_smb_files", "weirvern.zeek_notice", "weirvern.zeek_weird",
    ),
}


#: channel -> family for the channels a signature can name a value on. Derived from the specs,
#: never maintained as a second list: a channel becomes signable by declaring a value column and
#: a value-bearing kind, and stops being signable if it is moved to a pre-aggregated source.
#: `ripple_signatures.supports()` is the one definition; the console and the API both read this.
SIGNATURE_CHANNELS: dict[str, str] = ripple_signatures.channels_for(SPECS)

#: Kinds whose value is a SET per bucket, not a number that can be summed or averaged. They
#: need `sql_values` (which values?) rather than `sql_anchored` (how many?), and are therefore
#: measured at each scale instead of being rolled up from one-hour buckets.
SET_KINDS = frozenset({"novelty", "change"})


def effective_lookback_days(spec: ChannelSpec, lookback_days: int = LOOKBACK_DAYS,
                            retention_days: int | None = None) -> int:
    """How far back this source can actually be read: the lookback, capped by its retention.

    WHEN A LIVE RETENTION IS SUPPLIED IT WINS OVER THE PER-SPEC CONSTANT. `retention.converge`
    puts every table in this layer on ONE window (the derived one), so the 7/30/60/90 constants
    that describe what each source was DESIGNED to keep are no longer a separate limit: the TTL
    read back from `system.tables` is. Without a live value (a test, or the static inventory) the
    constant remains the only cap, which is what a hypothetical 30-day deployment has.

    `flows_window` and the Zeek tables are all on `retention.RETENTION_TABLES`, so the live
    value is the real one; a spec whose table was NOT managed would need its constant here. That
    is why the live read is per table (`days_in_force(names=...)`) and takes the minimum.
    """
    cap = max(0, int(retention_days)) if retention_days is not None else int(spec.retention_days)
    return max(0, min(int(lookback_days), cap))


def windows_for_bar(max_p: float = DEFAULT_FAMILY_MAX_P) -> int:
    """Baseline windows needed for a p-value strictly below `max_p` to exist at all.

    p = (1 + #{as extreme}) / (n + 1), so the attainable floor is 1/(n+1). Thirty windows can
    express no p below 0.031: that is the point at which a rank stops being noise, not the point
    at which the ripple bar becomes reachable. Reaching a p STRICTLY below max_p takes
    1/(n+1) < max_p, i.e. n > 1/max_p - 1; at 0.01 that is 100 windows.
    """
    return max(MIN_BASELINE_SAMPLES, math.floor(1.0 / float(max_p) - 1.0) + 1)


def required_lookback_days(scale: str, *, windows: int | None = None,
                           margin_windows: int = LOOKBACK_MARGIN_WINDOWS) -> int:
    """Lookback (whole days) that can hold `windows` + `margin_windows` baseline windows.

    `baseline_windows` excludes the current bucket, so n history windows need lookback for n+1.
    Passing `windows=min_baseline_samples(scale), margin_windows=0` reproduces the 30-window
    floor's number (2/8/31/217) that the API has always reported as `required_lookback_days`.
    """
    seconds = int(EVIDENCE_SCALE_SECONDS.get(scale) or 0)
    if not seconds:
        return 0
    need = (windows_for_bar() if windows is None else int(windows)) + int(margin_windows)
    return math.ceil((need + 1) * seconds / 86400)


def scale_lookback_days(scale: str, retention_days: int) -> int:
    """The lookback this scale is READ at: what it needs, never more than retention holds.

    `max(LOOKBACK_DAYS, required)` keeps the 1h baseline at the seven days this layer shipped
    with (167 windows) instead of shrinking it toward its 5-day minimum; for every coarser scale
    the requirement is already larger. The result is capped by the retention in force, so a
    query can never ask a table for history its TTL has already dropped.
    """
    retention = max(0, int(retention_days))
    return min(retention, max(LOOKBACK_DAYS, required_lookback_days(scale)))


def lookbacks_for(retention_days: int, lookback_days: int | None = None) -> dict[str, int]:
    """Every scale's read window from one retention. `lookback_days` overrides for tests."""
    retention = max(0, int(retention_days))
    if lookback_days is not None:
        return {scale: min(max(0, int(lookback_days)), retention) for scale in EVIDENCE_SCALES}
    return {scale: scale_lookback_days(scale, retention) for scale in EVIDENCE_SCALES}


def retention_in_force(client: Any, specs: tuple[ChannelSpec, ...] = SPECS) -> dict[str, Any]:
    """The retention the source tables have IN FORCE, read from their TTLs.

    One `system.tables` read for the tables this layer actually queries; see
    `retention.days_in_force` for why the TTL (what `converge` wrote) is used instead of a fresh
    disk derivation. When the TTLs cannot be read the answer is the 7-day floor with
    `source: "default"`: a read failure must not grant a long scan the tables cannot support.
    """
    names = tuple(sorted({spec.table.rsplit(".", 1)[-1] for spec in specs}))
    try:
        info = retention_mod.days_in_force(client, names)
    except Exception as exc:  # noqa: BLE001 - an unreadable TTL is a named state, not a crash
        info = {"days": None, "source": "unreadable", "tables": {}, "unknown": list(names),
                "reason": f"{type(exc).__name__}: {str(exc)[:160]}"}
    if info.get("days") is None:
        info = dict(info)
        info["days"] = LOOKBACK_DAYS
        info["source"] = "default"
        info["reason"] = (info.get("reason")
                          or "the source tables' TTL could not be read; using the 7-day floor")
    return info


def baseline_windows(scale: str, lookback_days: int = LOOKBACK_DAYS) -> int:
    """How many non-overlapping baseline windows of `scale` fit before the current one."""
    seconds = EVIDENCE_SCALE_SECONDS.get(scale)
    if not seconds:
        return 0
    return max(0, int(lookback_days * 86400) // int(seconds) - 1)


def scale_report(scale: str, lookback_days: int | None = None,
                 retention_days: int | None = None,
                 max_p: float = DEFAULT_FAMILY_MAX_P,
                 kind: str | None = None,
                 observed_windows: int | None = None) -> dict[str, Any]:
    """The baseline a scale can offer, which test would produce its p, and whether it decides.

    THREE STATES, AND THE METHOD IS NAMED IN EACH:

      * `empirical` -- the lookback holds at least `windows_for_bar()` (100) windows, so the
        rank-based p can express a value below the family bar with no distributional assumption.
      * `parametric` -- fewer than 100 windows but at least the per-scale minimum, the scale's
        tail has been validated (`TAIL_ENABLED`), and the channel's statistic is a count. The p
        comes from a fitted negative binomial (or Poisson, when over-dispersion is not
        detectable), and `p_floor` is retained only as the EMPIRICAL floor for comparison.
      * `insufficient` -- neither. The scale is not measured rather than measured and refused.

    `kind` is the channel's statistic kind. It is optional because the scale-level API
    (`/api/ripples`) reports the scale, not a channel; when it is omitted, parametric usability
    is reported for the count kinds that can use it, and `tail_kinds` names them. When a caller
    passes a non-count kind (sum/ratio/change), the parametric state is refused with that reason.

    `p_floor` is the smallest p a FULL empirical baseline at this scale could express. A fitted
    tail has no such floor; its trust floor is `ripple_tail.TAIL_P_FLOOR` (1e-6), reported as
    `tail_p_floor`. `required_lookback_days_for_bar` remains the EMPIRICAL requirement
    (5/26/103/721), which is still the number that decides the `empirical` state.

    `observed_windows` is what the deployment ACTUALLY holds for this scale in the reading being
    described. When it is supplied, the method and usability are judged on it and `baseline_windows`
    is that number; `expected_windows` keeps the lookback's theoretical count. This is the
    difference between "a 24h scale could hold 102 windows" and "this deployment has 29": the
    first is a capability, the second is what a reader needs.
    """
    retention = LOOKBACK_DAYS if retention_days is None else max(0, int(retention_days))
    if lookback_days is None:
        lookback = scale_lookback_days(scale, retention)
        derived = True
    else:
        lookback = max(0, int(lookback_days))
        derived = False
    expected = baseline_windows(scale, lookback)
    windows = expected if observed_windows is None else max(0, int(observed_windows))
    minimum = min_baseline_samples(scale)
    floor = pvalue_floor(windows)
    seconds = int(EVIDENCE_SCALE_SECONDS.get(scale) or 0)
    need_windows = windows_for_bar(max_p)
    need_days = required_lookback_days(scale, windows=need_windows)
    floor_days = required_lookback_days(scale, windows=minimum, margin_windows=0)
    tail_ok = scale in TAIL_ENABLED and (kind is None or kind in TAIL_KINDS)
    method = "insufficient"
    if observed_windows is not None and windows == 0:
        # NO ROWS IS NOT A ZERO-WINDOW BASELINE. The scale may be perfectly capable; this
        # reading simply holds no measurement at it (the pass has not run, or coverage refused
        # every host). Say that rather than blaming the baseline's length.
        method = "insufficient"
        usable = False
        reason = (f"no measured rows at this scale in this reading; the lookback can hold "
                  f"{expected} window(s)")
    elif windows >= need_windows:
        method = "empirical"
        reason = ""
        usable = True
    elif windows >= minimum and tail_ok:
        method = "parametric"
        reason = ""
        usable = True
    elif windows < minimum:
        reason = (f"baseline too short at this scale: {windows} window(s), "
                  f"{minimum} required")
        usable = False
    elif kind is not None and kind not in TAIL_KINDS:
        reason = (f"baseline too short at this scale: {windows} window(s) cannot resolve "
                  f"p<{max_p:g} empirically, and a fitted count tail is not defined for a "
                  f"{kind} statistic")
        usable = False
    else:
        # Enough windows for a fit, but the scale's tail has not been validated (or is disabled).
        reason = (f"baseline too short at this scale: {lookback} day(s) of lookback hold "
                  f"{windows} window(s), but {need_days} day(s) are needed for {need_windows} "
                  f"windows to resolve p<{max_p:g}; retention allows {retention}. "
                  f"The fitted tail is not enabled here: "
                  f"{TAIL_DISABLED_REASON.get(scale, 'not validated at this deployment')}")
        usable = False
    return {
        "baseline_windows": windows,
        "expected_windows": expected,
        "observed_windows": None if observed_windows is None else int(observed_windows),
        "minimum_windows": minimum,
        "scale_seconds": seconds,
        "lookback_days": lookback,
        "retention_days": retention,
        "lookback_derived": derived,
        "required_lookback_days": floor_days,
        "required_lookback_days_for_bar": need_days,
        "windows_for_bar": need_windows,
        "lookback_margin_windows": LOOKBACK_MARGIN_WINDOWS,
        "p_floor": round(floor, 6),
        "p_floor_kind": "empirical",
        "method": method,
        "fallback_method": ("parametric" if method == "empirical" and tail_ok else None),
        "tail_p_floor": ripple_tail.TAIL_P_FLOOR if method == "parametric" else None,
        "tail_supported": bool(tail_ok),
        "validation": TAIL_VALIDATION.get(scale),
        "usable": usable,
        "reason": reason,
    }


def supported_scales(spec: ChannelSpec, lookback_days: int | None = None,
                     retention_days: int | None = None) -> list[str]:
    """The scales this channel can be measured at: the USABLE ones, given retention and the bar.

    A scale missing here is not measured at all. The test is `scale_report(...)["usable"]` -- the
    same empirical rule, the same fitted-tail eligibility (scale validated AND statistic a
    count) and the same 30-window floor the read path applies -- so the worker never spends a
    query on a baseline that could not support a ripple.
    """
    retention = LOOKBACK_DAYS if retention_days is None else max(0, int(retention_days))
    out: list[str] = []
    for scale in spec.scales:
        if scale not in EVIDENCE_SCALE_SECONDS:
            continue
        if lookback_days is None:
            wanted = scale_lookback_days(scale, retention)
        else:
            wanted = min(max(0, int(lookback_days)), retention)
        lookback = effective_lookback_days(spec, wanted, retention)
        if scale_report(scale, lookback, retention, kind=spec.kind).get("usable"):
            out.append(scale)
    return out


def statistic(spec: ChannelSpec) -> str:
    """One phrase naming what the channel measures, for the inventory and the operator."""
    if spec.channel == SERVICE_CHANNEL:
        return "services opened, closed or changed since the previous complete scan"
    if spec.kind == "count":
        return "rows per window"
    if spec.kind == "sum":
        return f"sum of {spec.value_column or spec.sum_state} per window"
    if spec.kind == "diversity":
        return f"distinct {spec.value_column or spec.uniq_state} per window"
    if spec.kind == "novelty":
        return f"{spec.value_column} values never seen in this host's history"
    if spec.kind == "change":
        return f"1 when {spec.value_column} differs from the host's previous window"
    return f"fraction where {spec.predicate}"


def inventory(lookback_days: int = LOOKBACK_DAYS,
              retention_days: int | None = None) -> list[dict[str, Any]]:
    """What this deployment can hear, as data rather than prose.

    `scales` is what the channel can be measured at TODAY; `scale_detail` says why each declared
    scale is or is not usable, including the baseline's p-value floor. A scale missing from
    `scales` is missing for a reason, and the reason is visible in `baseline_windows` and
    `p_floor` rather than hidden in a comment. `required_columns` is what `availability()`
    checks against the live schema, so the inventory states the contract as well as the result.

    `retention_days` is the live derived window. The per-spec constants (7/30/60/90) describe
    what each source was DESIGNED to keep; on a box that derived 30 days, advertising 90 days
    of Kerberos history would be a claim the tables cannot support. Every reported value and
    every effective lookback is capped to the derived window when it is supplied.
    """
    out: list[dict[str, Any]] = []
    live = None if retention_days is None else max(0, int(retention_days))
    for spec in SPECS:
        # WHEN A LIVE WINDOW IS SUPPLIED IT IS THE TABLE'S RETENTION. `retention.converge` puts
        # every managed table on the same derived window, so the design constants (7/30/60/90)
        # are not a second cap; see `effective_lookback_days`. Without a live value the constants
        # are all this function can honestly report, which is what the static inventory needs.
        claimed = int(spec.retention_days) if live is None else live
        effective = effective_lookback_days(spec, lookback_days, live)
        out.append({
            "channel": spec.channel,
            "family": spec.family,
            "source": spec.table,
            "statistic": statistic(spec),
            "scales": supported_scales(spec, lookback_days, live),
            "scale_detail": {scale: scale_report(scale, effective, live, kind=spec.kind)
                             for scale in spec.scales},
            "retention_days": claimed,
            "required_columns": list(spec.required_columns),
        })
    return out


def availability(client: Any, *,
                 specs: tuple[ChannelSpec, ...] = SPECS) -> list[dict[str, Any]]:
    """Which channels this deployment can actually read, and why not when it cannot.

    A CHANNEL WHOSE TABLE LACKS A COLUMN MUST NOT LOOK QUIET. `compute()` used to catch every
    exception and move on, so a renamed column produced zero evidence indistinguishable from a
    host with nothing to report. This compares each spec's `required_columns` with the live
    `system.columns` once and reports the missing names.

    NO INFORMATION IS NOT A MISSING COLUMN. A table that is absent from the reply -- an older
    ClickHouse, a fake client in a unit test, a probe that failed -- is reported as available
    and left to the read to decide. Refusing on absence of evidence would make a working
    channel disappear behind one failed probe.
    """
    tables = sorted({spec.table.split(".")[-1] for spec in specs})
    in_list = ", ".join(f"'{table}'" for table in tables)
    columns: dict[str, set[str]] = {}
    try:
        rows = client.query(
            "SELECT table, name FROM system.columns "
            f"WHERE database = 'weirvern' AND table IN ({in_list})"
        ).result_rows
    except Exception:  # noqa: BLE001 - an unreadable catalogue is not a missing column
        rows = []
    for table, name in rows or []:
        columns.setdefault(str(table or ""), set()).add(str(name or ""))
    out: list[dict[str, Any]] = []
    for spec in specs:
        present = columns.get(spec.table.split(".")[-1])
        missing = sorted(set(spec.required_columns) - present) if present is not None else []
        out.append({
            "channel": spec.channel,
            "family": spec.family,
            "table": spec.table,
            "available": not missing,
            "missing_columns": missing,
            "reason": "" if not missing else
                      f"{spec.table} is missing column(s): {', '.join(missing)}",
        })
    return out


def available_channels(client: Any, *,
                       specs: tuple[ChannelSpec, ...] = SPECS) -> dict[str, bool]:
    """channel -> whether its OWN table carries every column the channel requires.

    One `system.columns` read, the same one `availability()` makes; the join and the compute path
    therefore agree about which channels exist today.
    """
    return {str(row["channel"]): bool(row["available"])
            for row in availability(client, specs=specs)}


def feed_lane_channels(lane: str, *, specs: tuple[ChannelSpec, ...] = SPECS,
                       available: dict[str, bool] | None = None) -> dict[str, str]:
    """channel -> family for every channel a row from `lane` can be corroborated by.

    THE LANE IS A PIPELINE, NOT A FAMILY. A channel is offered when its OWN source table is one
    the lane's collector writes (`FEED_LANE_TABLES`) and, when a live `available` map is given,
    when that table has the columns the channel requires. A channel whose table is unavailable is
    absent rather than offered-and-silent: its evidence cannot exist, and the compute path records
    it as insufficient with the missing column names.

    `available=None` is the static answer (a test, or a caller with no catalogue): every channel
    on a lane table is offered. An unknown lane is an empty answer, never "every channel" -- a
    lane this module has not been told about must not widen the join by accident.
    """
    tables = set(FEED_LANE_TABLES.get(str(lane or "").strip().lower(), ()))
    if not tables:
        return {}
    out: dict[str, str] = {}
    for spec in specs:
        if spec.table not in tables:
            continue
        if available is not None and not available.get(spec.channel, True):
            continue
        out[spec.channel] = channel_family(spec.channel, spec.family)
    return out


def feed_lane_families(lane: str, *, specs: tuple[ChannelSpec, ...] = SPECS,
                       available: dict[str, bool] | None = None) -> frozenset[str]:
    """The FAMILIES a row from `lane` can be corroborated by (the join's own unit)."""
    return frozenset(feed_lane_channels(lane, specs=specs, available=available).values())



# ── measuring ───────────────────────────────────────────────────────────────────────────────

def _aware(value: datetime) -> datetime:
    """ClickHouse and callers both hand back naive UTC; this package compares aware UTC."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _value(spec: ChannelSpec, bucket: tuple[float, float, float]) -> float:
    """The statistic for one bucket: (n rows, u distinct-or-numerator, b sum)."""
    n, u, b = bucket
    if spec.kind == "count":
        return float(n)
    if spec.kind == "sum":
        return float(b)
    if spec.kind == "diversity":
        return float(u)
    if spec.kind == "ratio":
        # A ratio is already normalised: "12% of this host's connections reset" is comparable
        # across volumes. Dividing by a median again would turn a 1% normal into infinity.
        return float(u) / float(n) if n else 0.0
    return float("nan")


def _fold(rows: list[Any], *, factor: int) -> dict[str, dict[int, tuple[float, float, float]]]:
    """Bucket rows into `factor`-sized groups by summing the parts.

    Only valid for additive statistics, and only called for those. `diversity` is queried at the
    scale itself because a distinct count cannot be reconstructed from smaller distinct counts.
    """
    out: dict[str, dict[int, tuple[float, float, float]]] = {}
    for row in rows:
        host = str(row[0] or "")
        if not host or row[1] is None:
            continue
        index = int(row[1]) // max(1, int(factor))
        n = float(row[2] or 0)
        u = float(row[3] or 0)
        b = float(row[4] or 0) if len(row) > 4 else 0.0
        held = out.setdefault(host, {}).get(index)
        out[host][index] = (n, u, b) if held is None else (
            held[0] + n, held[1] + u, held[2] + b)
    return out


def _buckets(
    client: Any, spec: ChannelSpec, *, scale: str, moment: datetime, lookback_days: int,
    scope_cidrs: tuple[str, ...] | None,
    signatures: ripple_signatures.SignatureFilter | None = None,
) -> dict[str, dict[int, tuple[float, float, float]]]:
    """One channel's per-bucket values for one scale, including the current bucket at k=0."""
    seconds = EVIDENCE_SCALE_SECONDS[scale]
    step = STEP_SECONDS if spec.kind in ADDITIVE_KINDS else seconds
    sql = spec.sql_anchored(
        bucket_s=step,
        anchor=moment,
        since=moment - timedelta(days=int(lookback_days)),
        until=moment,
        scope_cidrs=scope_cidrs,
        signatures=signatures,
    )
    rows = list(client.query(sql).result_rows)
    return _fold(rows, factor=max(1, seconds // step))


def _value_sets(
    client: Any, spec: ChannelSpec, *, scale: str, moment: datetime, lookback_days: int,
    scope_cidrs: tuple[str, ...] | None,
    signatures: ripple_signatures.SignatureFilter | None = None,
) -> dict[str, dict[int, set[str]]]:
    """One channel's per-bucket VALUE SETS for one scale, including the current bucket at k=0.

    Only for `SET_KINDS`: a novelty or change channel asks WHICH values a window held, and the
    server returns them deduplicated rather than one row per event. A normalized signature is
    absent from every bucket the query returns, so it cannot be new in the current one.
    """
    seconds = EVIDENCE_SCALE_SECONDS[scale]
    sql = spec.sql_values(
        bucket_s=seconds,
        anchor=moment,
        since=moment - timedelta(days=int(lookback_days)),
        until=moment,
        scope_cidrs=scope_cidrs,
        signatures=signatures,
    )
    rows = list(client.query(sql).result_rows)
    out: dict[str, dict[int, set[str]]] = {}
    for row in rows:
        host = str(row[0] or "")
        if not host or row[1] is None:
            continue
        index = int(row[1])
        if index < 0:
            continue
        out.setdefault(host, {}).setdefault(index, set()).add(str(row[2] or ""))
    return out


def _novelty_series(by_index: dict[int, set[str]]) -> tuple[float, list[float]]:
    """(values new in the current bucket, how many were new in each earlier bucket).

    NOVELTY IS A SET DIFFERENCE, NOT A COUNT. "This host has never sent this user-agent" can
    only be answered by remembering WHICH values its earlier windows held; a per-window distinct
    count cannot be re-derived into it. Each historical bucket is scored against the buckets
    OLDER than itself, which is the same question the current bucket is asked -- otherwise the
    reference would measure something else and the rank would be meaningless.
    """
    reference: list[float] = []
    seen: set[str] = set()
    oldest = True
    for index in sorted(by_index, reverse=True):
        values = by_index[index]
        if index == 0:
            continue
        # THE OLDEST BUCKET IS NOT A NOVELTY MEASUREMENT. Everything in it would be "new"
        # against a history this window cannot see, so scoring it puts one guaranteed positive
        # value in every reference and doubles the smallest p the test can express. It enters
        # `seen` (its values ARE part of the host's history) but scores zero.
        if oldest:
            reference.append(0.0)
            seen |= values
            oldest = False
            continue
        reference.append(float(len(values - seen)))
        seen |= values
    current = float(len(by_index.get(0, set()) - seen))
    return current, reference


def _change_series(by_index: dict[int, set[str]]) -> tuple[float, list[float]]:
    """(changed in the current bucket?, changed in each earlier bucket?).

    A BOOLEAN, NOT A RATE. 1 means this bucket's value set differs from the bucket the host was
    last seen in; 0 means it is the same. The first bucket a host ever appears in scores 0:
    there is no previous observation to differ from, and inventing one would report a change on
    every host's first window.
    """
    reference: list[float] = []
    previous: str | None = None
    current = 0.0
    for index in sorted(by_index, reverse=True):
        signature = "|".join(sorted(by_index[index]))
        changed = 0.0 if previous is None or signature == previous else 1.0
        if index == 0:
            current = changed
            continue
        reference.append(changed)
        previous = signature
    return current, reference


def _measure(spec: ChannelSpec, *, scale: str, host: str, moment: datetime, value: float,
             reference: list[float], coverage: float, clause: str = "") -> ChannelEvidence | None:
    """One measurement, or None when there is nothing a p-value could be computed from.

    THE SELECTION RULE, IN ONE PLACE AND IN THIS ORDER:
      1. n >= `EMPIRICAL_MIN_WINDOWS` (100): the empirical two-sided rank p, unchanged. It needs
         no distributional assumption and is preferred whenever it can resolve the bar.
      2. `MIN_BASELINE_BY_SCALE <= n < 100` and the statistic is a count and the scale's tail is
         validated: fit a negative binomial (or Poisson when over-dispersion is not detectable)
         and use its two-sided tail. `p_method` records 'negbin' or 'poisson'.
      3. Otherwise: 'insufficient'. The row is still emitted, with `pvalue = NaN`, because an
         absent row would read as "not measured" while the truth is "measured, and the baseline
         cannot support a decision". It can never support a ripple (`_usable` refuses NaN).

    THE TWO REFUSALS MADE HERE are a non-finite statistic and an empty reference; every kind of
    channel refuses identically. `baseline_short` and `p_floor` travel with the row so the reader
    can tell a measurement from a result.
    """
    reference = [item for item in reference if math.isfinite(item)]
    if not math.isfinite(value) or not reference:
        return None
    median = float(statistics.median(reference))
    count = len(reference)
    method = P_METHOD_INSUFFICIENT
    detail = ""
    pvalue = float("nan")
    if count >= EMPIRICAL_MIN_WINDOWS:
        pvalue = empirical_pvalue_two_sided(value, reference)
        method = P_METHOD_EMPIRICAL
        detail = f"ranks n={count}"
    elif tail_supported(scale, spec.kind):
        fit = ripple_tail.fit_counts(reference)
        if fit.usable:
            pvalue = ripple_tail.tail_pvalue(value, fit)
            method = fit.method
            detail = fit.summary()
        else:
            detail = fit.summary()
    elif spec.kind not in TAIL_KINDS:
        detail = (f"insufficient: a fitted count tail is not defined for a {spec.kind} "
                  f"statistic; {count} window(s) cannot resolve p<{DEFAULT_FAMILY_MAX_P:g} "
                  f"empirically")
    else:
        detail = (f"insufficient: the fitted tail is not enabled at {scale} "
                  f"({TAIL_DISABLED_REASON.get(scale, 'not validated at this deployment')})")
    if method in PARAMETRIC_METHODS and not math.isfinite(pvalue):
        # The fit said usable but the value was not a count (a non-integer statistic). Report
        # that rather than falling back to a rank the baseline cannot resolve.
        method = P_METHOD_INSUFFICIENT
        detail = "insufficient: the current value is not a non-negative integer count"
    direction = "rose" if value > median else "fell" if value < median else "unchanged"
    # A CHANNEL MAY CARRY A PLAIN-LANGUAGE CLAUSE. `clause` is what the operator reads ("<host>
    # opened 8080/tcp ..."); `p_detail` stays the stored provenance, so it holds both the clause
    # and the test's own note. Other channels pass nothing here and their rows are unchanged.
    p_detail = detail
    if clause:
        p_detail = f"{clause} — {detail}" if detail else clause
    return ChannelEvidence(
        channel=spec.channel, family=spec.family, scale=scale,
        model_id=f"source:{spec.channel}", model_version=MODEL_VERSION,
        score=value, pvalue=pvalue, freshness_s=0.0, present=True,
        host=host, observed_at=moment, value=value, baseline_median=median,
        sample_count=count, coverage=round(coverage, 4), direction=direction,
        p_floor=pvalue_floor(count),
        # A parametric or insufficient row is not "short": it has the per-scale minimum. The
        # short flag is reserved for the floor the grouping also refuses.
        baseline_short=count < min_baseline_samples(scale),
        p_method=method, p_detail=p_detail, detail=clause,
    )


def _series_evidence(spec: ChannelSpec, *, scale: str,
                     buckets: dict[str, dict[int, set[str]]], moment: datetime,
                     wanted: set[str] | None,
                     lookback_days: int) -> list[ChannelEvidence]:
    """Evidence for a novelty/change channel, under the same floor and coverage rules."""
    expected = baseline_windows(scale, lookback_days)
    minimum = min_baseline_samples(scale)
    out: list[ChannelEvidence] = []
    for host, by_index in buckets.items():
        if wanted is not None and host not in wanted:
            continue
        # NO CURRENT BUCKET, NO EVIDENCE, for the same reason as every other channel: silence
        # and a broken collector are indistinguishable here.
        if not by_index.get(0):
            continue
        history = {index: values for index, values in by_index.items() if index >= 1}
        coverage = len(history) / expected if expected else 0.0
        if len(history) < minimum or coverage < MIN_COVERAGE:
            continue
        if spec.kind == "novelty":
            value, reference = _novelty_series(by_index)
        else:
            value, reference = _change_series(by_index)
        item = _measure(spec, scale=scale, host=host, moment=moment, value=value,
                        reference=reference, coverage=coverage)
        if item is not None:
            out.append(item)
    return out


def _evidence_for_scale(spec: ChannelSpec, *, scale: str, buckets: dict[str, dict[int, tuple]],
                        moment: datetime, wanted: set[str] | None,
                        lookback_days: int) -> list[ChannelEvidence]:
    expected = baseline_windows(scale, lookback_days)
    minimum = min_baseline_samples(scale)
    out: list[ChannelEvidence] = []
    for host, by_index in buckets.items():
        if wanted is not None and host not in wanted:
            continue
        current = by_index.get(0)
        # NO CURRENT BUCKET, NO EVIDENCE. A host with no rows this hour may be silent or the
        # collector may be down; this layer cannot tell those apart, and inventing a zero would
        # turn a broken feed into a "drop" on every host at once.
        if current is None:
            continue
        history = {index: bucket for index, bucket in by_index.items() if index >= 1}
        coverage = len(history) / expected if expected else 0.0
        if len(history) < minimum or coverage < MIN_COVERAGE:
            continue
        value = _value(spec, current)
        reference = [_value(spec, bucket) for bucket in history.values()]
        item = _measure(spec, scale=scale, host=host, moment=moment, value=value,
                        reference=reference, coverage=coverage)
        if item is not None:
            out.append(item)
    return out


def _service_scope_where(scope_cidrs: tuple[str, ...] | None) -> str:
    """The monitored-scope predicate for the scanner tables, which key the host as `ip`.

    Same rule as every other channel: `None` means a caller without a scope list (tests), an
    empty list means nothing is ours and the query must match nothing rather than everything.
    """
    if scope_cidrs is None:
        return ""
    if not scope_cidrs:
        return " AND 0"
    checks = " OR ".join(f"isIPAddressInRange(ip, '{cidr}')" for cidr in scope_cidrs)
    return f" AND ({checks})"


def service_snapshots(
    client: Any, *, moment: datetime, lookback_days: int,
    scope_cidrs: tuple[str, ...] | None,
) -> dict[str, list[tuple[datetime, str, set[tuple[int, str, str, str, str]]]]]:
    """Each host's COMPLETE scans, oldest first, with the service set each one measured.

    The two reads are the scan LEDGER and the append-only HISTORY, never the current snapshot:
    a baseline must be built from what each scan measured, and `asset_services` is only the
    newest of those by design.

    A SCAN WITH NO HISTORY ROWS IS AN EMPTY SET, NOT A MISSING MEASUREMENT -- but only because
    the ledger says `scan_complete = 1`. That is the distinction the column exists for: a host
    that closed every port and a scan that timed out both produce no service rows, and only the
    first is evidence of closure.
    """
    since = moment - timedelta(days=int(lookback_days))
    parameters = {"since": since, "until": moment}
    where = _service_scope_where(scope_cidrs)
    scans = list(client.query(
        # THE AGGREGATE ALIAS IS NOT `finished_at`. ClickHouse substitutes a SELECT alias into
        # the WHERE clause, so `max(finished_at) AS finished_at` reads as an aggregate in WHERE
        # and the query fails with code 184 (measured live, first run of this channel). The
        # alias is `last_finished` for exactly that reason.
        "SELECT scan_id, ip, max(finished_at) AS last_finished "
        "FROM weirvern.asset_scans "
        "WHERE kind = 'service' AND status = 'done' AND scan_complete = 1 "
        "  AND finished_at IS NOT NULL "
        "  AND finished_at >= %(since)s AND finished_at < %(until)s"
        + where +
        " GROUP BY scan_id, ip ORDER BY last_finished",
        parameters=parameters,
    ).result_rows)
    rows = list(client.query(
        "SELECT scan_id, ip, port, protocol, service, product, version "
        "FROM weirvern.asset_service_history "
        "WHERE observed_at >= %(since)s AND observed_at < %(until)s"
        + where,
        parameters=parameters,
    ).result_rows)
    measured: dict[tuple[str, str], set[tuple[int, str, str, str, str]]] = {}
    for row in rows:
        try:
            port = int(row[2] or 0)
        except (TypeError, ValueError):
            continue
        key = (str(row[1] or ""), str(row[0] or ""))
        if not key[0] or not key[1]:
            continue
        measured.setdefault(key, set()).add((
            port, str(row[3] or "tcp").lower(), str(row[4] or ""), str(row[5] or ""),
            str(row[6] or ""),
        ))
    series: dict[str, list[tuple[datetime, str, set[tuple[int, str, str, str, str]]]]] = {}
    seen: set[tuple[str, str]] = set()
    for row in scans:
        scan_id, host = str(row[0] or ""), str(row[1] or "")
        if not scan_id or not host or row[2] is None:
            continue
        if (host, scan_id) in seen:
            continue
        seen.add((host, scan_id))
        series.setdefault(host, []).append(
            (_aware(row[2]), scan_id, measured.get((host, scan_id), set())))
    for entries in series.values():
        entries.sort(key=lambda entry: (entry[0], entry[1]))
    return series


def _service_label(row: tuple[int, str, str, str, str]) -> str:
    """What a person calls this service: its product and version, else its name."""
    _, _, service, product, version = row
    label = " ".join(part for part in (product, version) if part)
    return label or service or "open service"


def service_change_sentence(host: str, previous: Any, current: Any) -> str:
    """The change between two scans, in words an operator can act on.

    `192.0.2.10 opened 8080/tcp (Golang net/http) since the previous scan` is the contract; a
    version change names BOTH versions (`changed 22/tcp from OpenSSH 9.6 to OpenSSH 10.0`).
    The classification is `asset_changes.detect_service_changes`, the same definition the change
    ledger uses, so the sentence and the ledger cannot disagree about what kind of change it is.
    """
    before = {(row[0], row[1]): row for row in previous}
    after = {(row[0], row[1]): row for row in current}
    clauses: list[str] = []
    for change in detect_service_changes(sorted(previous), sorted(current)):
        key = (change.port, change.protocol)
        if change.kind == "port_opened" and key in after:
            row = after[key]
            clauses.append(f"opened {row[0]}/{row[1]} ({_service_label(row)})")
        elif change.kind == "port_closed" and key in before:
            row = before[key]
            clauses.append(f"closed {row[0]}/{row[1]} ({_service_label(row)})")
        elif key in before and key in after:
            old, new = before[key], after[key]
            clauses.append(f"changed {new[0]}/{new[1]} from {_service_label(old)} "
                           f"to {_service_label(new)}")
    if not clauses:
        return f"{host} has no service change since the previous scan"
    return f"{host} " + "; ".join(clauses) + " since the previous scan"


def _service_insufficient(spec: ChannelSpec, *, host: str, moment: datetime,
                          sentence: str) -> ChannelEvidence:
    """A measurement that exists but cannot be compared: no previous scan, or no baseline.

    EMITTED, NOT SKIPPED. "There is no previous scan" and "nothing changed" are different facts,
    and a missing row would read as the second. `pvalue` is NaN (never 1.0) and
    `baseline_short` is True, so `_usable` refuses it exactly as it refuses any other
    insufficient row.
    """
    return ChannelEvidence(
        channel=spec.channel, family=spec.family, scale="1h",
        model_id=f"source:{spec.channel}", model_version=MODEL_VERSION,
        score=float("nan"), pvalue=float("nan"), freshness_s=0.0, present=True,
        host=host, observed_at=moment, value=float("nan"), baseline_median=float("nan"),
        sample_count=0, coverage=1.0, direction="",
        p_floor=pvalue_floor(0), baseline_short=True,
        p_method=P_METHOD_INSUFFICIENT, p_detail=sentence, detail=sentence,
    )


def _service_evidence(
    spec: ChannelSpec, *, series: dict[str, list[tuple[datetime, str, set]]],
    wanted: set[str] | None,
) -> list[ChannelEvidence]:
    """One evidence row per host for its newest complete scan against the previous one."""
    out: list[ChannelEvidence] = []
    for host, entries in series.items():
        if wanted is not None and host not in wanted:
            continue
        if not entries:
            continue
        entries = entries[-SERVICE_SCAN_MAX_BASELINE:]
        latest_at, _latest_id, latest = entries[-1]
        if len(entries) < 2:
            out.append(_service_insufficient(
                spec, host=host, moment=latest_at,
                sentence=(f"insufficient: {host} has one complete scan, so there is no "
                          f"previous scan to compare it with")))
            continue
        previous = entries[-2][2]
        sentence = service_change_sentence(host, previous, latest)
        transitions = [
            1.0 if entries[index][2] != entries[index - 1][2] else 0.0
            for index in range(1, len(entries))
        ]
        value, reference = transitions[-1], transitions[:-1]
        if not reference:
            out.append(_service_insufficient(
                spec, host=host, moment=latest_at,
                sentence=(f"insufficient: {sentence}; this host has one earlier scan, which "
                          f"is a comparison but not a baseline")))
            continue
        item = _measure(spec, scale="1h", host=host, moment=latest_at, value=value,
                        reference=reference, coverage=1.0, clause=sentence)
        if item is not None:
            out.append(item)
    return out


def _slice_buckets(buckets: dict[str, dict[int, tuple[float, float, float]]],
                   keep: int) -> dict[str, dict[int, tuple[float, float, float]]]:
    """Keep the buckets inside one scale's OWN lookback (k=0 is the current bucket).

    ONE QUERY, SEVERAL SCALES. Additive channels are queried once at the finest bucket over the
    WIDEST usable scale's lookback, then folded. A coarser fold must not hand the 1h scale 103
    days of history: each scale gets exactly the windows its own lookback holds, so its coverage
    and p-value are the same numbers a per-scale query would have produced.
    """
    if keep <= 0:
        return {}
    return {host: {index: value for index, value in by_index.items() if index < keep}
            for host, by_index in buckets.items()}


def compute(client: Any, *, now: datetime | None = None, hosts: list[str] | None = None,
            lookback_days: int | None = None,
            retention_days: int | None = None,
            specs: tuple[ChannelSpec, ...] = SPECS,
            monitored_nets: list[Any] | None = None,
            signatures: ripple_signatures.SignatureFilter | None = None) -> list[ChannelEvidence]:
    """Every channel's evidence for every host it can be measured for, at every usable scale.

    THE OPERATOR'S SIGNATURES ARE A FILTER, NOT A SILENCE. When `signatures` is not supplied the
    live, unexpired ones are read once and handed to every value-bearing channel query, which
    excludes exactly those (host, channel, value) pairs from the distinct/novelty computation.
    The raw rows are not read differently, written or deleted; the statistic simply no longer
    counts the value the operator has said is expected. An unreadable signature store leaves the
    measurement UNFILTERED and says so in `run()`'s receipt -- a table problem must not turn into
    a quiet network.

    THE LOOKBACK IS DERIVED, PER SCALE, FROM RETENTION. With no explicit `lookback_days` each
    scale reads `scale_lookback_days(scale, retention)` days, where retention is read from the
    source tables' own TTLs (`retention_in_force`). `lookback_days` is the override tests and a
    caller that knows the window use; it is still capped by retention, so no query asks a table
    for history its TTL has dropped.

    ONLY MONITORED SUBJECTS. The operator's monitored networks are read from `network_scopes`
    unless the caller supplies them. Every row is attributed in SQL to its monitored endpoint
    (source first, otherwise destination), and an empty scope list produces no evidence at all:
    "we could not work out what we own" must not degrade into "measure everything".

    A source that cannot be read is skipped, not fatal: one missing table must not silence the
    other channels. A channel whose table lacks a REQUIRED COLUMN is skipped deliberately and
    named by `availability()`; one missing table must not become sixteen unexplained silences.
    """
    nets = (monitored_nets if monitored_nets is not None
            else monitored_mod.networks(client))
    if not nets:
        return []
    cidrs = tuple(str(net) for net in nets)
    moment = _aware(now or datetime.now(UTC)).replace(microsecond=0)
    if signatures is None:
        signatures = ripple_signatures.load_filter(client, today=moment.date(), hosts=hosts)
    if retention_days is not None:
        retention = max(0, int(retention_days))
    elif lookback_days is not None:
        # An explicit lookback IS the retention for this call: the old behaviour, kept so a
        # test (or a replay at a known window) never reads beyond what it asked for.
        retention = max(0, int(lookback_days))
    else:
        retention = int(retention_in_force(client, specs)["days"])
    lookbacks = lookbacks_for(retention, lookback_days)
    missing_columns = {row["channel"] for row in availability(client, specs=specs)
                       if not row["available"]}
    wanted = set(hosts) if hosts is not None else None
    out: list[ChannelEvidence] = []
    for spec in specs:
        if spec.channel in missing_columns:
            continue
        if spec.channel == SERVICE_CHANNEL:
            # THE ONE CHANNEL WHOSE WINDOW IS A SCAN, NOT A CLOCK INTERVAL. It cannot use the
            # generic SQL shapes (`sql_anchored` aggregates a table by time; this compares two
            # rows of a scan ledger), so it has its own reader, but the p-value, the floors, the
            # evidence row and the grouping are the SAME machinery as every other channel.
            try:
                scan_lookback = min(max(lookbacks.values()), SERVICE_SCAN_LOOKBACK_CAP_DAYS)
                series = service_snapshots(client, moment=moment,
                                           lookback_days=scan_lookback, scope_cidrs=cidrs)
                out.extend(_service_evidence(spec, series=series, wanted=wanted))
            except Exception:  # noqa: BLE001 - one unreadable source must not silence the rest
                pass
            continue
        scales = supported_scales(spec, lookback_days, retention)
        if not scales:
            continue
        try:
            if spec.kind in ADDITIVE_KINDS:
                # ONE QUERY AT THE FINEST BUCKET, folded up for every scale. The query covers the
                # WIDEST scale's lookback (103 days when 24h is usable, 26 when only 6h is); each
                # scale is then sliced back to its own window, so a coarse scale cannot lengthen
                # the 1h baseline. The per-scale cap is what keeps one pass from reading retention.
                widest = max(scales, key=lambda name: lookbacks[name])
                base = _buckets(client, spec, scale="1h", moment=moment,
                                lookback_days=lookbacks[widest], scope_cidrs=cidrs,
                                signatures=signatures)
                for scale in scales:
                    factor = EVIDENCE_SCALE_SECONDS[scale] // STEP_SECONDS
                    folded = _fold_from_buckets(base, factor)
                    window_limit = lookbacks[scale] * 86400 // EVIDENCE_SCALE_SECONDS[scale]
                    out.extend(_evidence_for_scale(
                        spec, scale=scale, buckets=_slice_buckets(folded, window_limit),
                        moment=moment, wanted=wanted, lookback_days=lookbacks[scale]))
            elif spec.kind in SET_KINDS:
                # A SET cannot be rolled up from smaller buckets: "was this value new?" is a
                # question about the whole window, so each scale is queried at its own length.
                for scale in scales:
                    value_sets = _value_sets(client, spec, scale=scale, moment=moment,
                                             lookback_days=lookbacks[scale], scope_cidrs=cidrs,
                                             signatures=signatures)
                    out.extend(_series_evidence(
                        spec, scale=scale, buckets=value_sets, moment=moment,
                        wanted=wanted, lookback_days=lookbacks[scale]))
            else:
                for scale in scales:
                    buckets = _buckets(client, spec, scale=scale, moment=moment,
                                       lookback_days=lookbacks[scale], scope_cidrs=cidrs,
                                       signatures=signatures)
                    out.extend(_evidence_for_scale(
                        spec, scale=scale, buckets=buckets, moment=moment,
                        wanted=wanted, lookback_days=lookbacks[scale]))
        except Exception:  # noqa: BLE001 - one unreadable source must not silence the rest
            continue
    # DEFENCE IN DEPTH: the SQL attributed every row, but a stored or injected row must never
    # leave this function under a peer address.
    out = [item for item in out if monitored_mod.in_scope(item.host, nets)]
    out.sort(key=lambda item: (item.host, item.channel, item.scale))
    if wanted is None and len({item.host for item in out}) > MAX_HOSTS:
        keep = sorted({item.host for item in out})[:MAX_HOSTS]
        out = [item for item in out if item.host in set(keep)]
    return out


def _fold_from_buckets(buckets: dict[str, dict[int, tuple[float, float, float]]],
                       factor: int) -> dict[str, dict[int, tuple[float, float, float]]]:
    """Roll already-folded one-hour buckets up to a coarser scale."""
    if factor <= 1:
        return buckets
    out: dict[str, dict[int, tuple[float, float, float]]] = {}
    for host, by_index in buckets.items():
        for index, (n, u, b) in by_index.items():
            target = index // factor
            held = out.setdefault(host, {}).get(target)
            out[host][target] = (n, u, b) if held is None else (
                held[0] + n, held[1] + u, held[2] + b)
    return out


# ── persistence ─────────────────────────────────────────────────────────────────────────────

COLUMNS = ["window_start", "window_end", "src_addr", "channel", "family", "scale", "value",
           "baseline_median", "p_value", "p_method", "p_detail", "sample_count", "coverage",
           "direction", "model_version", "observed_at", "computed_at"]


def _row(item: ChannelEvidence) -> list[Any]:
    moment = item.observed_at or datetime.now(UTC)
    start = moment.replace(minute=0, second=0, microsecond=0)
    return [start, start + timedelta(seconds=RIPPLE_WINDOW_S), item.host, item.channel,
            item.family, item.scale, float(item.value), float(item.baseline_median),
            float(item.pvalue), item.p_method, item.p_detail, int(item.sample_count),
            float(item.coverage), item.direction, MODEL_VERSION, moment, moment]


def store(client: Any, items: list[ChannelEvidence]) -> int:
    """Write one row per (window, host, channel, scale); ReplacingMergeTree keeps the newest."""
    rows = [_row(item) for item in items if item.host]
    if not rows:
        return 0
    client.insert("weirvern.ml_ripple_evidence", rows, column_names=COLUMNS)
    return len(rows)


READ_COLUMNS = ["window_start", "window_end", "src_addr", "channel", "family", "scale", "value",
                "baseline_median", "p_value", "p_method", "p_detail", "sample_count", "coverage",
                "direction", "observed_at"]

READ_SQL = (
    "SELECT " + ", ".join(READ_COLUMNS) + " "
    "FROM weirvern.ml_ripple_evidence FINAL "
    "WHERE window_start >= %(since)s "
    "ORDER BY window_start DESC, src_addr, channel, scale "
    "LIMIT %(limit)s"
)

#: The pre-`p_method` column list. Used ONLY when the read above fails because the migration has
#: not been applied yet (a rollout window): every row written before the column existed was
#: produced by the empirical test, so the fallback labels them correctly rather than taking the
#: Ripples page down. A real query failure still propagates from the fallback and is reported.
LEGACY_READ_COLUMNS = [name for name in READ_COLUMNS if name not in ("p_method", "p_detail")]
LEGACY_READ_SQL = (
    "SELECT " + ", ".join(LEGACY_READ_COLUMNS) + " "
    "FROM weirvern.ml_ripple_evidence FINAL "
    "WHERE window_start >= %(since)s "
    "ORDER BY window_start DESC, src_addr, channel, scale "
    "LIMIT %(limit)s"
)

#: A bounded read. 24h at this deployment's cardinality is ~26k rows; the cap keeps a 7-day
#: window from turning one poll into an unbounded scan while still covering every host.
MAX_READ_ROWS = 100_000


def _read_rows(client: Any, *, since: datetime, limit: int) -> list[Any]:
    """The stored rows, with a one-step fallback for a deployment mid-migration."""
    parameters = {"since": since, "limit": limit}
    try:
        return list(client.query(READ_SQL, parameters=parameters).result_rows)
    except Exception:
        return list(client.query(LEGACY_READ_SQL, parameters=parameters).result_rows)


def read(client: Any, *, hours: int = 24, now: datetime | None = None) -> list[ChannelEvidence]:
    """Evidence inside the window, newest first, as `ChannelEvidence` objects."""
    moment = _aware(now or datetime.now(UTC))
    since = moment - timedelta(hours=max(1, int(hours)))
    rows = _read_rows(client, since=since, limit=MAX_READ_ROWS)
    out: list[ChannelEvidence] = []
    for row in rows:
        if len(row) >= 15:
            (window_start, _window_end, host, channel, family, scale, value, median, pvalue,
             p_method, p_detail, sample_count, coverage, direction, observed_at) = row[:15]
        else:
            (window_start, _window_end, host, channel, family, scale, value, median, pvalue,
             sample_count, coverage, direction, observed_at) = row[:13]
            p_method, p_detail = P_METHOD_EMPIRICAL, ""
        out.append(ChannelEvidence(
            channel=str(channel or ""), family=str(family or ""), scale=str(scale or ""),
            model_id=f"source:{channel}", model_version=MODEL_VERSION,
            score=float(value or 0.0), pvalue=float(pvalue), freshness_s=0.0, present=True,
            host=str(host or ""), observed_at=_aware(observed_at),
            value=float(value or 0.0), baseline_median=float(median or 0.0),
            sample_count=int(sample_count or 0), coverage=float(coverage or 0.0),
            direction=str(direction or ""),
            p_floor=pvalue_floor(int(sample_count or 0)),
            baseline_short=int(sample_count or 0) < min_baseline_samples(str(scale or "")),
            p_method=str(p_method or P_METHOD_EMPIRICAL),
            p_detail=str(p_detail or ""),
            # A SERVICE ROW'S p_detail IS ITS SENTENCE. Every other channel's p_detail is the
            # fit's provenance, so restoring `detail` unconditionally would put "ranks n=254"
            # in the operator's sentence. Only the channel that WRITES a clause reads one back.
            detail=(str(p_detail or "") if str(channel or "") == SERVICE_CHANNEL else ""),
        ))
    return out


def run(client: Any, *, now: datetime | None = None, hosts: list[str] | None = None,
        lookback_days: int | None = None,
        retention_days: int | None = None) -> dict[str, Any]:
    """Measure every channel, store the evidence, and return the counts the worker logs.

    THE RIPPLES ARE NOT STORED. A ripple is a deterministic projection of its evidence, so
    persisting it would create a second copy that can disagree with the rows it is made of
    (after a TTL, a re-run, or a changed grouping constant). The read path groups evidence
    instead, which keeps the explanation and the numbers in the same rows.

    THE DERIVATION IS PART OF THE RECEIPT. `retention_days`, `retention_source` and the
    per-scale `lookbacks` are returned (and logged by the worker) so a pass that read 26 days
    for 6h can be told apart from one that fell back to 7 because the TTL was unreadable.
    """
    if retention_days is not None:
        info: dict[str, Any] = {"days": max(0, int(retention_days)), "source": "explicit",
                                "tables": {}, "unknown": [], "reason": ""}
    elif lookback_days is not None:
        info = {"days": max(0, int(lookback_days)), "source": "explicit lookback",
                "tables": {}, "unknown": [], "reason": ""}
    else:
        info = retention_in_force(client)
    # ONE READ, AND THE RECEIPT NAMES IT. A filter that could not be read leaves the measurement
    # unfiltered (the safe direction for a table problem) but must not be invisible: the worker
    # log prints `signatures=unavailable:<reason>` rather than quietly ignoring the operator's
    # normalizations.
    signatures = ripple_signatures.load_filter(client, today=_aware(now or datetime.now(UTC)).date())
    items = compute(client, now=now, hosts=hosts, lookback_days=lookback_days,
                    retention_days=info["days"], signatures=signatures)
    stored = store(client, items)
    unavailable = [{"channel": row["channel"], "reason": row["reason"]}
                   for row in availability(client) if not row["available"]]
    # THE METHOD IS PART OF THE RECEIPT. A pass that produced 6h rows from a fitted tail must be
    # distinguishable from one that produced them empirically (or not at all), per scale.
    methods: dict[str, int] = {}
    scale_methods: dict[str, dict[str, int]] = {}
    for item in items:
        methods[item.p_method] = methods.get(item.p_method, 0) + 1
        bucket = scale_methods.setdefault(item.scale, {})
        bucket[item.p_method] = bucket.get(item.p_method, 0) + 1
    return {
        "evidence": len(items),
        "rows": stored,
        "hosts": len({item.host for item in items}),
        "channels": len({item.channel for item in items}),
        "declared_channels": len(SPECS),
        "unavailable": unavailable,
        "scales": sorted({item.scale for item in items}),
        "p_methods": methods,
        "scale_methods": scale_methods,
        "tail_scales": sorted(TAIL_ENABLED),
        "retention_days": info["days"],
        "retention_source": info["source"],
        "lookbacks": lookbacks_for(info["days"], lookback_days),
        "signatures": {
            "available": signatures.available,
            "live": signatures.count,
            "reason": signatures.reason,
            "channels": len(SIGNATURE_CHANNELS),
        },
        "model_version": MODEL_VERSION,
    }


def overview(client: Any, *, hours: int = 24, now: datetime | None = None) -> dict[str, Any]:
    """The read path: ripples plus the evidence they were grouped from, newest first.

    A failed read is a NAMED, EMPTY answer, not an exception and never a 500: the Models card
    must be able to draw "the evidence could not be read" around an empty list, which is a
    different statement from "no ripple formed". `available: false` is that distinction.

    `baseline` is the other distinction the card needs: a scale whose baseline cannot resolve
    the ripple bar is reported as such, with its window count and p-value floor, instead of
    letting a floor value be printed as if it were a result. Each scale reports the lookback it
    is read at (`lookback_days`), the retention that lookback was derived from
    (`retention_days`), and what the bar actually needs (`required_lookback_days_for_bar`), so
    the empty state can say which number is short instead of only "not enough history".
    `monitored_networks` is the scope the subjects were filtered to; an empty list means no
    subject could be attributed.
    """
    window_hours = max(1, int(hours))
    try:
        items = read(client, hours=window_hours, now=now)
    except Exception as exc:  # noqa: BLE001 - a read failure is a state, not a crash
        return {
            "available": False,
            "reason": f"could not read the ripple evidence: {type(exc).__name__}: "
                      f"{str(exc)[:160]}",
            "window_hours": window_hours,
            "model_version": MODEL_VERSION,
            "count": 0,
            "ripples": [],
            "severity_bands": severity_bands(),
        }
    nets = monitored_mod.networks(client)
    in_scope = [item for item in items if monitored_mod.in_scope(item.host, nets)]
    ripples = group_evidence(in_scope, monitored=nets)
    # ONE READ FOR EVERY SCALE. The TTLs are read once and each scale derives its own lookback
    # from the same number; the block below is what makes that derivation inspectable.
    retention = retention_in_force(client)
    # WHAT THE DEPLOYMENT ACTUALLY HOLDS, per scale, from the rows just read. A scale whose
    # lookback COULD hold 102 windows but whose rows hold 29 is not a working scale, and the
    # baseline block below says so rather than printing the capability as if it were the state.
    observed_windows = {
        scale: max((item.sample_count for item in in_scope if item.scale == scale), default=0)
        for scale in EVIDENCE_SCALES
    }
    # WHICH EVIDENCE LINES CAN BECOME A SIGNATURE. The sheet puts the verb on every row, and a
    # row that measures a rate (volume, ratio, sum) has no single value to name. The capability
    # is computed HERE, from the specs, so the browser never keeps a second copy of the list.
    payload_ripples: list[dict[str, Any]] = []
    for ripple in ripples:
        data = ripple.as_dict()
        for event in data.get("evidence", []):
            event["signature_capable"] = event.get("channel") in SIGNATURE_CHANNELS
        payload_ripples.append(data)
    return {
        "available": True,
        "reason": "",
        "window_hours": window_hours,
        "model_version": MODEL_VERSION,
        "count": len(ripples),
        "ripples": payload_ripples,
        "signature_channels": sorted(SIGNATURE_CHANNELS),
        # THE CRITICALITY TABLE TRAVELS WITH THE ROWS. The page's legend and its fallback
        # banding read these numbers; none of them is restated in JavaScript.
        "severity_bands": severity_bands(),
        "monitored_networks": [str(net) for net in nets],
        "baseline": {scale: scale_report(scale, retention_days=retention["days"],
                                         observed_windows=observed_windows[scale])
                     for scale in EVIDENCE_SCALES},
        # WHICH TEST PRODUCED THE P-VALUES IN THIS WINDOW, per method and per scale. A reader
        # can tell a rank from a fitted tail without opening a row; the rows carry the same
        # label individually.
        "methods": {
            "by_method": {method: sum(1 for item in in_scope if item.p_method == method)
                          for method in sorted({item.p_method for item in in_scope})},
            "by_scale": {
                scale: {method: sum(1 for item in in_scope
                                    if item.scale == scale and item.p_method == method)
                        for method in sorted({item.p_method for item in in_scope
                                              if item.scale == scale})}
                for scale in sorted({item.scale for item in in_scope})
            },
            "tail_scales": sorted(TAIL_ENABLED),
            "tail_kinds": sorted(TAIL_KINDS),
            # THE OBSERVED WINDOW COUNT, not the lookback's theoretical one. A scale can be
            # capable of 102 windows and hold 29; the two numbers answer different questions.
            "observed_windows": observed_windows,
        },
        "retention": {
            "days": retention["days"],
            "source": retention["source"],
            "reason": retention.get("reason") or "",
            "tables": retention.get("tables") or {},
            "unknown": retention.get("unknown") or [],
        },
        "evidence": {
            "rows": len(items),
            "monitored_rows": len(in_scope),
            "subjects": len({item.host for item in in_scope}),
            "baseline_short_rows": sum(1 for item in in_scope if item.baseline_short),
            "insufficient_rows": sum(1 for item in in_scope
                                     if item.p_method == P_METHOD_INSUFFICIENT),
        },
    }


__all__ = ["COLUMNS", "FEED_LANE_TABLES", "LOOKBACK_DAYS", "LOOKBACK_MARGIN_WINDOWS", "MAX_HOSTS",
           "MIN_BASELINE_SAMPLES", "MIN_COVERAGE", "MODEL_VERSION", "SERVICE_CHANNEL",
           "SERVICE_SCAN_LOOKBACK_CAP_DAYS", "SERVICE_SCAN_MAX_BASELINE", "SERVICE_SPECS",
           "SET_KINDS", "SIGNATURE_CHANNELS", "SPECS", "TAIL_DISABLED_REASON", "TAIL_ENABLED",
           "TAIL_KINDS", "TAIL_VALIDATION",
           "availability", "available_channels", "baseline_windows", "compute",
           "effective_lookback_days", "feed_lane_channels", "feed_lane_families", "inventory",
           "lookbacks_for", "overview", "read", "required_lookback_days", "retention_in_force",
           "run", "scale_lookback_days", "scale_report", "service_change_sentence",
           "service_snapshots", "statistic", "store", "supported_scales", "tail_supported",
           "windows_for_bar"]
