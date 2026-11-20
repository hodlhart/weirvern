"""The pieces a ripple is made of: one host, one channel, one scale, one empirical p-value.

WHY THIS EXISTS. The operator asked to "show all the ml and the pieces of ripples, then the
anomaly page is actually the ripples". This module is the missing middle: the fusion in
`ripple.py` could say whether a handful of shadow models agreed, and `generic_channels.py` could
score one five-minute window per source, but nothing measured a channel against the SAME host's
own trailing history at more than one scale, and nothing stored the measurement so it could be
read back. A ripple is only as good as the evidence under it.

WHAT A RIPPLE IS HERE. A small, statistically significant change in one channel's behaviour for
one host, measured against that host's OWN trailing history with an empirical p-value. No human
labels and no synthetic ground truth: the baseline is the host's own past, ranked. Several
pieces of evidence that line up in one time window on one host are grouped into one `Ripple` by
`ripple.group_evidence`; the ripple is what an operator reads, the evidence is what it is made
of.

THE SCALES, AND A LOOKBACK DERIVED FROM THE RETENTION IN FORCE. A scale is the length of the
window being measured: 1h, 6h, 24h, 7d. A channel can only be measured at a scale the lookback
can supply a baseline for, and the baseline samples are NON-OVERLAPPING windows of that length.

The lookback is not a constant. `scale_lookback_days()` derives it per scale from the retention
the tables have IN FORCE -- `retention.days_in_force()`, which reads each source table's TTL
back from `system.tables` -- and caps it at what that scale needs:

    scale  1h    6h     24h    7d
    need   5d    26d    103d   721d      (100 windows + 2 spare, see below)
    read   7d    26d    103d   258d      (1h keeps the 7-day floor; 7d is capped by retention)
    at a 258-day retention the first three are usable; 7d is not

TWO NUMBERS, AND THEY ARE NOT THE SAME. The 30-window floor is what makes a rank worth
computing, and `required_lookback_days` still reports the lookback it needs (2/8/31/217). But
p = 1/(n+1), so thirty windows can express no p below 0.032 and only 100 windows can resolve the
0.01 family bar. A scale is therefore READ only when its lookback can hold `windows_for_bar()`
baseline windows. This is why 6h needs 26 days and not 8: at 8 days it has 31 windows and a
p-floor of 0.031, so no row from it could ever support a ripple. The 30-window floor is
unchanged and still refuses a measurement; it was simply never the only bar.

NEVER BEYOND RETENTION, AND NEVER A WISH. `scale_lookback_days` returns
`min(retention_days, max(7, required))`: a query never reads further back than the tables keep
(it would be empty), and a scale whose requirement exceeds retention is reported unusable with
both numbers named rather than measured at a lookback the tables cannot hold. The 7d scale needs
721 days at this bar, past the 365-day cap, so it is declared and reported as unreachable.

MEASURED ON THE LIVE BOX 2026-11-20: the TTLs in force were 258 days while `retention.derive()`
would have said 289. The TTL is what decides which rows still exist, so that is what the ripple
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
from weirvern.models.generic_channels import ChannelSpec
from weirvern.models.ripple import (
    DEFAULT_FAMILY_MAX_P,
    EVIDENCE_SCALE_SECONDS,
    EVIDENCE_SCALES,
    MIN_BASELINE_SAMPLES,
    RIPPLE_WINDOW_S,
    ChannelEvidence,
    empirical_pvalue_two_sided,
    group_evidence,
    min_baseline_samples,
    pvalue_floor,
    severity_bands,
)

MODEL_VERSION = "ripple-evidence-5"

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

SPECS: tuple[ChannelSpec, ...] = (
    FLOW_SPECS + CONN_SPECS + DNS_SPECS + IDENTITY_SPECS
    + TLS_SPECS + HTTP_SPECS + SSH_SPECS + NOTICE_SPECS
)

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
                 max_p: float = DEFAULT_FAMILY_MAX_P) -> dict[str, Any]:
    """The baseline a scale can offer, and whether that is enough to decide anything.

    `p_floor` is the smallest p a FULL baseline at this scale could express. A scale is usable
    only when it has the minimum number of windows AND that floor is strictly below the ripple
    family bar; otherwise the honest statement is "baseline too short at this scale", which the
    API exposes instead of printing a floor value as a result.

    THE TWO NUMBERS THE EMPTY STATE NEEDS, AND THEY DIFFER. `required_lookback_days` is the
    lookback the 30-window FLOOR needs (unchanged: 2/8/31/217). `required_lookback_days_for_bar`
    is the lookback at which a p below the family bar can exist (5/26/103/721).
    `lookback_days` is what is actually configured after the retention cap, and
    `retention_days` is the window that cap came from. Without all four a reader can only say
    "not enough history"; with them the console can say which number is short and whether more
    history is even the fix.
    """
    retention = LOOKBACK_DAYS if retention_days is None else max(0, int(retention_days))
    if lookback_days is None:
        lookback = scale_lookback_days(scale, retention)
        derived = True
    else:
        lookback = max(0, int(lookback_days))
        derived = False
    windows = baseline_windows(scale, lookback)
    minimum = min_baseline_samples(scale)
    floor = pvalue_floor(windows)
    seconds = int(EVIDENCE_SCALE_SECONDS.get(scale) or 0)
    need_windows = windows_for_bar(max_p)
    need_days = required_lookback_days(scale, windows=need_windows)
    floor_days = required_lookback_days(scale, windows=minimum, margin_windows=0)
    if windows < minimum:
        reason = (f"baseline too short at this scale: {windows} window(s), "
                  f"{minimum} required")
        usable = False
    elif floor >= max_p:
        reason = (f"baseline too short at this scale: {lookback} day(s) of lookback hold "
                  f"{windows} window(s), but {need_days} day(s) are needed for {need_windows} "
                  f"windows to resolve p<{max_p:g}; retention allows {retention}")
        usable = False
    else:
        reason = ""
        usable = True
    return {
        "baseline_windows": windows,
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
        "usable": usable,
        "reason": reason,
    }


def supported_scales(spec: ChannelSpec, lookback_days: int | None = None,
                     retention_days: int | None = None) -> list[str]:
    """The scales this channel can be measured at: the USABLE ones, given retention and the bar.

    A scale missing here is not measured at all. The test is `scale_report(...)["usable"]` -- the
    same 30-window floor and the same p-floor resolution the read path applies -- so the worker
    never spends a query on a baseline that could not support a ripple. `lookback_days` is an
    explicit override (tests, a caller that knows); otherwise each scale derives its own window.
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
        if scale_report(scale, lookback, retention).get("usable"):
            out.append(scale)
    return out


def statistic(spec: ChannelSpec) -> str:
    """One phrase naming what the channel measures, for the inventory and the operator."""
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
            "scale_detail": {scale: scale_report(scale, effective, live) for scale in spec.scales},
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
    )
    rows = list(client.query(sql).result_rows)
    return _fold(rows, factor=max(1, seconds // step))


def _value_sets(
    client: Any, spec: ChannelSpec, *, scale: str, moment: datetime, lookback_days: int,
    scope_cidrs: tuple[str, ...] | None,
) -> dict[str, dict[int, set[str]]]:
    """One channel's per-bucket VALUE SETS for one scale, including the current bucket at k=0.

    Only for `SET_KINDS`: a novelty or change channel asks WHICH values a window held, and the
    server returns them deduplicated rather than one row per event.
    """
    seconds = EVIDENCE_SCALE_SECONDS[scale]
    sql = spec.sql_values(
        bucket_s=seconds,
        anchor=moment,
        since=moment - timedelta(days=int(lookback_days)),
        until=moment,
        scope_cidrs=scope_cidrs,
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
             reference: list[float], coverage: float) -> ChannelEvidence | None:
    """One measurement, or None when there is nothing a p-value could be computed from.

    THE TWO REFUSALS ARE MADE HERE so every kind of channel refuses identically: a non-finite
    statistic, and an empty reference. `baseline_short` and `p_floor` travel with the row so the
    reader can tell a measurement from a result.
    """
    reference = [item for item in reference if math.isfinite(item)]
    if not math.isfinite(value) or not reference:
        return None
    median = float(statistics.median(reference))
    pvalue = empirical_pvalue_two_sided(value, reference)
    if not math.isfinite(pvalue):
        return None
    direction = "rose" if value > median else "fell" if value < median else "unchanged"
    return ChannelEvidence(
        channel=spec.channel, family=spec.family, scale=scale,
        model_id=f"source:{spec.channel}", model_version=MODEL_VERSION,
        score=value, pvalue=pvalue, freshness_s=0.0, present=True,
        host=host, observed_at=moment, value=value, baseline_median=median,
        sample_count=len(reference), coverage=round(coverage, 4), direction=direction,
        p_floor=pvalue_floor(len(reference)),
        baseline_short=len(reference) < min_baseline_samples(scale),
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
            monitored_nets: list[Any] | None = None) -> list[ChannelEvidence]:
    """Every channel's evidence for every host it can be measured for, at every usable scale.

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
                                lookback_days=lookbacks[widest], scope_cidrs=cidrs)
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
                                             lookback_days=lookbacks[scale], scope_cidrs=cidrs)
                    out.extend(_series_evidence(
                        spec, scale=scale, buckets=value_sets, moment=moment,
                        wanted=wanted, lookback_days=lookbacks[scale]))
            else:
                for scale in scales:
                    buckets = _buckets(client, spec, scale=scale, moment=moment,
                                       lookback_days=lookbacks[scale], scope_cidrs=cidrs)
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
           "baseline_median", "p_value", "sample_count", "coverage", "direction",
           "model_version", "observed_at", "computed_at"]


def _row(item: ChannelEvidence) -> list[Any]:
    moment = item.observed_at or datetime.now(UTC)
    start = moment.replace(minute=0, second=0, microsecond=0)
    return [start, start + timedelta(seconds=RIPPLE_WINDOW_S), item.host, item.channel,
            item.family, item.scale, float(item.value), float(item.baseline_median),
            float(item.pvalue), int(item.sample_count), float(item.coverage), item.direction,
            MODEL_VERSION, moment, moment]


def store(client: Any, items: list[ChannelEvidence]) -> int:
    """Write one row per (window, host, channel, scale); ReplacingMergeTree keeps the newest."""
    rows = [_row(item) for item in items if item.host]
    if not rows:
        return 0
    client.insert("weirvern.ml_ripple_evidence", rows, column_names=COLUMNS)
    return len(rows)


READ_COLUMNS = ["window_start", "window_end", "src_addr", "channel", "family", "scale", "value",
                "baseline_median", "p_value", "sample_count", "coverage", "direction",
                "observed_at"]

READ_SQL = (
    "SELECT " + ", ".join(READ_COLUMNS) + " "
    "FROM weirvern.ml_ripple_evidence FINAL "
    "WHERE window_start >= %(since)s "
    "ORDER BY window_start DESC, src_addr, channel, scale "
    "LIMIT %(limit)s"
)

#: A bounded read. 24h at this deployment's cardinality is ~26k rows; the cap keeps a 7-day
#: window from turning one poll into an unbounded scan while still covering every host.
MAX_READ_ROWS = 100_000


def read(client: Any, *, hours: int = 24, now: datetime | None = None) -> list[ChannelEvidence]:
    """Evidence inside the window, newest first, as `ChannelEvidence` objects."""
    moment = _aware(now or datetime.now(UTC))
    since = moment - timedelta(hours=max(1, int(hours)))
    rows = list(client.query(READ_SQL, parameters={"since": since,
                                                   "limit": MAX_READ_ROWS}).result_rows)
    out: list[ChannelEvidence] = []
    for row in rows:
        (window_start, _window_end, host, channel, family, scale, value, median, pvalue,
         sample_count, coverage, direction, observed_at) = row
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
    items = compute(client, now=now, hosts=hosts, lookback_days=lookback_days,
                    retention_days=info["days"])
    stored = store(client, items)
    unavailable = [{"channel": row["channel"], "reason": row["reason"]}
                   for row in availability(client) if not row["available"]]
    return {
        "evidence": len(items),
        "rows": stored,
        "hosts": len({item.host for item in items}),
        "channels": len({item.channel for item in items}),
        "declared_channels": len(SPECS),
        "unavailable": unavailable,
        "scales": sorted({item.scale for item in items}),
        "retention_days": info["days"],
        "retention_source": info["source"],
        "lookbacks": lookbacks_for(info["days"], lookback_days),
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
    return {
        "available": True,
        "reason": "",
        "window_hours": window_hours,
        "model_version": MODEL_VERSION,
        "count": len(ripples),
        "ripples": [ripple.as_dict() for ripple in ripples],
        # THE CRITICALITY TABLE TRAVELS WITH THE ROWS. The page's legend and its fallback
        # banding read these numbers; none of them is restated in JavaScript.
        "severity_bands": severity_bands(),
        "monitored_networks": [str(net) for net in nets],
        "baseline": {scale: scale_report(scale, retention_days=retention["days"])
                     for scale in EVIDENCE_SCALES},
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
        },
    }


__all__ = ["COLUMNS", "LOOKBACK_DAYS", "LOOKBACK_MARGIN_WINDOWS", "MAX_HOSTS",
           "MIN_BASELINE_SAMPLES", "MIN_COVERAGE", "MODEL_VERSION", "SET_KINDS", "SPECS",
           "availability", "baseline_windows", "compute", "effective_lookback_days", "inventory",
           "lookbacks_for", "overview", "read", "required_lookback_days", "retention_in_force",
           "run", "scale_lookback_days", "scale_report", "statistic", "store",
           "supported_scales", "windows_for_bar"]
