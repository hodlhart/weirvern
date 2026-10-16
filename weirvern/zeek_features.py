"""Zeek-derived features for the ML ensemble.

WHY THIS EXISTS. The ensemble trains and scores on NetFlow aggregates alone: bytes, packets,
destination and port diversity, and time-of-day. That describes VOLUME and BREADTH. It
cannot see what the traffic *is*, which is where most of the signal for real detection lives:

    a host beaconing to one destination every 60s with constant payload  -> low volume,
        low breadth, one destination. Every NetFlow feature says "quiet and normal".
        Zeek's conn.log shows the periodicity and the uniformity directly.
    a DNS-tunnelling exfil                                        -> a few large queries
        with high-entropy subdomains. NetFlow sees bytes; Zeek sees `query_entropy`.
    a TLS session with a known-bad client fingerprint              -> NetFlow sees a flow.
        Zeek sees `ja4`.
    a host that suddenly starts speaking a service it never has    -> NetFlow sees bytes.
        Zeek sees `service` change.
    a connection attempt that is always rejected                   -> NetFlow may not even
        record it. Zeek logs `conn_state = REJ` and `S0`.

WHAT THIS MODULE IS CAREFUL ABOUT, and why each matters:

  * **Absent is not zero.** Zeek and NetFlow are separate sensors. On a host that Zeek has
    never seen, every Zeek feature must be distinguishable from "Zeek saw it and there was
    nothing". A confident 0 would teach the model that a whole class of host is normal-by-
    emptiness. So every feature is computed from an explicit `_present` flag, and the
    imputation is the caller's decision, not this module's silent default.

  * **The join key is a host and a 5-minute window.** `flows_aggregated` is bucketed with
    `toStartOfFiveMinute`, so Zeek records are bucketed the SAME way. Joining on the host
    alone would compare a 5-minute NetFlow window against all of the host's Zeek history,
    which is a different question and would make a burst anywhere in the day look like it
    happened inside the current window.

  * **Measured overlap is low, and that is a fact about the deployment, not a bug here.**
    On the test box, `zeek_conn` sees 35 source addresses and `flows_aggregated` has 88,
    with an INTERSECTION OF 2 -- the sensor observes the real network while the NetFlow
    table is largely seeded test data. That is why the absent-case handling above is not
    theoretical: on that deployment most host-windows legitimately have no Zeek data, and a
    model that cannot tell that apart from "nothing happened" would learn nonsense. The
    first thing to check on any real deployment is the overlap, which `zeek_join_coverage`
    reports.

Pure functions plus SQL builders, so the feature maths is unit-testable without a database.
"""
from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any

# ── the Zeek feature set ─────────────────────────────────────────────────────────
#
# Chosen for what NetFlow cannot express, not for what is easy to compute. Every one of
# these is a property of the CONVERSATIONS a host had, not of the bytes it moved.
ZEEK_FEATURES = [
    # THE PRESENCE FLAG, and it goes FIRST in the block so the ordering is obvious.
    #
    # 1 means Zeek observed this host in this window; 0 means it did not. Every other Zeek
    # feature below is 0 in both cases, so WITHOUT this flag the model cannot tell "Zeek saw
    # nothing" from "Zeek saw a quiet host" -- and would learn that a whole class of
    # host-window is defined by empty features, which is an artefact of two sensors observing
    # different traffic rather than a property of the network.
    #
    # Measured on the test deployment: 35 hosts in zeek_conn against 88 in flows_aggregated
    # with an OVERLAP OF 2, so the absent case is the common one there. `zeek_join_coverage`
    # reports this so it can be watched rather than assumed.
    "zeek_present",
    # Connection shape. `S0` dominates a scan (SYN sent, nothing back); `REJ` is an active
    # refusal; `SF` is a normal completed connection. A shift in this mix with flat byte
    # volume is the signature of probing, and it is invisible in NetFlow.
    "zeek_conn_count",
    "zeek_rej_ratio",
    "zeek_s0_ratio",
    "zeek_completed_ratio",
    # DNS. High entropy across many queries is the shape of a tunnel; a long query name is
    # the same idea more crudely. Both are per-host so they describe THIS host's resolver
    # behaviour rather than the network's.
    "zeek_dns_count",
    "zeek_dns_mean_query_entropy",
    "zeek_dns_mean_query_len",
    "zeek_dns_rcode_error_ratio",
    "zeek_dns_failed_ratio",
    # Service variety and novelty. `zeek_service_count` is how many distinct protocols the
    # host spoke in the window; a host that normally does DNS and HTTPS suddenly doing SSH
    # is the interesting case, and NetFlow's port entropy is a weaker proxy for it.
    "zeek_service_count",
    "zeek_service_rarity",
    # TLS. `zeek_ja4_count` (distinct JA4 fingerprints) surfaces a client changing its TLS
    # stack, and `zeek_ssl_modern_ratio` catches a downgrade to something old.
    "zeek_ja4_count",
    "zeek_ssl_modern_ratio",
    # Notices and weird. Zeek's own detections, which are a second opinion on the same
    # traffic -- and `weird` is Zeek saying the protocol itself looked wrong.
    "zeek_notice_count",
    "zeek_weird_count",
    # Transfer shape. A single large outbound transfer with no matching inbound is exfil;
    # NetFlow gives bytes, Zeek gives the orig/resp split per connection.
    "zeek_outbound_ratio",
    "zeek_unique_dst_ips",
    # ── Tier 3: L2 identity, certificates, encapsulation, the TLS blind spot ──────────────
    #
    # DHCP. The only log with L2 identity -- but the FEATURES are lease behaviour, because that
    # is what can be anomalous. `dhcp_mac_count` > 1 is MAC spoofing or address churn;
    # `dhcp_server_count` > 1 means a server_addr that is not ours, i.e. a rogue DHCP server.
    "zeek_dhcp_events",
    "zeek_dhcp_mac_count",
    "zeek_dhcp_server_count",
    "zeek_dhcp_lease_mean",
    # Tunnel. The existence of a row is the finding, so the feature is whether encapsulation
    # occurred and of how many kinds.
    "zeek_tunnel_events",
    "zeek_tunnel_type_count",
    # QUIC. Closes the TLS blind spot: QUIC never reaches ssl.log, so a host that moves to QUIC
    # was previously unnamed. `quic_ratio` is against this host's own TLS traffic.
    "zeek_quic_count",
    "zeek_quic_server_count",
    "zeek_quic_ratio",
    # LDAP. Enumeration is defined by filter content; `result_count` is the numeric signal and
    # `ldap_filter_shapes` counts how many DISTINCT filters the host issued -- a burst of unique
    # filter shapes is the enumeration pattern.
    "zeek_ldap_search_count",
    "zeek_ldap_filter_shapes",
    "zeek_ldap_results_mean",
    "zeek_ldap_results_max",
    # ── SSH (zeek_ssh: also previously contributing NOTHING to the models) ───────────────
    #
    # The clearest brute-force signal on a tap, and invisible to NetFlow: a failed password
    # attempt is a few bytes each way, indistinguishable from a keepalive.
    "zeek_ssh_count",
    "zeek_ssh_attempts",
    "zeek_ssh_fail_ratio",
    "zeek_ssh_failures",
    "zeek_ssh_client_count",
    "zeek_ssh_server_count",
    "zeek_ssh_present",
    # ── HTTP (zeek_http: 327 rows on the live box, previously contributing NOTHING) ──────
    #
    # Added because Scripts/audit_schema.py found the table was ingested and read by no query,
    # no feature and no view. The three that carry signal no other log has:
    #   uri entropy  encoded or high-entropy paths are how simple C2 hides and how data is
    #                smuggled through a query string -- the HTTP analogue of DNS query entropy
    #   error ratio  a host whose requests overwhelmingly 404 is enumerating paths
    #   post ratio   a shift from GET-only to POST-heavy is a change in what the host DOES
    # NOT featurised: host, uri, user_agent -- unbounded cardinality, and they carry usernames
    # and session tokens. They stay queryable for hunting, which is a different job.
    "zeek_http_count",
    "zeek_http_uri_entropy_mean",
    "zeek_http_uri_entropy_max",
    "zeek_http_host_count",
    "zeek_http_error_ratio",
    "zeek_http_post_ratio",
    # ── Files (zeek_files: 321 rows, likewise unread until now) ─────────────────────────
    #
    # The size PROFILE is the point: NetFlow byte totals cannot distinguish one 500 MB
    # transfer from 500 transfers of 1 MB, and a burst of small files is a collection stage
    # while a few large ones is a bulk download.
    # NOT featurised: sha256/md5 (identifiers -- their place is threat-intel lookup) and
    # filename (free text, and the highest PII surface in the schema).
    "zeek_file_count",
    "zeek_file_bytes_mean",
    "zeek_file_bytes_max",
    "zeek_file_mime_count",
    "zeek_file_unique_ratio",
    # APPENDED, never inserted (see the ordering note above IF_FEATURES): a model rebuilds its
    # vector by name, so inserting would silently reinterpret every column after it.
    #
    # THE JA4 NOVELTY RATIO. JA4 appeared in this list only as `zeek_ja4_count` -- the NUMBER of
    # distinct fingerprints a host presented in a window -- which cannot distinguish "the same
    # client as every previous window" from "a client this host has never used before". That
    # second case is the one worth alerting on (a new TLS stack on an internal host is how
    # malware is introduced and how a rogue device announces itself), and a count cannot express
    # it: the count is 1 either way.
    #
    # This is the fraction of the window's fingerprints that the host has NOT used in the
    # longer baseline window. 0.0 means "all familiar", 1.0 means "entirely new clients".
    "zeek_ja4_novelty",
]

# The features that are DERIVED from the Zeek data being present at all. If Zeek saw nothing
# for this host-window, these are meaningless and must be imputed rather than set to 0.
ZEEK_PRESENCE_FEATURE = "zeek_present"

# Subset for DBSCAN, which uses a smaller set by design (clustering degrades with
# dimensionality on few samples). These are the ones that separate clusters most: how much
# the host talked, how varied it was, and how wrong the traffic looked.
#
# AND THE JA4 PAIR, at the operator\'s direction: a host presenting a TLS stack it has never
# used before is worth seeing, and a model that cannot see it cannot say so. The cost is stated
# rather than hidden -- two more dimensions on a space kept small on purpose, and most
# host-windows carry a zero there (a host with no TLS is 0 for both, exactly as it is for the
# logs it never speaks). DBSCAN already answers sparse density honestly -- "no opinion", not a
# fabricated one -- so a wider vector cannot make it lie; it can only make it quieter, and its
# own warning says when that happened.
ZEEK_DBSCAN_FEATURES = [
    "zeek_conn_count",
    "zeek_service_count",
    "zeek_rej_ratio",
    "zeek_notice_count",
    "zeek_weird_count",
    "zeek_present",
    # APPENDED, never inserted: appending keeps every prefix of a pre-existing artifact valid,
    # so a rollback can still read the old file it kept.
    "zeek_ja4_count",
    "zeek_ja4_novelty",
    # DNS (2026-10-16 -- the operator: "make sure dns is added to all ml as well"). The DNS
    # block was in the isolation forest's set but NOT in this clustering subset, so the DBSCAN
    # detector could not see a tunnel's query entropy or a resolver's error ratio AT ALL. The
    # three most separable signals, not all five: clustering degrades in high dimensions, and
    # count (activity), entropy (tunnelling shape) and the error ratio (failure bursts) cover
    # the space the other two would mostly echo.
    "zeek_dns_count",
    "zeek_dns_mean_query_entropy",
    "zeek_dns_rcode_error_ratio",
]

# THE JA4 SENTINELS, AND WHY THERE ARE THREE. Zeek writes `-` for "unset_field" and
# `(empty)` for "empty_field" (see ingester.zeek_value, which now normalises both). Historic
# rows ingested BEFORE that fix still hold the literal 7-character string `(empty)`, so the read
# layer must exclude all three -- otherwise:
#   * `uniqExactIf(ja4, ja4 != '')` counts `(empty)` as a REAL fingerprint, so the
#     `zeek_ja4_count` feature reported 1 on hosts that had no fingerprint at all;
#   * the T1573 TLS-downgrade rule compares `ja4` and would match against the text "(empty)";
#   * the new novelty feature would treat "(empty)" as a client build worth being novel about.
#
# Written as a SQL fragment rather than inline in each query so the definition cannot drift
# between the four places that need it.
JA4_REAL = "ja4 != '' AND ja4 != '-' AND ja4 != '(empty)'"

# The same predicate for a column that is already an array (`groupArray(ja4)`).
JA4_REAL_ARRAY = "x != '' AND x != '-' AND x != '(empty)'"


# TTL / value for modern TLS versions, used by `zeek_ssl_modern_ratio`.
MODERN_TLS = {"TLSv13", "TLSv12", "TLSv1.3", "TLSv1.2"}

# conn_states that mean "the connection was refused or never answered". `S0` is a SYN with
# no reply (a filtered port, the classic scan result); `REJ` is an active refusal.
REJECTED_STATES = {"REJ", "RSTO", "RSTR"}
UNANSWERED_STATES = {"S0", "S1", "SH"}
COMPLETED_STATES = {"SF", "S1", "S2", "S3", "OTH"}


def _f(v: Any, default: float = 0.0) -> float:
    """Float with a default, never raising on a NULL from ClickHouse."""
    try:
        if v is None:
            return default
        return float(v)
    except (TypeError, ValueError):
        return default


# ── the SQL that gathers the per-host-window Zeek summary ────────────────────────
#
# ONE query per model-training run and one per scoring sweep, not one per host. Everything
# is aggregated to (5-minute window, src_addr) so it lines up with `flows_aggregated`
# exactly.
#
# LEFT JOINed from the NetFlow side everywhere it is used, so a host with no Zeek data
# still produces a row -- with the presence flag false. An INNER JOIN would silently drop
# those hosts from training, which would bias the model toward the hosts Zeek happens to
# see and make the absent case unlearnable.

# HOW FAR BACK THE TWO DERIVED FEATURES LOOK. `zeek_service_rarity` and `zeek_ja4_novelty` are
# comparisons against what the host did BEFORE the window, not properties of the window. The
# history is a span of its own, ending where the feature range begins -- the same shape as the
# Adaptive Baseline's own window (RETRAIN_WINDOW_H, 72h by default), because that baseline is
# what the scoring path hands over as the history. Train and score must use the same span and
# the same formula, or the model is fitted on one question and asked another.
DERIVED_HISTORY_HOURS = 72


def zeek_window_summary_sql(start: str, end: str) -> str:
    """The per-(window, host) Zeek summary for a time range.

    BUILT AS A UNION OF KEYS, THEN JOINED -- not as a chain of FULL OUTER JOINs.

    Two bugs the earlier version had, both found by running it against the live database
    rather than by reading it:

      1. `coalesce(c.w, d.w, s.w, n.w, ww.w)` across a five-way FULL OUTER JOIN returned
         **1969-12-31** (epoch zero) for `window_start` and an EMPTY STRING for `src_addr`.
         The join keys were NULL in most branches, so the coalesce landed on something that
         was not a real key at all. A feature row keyed on (epoch, "") would silently join to
         nothing and every model would train on empty Zeek data while appearing to work.
      2. The five-way chain also cross-multiplied: connecting each aggregate to the running
         coalesce of the previous ones means a host present in three logs produces rows
         multiplied by its counts in each, and every COUNT is then wrong by that factor.

    The UNION of distinct keys first, then LEFT JOIN each aggregate to it, has neither
    problem: the key set is exactly the hosts Zeek saw in each window, and each aggregate
    contributes at most one row per key so no count can be multiplied.

    Each log is aggregated SEPARATELY before any join. Joining the raw logs on (host,
    window) and counting afterwards would count the cross-product -- a host with 10
    connections and 10 DNS queries would produce 100 joined rows and both counts would read
    100.

    The window function matches `flows_aggregated_mv`: toStartOfFiveMinute. Anything else
    would compare misaligned periods, making a burst look like it fell inside the current
    window when it did not.
    """
    from datetime import datetime, timedelta

    hist_start = (datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
                  - timedelta(hours=DERIVED_HISTORY_HOURS)).strftime("%Y-%m-%d %H:%M:%S")
    return f"""
        WITH
        conn_agg AS (
            SELECT
                toStartOfFiveMinute(ts) AS w,
                src_addr,
                count()                                             AS conn_count,
                countIf(conn_state IN ('REJ','RSTO','RSTR'))        AS rej_count,
                countIf(conn_state = 'S0')                          AS s0_count,
                countIf(conn_state IN ('SF','S1','S2','S3','OTH'))  AS completed_count,
                uniqExact(dst_addr)                                 AS uniq_dst,
                sum(orig_bytes)                                     AS ob,
                sum(resp_bytes)                                     AS rb,
                uniqExactIf(service, service != '')                 AS svc_count
            FROM weirvern.zeek_conn
            WHERE ts BETWEEN '{start}' AND '{end}'
            GROUP BY w, src_addr
        ),
        dns_agg AS (
            SELECT
                toStartOfFiveMinute(ts) AS w,
                src_addr,
                count()                                     AS dns_count,
                avg(query_entropy)                          AS mean_entropy,
                avg(query_len)                              AS mean_len,
                countIf(rcode != 0)                         AS rcode_err,
                countIf(answers = '' OR answers = '-')      AS no_answer
            FROM weirvern.zeek_dns
            WHERE ts BETWEEN '{start}' AND '{end}'
            GROUP BY w, src_addr
        ),
        ssl_agg AS (
            SELECT
                toStartOfFiveMinute(ts) AS w,
                src_addr,
                uniqExactIf(ja4, {JA4_REAL})              AS ja4_count,
                -- THE FINGERPRINTS THEMSELVES, not only how many there were. A count cannot
                -- tell "the same client as always" from "a client this host has never used",
                -- and that difference is the whole point of a fingerprint. Collected as a set
                -- so the novelty measure below can compare it against the host's baseline.
                --
                -- The EMPTY string is filtered out because `(empty)` and '-' both mean "Zeek
                -- produced nothing" (see ingester.zeek_value), and treating a missing
                -- fingerprint as a real one invents a client that does not exist.
                arrayDistinct(arrayFilter(x -> {JA4_REAL_ARRAY},
                                          groupArray(ja4)))  AS ja4_set,
                count()                                     AS ssl_count,
                countIf(version IN ('TLSv13','TLSv12','TLSv1.3','TLSv1.2')) AS modern_count
            FROM weirvern.zeek_ssl
            WHERE ts BETWEEN '{start}' AND '{end}'
            GROUP BY w, src_addr
        ),
        notice_agg AS (
            SELECT
                toStartOfFiveMinute(ts) AS w,
                src_addr,
                count() AS notice_count
            FROM weirvern.zeek_notice
            WHERE ts BETWEEN '{start}' AND '{end}'
            GROUP BY w, src_addr
        ),
        weird_agg AS (
            SELECT
                toStartOfFiveMinute(ts) AS w,
                src_addr,
                count() AS weird_count
            FROM weirvern.zeek_weird
            WHERE ts BETWEEN '{start}' AND '{end}'
            GROUP BY w, src_addr
        ),
        -- ── HTTP: was ingested and contributed NOTHING to the models ───────────
        --
        -- `zeek_http` had 327 rows in the live deployment and was read by no query, no feature
        -- and no view (found by Scripts/audit_schema.py, section B). The data was collected,
        -- stored, and then ignored -- the same shape as the Tier-2 tables that had no mapper.
        --
        -- WHAT IS WORTH FEATURISING, and why these three rather than anything else:
        --
        --   uri_entropy mean/max  Encoded or high-entropy URIs are the transport of choice for
        --                         simple C2 and for data smuggled in a query string. A plain
        --                         path on a normal site is low entropy; base64 or a long random
        --                         token is high. This is the HTTP analogue of the DNS query
        --                         entropy feature that has already proved useful.
        --   http_error_ratio      A host whose requests overwhelmingly 404 is enumerating paths
        --                         (content discovery). A host whose POSTs 5xx is a different
        --                         thing again, but both are deviations from "browsing".
        --   http_post_ratio       GET-only hosts and POST-heavy hosts behave differently; a
        --                         sudden shift is a change in what the host DOES, not how much.
        --
        -- DELIBERATELY NOT FEATURISED: `host`, `uri` and `user_agent` are free text with
        -- unbounded cardinality -- as features they would be noise, and they carry usernames
        -- and session tokens. They remain queryable for hunting, which is a different job from
        -- scoring.
        -- ── SSH: also ingested and unread until the schema audit found it ──────
        --
        -- A third table in the same state as http and files. SSH auth behaviour is the clearest
        -- brute-force signal available on a network tap, and it is invisible to NetFlow: a
        -- failed password attempt is a handful of bytes in both directions, indistinguishable
        -- from a keepalive.
        --
        --   ssh_auth_fail_ratio  attempts with no success -- the brute-force signature. A host
        --                        that normally authenticates cleanly and suddenly fails 90% of
        --                        the time is either being attacked or is attacking.
        --   ssh_attempts         volume, so the ratio has a scale attached. A 100% failure rate
        --                        over 2 attempts is not a finding.
        --   ssh_server_ratio     whether this host is mostly the CLIENT or the SERVER of its
        --                        SSH sessions. A workstation that starts accepting logins is a
        --                        change in role, not in volume.
        -- ── Tier 3: L2 identity, certificates, encapsulation, the TLS blind spot ──
        --
        -- Chosen from two independent research passes over every log Zeek 9.0.0 ships.
        -- See weirvern/schema/006_zeek_tier3.sql.
        --
        -- DHCP is the only log with L2 IDENTITY, which is what makes a per-host baseline stable:
        -- a MAC persists across leases and an IP does not. The features here are about LEASE
        -- BEHAVIOUR rather than identity, because that is what can be anomalous:
        --   dhcp_distinct_macs     a host claiming many MACs is MAC spoofing or address churn
        --   dhcp_rogue_servers     a server_addr that is not ours is a rogue DHCP server, which
        --                          is the whole detection for this log
        --   dhcp_lease_time        how long this host's leases are; a sudden drop to seconds is
        --                          a starvation attack or a misconfiguration
        dhcp_agg AS (
            SELECT
                toStartOfFiveMinute(ts) AS w,
                toString(client_addr) AS src_addr,
                count()                                          AS dhcp_events,
                uniqExactIf(mac, mac != '')                      AS dhcp_macs,
                uniqExactIf(server_addr, server_addr != '0.0.0.0') AS dhcp_servers,
                avg(lease_time)                                  AS dhcp_lease_mean
            FROM weirvern.zeek_dhcp
            WHERE ts BETWEEN '{start}' AND '{end}'
            GROUP BY w, src_addr
        ),
        -- x509 is deliberately NOT a feature source, and the reason is structural.
        --
        -- The feature join is (5-minute window, src_addr). x509.log has NO src_addr: it is keyed
        -- on the certificate FINGERPRINT, because one certificate is presented by many hosts and
        -- Zeek deduplicates it per certificate rather than per connection. There is therefore no
        -- way to attribute a certificate to a host from this log.
        --
        -- Joining it by a constant would give one row whose columns read the default for EVERY
        -- host -- a feature that is always 0.0 and indistinguishable from a quiet network. That
        -- is the defect this project has already shipped twice (dead ja3/ja3s columns; the six
        -- Tier-2 tables with no mapper), so the table is ingested and queryable for HUNTING
        -- ("is this certificate self-signed?", "which hosts share this issuer?" -- both joins via
        -- ssl.log's cert_chain_fps) but contributes no ML feature.
        --
        -- A test enforces this: test_every_aggregation_is_joined_not_just_selected fails if a
        -- CTE is defined but never joined, which is how this was caught.
        -- Tunnel: the EXISTENCE of a row is the signal, so the feature is simply whether
        -- encapsulation occurred and of how many kinds. conn.log has tunnel_parents (UIDs) and
        -- never the type.
        tunnel_agg AS (
            SELECT
                toStartOfFiveMinute(ts) AS w,
                toString(src_addr) AS src_addr,
                count()                                          AS tunnel_events,
                uniqExact(tunnel_type)                            AS tunnel_types
            FROM weirvern.zeek_tunnel
            WHERE ts BETWEEN '{start}' AND '{end}'
            GROUP BY w, src_addr
        ),
        -- QUIC closes the TLS blind spot: it never reaches ssl.log, so without this a host's
        -- QUIC destinations are unnamed.
        --   quic_ratio              share of this host's named TLS-like traffic that is QUIC.
        --                           A host moving to QUIC has been invisible until now.
        --   quic_server_count       distinct QUIC destinations
        quic_agg AS (
            SELECT
                toStartOfFiveMinute(ts) AS w,
                toString(src_addr) AS src_addr,
                count()                                          AS quic_count,
                uniqExactIf(server_name, server_name != '')      AS quic_servers
            FROM weirvern.zeek_quic
            WHERE ts BETWEEN '{start}' AND '{end}'
            GROUP BY w, src_addr
        ),
        -- LDAP: enumeration is defined by filter CONTENT, and nothing else exposes directory
        -- queries at all. The numeric signal is result_count; the categorical is filter novelty,
        -- which needs a per-host history and is therefore computed as a COUNT here.
        ldap_agg AS (
            SELECT
                toStartOfFiveMinute(ts) AS w,
                toString(src_addr) AS src_addr,
                count()                                          AS ldap_searches,
                uniqExactIf(ldap_filter, ldap_filter != '')      AS ldap_filter_shapes,
                avg(result_count)                                AS ldap_results_mean,
                max(result_count)                                AS ldap_results_max
            FROM weirvern.zeek_ldap_search
            WHERE ts BETWEEN '{start}' AND '{end}'
            GROUP BY w, src_addr
        ),
        ssh_agg AS (
            SELECT
                toStartOfFiveMinute(ts) AS w,
                src_addr,
                count()                                          AS ssh_conns,
                sum(auth_attempts)                               AS ssh_attempts,
                sum(auth_success)                                AS ssh_successes,
                -- TWO FIELDS DELIBERATELY NOT USED, both measured on the live sensor:
                --
                --   `direction`  declared in ssh.log's #fields list and left UNSET for every
                --                row (188 of 188 empty), so any feature from it is dead by
                --                construction.
                --   `version`    a UInt8 PROTOCOL NUMBER (value 2 for every row), not a
                --                banner string. Comparing it to '' is a type error at query
                --                time, and it cannot distinguish hosts: protocol 2 is the
                --                only version anyone runs.
                --
                -- What DOES vary between hosts is the software BANNER, which Zeek stores in
                -- `client` / `server` (e.g. "SSH-2.0-OpenSSH_10.5"). Distinct banners per host
                -- is the usable signal: a new banner is a new SSH stack on the network, which
                -- is exactly the kind of change a baseline should notice.
                uniqExactIf(client, client != '')                AS ssh_clients,
                uniqExactIf(server, server != '')                AS ssh_servers
            FROM weirvern.zeek_ssh
            WHERE ts BETWEEN '{start}' AND '{end}'
            GROUP BY w, src_addr
        ),
        http_agg AS (
            SELECT
                toStartOfFiveMinute(ts) AS w,
                src_addr,
                count()                                          AS http_count,
                avg(uri_entropy)                                 AS uri_entropy_mean,
                max(uri_entropy)                                 AS uri_entropy_max,
                countIf(status_code IN (400, 401, 403, 404))     AS http_errors,
                countIf(method = 'POST')                         AS http_posts,
                uniqExactIf(host, host != '')                    AS http_host_count
            FROM weirvern.zeek_http
            WHERE ts BETWEEN '{start}' AND '{end}'
            GROUP BY w, src_addr
        ),
        -- ── files: also ingested and unread ───────────────────────────────────
        --
        -- `zeek_files` had 321 rows and was likewise unread. The feature here is deliberately
        -- narrow, because most of what files.log holds is either an identifier or a name:
        --
        --   file_count            How many distinct objects the host moved. A burst is either a
        --                         legitimate bulk download or a collection stage.
        --   file_bytes_mean       Size profile. A host suddenly moving many SMALL files differs
        --                         from one moving a few large ones, and neither is visible in
        --                         NetFlow byte totals alone -- NetFlow cannot tell one 500 MB
        --                         transfer from 500 transfers of 1 MB.
        --   file_mime_rarity      Executables and archives arriving where a host normally sees
        --                         images and HTML. Rarity against the HOST's own history is the
        --                         point, matching how the service-rarity feature is built.
        --
        -- DELIBERATELY NOT FEATURISED: `sha256`/`md5` (an identifier, not a measurement -- and
        -- the right place for them is threat-intel lookup, which is a separate feature);
        -- `filename` (free text, and the highest PII surface in the schema).
        files_agg AS (
            SELECT
                toStartOfFiveMinute(ts) AS w,
                src_addr,
                count()                                     AS file_count,
                uniqExactIf(sha256, sha256 != '')           AS file_hashes,
                avg(total_bytes)                            AS file_bytes_mean,
                max(total_bytes)                            AS file_bytes_max,
                uniqExactIf(mime_type, mime_type != '')     AS file_mime_count
            FROM weirvern.zeek_files
            WHERE ts BETWEEN '{start}' AND '{end}'
            GROUP BY w, src_addr
        ),
        -- ── THE HISTORY WINDOWS FOR THE TWO DERIVED FEATURES ──────────────────────────────────
        --
        -- They end where the feature range begins, so no feature row can treat its own window
        -- as history, and they are capped exactly like the scoring side's baseline set (64
        -- fingerprints) so the two paths cannot disagree about membership. One difference from
        -- the scoring path, stated because it is real: scoring compares against the baseline the
        -- detector actually trained on, while training compares against the 72h before the
        -- range. Same formula, same span, same semantics.
        hist_ja4 AS (
            SELECT
                src_addr,
                arraySlice(arrayDistinct(arrayFilter(x -> {JA4_REAL_ARRAY},
                                                     groupArray(ja4))), 1, 64) AS hist_set
            FROM weirvern.zeek_ssl
            WHERE ts >= '{hist_start}' AND ts < '{start}' AND src_addr != ''
            GROUP BY src_addr
        ),
        hist_svc AS (
            SELECT
                src_addr,
                uniqExactIf(service, service != '')      AS hist_service_count
            FROM weirvern.zeek_conn
            WHERE ts >= '{hist_start}' AND ts < '{start}' AND src_addr != ''
            GROUP BY src_addr
        ),
        keys AS (
            SELECT w, src_addr FROM conn_agg
            UNION DISTINCT SELECT w, src_addr FROM dns_agg
            UNION DISTINCT SELECT w, src_addr FROM ssl_agg
            UNION DISTINCT SELECT w, src_addr FROM dhcp_agg
            UNION DISTINCT SELECT w, src_addr FROM tunnel_agg
            UNION DISTINCT SELECT w, src_addr FROM quic_agg
            UNION DISTINCT SELECT w, src_addr FROM ldap_agg
            UNION DISTINCT SELECT w, src_addr FROM ssh_agg
            UNION DISTINCT SELECT w, src_addr FROM http_agg
            UNION DISTINCT SELECT w, src_addr FROM files_agg
            UNION DISTINCT SELECT w, src_addr FROM notice_agg
            UNION DISTINCT SELECT w, src_addr FROM weird_agg
        )
        SELECT
            k.w        AS window_start,
            k.src_addr AS src_addr,
            -- ONE NAME PER CONCEPT: these aliases are the FEATURE names, so the training
            -- queries can select ZEEK_FEATURES verbatim and a typo is a query error rather
            -- than a silently-zero feature. An earlier version exposed raw names
            -- (conn_count, s0_count) while the features were zeek_conn_count and
            -- zeek_s0_ratio, so every training query named a column that did not exist.
            -- ── LOG-SCALED, MATCHING THE SCORING PATH EXACTLY ─────────────────────────────────
            --
            -- `extract_zeek_features` log1p's these seven counts at scoring time, with the
            -- right rationale (a host with 10,000 connections must not dominate a distance
            -- metric -- DBSCAN's most of all) -- and THE TRAINING MATRIX CARRIED THEM RAW.
            -- The same host-window therefore meant different numbers on the two sides of the
            -- pipeline: fitted on one distribution, scored on another, and nothing raised
            -- because every number stayed a valid number. One transform, applied in both
            -- places. The ratios below still divide by the RAW counts, which is what the
            -- scoring path does too -- it scales these columns after the ratios are taken.
            log1p(coalesce(c.conn_count, 0))                      AS zeek_conn_count,
            log1p(coalesce(c.uniq_dst, 0))                        AS zeek_unique_dst_ips,
            log1p(coalesce(c.svc_count, 0))                       AS zeek_service_count,
            log1p(coalesce(d.dns_count, 0))                       AS zeek_dns_count,
            coalesce(d.mean_entropy, 0)                            AS zeek_dns_mean_query_entropy,
            coalesce(d.mean_len, 0)                                AS zeek_dns_mean_query_len,
            log1p(coalesce(s.ja4_count, 0))                      AS zeek_ja4_count,
            -- The window's fingerprint set, passed through for the novelty measure. It is NOT a
            -- feature itself: a fingerprint is an IDENTIFIER, and this codebase's rule is that
            -- identifiers are join keys, never model inputs. What enters the model is the
            -- DERIVED novelty ratio, which is a number about the host, not a name for a client.
            ifNull(s.ja4_set, [])                                  AS ja4_set,
            log1p(coalesce(n.notice_count, 0))                    AS zeek_notice_count,
            log1p(coalesce(ww.weird_count, 0))                    AS zeek_weird_count,
            -- Tier 3. Counts, ratios and bounded categoricals only -- no identifier becomes a
            -- feature (fingerprints, MACs and uids are join keys, never inputs).
            coalesce(dh.dhcp_events, 0)                            AS zeek_dhcp_events,
            coalesce(dh.dhcp_macs, 0)                              AS zeek_dhcp_mac_count,
            coalesce(dh.dhcp_servers, 0)                           AS zeek_dhcp_server_count,
            coalesce(dh.dhcp_lease_mean, 0)                        AS zeek_dhcp_lease_mean,
            coalesce(tn.tunnel_events, 0)                          AS zeek_tunnel_events,
            coalesce(tn.tunnel_types, 0)                           AS zeek_tunnel_type_count,
            coalesce(qq.quic_count, 0)                             AS zeek_quic_count,
            coalesce(qq.quic_servers, 0)                           AS zeek_quic_server_count,
            if(coalesce(qq.quic_count, 0) + coalesce(s.ssl_count, 0) > 0,
               coalesce(qq.quic_count, 0) / (coalesce(qq.quic_count, 0)
                                             + coalesce(s.ssl_count, 0)), 0)
                                                                   AS zeek_quic_ratio,
            coalesce(lp.ldap_searches, 0)                          AS zeek_ldap_search_count,
            coalesce(lp.ldap_filter_shapes, 0)                     AS zeek_ldap_filter_shapes,
            coalesce(lp.ldap_results_mean, 0)                      AS zeek_ldap_results_mean,
            coalesce(lp.ldap_results_max, 0)                       AS zeek_ldap_results_max,
            -- SSH. The failure RATIO is the signal; `ssh_attempts` is carried so the ratio has
            -- a scale attached (a 100% failure rate over two attempts is not a finding).
            coalesce(ss.ssh_conns, 0)                              AS zeek_ssh_count,
            coalesce(ss.ssh_attempts, 0)                           AS zeek_ssh_attempts,
            if(coalesce(ss.ssh_attempts, 0) > 0,
               1 - (coalesce(ss.ssh_successes, 0) / ss.ssh_attempts), 0)
                                                                   AS zeek_ssh_fail_ratio,
            coalesce(ss.ssh_clients, 0)                            AS zeek_ssh_client_count,
            coalesce(ss.ssh_servers, 0)                            AS zeek_ssh_server_count,
            -- Zero when the host has no SSH at all. Carried explicitly because on a segment
            -- with no SSH traffic the ratio features are all 0.0, which is indistinguishable
            -- from a host whose SSH is entirely unremarkable -- `ssh_present` is what tells
            -- them apart, matching how `zeek_present` works for the join as a whole.
            if(coalesce(ss.ssh_conns, 0) = 0, 0, 1)                AS zeek_ssh_present,
            -- FAILURE COUNT as well as the ratio. A ratio alone cannot distinguish "3 failures
            -- out of 4" from "3000 out of 4000", and those are different events: the second is
            -- a brute-force run in progress, the first is a typo.
            coalesce(ss.ssh_attempts, 0)
              - coalesce(ss.ssh_successes, 0)                      AS zeek_ssh_failures,
            -- HTTP. Counts alone would just duplicate conn_count; the entropy and the error
            -- ratio are what HTTP adds that no other log can.
            coalesce(hh.http_count, 0)                             AS zeek_http_count,
            coalesce(hh.uri_entropy_mean, 0)                       AS zeek_http_uri_entropy_mean,
            coalesce(hh.uri_entropy_max, 0)                        AS zeek_http_uri_entropy_max,
            coalesce(hh.http_host_count, 0)                        AS zeek_http_host_count,
            if(coalesce(hh.http_count, 0) > 0,
               coalesce(hh.http_errors, 0) / hh.http_count, 0)     AS zeek_http_error_ratio,
            if(coalesce(hh.http_count, 0) > 0,
               coalesce(hh.http_posts, 0) / hh.http_count, 0)      AS zeek_http_post_ratio,
            -- Files. Size PROFILE, which NetFlow cannot express: it cannot distinguish one
            -- 500 MB transfer from 500 transfers of 1 MB.
            coalesce(ff.file_count, 0)                             AS zeek_file_count,
            coalesce(ff.file_bytes_mean, 0)                        AS zeek_file_bytes_mean,
            coalesce(ff.file_bytes_max, 0)                         AS zeek_file_bytes_max,
            coalesce(ff.file_mime_count, 0)                        AS zeek_file_mime_count,
            if(coalesce(ff.file_count, 0) > 0,
               coalesce(ff.file_hashes, 0) / ff.file_count, 0)     AS zeek_file_unique_ratio,
            -- RATIOS: computed in SQL so they cannot disagree with the Python path, and
            -- each guards its own denominator. A host with zero connections has no
            -- meaningful rejection ratio, and dividing by zero would produce nan, which
            -- sklearn rejects outright rather than treating as missing.
            if(coalesce(c.conn_count, 0) > 0,
               coalesce(c.rej_count, 0) / c.conn_count, 0)         AS zeek_rej_ratio,
            if(coalesce(c.conn_count, 0) > 0,
               coalesce(c.s0_count, 0) / c.conn_count, 0)          AS zeek_s0_ratio,
            if(coalesce(c.conn_count, 0) > 0,
               coalesce(c.completed_count, 0) / c.conn_count, 0)   AS zeek_completed_ratio,
            if(coalesce(c.ob, 0) + coalesce(c.rb, 0) > 0,
               coalesce(c.ob, 0) / (coalesce(c.ob, 0) + coalesce(c.rb, 0)), 0)
                                                                   AS zeek_outbound_ratio,
            if(coalesce(d.dns_count, 0) > 0,
               coalesce(d.rcode_err, 0) / d.dns_count, 0)          AS zeek_dns_rcode_error_ratio,
            if(coalesce(d.dns_count, 0) > 0,
               coalesce(d.no_answer, 0) / d.dns_count, 0)          AS zeek_dns_failed_ratio,
            if(coalesce(s.ssl_count, 0) > 0,
               coalesce(s.modern_count, 0) / s.ssl_count, 0)       AS zeek_ssl_modern_ratio,
            -- ── THE HISTORY COMPARISONS, COMPUTED HERE SO TRAINING AND SCORING AGREE ──────────
            --
            -- These two were 0 placeholders -- "filled by the caller that holds the baseline" --
            -- and the caller that TRAINS never had one. So both features were CONSTANT ZERO in
            -- every training matrix while the scoring path computed real values from the
            -- baseline dict: a model cannot use a column it never saw vary, and the JA4 work's
            -- entire point -- noticing a TLS stack this host has never presented -- was
            -- invisible to all four detectors. The comparisons now happen here, against the
            -- `hist_*` windows above, in the same arithmetic `extract_zeek_features` uses at
            -- scoring time.
            --
            -- (The columns must exist either way: `detectors._zeek_clause` maps over
            -- ZEEK_FEATURES, so a name without a column here breaks every training query
            -- outright -- the 51-names-against-49-aliases failure that once shipped.)
            --
            -- Rarity: how much of this window's service variety is NEW, as a share of what the
            -- host normally speaks. Clamped at 0 -- using fewer services than usual is not
            -- novelty -- and a missing history reads as one known service, the scoring side's
            -- own floor, so no comparison is invented from nothing.
            if(coalesce(c.svc_count, 0) = 0, 0,
               greatest(0, coalesce(c.svc_count, 0)
                           - greatest(ifNull(hsvc.hist_service_count, 0), 1))
               / greatest(ifNull(hsvc.hist_service_count, 0), 1))
                                                                   AS zeek_service_rarity,
            -- JA4 novelty: the share of the window's fingerprints the host has not presented
            -- in the history window -- EXACT MEMBERSHIP, matching the extractor line for line.
            -- An empty window is 0.0 (no fingerprints is not novelty); a missing history reads
            -- as an empty one, "we have never seen this host's TLS", rather than inventing one.
            if(empty(ifNull(s.ja4_set, [])), 0,
               (length(ifNull(s.ja4_set, []))
                - arrayCount(x -> has(ifNull(hj.hist_set, []), x), ifNull(s.ja4_set, [])))
               / length(ifNull(s.ja4_set, [])))
                                                                   AS zeek_ja4_novelty,
            -- PRESENCE as a real column, so ZEEK_FEATURES works verbatim as a SELECT list.
            if(coalesce(c.conn_count, 0) + coalesce(d.dns_count, 0) + coalesce(s.ssl_count, 0)
               + coalesce(n.notice_count, 0) + coalesce(ww.weird_count, 0) > 0, 1, 0)
                                                                   AS zeek_present
        FROM keys k
        LEFT JOIN conn_agg   c  ON c.w  = k.w AND c.src_addr  = k.src_addr
        LEFT JOIN dns_agg    d  ON d.w  = k.w AND d.src_addr  = k.src_addr
        LEFT JOIN ssl_agg    s  ON s.w  = k.w AND s.src_addr  = k.src_addr
        LEFT JOIN notice_agg n  ON n.w  = k.w AND n.src_addr  = k.src_addr
        LEFT JOIN weird_agg  ww ON ww.w = k.w AND ww.src_addr = k.src_addr
        LEFT JOIN dhcp_agg   dh ON dh.w = k.w AND dh.src_addr = k.src_addr
        LEFT JOIN tunnel_agg tn ON tn.w = k.w AND tn.src_addr = k.src_addr
        LEFT JOIN quic_agg   qq ON qq.w = k.w AND qq.src_addr = k.src_addr
        LEFT JOIN ldap_agg   lp ON lp.w = k.w AND lp.src_addr = k.src_addr
        LEFT JOIN ssh_agg    ss ON ss.w = k.w AND ss.src_addr = k.src_addr
        LEFT JOIN http_agg   hh ON hh.w = k.w AND hh.src_addr = k.src_addr
        LEFT JOIN files_agg  ff ON ff.w = k.w AND ff.src_addr = k.src_addr
        LEFT JOIN hist_ja4   hj ON hj.src_addr = k.src_addr
        LEFT JOIN hist_svc  hsvc ON hsvc.src_addr = k.src_addr
        WHERE k.src_addr != ''
        ORDER BY window_start, src_addr
    """


def zeek_baseline_sql(start: str, end: str) -> str:
    """Per-host service and fingerprint baselines, over a LONGER window than the feature one.

    This is what makes novelty measurable. "This host spoke 4 services in the last 5 minutes"
    is not interesting on its own; "this host spoke 4 services, none of which it has used in
    the last 30 days" is. The baseline is deliberately separate so it can use a much longer
    range than the per-window features without widening the feature query.

    THE FINGERPRINT BASELINE IS COMPUTED IN ITS OWN SUBQUERY, NOT JOINED ONTO zeek_conn. The
    previous form was

        FROM weirvern.zeek_conn
        LEFT JOIN (SELECT src_addr AS f_addr, ja4 FROM weirvern.zeek_ssl ...) fp
               ON fp.f_addr = src_addr
        GROUP BY src_addr

    and it MULTIPLIED THE ROWS: measured on the live deployment, 64,240 conn rows became 92,969
    after the join. One conn row per matching SSL row means `count() AS baseline_conn_count`
    counts conn x ssl pairs, not connections, so the "is this many connections normal for this
    host" comparison was inflated by whatever TLS the host happened to be doing -- and it was
    inflated MORE for busier hosts, which is the direction that hides an anomaly.

    `uniqExact` is unaffected by fan-out (it deduplicates), which is why only the counts were
    wrong and nothing looked broken. Counting each source separately avoids the whole class of
    error rather than compensating for it.
    """
    return f"""
        SELECT
            src_addr,
            uniqExactIf(service, service != '')  AS baseline_service_count,
            count()                              AS baseline_conn_count
        FROM weirvern.zeek_conn
        WHERE ts BETWEEN '{start}' AND '{end}' AND src_addr != ''
        GROUP BY src_addr
    """


def zeek_baseline_ja4_sql(start: str, end: str) -> str:
    """Per-host distinct JA4 fingerprints, from zeek_ssl alone.

    Kept separate from the connection baseline so the join cannot fan out. A host's
    fingerprints are a fact about its TLS clients; its connection count is a fact about its
    connections. Combining them in one row shape was what produced the inflated count.
    """
    return f"""
        SELECT
            src_addr,
            uniqExactIf(ja4, {JA4_REAL})               AS baseline_ja4_count,
            -- THE SET, NOT ONLY ITS SIZE. Novelty needs an exact membership test: "is this
            -- fingerprint one the host has used before?" A count cannot answer that, and the
            -- approximation available from a count (assume the first N are familiar) overstates
            -- novelty on exactly the hosts that use TLS most -- which is where a false alert is
            -- most expensive. The set is bounded in practice (a host presents a handful of
            -- client builds) and capped so a pathological host cannot pull an unbounded array.
            arraySlice(arrayDistinct(arrayFilter(x -> {JA4_REAL_ARRAY},
                                                 groupArray(ja4))), 1, 64) AS baseline_ja4_set,
            count()                                    AS ssl_count
        FROM weirvern.zeek_ssl
        WHERE ts BETWEEN '{start}' AND '{end}' AND src_addr != ''
        GROUP BY src_addr
    """


def _as_list(value: Any) -> list[str] | None:
    """A ClickHouse array or a hand-written string as a list of strings, else None.

    Both shapes occur: the database returns a real array, while tests and older callers build
    rows by hand and pass the repr. `None` means "no value at all", which callers must tell
    apart from an EMPTY list -- an empty history and a missing history need different handling,
    and collapsing them would make a missing field look like a host with no fingerprints.
    """
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip().strip("[]")
        return [part.strip().strip("'\"") for part in text.split(",") if part.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return None


def extract_zeek_features(row: dict[str, Any],
                          baseline: dict[str, Any] | None = None) -> dict[str, float]:
    """Turn one summary row into the model's Zeek feature dict.

    `row` is a row from `zeek_window_summary_sql`. A row of all-NULLs (or None) means Zeek
    had no record of this host in this window -- which sets `zeek_present` to 0 and lets
    every other feature fall to a neutral value that the CALLER can recognise and impute.

    The ratios guard their own denominators: a host with zero connections has no meaningful
    rejection ratio, and dividing by zero into `nan` would poison the whole feature vector,
    since sklearn treats nan as an error rather than as missing.
    """
    out: dict[str, float] = {name: 0.0 for name in ZEEK_FEATURES}
    out[ZEEK_PRESENCE_FEATURE] = 0.0
    if not row:
        return out

    # The summary columns are named after the FEATURES now, so presence is decided from the
    # feature names -- NOT from the pre-rename ones (`conn_count`, `dns_count`), which no
    # longer exist. Deciding it from the old names made every row look absent: the tests
    # caught it as `zeek_present == 0` for a real scan row that had 89 connections.
    # HTTP and files: carried straight through. They are already per-host-window aggregates
    # from the SQL, so there is nothing to compute here -- the ratio guards live in the query
    # so the two paths cannot disagree.
    for name in ("zeek_ssh_count", "zeek_ssh_attempts", "zeek_ssh_fail_ratio",
                 "zeek_ssh_failures", "zeek_ssh_client_count", "zeek_ssh_server_count",
                 "zeek_ssh_present",
                 "zeek_http_count", "zeek_http_uri_entropy_mean", "zeek_http_uri_entropy_max",
                 "zeek_http_host_count", "zeek_http_error_ratio", "zeek_http_post_ratio",
                 "zeek_file_count", "zeek_file_bytes_mean", "zeek_file_bytes_max",
                 "zeek_file_mime_count", "zeek_file_unique_ratio"):
        if row.get(name) is not None:
            out[name] = _f(row.get(name))

    conn_n = _f(row.get("zeek_conn_count"))
    dns_n = _f(row.get("zeek_dns_count"))
    # `ssl_count` ONLY. The fallback to `zeek_ssl_count` pointed at a name no query emits, and
    # because 0 is falsy a host with zero TLS sessions fell through to it -- so the one case the
    # fallback "handled" was the case where the real value was legitimately zero.
    ssl_n = _f(row.get("ssl_count"))
    notice_n = _f(row.get("zeek_notice_count"))
    weird_n = _f(row.get("zeek_weird_count"))

    # An explicit flag from the query wins when present: the SQL computes presence from the
    # raw counts across all five logs, including ones this function does not inspect.
    explicit = row.get("zeek_present")
    if explicit is not None and _f(explicit) > 0:
        out[ZEEK_PRESENCE_FEATURE] = 1.0
        _fill(out, row, baseline)
        return out

    if conn_n == 0 and dns_n == 0 and ssl_n == 0 and notice_n == 0 and weird_n == 0:
        # Zeek knows nothing about this host-window. Reported as absence rather than as a
        # row of zeroes, because "we did not look" and "we looked and saw nothing" are
        # different facts and only one of them is evidence of normality.
        return out

    out[ZEEK_PRESENCE_FEATURE] = 1.0
    _fill(out, row, baseline)
    return out


def _fill(out: dict[str, float], row: dict[str, Any],
          baseline: dict[str, Any] | None = None) -> None:
    """Copy the feature-named columns out of the row, then compute the two features that
    cannot come from the row alone.

    ONE place reads a column. An earlier version had the presence check and the value reading
    as separate copies, and after the SQL rename they disagreed -- the presence check read the
    pre-rename names and so decided every row was absent, which the tests caught as
    `zeek_present == 0` for a real scan row with 89 connections.
    """
    for name in ZEEK_FEATURES:
        if name in row and name != ZEEK_PRESENCE_FEATURE:
            out[name] = _f(row.get(name))

    # HTTP and files: carried straight through. They are already per-host-window aggregates
    # from the SQL, so there is nothing to compute here -- the ratio guards live in the query
    # so the two paths cannot disagree.
    for name in ("zeek_ssh_count", "zeek_ssh_attempts", "zeek_ssh_fail_ratio",
                 "zeek_ssh_failures", "zeek_ssh_client_count", "zeek_ssh_server_count",
                 "zeek_ssh_present",
                 "zeek_http_count", "zeek_http_uri_entropy_mean", "zeek_http_uri_entropy_max",
                 "zeek_http_host_count", "zeek_http_error_ratio", "zeek_http_post_ratio",
                 "zeek_file_count", "zeek_file_bytes_mean", "zeek_file_bytes_max",
                 "zeek_file_mime_count", "zeek_file_unique_ratio"):
        if row.get(name) is not None:
            out[name] = _f(row.get(name))

    conn_n = _f(row.get("zeek_conn_count")) or _f(row.get("conn_count"))

    # LEGACY FALLBACK for rows built against the pre-rename column names, which tests and
    # external callers may still use. Applied only where the feature-named key was absent, so
    # it can never override a real value.
    legacy = {
        "zeek_s0_ratio": ("s0_count", conn_n),
        "zeek_rej_ratio": ("rej_count", conn_n),
        "zeek_completed_ratio": ("completed_count", conn_n),
        "zeek_unique_dst_ips": ("uniq_dst", 1.0),
        "zeek_service_count": ("service_count", 1.0),
    }
    for feature, (old, denom) in legacy.items():
        if out[feature] == 0.0 and row.get(old) is not None and denom:
            out[feature] = _f(row.get(old)) / denom
    if out["zeek_outbound_ratio"] == 0.0 and row.get("orig_bytes") is not None:
        ob, rb = _f(row.get("orig_bytes")), _f(row.get("resp_bytes"))
        if ob + rb > 0:
            out["zeek_outbound_ratio"] = ob / (ob + rb)

    # SERVICE RARITY: how much of this window's service variety is OUTSIDE what the host
    # normally does. Needs the longer-window baseline, which the summary query cannot supply
    # (it only sees this window), so it is 0 when no baseline is given rather than guessed.
    # Clamped at 0 because using FEWER services than the baseline is not novelty.
    svc = out["zeek_service_count"]
    if baseline and svc:
        known = max(_f(baseline.get("baseline_service_count")), 1.0)
        out["zeek_service_rarity"] = max(0.0, svc - known) / known

    # JA4 NOVELTY: the share of this window's TLS fingerprints the host has not used before.
    #
    # IT NEEDS BOTH HALVES AND THEY COME FROM DIFFERENT PLACES. The window's fingerprints arrive
    # on the row (`ja4_set`, collected by ssl_agg); the host's history arrives in `baseline` from
    # the longer window. With no baseline there is nothing to be novel AGAINST, so the feature
    # stays 0.0 rather than being guessed -- the same rule service rarity follows.
    #
    # A host with no TLS at all also gets 0.0, which is correct: no fingerprints is not novelty.
    seen = _as_list(row.get("ja4_set")) or []
    if seen and baseline is not None:
        # EXACT MEMBERSHIP, using the baseline SET. The count alone could only support a guess
        # ("assume the first N are familiar"), and that guess overstates novelty on the hosts
        # with the most TLS -- the ones where a false alert costs most.
        history = _as_list(baseline.get("baseline_ja4_set"))
        if history is None:
            # A baseline without the set (an older caller) cannot support the test. Fall back to
            # the count-based lower bound and never claim more novelty than that, so a missing
            # field degrades the signal rather than manufacturing one.
            familiar = min(len(seen), _f(baseline.get("baseline_ja4_count")))
        else:
            # `known_fps`, NOT `known`: `known` already holds the service-count float twelve
            # lines above, and reusing the name rebinds it to a set there -- which mypy caught
            # as a type error and which would have been a silent wrong answer at runtime if the
            # two blocks were ever reordered.
            known_fps = set(history)
            familiar = 0
            for fp in seen:
                if fp in known_fps:
                    familiar += 1
        out["zeek_ja4_novelty"] = max(0.0, len(seen) - familiar) / len(seen)

    # Log-scale the counts so they sit on a comparable range to the NetFlow features, which
    # are log1p'd. Without this a host with 10,000 connections dominates any distance metric
    # -- DBSCAN's most of all, since it clusters on distance.
    #
    # Applied LAST, after rarity, because rarity is a ratio of raw service counts: scaling the
    # counts first would make rarity a ratio of logarithms, which is a different quantity.
    for name in ("zeek_conn_count", "zeek_dns_count", "zeek_notice_count",
                 "zeek_weird_count", "zeek_unique_dst_ips", "zeek_ja4_count",
                 "zeek_service_count"):
        out[name] = math.log1p(max(out[name], 0.0))


def zeek_join_coverage(netflow_hosts: int, zeek_hosts: int, overlapping: int) -> dict:
    """A one-line health reading of the NetFlow/Zeek join, for an operator to act on.

    WHY THIS IS PART OF THE FEATURE MODULE: if the two sensors are not observing the same
    hosts, every Zeek feature is imputed for nearly every row and the ensemble is training
    on NetFlow alone while appearing to use Zeek. That failure is invisible in the metrics
    -- the models train, score, and report normally. Measured on the test box: 35 Zeek hosts,
    88 NetFlow hosts, 2 overlapping, because the NetFlow table was largely seeded test data.
    """
    coverage = (overlapping / netflow_hosts) if netflow_hosts else 0.0
    if netflow_hosts == 0:
        verdict = "no NetFlow hosts; nothing to join"
    elif coverage >= 0.7:
        verdict = "good: Zeek covers most NetFlow hosts"
    elif coverage >= 0.2:
        verdict = ("partial: most host-windows will have no Zeek data, so Zeek features are "
                   "imputed for the majority. Check that both sensors see the same segment.")
    else:
        verdict = ("poor: the sensors are observing almost disjoint sets of hosts, so the "
                   "Zeek features carry almost no signal. Check CAPTURE_IFACE/ZEEK_IFACE and "
                   "whether the NetFlow table holds seeded data.")
    return {
        "netflow_hosts": netflow_hosts,
        "zeek_hosts": zeek_hosts,
        "overlapping": overlapping,
        "coverage": round(coverage, 3),
        "verdict": verdict,
    }


# ── the join fragment the training queries share ─────────────────────────────────
#
# ONE definition, used by all four detectors. Duplicating it per detector is how the join
# drifts: three models silently training on a slightly different window or key than the
# fourth, which is invisible in every metric and only shows up as one model disagreeing with
# the others for no stated reason.
#
# LEFT JOIN, not INNER. An inner join would drop every host-window Zeek did not see, which
# on the measured deployment is most of them -- the model would then be trained only on the
# hosts both sensors observe and would have no idea what to do with the rest. The
# `zeek_present` flag carries the distinction instead.
#
# The subquery is materialised per query via the CTE, and the join is on BOTH parts of the
# key. Joining on the host alone would compare a 5-minute NetFlow window against the host's
# entire Zeek history, so a burst from any time in the range would look like it happened
# inside the current window.
ZEEK_JOIN_CTE = """zeek_w AS ({summary})"""

ZEEK_JOIN_ON = """LEFT JOIN zeek_w z
                    ON z.window_start = a.window_start AND z.src_addr = a.src_addr"""


def zeek_join_cte(start: str, end: str) -> str:
    """The WITH-clause entry that makes `zeek_w` available to a training query."""
    return ZEEK_JOIN_CTE.format(summary=zeek_window_summary_sql(start, end))


def zeek_select_columns() -> str:
    """The Zeek columns a training query must SELECT, in the vector's tail order.

    ORDER IS LOAD-BEARING. These are appended to the NetFlow columns and must appear in the
    same order as ZEEK_FEATURES / ZEEK_DBSCAN_FEATURES, because the model rebuilds its
    input by position. A mismatch here produces a vector of the right LENGTH holding the
    wrong values -- nothing raises, and the model is quietly wrong.
    """
    return ",\n".join(f"    {c}" for c in ZEEK_FEATURES)


def zeek_window_sql(since: str, until: str | None = None) -> str:
    """The scoring-side summary: everything from `since` up to now (or `until`).

    A separate entry point from `zeek_window_summary_sql` because the two callers ask
    different questions. Training takes an explicit closed range so a retrain is
    reproducible; a live sweep takes "since the last sweep" and lets ClickHouse use `now()`.
    Wrapping the same builder keeps the join key and window function identical between them,
    which is the property that matters -- a scoring query bucketing differently from the
    training query would put the same traffic in different rows and the features would not
    line up with the model.
    """
    from datetime import datetime, timedelta

    if until is None:
        # A small forward margin so a record written during the sweep is not excluded by
        # clock skew between the worker and ClickHouse.
        until = (datetime.now() + timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")
    return f"SELECT * FROM ({zeek_window_summary_sql(since, until)})"


def zeek_coverage_sql(since: str) -> str:
    """Host-set overlap between NetFlow and Zeek, for `zeek_join_coverage`.

    The check that tells an operator whether the Zeek features are carrying signal or being
    imputed for nearly every row. Cheap enough to run on each retrain, and it is the only
    thing that would reveal two sensors observing different segments.
    """
    return f"""
        SELECT
            (SELECT uniqExact(src_addr) FROM weirvern.flows_aggregated
              WHERE window_start >= '{since}') AS netflow_hosts,
            (SELECT uniqExact(src_addr) FROM weirvern.zeek_conn
              WHERE ts >= '{since}') AS zeek_hosts,
            (SELECT count() FROM (
                SELECT DISTINCT src_addr FROM weirvern.flows_aggregated
                 WHERE window_start >= '{since}'
                INTERSECT
                SELECT DISTINCT src_addr FROM weirvern.zeek_conn
                 WHERE ts >= '{since}'
            )) AS overlapping
    """


def zeek_protocol_records_sql(since: str, until: str | None = None) -> str:
    """The Tier-2 protocol records for a host, as the ATT&CK mapper consumes them.

    WHY A SEPARATE QUERY FROM `zeek_window_summary_sql`. That one AGGREGATES -- it collapses a
    host-window into counts, which is what the ML features need. The technique mapping needs
    the opposite: the individual protocol facts, because `smb_mapping.path` and
    `dce_rpc.operation` are meaningful per row and meaningless as a count. Aggregating first
    and mapping after would lose exactly the evidence the Tier-2 logs were ingested for.

    UNION ALL over the five tables rather than a join, because they share no key beyond the
    host and the fact that they are all records about it. A join on (host, window) would
    cross-multiply: a host with 3 Kerberos records and 4 SMB records would produce 12 rows, and
    the mapper would report 12 service-creates for the 3 that happened. That cross-
    multiplication is the same defect the feature join had, which is why it is called out here.

    `-` (Zeek's unset sentinel) is normalised to '' in SQL as well as in the reader, so a
    mapper called here sees the same contract as one called from the tailer. Without this a
    path of '-' would match nothing while looking like data.
    """
    from datetime import datetime, timedelta

    if until is None:
        until = (datetime.now() + timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")

    # ── EVERY ARM MUST CARRY THE SAME COLUMNS, AND FOUR WERE MISSING ──────────────────────────
    #
    # UNION ALL requires one shape across all branches, so a field only one log has must be
    # PADDED on every other arm. Four columns were absent from the union entirely, and each
    # omission made an ATT&CK rule silently dead:
    #
    #   username, success  -> T1110 (NTLM brute force). The zeek_ntlm branch aliased NOTHING, so
    #                         `username` was always absent, the rule's `if r.get("username")`
    #                         guard never passed, and NTLM brute force could not be reported
    #                         however noisy the network was.
    #   version, ja4       -> T1573 (deprecated TLS). There was no zeek_ssl branch AT ALL, so both
    #                         were always absent and the TLS-downgrade rule could never fire.
    #
    # `carries` is how a branch supplies real values; anything it does not name is padded with a
    # type-matching zero. The padding is not decoration -- omitting a column from one arm is a SQL
    # error, and NULL where the type is UInt8 raises at query time. Both were verified against
    # ClickHouse rather than assumed.
    ZEROS = {"username": "''", "success": "0", "version": "''", "ja4": "''"}

    def branch(table: str, extra: str, carries: dict[str, str] | None = None,
               host: str = "src_addr", attempts: str = "0", successes: str = "0") -> str:
        """One arm of the union, with every optional column present.

        `carries` maps a trailing column to the table expression that supplies it; anything
        absent is padded. `host` overrides the host column for tables that name it differently --
        see the zeek_dhcp note, where the wrong name broke the ENTIRE query.
        """
        carried = carries or {}
        tail = ", ".join(f"{carried.get(k, ZEROS[k])} AS {k}" for k in ZEROS)
        return (
            f"SELECT '{table}' AS kind, {host} AS src_addr, ts, "
            f"{attempts} AS attempts, {successes} AS successes, {extra}, {tail} "
            f"FROM weirvern.{table} WHERE ts >= '{since}' AND ts < '{until}'"
        )

    return " UNION ALL ".join([
        # SSH carries the ONLY real attempt counts, so it overrides the helper's zeros.
        branch("zeek_ssh", "'' AS smb_path, '' AS service, direction AS operation, '' AS endpoint",
               attempts="auth_attempts", successes="auth_success"),
        branch("zeek_smb_mapping", "path AS smb_path, service, '' AS operation, '' AS endpoint"),
        branch("zeek_smb_files", "path AS smb_path, '' AS service, action AS operation, '' AS endpoint"),
        branch("zeek_dce_rpc", "'' AS smb_path, '' AS service, operation, endpoint"),
        branch("zeek_kerberos",
               "'' AS smb_path, '' AS service, request_type AS operation, service AS endpoint"),
        # x509 is included in the PROTOCOL query even though it cannot be a per-host ML feature.
        # It has no src_addr (keyed on the certificate fingerprint), so it gets the fingerprint
        # as its identity and an empty address. This is what makes the table READABLE for
        # hunting -- self-signed certificates, weak keys, issuer reuse -- rather than collected
        # and never used. The audit's exemption for it is verified by a test, not asserted.
        branch("zeek_x509", "'' AS smb_path, '' AS service, fingerprint AS operation, "
                            "subject AS endpoint", host="''"),
        branch("zeek_tunnel", "'' AS smb_path, '' AS service, tunnel_type AS operation, "
                              "action AS endpoint"),
        branch("zeek_quic", "'' AS smb_path, '' AS service, client_protocol AS operation, "
                            "server_name AS endpoint"),
        branch("zeek_ldap_search", "'' AS smb_path, '' AS service, scope AS operation, "
                                   "base_object AS endpoint"),
        # zeek_dhcp HAS NO src_addr -- it keys its peers as client_addr/server_addr. The branch
        # used to select a bare `src_addr`, which made the ENTIRE union raise
        #     Code: 47. Unknown expression identifier `src_addr`
        # and because worker.py catches that and carries on, every Zeek-derived technique was
        # silently absent, reported only as "mapping will use volumetric evidence only". A whole
        # half of the ATT&CK mapping was off and it looked like a quiet network.
        branch("zeek_dhcp", "'' AS smb_path, '' AS service, msg_types AS operation, mac AS endpoint",
               host="client_addr"),
        # NTLM: `username` and `success` are REAL columns and are exactly what T1110 reads. This
        # branch previously aliased nothing, so the rule's `if r.get("username")` guard never
        # passed. toUInt8 keeps the type matching the 0 every other arm pads with.
        branch("zeek_ntlm", "'' AS smb_path, '' AS service, '' AS operation, '' AS endpoint",
               carries={"username": "username", "success": "toUInt8(success)"}),
        # ── zeek_ssl: THE BRANCH THAT DID NOT EXIST ───────────────────────────────────────────
        # T1573 reads `ja4` and `version` expecting TLS records, and there was no SSL arm at all,
        # so both keys were always absent and the deprecated-TLS rule could never fire however
        # many hosts downgraded. `version` goes to `operation` as well, matching how the other
        # protocol arms map their distinguishing field for a human reading the row.
        branch("zeek_ssl", "'' AS smb_path, '' AS service, version AS operation, '' AS endpoint",
               carries={"version": "version", "ja4": "ja4"}),
    ])


def index_protocol_records(rows: Sequence[Sequence[Any]],
                           columns: Sequence[str]) -> dict[str, list[dict[str, Any]]]:
    """Group protocol records by host, the way the mapper wants them.

    Keyed on `src_addr` only -- NOT on (host, window). The mapper's rules are per-host facts
    ("this host accessed ADMIN$ in the last sweep"), and the query is already bounded to the
    sweep window, so re-bucketing by five-minute window here would split a single Kerberoasting
    burst across windows and drop it below the threshold.
    """
    out: dict[str, list[dict[str, Any]]] = {}
    idx = {name: i for i, name in enumerate(columns)}
    for row in rows:
        rec = {name: row[i] if i < len(row) else None for name, i in idx.items()}
        src = str(rec.get("src_addr") or "")
        if not src:
            continue
        out.setdefault(src, []).append(rec)
    return out



