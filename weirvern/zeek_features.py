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
]

# The features that are DERIVED from the Zeek data being present at all. If Zeek saw nothing
# for this host-window, these are meaningless and must be imputed rather than set to 0.
ZEEK_PRESENCE_FEATURE = "zeek_present"

# Subset for DBSCAN, which uses a smaller set by design (clustering degrades with
# dimensionality on few samples). These are the ones that separate clusters most: how much
# the host talked, how varied it was, and how wrong the traffic looked.
ZEEK_DBSCAN_FEATURES = [
    "zeek_conn_count",
    "zeek_service_count",
    "zeek_rej_ratio",
    "zeek_notice_count",
    "zeek_weird_count",
    "zeek_present",
]

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
                uniqExactIf(ja4, ja4 != '')                 AS ja4_count,
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
        keys AS (
            SELECT w, src_addr FROM conn_agg
            UNION DISTINCT SELECT w, src_addr FROM dns_agg
            UNION DISTINCT SELECT w, src_addr FROM ssl_agg
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
            coalesce(c.conn_count, 0)                              AS zeek_conn_count,
            coalesce(c.uniq_dst, 0)                                AS zeek_unique_dst_ips,
            coalesce(c.svc_count, 0)                               AS zeek_service_count,
            coalesce(d.dns_count, 0)                               AS zeek_dns_count,
            coalesce(d.mean_entropy, 0)                            AS zeek_dns_mean_query_entropy,
            coalesce(d.mean_len, 0)                                AS zeek_dns_mean_query_len,
            coalesce(s.ja4_count, 0)                               AS zeek_ja4_count,
            coalesce(n.notice_count, 0)                            AS zeek_notice_count,
            coalesce(ww.weird_count, 0)                            AS zeek_weird_count,
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
            -- Rarity needs the host's longer-window baseline, which is a separate query;
            -- left at 0 here and filled by the caller that has it.
            0                                                      AS zeek_service_rarity,
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
        LEFT JOIN ssh_agg    ss ON ss.w = k.w AND ss.src_addr = k.src_addr
        LEFT JOIN http_agg   hh ON hh.w = k.w AND hh.src_addr = k.src_addr
        LEFT JOIN files_agg  ff ON ff.w = k.w AND ff.src_addr = k.src_addr
        WHERE k.src_addr != ''
        ORDER BY window_start, src_addr
    """


def zeek_baseline_sql(start: str, end: str) -> str:
    """Per-host service and fingerprint baselines, over a LONGER window than the feature one.

    This is what makes novelty measurable. "This host spoke 4 services in the last 5 minutes"
    is not interesting on its own; "this host spoke 4 services, none of which it has used in
    the last 30 days" is. The baseline is deliberately separate so it can use a much longer
    range than the per-window features without widening the feature query.
    """
    return f"""
        SELECT
            src_addr,
            uniqExactIf(service, service != '')  AS baseline_service_count,
            uniqExactIf(ja4, ja4 != '')          AS baseline_ja4_count,
            count()                              AS baseline_conn_count
        FROM weirvern.zeek_conn
        LEFT JOIN (
            SELECT src_addr AS f_addr, ja4 FROM weirvern.zeek_ssl
            WHERE ts BETWEEN '{start}' AND '{end}'
        ) fp ON fp.f_addr = src_addr
        WHERE ts BETWEEN '{start}' AND '{end}'
        GROUP BY src_addr
    """


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

    # Each branch names its columns so the union has one shape: a discriminator, the host, and
    # the protocol-specific fields the mapper reads.
    def branch(table: str, extra: str) -> str:
        """One arm of the union.

        `attempts` and `successes` default to 0 on every arm that has no such concept, because
        UNION ALL requires one column shape across all branches. Only zeek_ssh populates them.
        """
        return (
            f"SELECT '{table}' AS kind, src_addr, ts, 0 AS attempts, 0 AS successes, {extra} "
            f"FROM weirvern.{table} WHERE ts >= '{since}' AND ts < '{until}'"
        )

    return " UNION ALL ".join([
        # `attempts` / `successes` are carried on the SSH branch so the brute-force rule has a
        # real source. They are zero for every other log, which is what the rule keys on.
        # zeek_ssh is the only branch with real attempt counts, so it is written to override
        # the zeros the helper injects.
        f"SELECT 'zeek_ssh' AS kind, src_addr, ts, auth_attempts AS attempts, "
        f"auth_success AS successes, '' AS smb_path, '' AS service, direction AS operation, "
        f"'' AS endpoint FROM weirvern.zeek_ssh "
        f"WHERE ts >= '{since}' AND ts < '{until}'",
        branch("zeek_smb_mapping", "path AS smb_path, service, '' AS operation, '' AS endpoint"),
        branch("zeek_smb_files", "path AS smb_path, '' AS service, action AS operation, '' AS endpoint"),
        branch("zeek_dce_rpc", "'' AS smb_path, '' AS service, operation, endpoint"),
        branch("zeek_kerberos",
               "'' AS smb_path, '' AS service, request_type AS operation, service AS endpoint"),
        branch("zeek_ntlm",
               "'' AS smb_path, '' AS service, '' AS operation, '' AS endpoint"),
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
