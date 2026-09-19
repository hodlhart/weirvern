# Weirvern Zeek site policy.
#
# Loaded by Zeek as a BARE PATH argument on the command line (see
# k8s/32-zeek.yaml) — a non-X=Y argument is a script to load, verified against
# Zeek's src/Options.cc. It is NOT loaded via a `SitePolicyFile=` option, which
# does not exist in Zeek.
#
# Keep the default local site policy so the standard conn/dns/ssl/notice logs
# are produced, then add the detections that are genuinely useful as
# anomaly-detection input.

@load local

# ── TLS fingerprints (JA4 -- BSD 3-Clause ONLY) ─────────────────────────────
#
# WHY JA4 AND NOT JA3: Zeek 9.0.0 core ships NEITHER. Grepping the whole
# /usr/local/zeek/share/zeek tree returns zero hits for ja3 or ja4 -- the schemas
# that once carried ja3/ja3s were removed from core, and the zeek_ssl.ja3 column
# this project declared was therefore permanently empty. JA4 is its successor: same
# "fingerprint the TLS ClientHello" idea, readable a_b_c format, and it also covers
# QUIC.
#
# LICENSING: JA4+ IS NOT IN THE IMAGE.
# The JA4+ half of the package (JA4S/H/X/SSH/T/L/D) is FoxIO License 1.1 -- permissive
# for internal and academic use, NOT for monetization, with patent-pending methods. At
# image BUILD time every FoxIO submodule directory, the package's recorded JA4+ test
# output, the loader lines that referenced them, and the options that gated them are all
# DELETED. See zeek/prune-ja4plus.sh, which fails the build if any of that did not take.
#
# THERE IS DELIBERATELY NO DISABLE LIST HERE ANY MORE. This file used to carry ten
# `redef FINGERPRINT::JA4*_enabled = F` lines, because the package's submodules are gated
# with `@if (X_enabled) @load ./x @endif` and `@if` is evaluated WHEN THE FILE IS LOADED --
# so disabling after loading was silently ignored (measured: 28 of 28 ssl records carried a
# populated ja4s while the config claimed it was off). That was fixable by load ordering,
# and it was fixed.
#
# But it left the licensed code sitting in the image with only a load ORDER standing
# between it and being shipped, and nothing in the config could tell you if that order
# broke. Deleting the files removes the question entirely: there is nothing to mis-order,
# nothing a package update can turn back on by changing a default, and no licensed source
# in the artefact we distribute.
#
# If you find yourself wanting to re-add a `redef FINGERPRINT::JA4S_enabled = F` line, that
# option no longer exists -- and its absence is the point.
@load packages/ja4-zeek-scripts

# ── Detection scripts ───────────────────────────────────────────────────────
# Host/service inventory: turns "this host started speaking something new" into
# a notice, which is a useful explainability signal for an anomaly.
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services

# Certificate validation, so a plaintext or mismatched cert produces a notice.
@load policy/protocols/ssl/validate-certs

# NOTE ON SCAN DETECTION: `policy/misc/scan` is NOT loaded here. It existed
# through Zeek 6.0 and was removed in 6.1+, so on the current LTS image it is a
# "failed to locate script" error that aborts startup and takes the whole policy
# with it. Port-scan detection comes from Weirvern's own DBSCAN detector plus the
# structural port-diversity signature in weirvern/ensemble.py, which is why the
# absence is tolerable rather than a gap. If you want Zeek-side scanning on a
# modern build, install a maintained package via zkg (e.g. ncsa/bro-simple-scan)
# into the image and @load it from here.

# ── Reduce noise on a busy home network ─────────────────────────────────────
# Do not emit notices for routine conditions that are always true on a mixed
# home/lab LAN; they would swamp the alert channel.
redef Notice::ignored_types += {
    SSL::Invalid_Server_Cert,       # self-signed certs everywhere in a homelab
    Weird::Activity,                # too noisy to be actionable
};

# No MTA in the container, so notice emails must stay off.
redef Notice::mail_dest = "";

event zeek_init()
    {
    print fmt("[Weirvern] Zeek site policy loaded at %s", strftime("%Y-%m-%d %H:%M:%S", network_time()));
    }

# ── Tier 3: the logs added for L2 identity, encapsulation and the TLS blind spot ──────────
#
# WHICH OF THESE ACTUALLY NEED A LOAD is MEASURED rather than assumed. `ls /zeek/logs/` on the
# running sensor is the ground truth, and it shows dhcp already being written (DHCP exists on
# this segment) while x509/quic/tunnel/ldap have produced nothing yet -- for four different
# reasons, which is why they are recorded instead of guessed at:
#
#   dhcp / known_hosts / known_services / software
#       ALREADY WRITING. Nothing to do; confirmed in the sensor's log directory.
#
#   x509
#       IN THE DEFAULT CLOSURE and needs no @load -- base/files/x509 is loaded by
#       base/init-default.zeek. It has produced no rows only because no certificate has been
#       observed since this sensor started. Nothing to change.
#
#   quic
#       IN THE DEFAULT CLOSURE as well. QUIC is a default analyzer in Zeek 9, so this log appears
#       when QUIC traffic does. This matters: QUIC is now a large share of egress on modern
#       networks, so a corpus without it has a growing unnamed hole.
#
#   tunnel
#       NEEDS AN EXPLICIT LOAD. Tunnel detection is not enabled by default; without this the log
#       file is never even created. This is the one genuine configuration addition in the
#       Tier 3 set.
#
#   ldap_search
#       The LDAP analyzer ships and logs to separate streams for messages and searches. Nothing
#       extra is required; it appears when LDAP is on the wire. No LDAP traffic on this segment
#       yet, which is why the table is empty.
#
# @load base/frameworks/tunnels
#
# (Commented out because it is a BEHAVIOUR change rather than a bug fix: enabling tunnel
# detection adds analyzer work on every packet. Turn it on when you want tunnel.log, and note
# that the ingest is already in place -- `zeek_tunnel` exists, the mapper and features are
# wired, and the table is simply empty until the log is produced.)

# ── Two Zeek defaults that SILENCE evidence, both verified against the installed source ──────
#
# These are not tuning. Each one hides a specific attack, and both are the SHIPPED default --
# so leaving them alone means a detection that cannot fire, silently, with a healthy-looking log.

# 1. kerberos.log: `ignored_errors` defaults to {NEEDED_PREAUTH, "Need to use
#    PA-ENC-TIMESTAMP/PA-PK-AS-REQ"} in base/protocols/krb/main.zeek. NEEDED_PREAUTH is EXACTLY
#    what AS-REP roasting produces: the attacker iterates principals looking for ones that do
#    not require preauth, then attacks the returned ticket offline.
#
#    Zeek's own comment in that file says it suppresses the value because logging it
#    "will significantly increase the noisiness of the log" -- and then says, in the same
#    comment, "To detect that attack, log NEEDED_PREAUTH."
#
#    So this redef is the difference between being able to detect AS-REP roasting at all and not.
#    It costs log volume on a network with misconfigured Kerberos clients; that is the trade, and
#    it is the right one for a detection tool. Remove these two lines to go back to the default.
redef KRB::ignored_errors -= { "NEEDED_PREAUTH" };
redef KRB::ignored_errors -= { "Need to use PA-ENC-TIMESTAMP/PA-PK-AS-REQ" };

# 2. smb_files.log: `logged_file_actions` defaults to {FILE_OPEN, FILE_RENAME, FILE_DELETE,
#    PRINT_OPEN, PRINT_CLOSE} -- FILE_WRITE is NOT in it. Ransomware detection survives that
#    (RENAME and DELETE are the burst), but TOOL TRANSFER does not: writing a binary to a remote
#    admin share and then starting a service is the canonical lateral-movement path, and the
#    write half of it would be invisible.
#
#    Adding FILE_WRITE means one row per file write, which on a busy file server is real volume.
#    It is added because without it a `FILE_WRITE`-based feature is structurally always zero --
#    the failure mode this project has already shipped twice (dead ja3/ja3s columns; three tables
#    ingested and read by nothing).
redef SMB::logged_file_actions += { FILE_WRITE };
