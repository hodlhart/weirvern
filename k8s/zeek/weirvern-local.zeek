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
# LICENSING -- DO NOT REORDER THESE LINES.
# The JA4+ suite is split-licensed: JA4 itself is BSD-3-Clause (free for any use,
# including commercial), while JA4S/JA4H/JA4X/JA4SSH/JA4T/JA4L/JA4D are FoxIO
# License 1.1 -- permissive for internal and academic use but NOT for monetization,
# with patent-pending methods. Weirvern ships JA4 only. See zeek/JA4-NOTICE.
#
# The load ORDER is load-bearing. The package gates its submodules with
#     @if (JA4S_enabled) @load ./ja4s @endif
# and `@if` is evaluated WHEN THE FILE IS LOADED, not when the option changes. So
# disabling the options AFTER loading the package is silently ignored: we measured
# 28 of 28 ssl records carrying a populated ja4s while the config said it was off.
# Loading config FIRST, disabling, and only then loading the package is what makes
# the restriction real. Verified: ja4 populated 28/28, ja4+ populated 0/28.
@load packages/ja4-zeek-scripts/config

redef FINGERPRINT::JA4S_enabled   = F;
redef FINGERPRINT::JA4H_enabled   = F;
redef FINGERPRINT::JA4L_enabled   = F;
redef FINGERPRINT::JA4SSH_enabled = F;
redef FINGERPRINT::JA4T_enabled   = F;
redef FINGERPRINT::JA4TS_enabled  = F;
redef FINGERPRINT::JA4D_enabled   = F;

@load packages
@load ja4-zeek-scripts

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
