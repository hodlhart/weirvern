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
