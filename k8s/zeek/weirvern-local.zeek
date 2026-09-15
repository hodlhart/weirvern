# Weirvern Zeek site policy.
#
# Loaded by Zeek at startup. Keeps the default local site policy (so the
# standard conn/dns/ssl/http/files/notice logs are produced) and adds the
# detections that are genuinely useful as an anomaly-detection input.

@load local

# ── Detection scripts relevant to the attacks Weirvern cares about ──────────
# Scan detection (port sweeps, host sweeps) — corroborates the DBSCAN
# port-diversity signal with an independent packet-level view.
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services

# Notice framework: produces notice.log entries with a stable `note` field the
# ingester maps to severity. This is the highest-value integration point — Zeek
# already ships curated detection logic for the behaviours we want.
@load policy/misc/scan

# Software/version detection enriches notices when a host starts speaking
# something new (helps explain "why did this host suddenly look anomalous").
@load policy/protocols/ssl/validate-certs

# ── Reduce noise on a busy home network ─────────────────────────────────────
# Do not emit notices for the routine conditions that are always true on a
# mixed home/lab LAN; they would swamp the alert channel.
redef Notice::ignored_types += {
    SSL::Invalid_Server_Cert,       # self-signed certs everywhere in a homelab
    Weird::Activity,                # too noisy to be actionable
};

# Keep notice emails off (no MTA in the container).
redef Notice::mail_dest = "";

event zeek_init()
    {
    print fmt("[Weirvern] Zeek site policy loaded at %s", strftime("%Y-%m-%d %H:%M:%S", network_time()));
    }
