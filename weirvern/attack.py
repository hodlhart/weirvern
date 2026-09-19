"""MITRE ATT&CK technique mapping for Weirvern anomalies.

WHAT THIS IS FOR, AND WHAT IT IS NOT.

An alert that says "score 0.94, DBSCAN and IF agree" tells an analyst that something is
unusual. It does not tell them what to LOOK for. The technique mapping's whole job is to
convert a statistical verdict into a named behaviour with a lookup: "this window is consistent
with T1046 Network Service Discovery -- check whether the source is a sanctioned scanner
before treating it as an intrusion."

IT IS A HYPOTHESIS, NOT A FINDING, and every structure here is built to say so. The mapping is
derived from measurements, so it can be wrong in both directions:

  * A port scan from a vulnerability scanner is T1046 and completely benign.
  * A single-flow exfiltration is not a "technique" at all; it is one transfer that happens to
    be large.
  * Absence of a mapping is not absence of an attack. Weirvern sees flow metadata and Zeek
    protocol records -- no endpoint telemetry, no process names, no command lines, no memory.
    Most of ATT&CK is structurally invisible from a network tap, and claiming otherwise would
    be the worst failure mode: an analyst who trusts a thin mapping stops looking.

So `coverage()` reports what is visible, what is out of reach and why, and every technique
carries its own confidence and the evidence that produced it.

WHY THE IDS AND NAMES ARE HERE RATHER THAN FETCHED. The mapping is a small, stable, curated
set of techniques that this sensor can actually observe. Fetching the ATT&CK STIX bundle would
add a runtime dependency, a network call, and a versioning problem, in exchange for a list we
would immediately filter down to these ~12 anyway. The IDs and names are MITRE's, reproduced
under their terms; see ATTRIBUTION below.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ATTRIBUTION: technique IDs, names and tactic associations are from the MITRE ATT&CK
# knowledge base (https://attack.mitre.org/), which is free to use commercially with
# attribution. Weirvern reproduces a small subset of the technique list; it does not reproduce
# ATT&CK's descriptions. MITRE ATT&CK is a registered trademark of The MITRE Corporation.
ATTACK_VERSION = "v17"
ATTRIBUTION = "MITRE ATT&CK® v17 (attack.mitre.org), used with attribution."


@dataclass(frozen=True)
class Technique:
    """One ATT&CK technique, with the evidence that would indicate it HERE."""

    id: str
    name: str
    tactic: str
    # What a network sensor can and cannot see for this technique. Rendered in the GUI and in
    # the alert, because the difference between "detected" and "detectable" is the whole
    # question an analyst asks next.
    network_visibility: str = "partial"


# ── the techniques this sensor can actually observe ─────────────────────────────
#
# Every entry is here because a specific measurement in this project maps to it. Nothing was
# added because it "seemed related" -- an inaccurate mapping is worse than no mapping, since it
# sends an analyst down a path with confidence they should not have.

TECHNIQUES: dict[str, Technique] = {
    "T1046": Technique(
        "T1046", "Network Service Discovery", "Discovery",
        "STRONG. Many destination ports from one source in a short window, with little or no "
        "return traffic, is the signature itself. Whether it is hostile is a question about "
        "authorization, not detection.",
    ),
    "T1595": Technique(
        "T1595", "Active Scanning", "Reconnaissance",
        "STRONG. The pre-compromise form of T1046: scanning from outside, or against a range "
        "rather than a host. Distinguished by scale and by the source being external.",
    ),
    "T1021": Technique(
        "T1021", "Remote Services", "Lateral Movement",
        "PARTIAL. Zeek shows the protocol and the destination service, and smb_mapping shows "
        "the share path -- so admin-share access is visible. The credential used is not.",
    ),
    "T1021.002": Technique(
        "T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement",
        "STRONG for the connection, PARTIAL for intent. `\\\\HOST\\ADMIN$` or `C$` in "
        "smb_mapping.log is a direct observation; whether the tool behind it is PsExec or an "
        "administrator's script is not.",
    ),
    "T1021.003": Technique(
        "T1021.003", "Remote Services: Distributed Component Object Model", "Lateral Movement",
        "STRONG. dce_rpc.log carries the endpoint UUID and the operation, which is exactly how "
        "WMI/service execution appears on the wire -- e.g. SVCCTL CreateServiceW.",
    ),
    "T1569.002": Technique(
        "T1569.002", "System Services: Service Execution", "Execution",
        "PARTIAL. The service-control RPC is visible in dce_rpc.log (CreateServiceW); the "
        "binary that was launched and whether it persisted are not.",
    ),
    "T1059": Technique(
        "T1059", "Command and Scripting Interpreter", "Execution",
        "WEAK. A scripting interpreter reached over a network looks like ordinary traffic. "
        "Only its consequence -- a service created, a file written, a shell established -- is "
        "observable, and only via those other techniques.",
    ),
    "T1041": Technique(
        "T1041", "Exfiltration Over C2 Channel", "Exfiltration",
        "PARTIAL. A large, sustained outbound transfer with little return traffic is "
        "measurable. Whether the destination is C2 or a backup service is not -- that needs "
        "reputation, which this deployment does not ship.",
    ),
    "T1048": Technique(
        "T1048", "Exfiltration Over Alternative Protocol", "Exfiltration",
        "PARTIAL. Unusual protocol on an unusual port for the volume moved. DNS is the common "
        "case here, and the DNS features (query entropy, length, NXDOMAIN rate) are what make "
        "it visible.",
    ),
    "T1071.004": Technique(
        "T1071.004", "Application Layer Protocol: DNS", "Command and Control",
        "PARTIAL. Tunnelling shows as high-entropy, long, frequently-unanswered queries. "
        "Legitimate CDNs and some malware defences look the same.",
    ),
    "T1573": Technique(
        "T1573", "Encrypted Channel", "Command and Control",
        "PARTIAL. Weirvern observes the TLS handshake and the JA4 fingerprint, never the "
        "plaintext. A changing client fingerprint or a downgraded version is visible; the "
        "content is not, by design.",
    ),
    "T1078": Technique(
        "T1078", "Valid Accounts", "Defense Evasion",
        "WEAK, and this is the honest answer. A valid credential used from a valid host "
        "produces normal-looking traffic. Kerberos `request_type` and principal anomalies "
        "raise the odds; only endpoint or directory logs settle it.",
    ),
    "T1558": Technique(
        "T1558", "Steal or Forge Kerberos Tickets", "Credential Access",
        "PARTIAL. Kerberoasting appears as TGS requests naming many SPNs from one principal. "
        "AS-REP roasting -- iterating principals to find ones that do not require preauth and "
        "then attacking the ticket offline -- has its ONLY signal SUPPRESSED BY DEFAULT: Zeek "
        "ships `ignored_errors = {NEEDED_PREAUTH, ...}` in base/protocols/krb/main.zeek, and "
        "NEEDED_PREAUTH is precisely the error the attack generates. The log deliberately omits "
        "it because logging it 'significantly increase[s] the noisiness of the log', and Zeek's "
        "own comment says logging it is how you detect the attack. So `error_msg` cannot carry "
        "this signal until the policy redefines `ignored_errors` -- see weirvern-local.zeek. The "
        "ticket contents do not exist in the log at all.",
    ),
    "T1110": Technique(
        "T1110", "Brute Force", "Credential Access",
        "PARTIAL. A burst of authentication attempts against one service, with a high "
        "failure ratio, is visible for SSH (auth_attempts/auth_success) and NTLM. Credential "
        "stuffing distributed across many accounts is much harder.",
    ),
    "T1018": Technique(
        "T1018", "Remote System Discovery", "Discovery",
        "STRONG. One host contacting many hosts on discovery ports within a window, without "
        "transferring data.",
    ),
    "T1200": Technique(
        "T1200", "Hardware Additions", "Initial Access",
        "NOT VISIBLE. A device plugged into the network is not observable from a flow record; "
        "this requires switch MAC-table or 802.1X telemetry.",
    ),
    "T1190": Technique(
        "T1190", "Exploit Public-Facing Application", "Initial Access",
        "WEAK. The exploit traffic is an HTTP request, indistinguishable in flow metadata from "
        "legitimate use. URI patterns and response codes help; request bodies are not stored.",
    ),
    "T1071": Technique(
        "T1071", "Application Layer Protocol", "Command and Control",
        "WEAK without payload inspection. Beacon regularity is the usable signal -- periodicity "
        "in a host's connections to one destination -- and Weirvern does not currently compute "
        "it. Named here so its absence is explicit rather than assumed covered.",
    ),
}

# Techniques that are structurally out of reach for a network sensor, with the reason. Stated
# so that "no technique mapped" is never confused with "no attack present".
OUT_OF_REACH: dict[str, str] = {
    "T1055": "Process injection -- requires endpoint process telemetry",
    "T1003": "OS credential dumping -- requires endpoint file/memory telemetry",
    "T1486": "Data encrypted for impact -- file action bursts help (smb_files RENAME/DELETE), "
             "but confirmation requires the endpoint",
    "T1053": "Scheduled task/job -- the RPC to create one is visible (dce_rpc), the task "
             "itself is not",
    "T1547": "Boot or logon autostart -- requires host registry/plist/filesystem visibility",
    "T1112": "Modify registry -- requires host telemetry",
    "T1562": "Impair defenses -- requires host or security-tool telemetry",
}


# ── the evidence -> technique rules ─────────────────────────────────────────────
#
# Each rule states the MEASUREMENT, the threshold, and the technique. The thresholds are named
# constants rather than inline literals so they can be reviewed against real data instead of
# being buried in a condition -- and so a test can pin them.
#
# A rule fires only on evidence that Weirvern actually collects. Nothing here infers a
# technique from a detector's score alone: a high score means "unusual", and "unusual" is not
# a behaviour.

# Port-scan / service-discovery: mirrors the corroboration thresholds already used by
# ensemble.signature_corroboration, deliberately, so the mapping cannot disagree with the
# severity logic about what a scan looks like.
DISCOVERY_MIN_PORTS = 100
DISCOVERY_MIN_ENTROPY = 3.0
# A scan moves no bytes. Without this a busy legitimate server would map to T1046.
DISCOVERY_MAX_BYTES = 8192
# Active Scanning (T1595) is reconnaissance of a RANGE. Measured in HOSTS, because a deep
# single-host scan is T1046 -- see the comment at the rule.
SCAN_RANGE_MIN_HOSTS = 25
# Exfiltration: outbound bytes dominating, above a floor that makes the ratio meaningful.
EXFIL_MIN_BYTES = 10_000_000
EXFIL_MIN_RATIO = 0.9
# Brute force: attempts against one service with a high failure rate.
BRUTE_MIN_ATTEMPTS = 20
BRUTE_MIN_FAILURE_RATIO = 0.8
# Kerberoasting: one principal requesting many distinct service principals.
KERB_MIN_SPNS = 10
# DNS tunnelling: sustained high-entropy, long queries with failures.
DNS_MIN_QUERIES = 50
DNS_MIN_ENTROPY = 3.5
DNS_MIN_NO_ANSWER_RATIO = 0.5


@dataclass
class Match:
    """One technique matched to one window, with the evidence and a confidence."""

    technique: Technique
    confidence: str          # "high" | "medium" | "low"
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.technique.id,
            "name": self.technique.name,
            "tactic": self.technique.tactic,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "network_visibility": self.technique.network_visibility,
        }


def _f(v: Any, default: float = 0.0) -> float:
    """Coerce a ClickHouse/JSON value to float without raising.

    Everything reaching this module comes from either a database row or a JSON blob, so types
    are not guaranteed. A mapping that raises on a malformed row would take the alert path down
    with it, which is a worse outcome than a missing technique.
    """
    if v is None:
        return default
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _truthy(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in {"1", "true", "t", "yes"}


def map_techniques(row: dict[str, Any]) -> list[Match]:
    """Map one anomaly window to the ATT&CK techniques its measurements support.

    `row` is a network-window row: the volumetric measurements plus any Zeek-derived features
    (which may be absent -- the join is sparse by design, so every Zeek rule below requires its
    own evidence to be present rather than assuming it).

    Returns an empty list when nothing matches, which is the common and correct outcome. An
    empty list means "no technique in this set is supported by these measurements" -- it does
    NOT mean the window is benign, and callers must not present it that way.
    """
    out: list[Match] = []

    ports = _f(row.get("unique_dst_ports"))
    entropy = _f(row.get("port_entropy"))
    # `total_bytes` ONLY. There was an `or _f(row.get("orig_bytes"))` here, and orig_bytes is
    # not a column of flows_aggregated -- so the fallback could never succeed, while making the
    # code look like it handled a second source.
    bytes_out = _f(row.get("total_bytes"))
    # ── resp_bytes HAS NO SOURCE, AND PRETENDING IT DOES IS WORSE THAN NOT HAVING IT ────────
    #
    # `flows_aggregated` carries no inbound-bytes column, and nothing merges one in: the
    # NetFlow aggregate stores per-source volume only. So this read is always 0.0, and the
    # consequence is not merely a missing fact -- it INVERTS a verdict:
    #
    #     ratio = bytes_out / (bytes_out + 0) = 1.0
    #
    # 1.0 clears EXFIL_MIN_RATIO (0.9) unconditionally, so T1041 (Exfiltration Over C2) fired on
    # EVERY large transfer with no evidence of asymmetry at all -- including a legitimate backup
    # uploading 50 MB. A rule that cannot fail is not a detection, and this one was reported as
    # a medium-severity finding each time.
    #
    # The honest form states that the ratio is UNKNOWN and does not gate on it. Where a real
    # inbound figure is available (Zeek's conn.log orig/resp bytes, which the protocol rows
    # carry) map_zeek_techniques can judge asymmetry properly; here it cannot.
    #
    # No `bytes_back` variable is kept: an unused binding that reads as a value this function
    # obtained is how the original defect looked plausible. The exfiltration branch below says
    # in its own evidence that the inbound half is unavailable.

    # ── Discovery: T1046 / T1595 ───────────────────────────────────────────────
    # Many ports, wide spread, and almost nothing transferred. The zero-byte qualifier is
    # load-bearing: a web server serving 500 clients touches many ports with real volume, and
    # without this condition every busy host would be mapped to a port scan.
    scan_like = ports >= DISCOVERY_MIN_PORTS and entropy >= DISCOVERY_MIN_ENTROPY
    low_volume = bytes_out <= DISCOVERY_MAX_BYTES
    if scan_like and low_volume:
        m = Match(
            TECHNIQUES["T1046"],
            "high" if ports >= 250 else "medium",
            [
                f"{ports:.0f} distinct destination ports (threshold {DISCOVERY_MIN_PORTS})",
                f"port entropy {entropy:.2f} (threshold {DISCOVERY_MIN_ENTROPY})",
                f"{bytes_out:.0f} bytes out, so no data was moved",
            ],
        )
        out.append(m)
        # Active Scanning (T1595) is the RECON form: sweeping a RANGE rather than probing one
        # host deeply. The distinguishing measurement is therefore HOSTS, not ports -- a
        # 500-port scan of a single host is a deep T1046, not reconnaissance. Reporting it as
        # T1595 would point the analyst at "something external is mapping us" when the
        # evidence says "something is probing one host hard".
        if _f(row.get("unique_dst_ips")) >= SCAN_RANGE_MIN_HOSTS:
            out.append(Match(
                TECHNIQUES["T1595"], "medium",
                [f"{_f(row.get('unique_dst_ips')):.0f} distinct hosts swept in one window, "
                 f"which is range reconnaissance rather than a single-host probe"],
            ))

    # ── Remote system discovery: T1018 ─────────────────────────────────────────
    # Many HOSTS rather than many ports. `unique_dst_ips` is the measurement, and it is a
    # distinct question from service discovery -- so it is a distinct technique.
    hosts = _f(row.get("unique_dst_ips"))
    if hosts >= 20 and bytes_out <= DISCOVERY_MAX_BYTES:
        out.append(Match(
            TECHNIQUES["T1018"], "medium" if hosts < 50 else "high",
            [f"{hosts:.0f} distinct destinations contacted with only {bytes_out:.0f} bytes "
             f"transferred"],
        ))

    # ── Exfiltration: T1041 / T1048 ────────────────────────────────────────────
    #
    # THE ASYMMETRY COMES FROM ZEEK, NOT FROM THE FLOW ROW. There is no inbound-bytes column in
    # `flows_aggregated` -- the NetFlow aggregate stores per-source volume only -- so a ratio
    # computed from a flow row is bytes_out/(bytes_out+0) == 1.0, which clears EXFIL_MIN_RATIO
    # unconditionally. That made the rule fire on EVERY large transfer, including a legitimate
    # backup uploading 50 MB. (The previous form read `resp_bytes` from this row; the old tests
    # passed only because they hand-built rows carrying `orig_bytes`/`resp_bytes` that nothing in
    # production ever merged in.)
    #
    # `zeek_outbound_ratio` is the real thing: conn.log's orig/(orig+resp), computed per
    # host-window by zeek_window_summary_sql, merged onto this row by worker.py, and already used
    # as an ML feature. It is present only when the sensor saw the host's connections, so the
    # rule REQUIRES it rather than defaulting -- "we could not measure asymmetry" must not read
    # as "asymmetry confirmed", and it must not read as "balanced" either.
    outbound_ratio = row.get("zeek_outbound_ratio")
    if bytes_out >= EXFIL_MIN_BYTES:
        if outbound_ratio is None:
            evidence = [
                f"{bytes_out / 1e6:.1f} MB outbound in one window; the Zeek sensor has no "
                f"connection records for this host, so asymmetry cannot be judged",
            ]
            # Low confidence and explicitly unmeasured: volume alone does not distinguish a leak
            # from an upload. Reported because someone should look; not asserted as exfiltration.
            out.append(Match(TECHNIQUES["T1041"], "low", evidence))
        elif _f(outbound_ratio) >= EXFIL_MIN_RATIO:
            pct = _f(outbound_ratio)
            evidence = [
                f"{bytes_out / 1e6:.1f} MB outbound, {pct:.0%} of the host's bytes sent "
                f"(one-way; threshold {EXFIL_MIN_RATIO:.0%})",
            ]
            out.append(Match(TECHNIQUES["T1041"], "medium", evidence))
            # T1048 (Over Alternative Protocol) is the same volume on a port that is not plain
            # web/TLS. `dst_port` is not on this row either -- it is a per-FLOW fact on raw
            # `flows` -- so the port half of the argument stays with the Zeek records rather than
            # being invented here.

    # ── DNS tunnelling / C2: T1071.004 ─────────────────────────────────────────
    #
    # NAMES CORRECTED. The first version read `dns_query_count` / `dns_mean_entropy` /
    # `dns_no_answer`, none of which any query produces -- the Zeek summary aliases them
    # `zeek_dns_count`, `zeek_dns_mean_query_entropy` and `zeek_dns_failed_ratio`. Every read
    # returned 0.0, so this rule could never fire and would have looked like a quiet network.
    # Caught by tests/test_attack_wiring.py, which requires each key the mapper reads to be
    # produced by a real query or table.
    #
    # The failure ratio is used rather than a raw no-answer count: the Zeek feature is already
    # a ratio, and a count would need the total alongside it, which is a second chance to
    # mismatch. `zeek_dns_failed_ratio` covers rcode errors and no-answer together, which is
    # the signal tunnelling actually produces.
    #
    # NO FALLBACK NAMES. These were briefly written as
    #   `_f(row.get("zeek_dns_count")) or _f(row.get("dns_query_count"))`  [removed]
    # which is worse than useless: 0 is falsy, so a host with a legitimate zero queries fell
    # through to a name that does not exist, and the code APPEARED to handle two sources. One
    # name per concept, the one a query actually produces.
    queries = _f(row.get("zeek_dns_count"))
    dns_entropy = _f(row.get("zeek_dns_mean_query_entropy"))
    failed_ratio = _f(row.get("zeek_dns_failed_ratio"))
    # Only meaningful when Zeek actually saw DNS for this host. Without this the rule would
    # treat "no Zeek data" as "no failures" and also as "no queries", which is correct by
    # accident -- but for a host with 200 queries and a 0.0 ratio it must NOT fire, and the
    # ratio condition is what decides.
    if (queries >= DNS_MIN_QUERIES and dns_entropy >= DNS_MIN_ENTROPY
            and failed_ratio >= DNS_MIN_NO_ANSWER_RATIO):
        out.append(Match(
            TECHNIQUES["T1071.004"], "medium",
            [f"{queries:.0f} DNS queries at mean entropy {dns_entropy:.2f}, "
             f"{failed_ratio:.0%} failed or unanswered",
             "high-entropy, frequently-failing queries are the tunnelling signature"],
        ))

    # Kerberos (T1558) is deliberately NOT mapped from the flow row.
    #
    # There was a branch here reading `kerberos_distinct_services` / `kerb_distinct_services`,
    # and neither is produced by any query -- the Kerberos evidence lives in the Tier-2
    # protocol records and is mapped by `map_zeek_techniques`. So the branch was dead code that
    # looked like coverage. Removing it makes the real source the only one, and
    # tests/test_attack_wiring.py now fails if a rule is pointed at a key nothing produces.
    #
    # The distinction it encodes: Kerberos ticket abuse is a PROTOCOL fact (which principal
    # asked for which SPN), not a volumetric one. It cannot be counted into existence.

    # ── Brute force (T1110) IS NOT MAPPED FROM THIS ROW ────────────────────────
    #
    # A block here read `attempts` / `successes` and claimed they were "what the protocol
    # query's zeek_ssh branch aliases" -- which is exactly the problem. That branch feeds
    # `map_zeek_techniques`, not this function, and `flows_aggregated` has no such columns. So
    # the read was always 0, the `>= BRUTE_MIN_ATTEMPTS` guard never passed, and the technique
    # could not fire from here no matter what the network did.
    #
    # It also sat one comment away from a note explaining that the Kerberos rule had been
    # removed for the identical reason, so the same mistake survived beside its own correction.
    #
    # SSH brute force is now raised in `map_zeek_techniques`, where the rows genuinely carry
    # per-connection auth_attempts/auth_success. The distinction is the same as Kerberos':
    # authentication failure counts are a PROTOCOL fact and cannot be counted into existence
    # from volumetric aggregates.

    return out


def map_zeek_techniques(rows: list[dict[str, Any]], src_addr: str | None = None) -> list[Match]:
    """Map Zeek-derived records to the techniques only a protocol log can support.

    These cannot come from the flow row, because they are facts about PROTOCOLS rather than
    about volume. `smb_mapping.path` exists in no NetFlow record at all, which is the reason
    the Tier-2 logs were added -- so it is also the reason these techniques are only mappable
    when the Zeek join is populated.

    An empty `rows` list returns an empty match list. On a deployment where the sensors see
    different segments (measured on this box: 91 NetFlow hosts against 35 Zeek hosts, overlap
    of 2), that is the normal case, and it must not be reported as "no lateral movement".
    """
    out: list[Match] = []
    if not rows:
        return out

    admin_shares: list[str] = []
    service_creates: list[str] = []
    dce_endpoints: list[str] = []
    kerb_types: dict[str, int] = {}
    ntlm_failures = 0.0
    ntlm_total = 0.0
    weak_tls = 0.0
    tls_total = 0.0
    # SSH brute force. `attempts`/`successes` are aliased by the protocol query's zeek_ssh branch
    # to auth_attempts/auth_success, which are PER-CONNECTION counts -- the only place in this
    # system where a failed-login burst is visible. The volumetric row has no such columns, so
    # the rule that used to read them there could never fire (see map_techniques).
    ssh_attempts = 0.0
    ssh_successes = 0.0

    for r in rows:
        # ── T1021.002: admin shares via SMB ────────────────────────────────────
        # `smb_path` ONLY. The protocol query aliases both smb_mapping.path and
        # smb_files.path to `smb_path`; falling back to a bare `path` would also pick up an
        # unrelated column from another table in the union and could report an admin-share hit
        # for a non-SMB record.
        path = str(r.get("smb_path") or "")
        if path:
            # ADMIN$, C$, IPC$ are the shares lateral-movement tooling writes to. Matching on
            # the share NAME rather than the whole path keeps this correct across hosts.
            tail = path.rstrip("\\").split("\\")[-1].upper()
            if tail in {"ADMIN$", "C$", "IPC$"}:
                admin_shares.append(path)

        # ── T1021.003 / T1569.002: DCE/RPC service control ─────────────────────
        op = str(r.get("operation") or "")
        ep = str(r.get("endpoint") or "")
        if op or ep:
            dce_endpoints.append(ep or op)
        if op.lower() in {"createservicew", "startservicew", "changeserviceconfigw"}:
            service_creates.append(op)

        # ── T1558: Kerberos ────────────────────────────────────────────────────
        rt = str(r.get("operation") or r.get("request_type") or "").upper()
        if rt:
            kerb_types[rt] = kerb_types.get(rt, 0) + 1

        # ── T1110: NTLM authentication failures ────────────────────────────────
        # NTLM successes are identified by the presence of a username, which only
        # zeek_ntlm carries in this union.
        if r.get("username"):
            ntlm_total += 1
            if not _truthy(r.get("success")):
                ntlm_failures += 1

        # ── T1110: SSH authentication failures ─────────────────────────────────
        # Keyed on `kind` so only the zeek_ssh branch contributes: the union pads every other
        # table's rows with `0 AS attempts, 0 AS successes`, so summing unconditionally would
        # work by luck rather than by design -- and would silently start counting the wrong rows
        # if another branch ever aliased those names.
        if str(r.get("kind") or "") == "zeek_ssh":
            ssh_attempts += _f(r.get("attempts"))
            ssh_successes += _f(r.get("successes"))

        # ── T1573: TLS fingerprint and version ─────────────────────────────────
        j = str(r.get("ja4") or "")
        if j:
            tls_total += 1
            ver = str(r.get("version") or "")
            # Zeek logs "TLSv10"/"TLSv11" for versions long deprecated. A host that newly
            # downgrades its TLS stack is worth naming. (The JA4 fingerprint itself is
            # collected and stored -- see weirvern/features.py -- but a fingerprint alone is
            # not a technique: it needs a reputation source to mean anything, and this
            # deployment deliberately ships none.)
            if ver in {"TLSv10", "TLSv11", "SSLv3"}:
                weak_tls += 1

    if admin_shares:
        out.append(Match(
            TECHNIQUES["T1021.002"], "high",
            [f"admin share accessed: {p}" for p in sorted(set(admin_shares))[:3]],
        ))
        out.append(Match(
            TECHNIQUES["T1021"], "medium",
            [f"{len(set(admin_shares))} distinct administrative share path(s) in this window"],
        ))

    if service_creates:
        out.append(Match(
            TECHNIQUES["T1569.002"], "high",
            [f"service-control RPC observed: {op}" for op in sorted(set(service_creates))[:3]],
        ))
    if dce_endpoints and not service_creates:
        # An endpoint was touched but not a service-control operation: report the technique at
        # low confidence rather than claiming service execution that the operation does not
        # support. This is the distinction that keeps the mapping from overstating.
        out.append(Match(
            TECHNIQUES["T1021.003"], "low",
            [f"DCE/RPC to endpoint {ep} without a service-control operation"
             for ep in sorted(set(dce_endpoints))[:2]],
        ))
    elif service_creates:
        out.append(Match(
            TECHNIQUES["T1021.003"], "medium",
            ["WMI/service execution arrives as DCE/RPC to SVCCTL"],
        ))

    # Many TGS requests from one principal is Kerberoasting; AS requests for preauth-exempt
    # accounts is AS-REP roasting. Reported separately because they are different weaknesses.
    if kerb_types.get("TGS", 0) >= KERB_MIN_SPNS:
        out.append(Match(
            TECHNIQUES["T1558"], "medium",
            [f"{kerb_types['TGS']} TGS requests in this window -- Kerberoasting signature"],
        ))
    if kerb_types.get("AS", 0) >= KERB_MIN_SPNS:
        out.append(Match(
            TECHNIQUES["T1558"], "low",
            [f"{kerb_types['AS']} AS requests in this window -- check for accounts without "
             f"preauthentication required (AS-REP roasting)"],
        ))

    if ntlm_total >= BRUTE_MIN_ATTEMPTS:
        fail_ratio = ntlm_failures / ntlm_total
        if fail_ratio >= BRUTE_MIN_FAILURE_RATIO:
            out.append(Match(
                TECHNIQUES["T1110"], "medium",
                [f"{ntlm_total:.0f} NTLM authentications, {fail_ratio:.0%} unsuccessful"],
            ))

    # SSH brute force, raised HERE because this is where the counts exist. The same thresholds
    # as NTLM: enough attempts, mostly failing.
    if ssh_attempts >= BRUTE_MIN_ATTEMPTS:
        ssh_fail_ratio = 1.0 - (ssh_successes / ssh_attempts) if ssh_attempts else 0.0
        if ssh_fail_ratio >= BRUTE_MIN_FAILURE_RATIO:
            out.append(Match(
                TECHNIQUES["T1110"], "high" if ssh_fail_ratio > 0.95 else "medium",
                [f"{ssh_attempts:.0f} SSH authentication attempts, {ssh_fail_ratio:.0%} "
                 f"unsuccessful"],
            ))

    if tls_total and weak_tls / tls_total >= 0.5:
        out.append(Match(
            TECHNIQUES["T1573"], "low",
            [f"{weak_tls / tls_total:.0%} of TLS sessions used a deprecated version"],
        ))

    return out


def label(matches: list[Match]) -> str:
    """A short technique string for a table cell: `T1046 (high), T1018 (medium)`.

    Deliberately short. This appears in a list view where an analyst is scanning for the
    interesting row, and the full evidence belongs in the detail view rather than being
    truncated here.
    """
    if not matches:
        return ""
    return ", ".join(f"{m.technique.id} ({m.confidence})" for m in matches)


def summarise(matches: list[Match]) -> str:
    """One human sentence for an alert message.

    States the technique and the confidence, and says plainly that it is a hypothesis. An
    alert is read on a phone; "T1046 (medium) - possible service discovery" with no hedge
    invites the reader to treat a threshold crossing as a conclusion.
    """
    if not matches:
        # The absence case. Never rendered as "benign" -- the honest statement is that no
        # technique in the mapped set is supported, which is not the same thing.
        return "no ATT&CK technique matched these measurements"
    top = max(matches, key=lambda m: {"high": 3, "medium": 2, "low": 1}[m.confidence])
    others = [m for m in matches if m is not top]
    head = f"consistent with {top.technique.id} {top.technique.name} ({top.confidence})"
    if others:
        head += f"; also {', '.join(m.technique.id for m in others)}"
    return head


def mapped_ids() -> set[str]:
    """Every technique id this module can emit. Used by the coverage test."""
    return set(TECHNIQUES)


def coverage() -> dict[str, Any]:
    """What this sensor can and cannot map, for the GUI and for honest documentation.

    Exists because an empty technique list has two completely different meanings -- "nothing
    matched" and "nothing here is observable" -- and a reader has no way to tell them apart
    from the output alone. This function makes the difference explicit, including the
    techniques that are deliberately NOT mapped and the reason for each.
    """
    by_tactic: dict[str, list[dict[str, str]]] = {}
    for t in TECHNIQUES.values():
        by_tactic.setdefault(t.tactic, []).append({"id": t.id, "name": t.name})

    return {
        "attack_version": ATTACK_VERSION,
        "attribution": ATTRIBUTION,
        "tactics": {k: sorted(v, key=lambda x: x["id"]) for k, v in sorted(by_tactic.items())},
        "technique_count": len(TECHNIQUES),
        "out_of_reach": dict(sorted(OUT_OF_REACH.items())),
        "limits": (
            "Network-visible techniques only. Weirvern reads flow metadata and Zeek protocol "
            "records: no endpoint telemetry, no process names, no command lines, no memory, "
            "and no decrypted payloads. A technique absent from an alert is not evidence that "
            "it did not occur -- most of ATT&CK is structurally invisible from a network tap."
        ),
    }

