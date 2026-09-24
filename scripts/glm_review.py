#!/usr/bin/env python3
"""Drive GLM 5.3 (via Ollama's HTTP API) through a scoped code review.

WHY A SCRIPT AND NOT A CLAUDE CODE SESSION. The user asked for GLM 5.3 to drive this review, and
Claude Code is explicitly out of scope (user directive). Ollama's `/api/chat` is the direct path and
needs no agent framework: it takes messages, returns a message.

DESIGN NOTES THAT MATTER FOR USABILITY:
  * `num_ctx` is requested explicitly. The model reports a 1M window but Ollama allocates the
    context you ask for, and a file bundle silently truncated by a small default is the worst possible
    failure here -- the model would review a fragment and report confidently on the whole.
  * The bundle is built from EXPLICIT line ranges so the prompt can cite file:line, which is what
    makes a finding checkable.
  * Output is written to a JSONL file per (unit, model) so a timeout loses one unit, not the run.
  * Findings are returned as strict JSON so they can be counted and de-duplicated rather than
    eyeballed.

Usage:
    python3 scripts/glm_review.py --list
    python3 scripts/glm_review.py --unit siphon-intercept
    python3 scripts/glm_review.py --all
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

# DERIVED FROM __file__, NOT HARDCODED. The obvious literal here is the absolute path of this
# checkout, and this checkout's directory still carries the project's former name -- so embedding it
# tripped the repo's own stale-name guard the moment this script became tracked:
#
#     tests/test_naming.py::test_no_stale_old_name_in_any_tracked_file
#     scripts/glm_review.py:32: ROOT = pathlib.Path("....")
#
# The push was refused, which is the guard working. A path relative to the script also means the tool
# runs from any checkout instead of only the one machine it was written on.
ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = pathlib.Path(os.environ.get("GLM_REVIEW_OUT")
                   or tempfile.gettempdir()) / "glm_review"
OUT.mkdir(parents=True, exist_ok=True)
OLLAMA = os.environ.get("OLLAMA_CHAT_URL", "http://localhost:11434/api/chat")

# The review units. Each names the files GLM should read and the specific question it must answer.
# A unit is deliberately narrow: a model reviewing "the whole project" produces generic advice, and a
# model reviewing one mechanism with the code in front of it produces findings that can be checked.
UNITS: dict[str, dict] = {
    "siphon-intercept": {
        "title": "Siphon in-path interception: correctness and traffic impact",
        "files": ["weirvern/admin/intercept.py", "weirvern/admin/siphonnet.py"],
        "focus": (
            "This is the in-path ARP interception (mode=siphon). It forges ARP so a target's traffic "
            "flows through this host, then relays it. Two questions, in priority order:\n"
            "1. CORRECTNESS: can this leak, black-hole, or fail to restore a segment? Look for paths "
            "where forwarding state is installed but not guaranteed removed, where a peer is left "
            "with a forged ARP mapping, or where an error is swallowed so 'restored' is reported "
            "without proof.\n"
            "2. TRAFFIC IMPACT: the user's explicit requirement is that siphon must not slow traffic. "
            "Identify every place a packet could be delayed, dropped, or reordered -- sleeps, "
            "unbounded work in a forwarding path, per-packet Python, lock contention, buffer sizes."
        ),
    },
    "siphon-supervisor": {
        "title": "Siphon supervision, sysctls, and teardown guarantees",
        "files": ["weirvern/admin/siphon_supervisor.py", "weirvern/admin/sysctl_guard.py",
                  "weirvern/admin/mode.py"],
        "focus": (
            "The supervisor keeps an intercept alive and the sysctl guard prepares the node "
            "(ip_forward=1, rp_filter=0, send_redirects=0). Questions:\n"
            "1. Is every sysctl write reverted, and is the revert reachable from every teardown path "
            "(including SIGKILL of the supervising process, and a node rebooting mid-intercept)?\n"
            "2. Does the guard's failure list get ENFORCED by its caller, or acknowledged and "
            "ignored?\n"
            "3. Can two overlapping intercepts or two supervisor generations fight over the same "
            "state?\n"
            "4. Is mode validation exhaustive -- does anything accept a mode string the rest of the "
            "system cannot honour?"
        ),
    },
    "siphon-traffic-blocking": {
        "title": "Blocking traffic selected by the user (the stated next goal)",
        "files": ["weirvern/admin/siphonnet.py", "weirvern/admin/intercept.py",
                  "weirvern/sluice.py", "weirvern/sluice_store.py"],
        "focus": (
            "The user's next goal is the ability to BLOCK traffic selected in the GUI. Read what "
            "exists today (the sluice gate plus the interception path). Answer:\n"
            "1. What is the SMALLEST correct implementation that reuses what is here? Be specific "
            "about which existing function or table it extends.\n"
            "2. What are the failure modes that would make blocking dangerous -- a rule that blocks "
            "the management interface, a rule that outlives its TTL, a rule that cannot be removed, "
            "blocking that reports success without taking effect?\n"
            "3. What must NEVER be blockable, and how is that enforced in code rather than prose?"
        ),
    },
    "weirlings-fleet": {
        "title": "Weirlings: distributed sensors feeding the hub",
        "files": ["weirvern/fleet.py", "weirvern/fleet_store.py",
                  "weirvern/schema/012_weirlings.sql"],
        "focus": (
            "Weirlings are additional Zeek sensors distributed across a network, each feeding the "
            "central hub (ClickHouse + GUI + worker). Questions:\n"
            "1. Can a weirling register, be trusted, and feed data without an operator action that "
            "the operator would not expect? What authenticates a sensor?\n"
            "2. What happens when a registered weirling goes away, comes back with a new identity, or "
            "duplicates an existing sensor_id?\n"
            "3. Is the fleet view showing TRUTH -- does 'registered' mean 'feeding right now', or "
            "just 'a row exists'? (This project has a long history of row-existence read as "
            "liveness.)\n"
            "4. What is missing before a fleet of 20 sensors is manageable rather than a liability?"
        ),
    },
}

SYSTEM = (
    "You are a senior systems and network engineer reviewing a production security tool called "
    "Weirvern. You are reviewing REAL code with the files in front of you, not a description.\n\n"
    "RULES THAT MAKE YOUR REVIEW USEFUL:\n"
    "1. Cite file:line for every finding. If you cannot cite it, do not claim it.\n"
    "2. Distinguish CONFIRMED (you read the code and it does this) from SUSPECTED (it looks wrong "
    "but you cannot tell without running it). Never blur these.\n"
    "3. Say when something is FINE. A review that only lists problems cannot be used to decide "
    "where to stop.\n"
    "4. Prefer a small number of specific, actionable findings over a long list of general advice. "
    "'Consider adding error handling' is worthless. 'line 412 ignores the return value of apply(), so "
    "a failed sysctl still arms the watchdog' is worth acting on.\n"
    "5. The project's dominant failure mode is a check that reports success over work that did not "
    "happen. Hunt for that shape specifically.\n"
    "6. Do not propose rewrites of working code. Propose the smallest change that fixes the defect.\n\n"
    "Return ONLY a JSON object, no prose around it:\n"
    '{"findings":[{"id":"short-slug","severity":"critical|high|medium|low",'
    '"confidence":"confirmed|suspected","location":"file.py:123",'
    '"problem":"what is wrong and what happens as a result",'
    '"fix":"the smallest change that fixes it","rationale":"why this matters"}],'
    '"considered_fine":["file.py:NN -- what is correct about it"],'
    '"coverage":"what you actually read, and what you could not judge from these files"}'
)


def build_bundle(paths: list[str], max_chars: int = 400_000) -> tuple[str, list[str]]:
    """Concatenate the named files with line numbers, so findings can cite them."""
    parts: list[str] = []
    included: list[str] = []
    total = 0
    for rel in paths:
        p = ROOT / rel
        if not p.exists():
            parts.append(f"### {rel}\n(MISSING -- this file does not exist)\n")
            continue
        lines = p.read_text(errors="replace").splitlines()
        # Number every line: a finding must be checkable, and an unnumbered blob invites invented lines.
        body = "\n".join(f"{i:>5}| {ln}" for i, ln in enumerate(lines, 1))
        chunk = f"### {rel}  ({len(lines)} lines)\n{body}\n"
        if total + len(chunk) > max_chars:
            # Truncate LOUDLY rather than silently: a model reviewing a fragment must be told.
            room = max_chars - total
            note = (f"\n\n!!! TRUNCATED at {max_chars} chars -- the rest of {rel} "
                    f"is NOT shown. Say so in coverage.\n")
            chunk = chunk[:room] + note
        parts.append(chunk)
        included.append(rel)
        total += len(chunk)
    return "\n".join(parts), included


def call_glm(unit_key: str, model: str, timeout: int = 1800) -> dict:
    unit = UNITS[unit_key]
    bundle, included = build_bundle(unit["files"])
    prompt = (
        f"REVIEW UNIT: {unit['title']}\n\n"
        f"WHAT TO LOOK FOR:\n{unit['focus']}\n\n"
        f"THE CODE ({len(included)} file(s)):\n\n{bundle}"
    )
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": prompt}],
        "stream": False,
        # ASK FOR THE WINDOW EXPLICITLY. A silently-truncated context would produce a confident
        # review of a fragment, which is the failure mode this whole project keeps finding.
        "options": {"num_ctx": 200_000, "temperature": 0.0},
    }
    t0 = time.time()
    # THE PAYLOAD GOES ON STDIN, NOT IN `-d`. With `-d <json>` the whole request becomes one argv
    # string, and a file bundle large enough to be worth reviewing exceeds ARG_MAX:
    #
    #     OSError: [Errno 7] Argument list too long: 'curl'
    #
    # which failed the siphon-traffic-blocking unit on the first run while the smaller units
    # succeeded -- so the failure scaled with the size of what was being reviewed, which is exactly
    # backwards. `--data-binary @-` streams it instead and has no length limit.
    r = subprocess.run(
        ["curl", "-s", "--max-time", str(timeout),
         "-H", "Content-Type: application/json",
         "--data-binary", "@-", OLLAMA],
        input=json.dumps(payload),
        capture_output=True, text=True)
    dt = time.time() - t0
    rec = {"unit": unit_key, "model": model, "elapsed_s": round(dt, 1),
           "prompt_files": included, "prompt_chars": len(prompt)}
    if r.returncode != 0:
        rec["error"] = f"curl rc={r.returncode}: {r.stderr[:300]}"
        return rec
    try:
        d = json.loads(r.stdout)
    except Exception as exc:
        rec["error"] = f"bad json: {exc}: {r.stdout[:300]}"
        return rec
    if "error" in d:
        rec["error"] = str(d["error"])[:400]
        return rec
    rec["content"] = d.get("message", {}).get("content", "")
    for k in ("prompt_eval_count", "eval_count", "prompt_eval_cached_count"):
        if k in d:
            rec[k] = d[k]
    return rec


def parse_findings(content: str) -> dict:
    """Extract the JSON object, tolerating a fence or surrounding prose."""
    s = content.strip()
    if "```" in s:
        # take the largest fenced block that parses
        blocks = s.split("```")
        cands = [b for b in blocks if "{" in b]
        for b in sorted(cands, key=len, reverse=True):
            b = b.strip()
            if b.lower().startswith("json"):
                b = b[4:].strip()
            try:
                return json.loads(b)
            except Exception:
                continue
    # fall back to first { .. last }
    i, j = s.find("{"), s.rfind("}")
    if i >= 0 and j > i:
        try:
            return json.loads(s[i:j+1])
        except Exception as exc:
            return {"_parse_error": str(exc)}
    return {"_parse_error": "no JSON object found"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--unit", choices=sorted(UNITS))
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--model", default="glm-5.3:cloud")
    ap.add_argument("--timeout", type=int, default=1800)
    args = ap.parse_args()

    if args.list:
        for k, v in UNITS.items():
            print(f"  {k:26} {v['title']}")
            print(f"  {'':26} files: {', '.join(v['files'])}")
        return 0

    units = sorted(UNITS) if args.all else ([args.unit] if args.unit else [])
    if not units:
        ap.error("pass --unit, --all, or --list")

    for key in units:
        print(f"\n=== {key} ({args.model}) ===", flush=True)
        rec = call_glm(key, args.model, timeout=args.timeout)
        if "error" in rec:
            print(f"  ERROR: {rec['error']}", flush=True)
        else:
            parsed = parse_findings(rec["content"])
            rec["parsed"] = parsed
            n = len(parsed.get("findings", [])) if isinstance(parsed, dict) else 0
            print(f"  {rec['elapsed_s']}s  prompt={rec.get('prompt_eval_count')} "
                  f"out={rec.get('eval_count')}  findings={n}", flush=True)
        # One line per unit, appended: a timeout loses the unit, not the run.
        path = OUT / f"{key}.jsonl"
        with path.open("a") as fh:
            fh.write(json.dumps(rec) + "\n")
        print(f"  -> {path}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
