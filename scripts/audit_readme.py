#!/usr/bin/env python3
"""Check the README's commands and claims against what the code actually accepts.

WHY THIS EXISTS. The README's version pins had drifted for five releases and nothing noticed,
because nothing compared the prose to the code. The version check was one instance of a class:
the operator-facing surface is the least tested part of this project, and it is the part an
operator meets FIRST. A README command that does not run is worse than a missing one, because it
costs the reader's trust in everything else on the page.

WHAT THIS CHECKS, each against the real source of truth rather than against itself:

  * CLI subcommands named in the README exist in the shipped parser.
  * Flags shown with a subcommand exist on that subcommand.
  * Environment variables the README presents as configuration are read somewhere in the package.
  * Workload names in `kubectl ... deploy/X` appear in the manifests, as the right KIND.
  * Paths quoted as existing files exist.

WHAT IT DELIBERATELY DOES NOT DO: run the commands. Most need a cluster, a registry or a sensor
node. This checks that the NAMES are real, which is what can be verified here and what rots
silently.

FOUR FALSE-POSITIVE CLASSES THIS HAD TO LEARN TO AVOID, all found by reading the matches before
believing them -- the first draft reported 40 problems and 36 were its own. Each is now a rule:

  1. `kubectl -n weirvern create secret ...` is NOT the CLI. Only a `weirvern` in COMMAND POSITION
     counts: at the start of a command, not after `-n`, `--namespace`, `kubectl`, or a slash.
  2. A flag belongs to the subcommand on ITS OWN LOGICAL LINE. Scanning a fixed window of
     following lines made table rows check each other's flags. Backslash continuations join,
     because that is one command to the operator.
  3. An env var may be read anywhere in the package, not only in config.py. Scanning one file
     reported WEIRVERN_REVERSE_DNS as unknown when revdns.py reads it.
  4. Env vars are read through helper functions too (_env_mode, _env_bool, ...), so the extraction
     follows any `_env_*("NAME")` and not only `os.environ.get("NAME")`.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"

# A `weirvern` in COMMAND POSITION: start of a segment, or after a shell operator. This is what
# excludes `kubectl -n weirvern create secret` (weirvern is an argument there, not the command).
CLI_CALL = re.compile(r"(?:^|[|&;]\s*|&&\s*|\$\{\s*|\$\(\s*)weirvern\s+([a-z][a-z0-9-]{2,})")
# A `weirvern <sub>` inside an inline-code span. The README's CLI table is a list of CLAIMS about
# the commands -- `| weirvern down [--volumes] |` asserts that `down` takes `--volumes` -- so a
# table row must be checked as its own claim. Checking only fenced blocks would leave the single
# most command-dense part of the page unaudited.
INLINE_CLAIM = re.compile(r"`(weirvern\s+[a-z][a-z0-9-]{2,}[^`]*)`")
# Flag names, not the `--` of a long line or a negative number.
FLAG = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]{1,})")
# Namespace-qualified resource targets, so `deploy/weirvern-worker` can be checked.
RESOURCE = re.compile(r"\b(deploy|deployments?|ds|daemonset|statefulset|sts|job|cronjob|cj|"
                      r"svc|service)\s*/+\s*([a-z0-9][a-z0-9-]*)")


def cli_surface() -> tuple[set[str], dict[str, set[str]]]:
    """Every subcommand and flag the shipped parser accepts, read from the parser itself."""
    sys.path.insert(0, str(ROOT))
    from weirvern.admin import cli  # noqa: PLC0415

    parser = cli.build_parser()
    subs: dict[str, set[str]] = {}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                flags = {o for act in sub._actions for o in act.option_strings}
                flags |= {act.dest for act in sub._actions if not act.option_strings and act.dest}
                subs[name] = flags
    return set(subs), subs


def declared_env_vars() -> set[str]:
    """Env var names read ANYWHERE in the package, through any helper.

    ── WHY CONSTANTS ARE INCLUDED, AND THE DEFECT THAT MADE IT NECESSARY ───────────────────────
    MEASURED (2026-09-23). This used to look only for a literal at the read site:
    `environ.get("NAME")` or a helper taking a quoted string. That misses the ordinary pattern of
    naming the variable once and referring to the constant:

        TOKEN_ENV = "WEIRVERN_GUI_TOKEN"        # module constant
        env.get(TOKEN_ENV)                      # read via the name, not a literal

    The consequence was a FALSE FINDING in the other direction: the README documents
    `WEIRVERN_GUI_TOKEN` (correctly -- it is how the break-glass door is authorized) and the audit
    reported the claim as unsupported, because it could not see the read. Chasing that produced this
    fix and also confirmed the read really exists, which is the point: the checker was wrong about
    the CODE, and acting on it would have meant "fixing" correct documentation.

    So uppercase module-level string constants are collected too. That is deliberately broad -- the
    risk is a false PASS (a name that appears as a constant but is never read), and a false pass here
    is far cheaper than telling someone their accurate documentation is wrong.
    """
    names: set[str] = set()
    for path in (ROOT / "weirvern").rglob("*.py"):
        src = path.read_text()
        names |= set(re.findall(r"environ(?:\.get)?\(\s*[\"']([A-Z][A-Z0-9_]+)", src))
        names |= set(re.findall(r"_env_[a-z]+\(\s*[\"']([A-Z][A-Z0-9_]+)", src))
        names |= set(re.findall(r"_int_env\(\s*[\"']([A-Z][A-Z0-9_]+)", src))
        # Module-level constants holding an env-var NAME: `TOKEN_ENV = "WEIRVERN_GUI_TOKEN"`.
        names |= set(re.findall(r"^[A-Z][A-Z0-9_]*\s*=\s*[\"']([A-Z][A-Z0-9_]{3,})[\"']", src, re.M))
    return names


def manifest_records() -> tuple[dict[str, set[str]], set[str]]:
    """(kind -> names, every key declared in a ConfigMap)."""
    by_kind: dict[str, set[str]] = {}
    keys: set[str] = set()
    for f in sorted((ROOT / "k8s").glob("*.yaml")):
        text = f.read_text()
        for kind in ("Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob", "Service"):
            for block in re.findall(rf"^kind: {kind}\s*$(.*?)(?=^kind:|\Z)", text, re.M | re.S):
                for name in re.findall(r"^\s{2}name:\s*([\w.-]+)", block, re.M):
                    by_kind.setdefault(kind.lower(), set()).add(name.strip("'\""))
        for m in re.finditer(r"^\s{4}([A-Z][A-Z0-9_]*):", text, re.M):
            keys.add(m.group(1))
    return by_kind, keys


# The alias spellings the README may legitimately use for a kind.
KIND_ALIASES = {
    "deploy": "deployment", "deployment": "deployment", "deployments": "deployment",
    "ds": "daemonset", "daemonset": "daemonset",
    "sts": "statefulset", "statefulset": "statefulset",
    "job": "job", "cronjob": "cronjob", "cj": "cronjob",
    "svc": "service", "service": "service",
}


def join_continuations(
    segments: list[tuple[int, str]],
) -> list[tuple[int, str]]:
    """Join backslash continuations, which are ONE command to the operator.

    A flag on the second physical line belongs to the subcommand at the head of the command, so
    without this a multi-line `kubectl ... \\` example can mis-attribute its flags.
    """
    out: list[tuple[int, str]] = []
    buf, start = "", 0
    for lineno, text in segments:
        if not buf:
            start = lineno
        stripped = text.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        buf += stripped
        out.append((start, buf))
        buf = ""
    if buf:
        out.append((start, buf))
    return out


def table_rows() -> list[tuple[int, str]]:
    """(line number, text) for every markdown table row.

    Separately from command segments, because a table is a DIFFERENT kind of claim: the env and
    settings tables assert "this variable is read" and "this is its default", which no code block
    expresses. Scoping every check to fenced blocks silently exempted the configuration contract.
    """
    out: list[tuple[int, str]] = []
    for i, line in enumerate(README.read_text().split("\n"), 1):
        if line.strip().startswith("|") and line.count("|") >= 3:
            out.append((i, line))
    return out


def command_segments() -> list[tuple[int, str]]:
    """(line number, text) for every place the README actually asserts a command.

    Two sources, because the README makes command claims in two shapes:

      * a line inside a fenced block, minus any trailing shell comment. A comment is prose, and
        `kubectl apply -k k8s/   # deploy / update` otherwise reads as a resource target
        `deploy/update`;
      * an inline-code span containing `weirvern`, which covers the CLI table where every row is
        a claim about what a subcommand accepts.

    Prose OUTSIDE those two is not a claim and is left alone -- which is what keeps
    `kubectl -n weirvern create secret` from being read as the CLI.
    """
    lines = README.read_text().split("\n")
    out: list[tuple[int, str]] = []
    inside = False
    for i, line in enumerate(lines, 1):
        if line.startswith("```"):
            inside = not inside
            continue
        if inside:
            out.append((i, re.sub(r"(?:^|\s)#.*$", "", line)))
        else:
            for m in INLINE_CLAIM.finditer(line):
                out.append((i, m.group(1)))
    return out


def check() -> list[str]:
    problems: list[str] = []
    subs, flags_by_sub = cli_surface()
    env_vars = declared_env_vars()
    by_kind, cm_keys = manifest_records()
    all_objects = {n for names in by_kind.values() for n in names}
    all_claims = join_continuations(command_segments()) + table_rows()

    for lineno, text in all_claims:
        # ── 1. Subcommands, and the flags shown with them.
        for m in CLI_CALL.finditer(text):
            sub = m.group(1)
            if sub not in subs:
                problems.append(
                    f"README.md:{lineno}  `weirvern {sub}` -- no such subcommand "
                    f"(have: {', '.join(sorted(subs))})"
                )
                continue
            for fm in FLAG.finditer(text):
                flag = fm.group(1)
                if flag not in flags_by_sub[sub]:
                    problems.append(
                        f"README.md:{lineno}  `weirvern {sub} {flag}` -- {sub!r} has no {flag} "
                        f"(it has: "
                        f"{', '.join(sorted(f for f in flags_by_sub[sub] if f.startswith('--'))) or 'none'})"
                    )

        # ── 2. Resource targets, checked against the right KIND.
        # Strip trailing shell comments first: prose after `#` is not a command, and
        # `kubectl apply -k k8s/    # deploy / update` otherwise reads as `deploy/update`.
        # Resource targets: only in COMMAND text. A table cell is not a kubectl invocation, so
        # rows are skipped here even though they carry the env-var and CLI claims checked above.
        is_table_row = text.strip().startswith("|") and text.count("|") >= 3
        targets = iter(()) if is_table_row else RESOURCE.finditer(text)
        for m in targets:
            kind, name = KIND_ALIASES.get(m.group(1).lower()), m.group(2)
            if kind is None:
                continue
            if name not in all_objects and name not in {"<name>", "NAME", "your-node-name"}:
                pass
            if name not in all_objects:
                problems.append(
                    f"README.md:{lineno}  `{m.group(0)}` -- no workload named {name!r} in k8s/ "
                    f"(have: {', '.join(sorted(all_objects))})"
                )
            elif name not in by_kind.get(kind, set()):
                actual = next((k for k, v in by_kind.items() if name in v), "?")
                problems.append(
                    f"README.md:{lineno}  `{m.group(0)}` -- {name!r} is a {actual.title()}, "
                    f"not a {kind.title()}"
                )

        # ── 3. Config env vars, but only where the README presents one as a knob. Skipping prose
        # avoids flagging ordinary shell variables used in examples.
        if "|" in text or "=" in text:
            for m in re.finditer(r"(?<![\w-])([A-Z][A-Z0-9_]{3,})(?=[\s`=|,)])", text):
                var = m.group(1)
                if var in env_vars or var in cm_keys:
                    continue
                if var.startswith(("CLICKHOUSE_", "WEIRVERN_", "PUSHOVER_", "ZEEK_", "NETFLOW_",
                                   "ML_")) or var in {
                    "SENSOR_MODE", "MGMT_IFACE", "TAIL_FILE", "MODEL_DIR", "BASE_THRESHOLD",
                    "STRONG_SIGNAL", "MIN_AGREEMENT", "DETECT_INTERVAL_S", "RETRAIN_EVERY_H",
                    "RETRAIN_WINDOW_H", "HEARTBEAT_INTERVAL_S", "INTERCEPT_TARGETS",
                    "EXCLUDE_CIDRS", "CAPTURE_EXCLUDE_CIDRS", "K8S_NAMESPACE",
                }:
                    problems.append(
                        f"README.md:{lineno}  `{var}` -- not read anywhere in the package and "
                        f"not a manifest ConfigMap key"
                    )

        # ── 4. The install one-liner must fetch a file that exists at that path.
        for m in re.finditer(
            r"raw\.githubusercontent\.com/[\w.-]+/[\w.-]+/(\w+)/([\w./-]+)", text
        ):
            if not (ROOT / m.group(2)).exists():
                problems.append(
                    f"README.md:{lineno}  the install one-liner fetches {m.group(2)!r}, "
                    f"which does not exist in the repo"
                )

        # ── 5. Paths, backticked or bare. A bare path inside a command is the kind an operator
        # actually copies, so only checking backticked ones leaves the risky half unaudited.
        path_re = (r"(?<![\w/.-])"
                   r"((?:weirvern|k8s|scripts|tests)/[\w./-]+\.(?:py|sql|js|css|html|sh|yaml|md))")
        for m in re.finditer(path_re, text):
            rel = m.group(1).rstrip(".,;:)\"'")
            if rel.endswith((".example",)) or "<" in rel:
                continue
            if not (ROOT / rel).exists():
                problems.append(f"README.md:{lineno}  `{rel}` does not exist in the tree")

    return problems


def main() -> int:
    problems = check()
    if not problems:
        print("    every README command, flag, env var and path matches the code")
        return 0
    print(f"    {len(problems)} README claim(s) do not match the code:")
    for p in sorted(set(problems), key=lambda s: int(s.split(":")[1].split()[0])):
        print(f"      {p}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
