"""Count real intercept processes, robustly. Run INSIDE the worker pod.

WHY NOT A STRING MATCH. Two earlier probes searched the joined cmdline for "weirvern.admin.cli"
and "intercept" -- and the probe's OWN `python -c '<that search>'` contains both literals, so it
counted itself. Reported counts were therefore never below 1, which made a clean shutdown look
like a surviving orphan. That is the fifth time in this project a measurement said something about
the instrument rather than the system, so this one checks argv POSITIONALLY instead:

    python -m weirvern.admin.cli intercept ...

argv is exactly: [exe, "-m", "weirvern.admin.cli", "intercept", ...]. A `python -c` has "-c" in
position 1, so it cannot match regardless of what its source text contains.
"""

from __future__ import annotations

import os
import sys


def real_intercepts() -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as handle:
                argv = [a.decode("utf-8", "replace") for a in handle.read().split(b"\0") if a]
        except OSError:
            continue
        # Positional: python -m weirvern.admin.cli intercept
        if len(argv) >= 4 and argv[1] == "-m" and argv[2] == "weirvern.admin.cli" and argv[3] == "intercept":
            found.append((int(entry), " ".join(argv)[:120]))
    return found


def main() -> int:
    found = real_intercepts()
    print(f"REAL_INTERCEPTS={len(found)}", flush=True)
    for pid, cmd in found:
        print(f"  pid {pid}: {cmd}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
