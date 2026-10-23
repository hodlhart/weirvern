#!/usr/bin/env python3
"""Run the Matrix Profile shadow channel and print the top discords."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from weirvern import db  # noqa: E402
from weirvern.config import get_settings  # noqa: E402
from weirvern.models import temporal  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=25)
    ap.add_argument("--days", type=int, default=3)
    a = ap.parse_args()
    print(json.dumps(temporal.run(db.connect(get_settings()), limit_hosts=a.hosts, days=a.days),
                     indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
