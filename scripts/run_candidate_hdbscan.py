#!/usr/bin/env python3
"""Run the HDBSCAN shadow challenger and print its report. Writes candidate scores only."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from weirvern import db  # noqa: E402
from weirvern.config import get_settings  # noqa: E402
from weirvern.models import candidates  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=5000)
    ap.add_argument("--min-cluster-size", type=int, default=40)
    args = ap.parse_args()
    report = candidates.run(db.connect(get_settings()), limit=args.limit,
                            min_cluster_size=args.min_cluster_size)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("available") else 2


if __name__ == "__main__":
    raise SystemExit(main())
