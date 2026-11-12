"""Run the ripple stack against the generated corpus and print the measurement (RIP-1..RIP-4).

    python scripts/ripple_eval.py --seed 20261112
    python scripts/ripple_eval.py --corpus data/replay/ripple-corpus-20261112.json --out /tmp/r.json

The corpus is generated, never captured: every number this prints is reproducible from the seed
and the generator version printed at the top of the report.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from weirvern.models import ripple_corpus as corpus
from weirvern.models import ripple_eval as evaluation


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=20261112)
    parser.add_argument("--corpus", type=Path, help="use an existing corpus file")
    parser.add_argument("--hosts-per-scenario", type=int, default=2)
    parser.add_argument("--reference-days", type=int, default=40,
                        help="clean host-days used only for seasonal calibration")
    parser.add_argument("--max-p", type=float, default=0.05)
    parser.add_argument("--grace-minutes", type=int, default=60,
                        help="how long after the labelled window a late fire still counts")
    parser.add_argument("--min-consecutive", type=int, default=3,
                        help="buckets a fire must last to count as a ripple (definition: persistent)")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--min-families", type=int, default=2)
    parser.add_argument("--min-scales", type=int, default=2)
    parser.add_argument("--ablate", action="store_true",
                        help="also score the unguarded fusions, to show what the guards buy")
    args = parser.parse_args()

    if args.corpus:
        payload = corpus.load(args.corpus)
    else:
        payload = corpus.generate(seed=args.seed, hosts_per_scenario=args.hosts_per_scenario,
                                  reference_days=args.reference_days)

    days = corpus.host_days(payload)
    # Calibration uses CLEAN host-days only, and every day is then measured: a clean day that
    # fires is a false alarm, and excluding it from the run would hide exactly that.
    clean = [day for day in days if day.scenario in {"clean", "clean_reference"}]
    reference = evaluation._reference([evaluation.channel_series(day) for day in clean])
    measured = [day for day in days if day.scenario != "clean_reference"]
    results = evaluation.evaluate_days(measured, reference, max_p=args.max_p,
                                       min_consecutive=args.min_consecutive,
                                       grace_minutes=args.grace_minutes,
                                       min_families=args.min_families,
                                       min_scales=args.min_scales)
    summary = evaluation.summarise(results, min_consecutive=args.min_consecutive)
    if args.ablate:
        ablation = {}
        for families, scales in ((1, 1), (2, 1), (1, 2), (2, 2)):
            alt = evaluation.evaluate_days(
                measured, reference, max_p=args.max_p, min_consecutive=args.min_consecutive,
                grace_minutes=args.grace_minutes, min_families=families, min_scales=scales)
            alt_summary = evaluation.summarise(alt, min_consecutive=args.min_consecutive)
            ablation[f"families={families},scales={scales}"] = {
                "detection_rate": alt_summary["detection_rate"],
                "detection_rate_with_grace": alt_summary["detection_rate_with_grace"],
                "false_alarms_per_host_day": alt_summary["false_alarms_per_host_day"],
                "negative_days_that_fired": {k: v["fired"] for k, v in
                                             alt_summary["by_scenario"].items()},
            }
        summary["ablation"] = ablation
    summary["corpus"] = payload["manifest"]
    summary["max_p"] = args.max_p

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"corpus: {corpus.summarise(payload)}")
        print(f"detection: {summary['detected_host_days']}/{summary['positive_host_days']} "
              f"labelled ripple-days ({summary['detection_rate']:.1%}, "
              f"95% CI {summary['detection_ci95'][0]:.1%}-{summary['detection_ci95'][1]:.1%})")
        print(f"with a {args.grace_minutes}-min grace: "
              f"{summary['detected_with_grace']}/{summary['positive_host_days']} "
              f"({summary['detection_rate_with_grace']:.1%}, "
              f"95% CI {summary['detection_ci95_with_grace'][0]:.1%}-"
              f"{summary['detection_ci95_with_grace'][1]:.1%})")
        print(f"scales that carried detections: {summary['scale_usage']}")
        print(f"families that carried detections: {summary['family_usage']}")
        print(f"latency: median {summary['median_latency_min']} min")
        print(f"false alarms: {summary['false_alarm_windows']} windows on "
              f"{summary['negative_host_days']} negative host-days "
              f"({summary['false_alarms_per_host_day']}/host-day)")
        print("negatives that fired:", summary["by_scenario"])
        if args.ablate:
            print("ablation (what the guards buy):")
            for key, row in summary["ablation"].items():
                print(f"  {key}: detection {row['detection_rate']:.0%}, "
                      f"FA/host-day {row['false_alarms_per_host_day']}, "
                      f"negatives fired {row['negative_days_that_fired']}")
        print("by cell:")
        for key, cell in summary["cells"].items():
            print(f"  {key}: {cell['detected']}/{cell['total']} "
                  f"({cell['rate']:.0%}, CI {cell['ci95'][0]:.0%}-{cell['ci95'][1]:.0%}), "
                  f"median latency {cell['median_latency_min']} min")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
