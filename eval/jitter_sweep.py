#!/usr/bin/env python3
"""The jitter sweep — the experiment most teams skip.

Real C2 frameworks randomise their sleep interval (10-40% is typical) precisely
to defeat periodicity detection. A beaconing detector demonstrated only on
fixed-interval traffic tells you nothing about whether it works.

This measures beacon recall across the jitter range and writes both a CSV and an
ASCII chart. Every number below is produced by running the actual detector over
actual generated traffic — nothing here is drawn by hand.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prahari.engine import Engine
from prahari.generate import TrafficGenerator

JITTERS = [0.0, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]
SEEDS = [3101, 3102, 3103]          # seeds unused in training
DURATION = 1800


def recall_at(jitter: float) -> tuple[float, int, int]:
    found = total = 0
    for seed in SEEDS:
        flows = TrafficGenerator(seed=seed, jitter=jitter).capture(
            DURATION, classes={"c2_beaconing"})
        truth = {f.src_ip for f in flows if f.label == "c2_beaconing"}
        alerts = Engine(window=60.0).run(flows)
        got = {a.src_ip for a in alerts if a.threat_class == "c2_beaconing"}
        found += len(truth & got)
        total += len(truth)
    return (found / total if total else 0.0), found, total


def main() -> int:
    print("PRAHARI beacon detection vs C2 jitter")
    print(f"  {len(SEEDS)} captures per point, {DURATION}s each, "
          f"held-out seeds {SEEDS}")
    print("=" * 66)
    rows = []
    for j in JITTERS:
        rec, found, total = recall_at(j)
        rows.append({"jitter": j, "recall": round(rec, 4),
                     "detected": found, "beacons": total})
        bar = "#" * int(round(rec * 40))
        print(f"  jitter {j:>4.0%}   recall {rec:>5.2f}  {bar:<40} {found}/{total}")
    print("=" * 66)

    out = Path("eval/jitter_sweep.csv")
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["jitter", "recall", "detected", "beacons"])
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {out}")

    worst = min(rows, key=lambda r: r["recall"])
    print(f"\nWorst point: {worst['jitter']:.0%} jitter -> recall {worst['recall']:.2f}")
    print("Report this curve, not a single headline number. A detector that only "
          "works at zero jitter is a detector that does not work.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
