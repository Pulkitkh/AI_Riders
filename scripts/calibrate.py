#!/usr/bin/env python3
"""Fit per-class score calibration so a reported confidence means what it says.

A raw detector score of 0.9 is not a promise that nine in ten such alerts are
real. Calibration makes it one: we run the engine over held-out *calibration*
captures (seeds used neither in training nor in the eval report), collect every
alert's raw score together with whether it was actually correct (strict host
label — no class-equivalence credit), and fit an isotonic map from raw score to
observed precision for each threat class.

    python3 scripts/calibrate.py     # writes prahari/models/calibration.json

`eval/report.py` then measures the calibration quality (ECE / Brier) on the
separate evaluation captures, so the number we advertise is itself validated on
data the calibration never saw.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval"))

from prahari.engine import Engine
from prahari.generate import ALL_ATTACKS, TrafficGenerator
from prahari.model import isotonic_like_calibration
from common import DDOS_TARGET, host_truth   # noqa: E402  (eval/common.py)

# Distinct from training {11,23,37,41} and from eval/report.py {2001..,3007..}.
CALIB = [(4101, 0.12), (4102, 0.26), (4103, 0.34), (4104, 0.19), (4105, 0.08)]


def main() -> int:
    print("PRAHARI calibration — fitting raw score -> empirical precision")
    print("=" * 66)
    scores = defaultdict(list)   # class -> [raw_score]
    labels = defaultdict(list)   # class -> [1 correct / 0 wrong]

    for seed, jitter in CALIB:
        flows = TrafficGenerator(seed=seed, jitter=jitter).capture(1800, classes=ALL_ATTACKS)
        engine = Engine(window=60.0)
        engine.fusion.calibration = {}          # fit on RAW scores
        alerts = engine.run(flows)
        truth = host_truth(flows)
        for a in alerts:
            host = DDOS_TARGET if a.threat_class == "volumetric_ddos" else a.src_ip
            correct = 1 if a.threat_class in truth.get(host, set()) else 0
            scores[a.threat_class].append(a.score)
            labels[a.threat_class].append(correct)

    cal = {}
    for cls in sorted(scores):
        s, y = scores[cls], labels[cls]
        # Need both correct and incorrect examples and enough of them; otherwise a
        # single-point map would just assert 1.0, which is the opposite of honest.
        if len(s) >= 12 and 0 < sum(y) < len(y):
            cal[cls] = isotonic_like_calibration(s, y, bins=6)
            emp = sum(y) / len(y)
            print(f"  {cls:<20} n={len(s):>4}  empirical precision {emp:.3f}  "
                  f"({len(cal[cls]['edges'])} bins)")
        else:
            print(f"  {cls:<20} n={len(s):>4}  skipped (too few / all-correct — "
                  f"confidence falls back to raw score)")

    out = Path(__file__).resolve().parents[1] / "prahari" / "models" / "calibration.json"
    out.write_text(json.dumps(cal, indent=2), encoding="utf-8")
    print(f"\nwrote {out}  ({len(cal)} calibrated classes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
