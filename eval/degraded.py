"""What survives if only ONE direction of each flow is visible.

The problem statement says "unidirectional IP traffic". We read that as a diode
carrying a TAP copy of both directions into a read-only enclave. A stricter
reading is possible — only one direction of each flow ever observable, as with
asymmetric routing or a one-way tap on a single fibre — and we do not get to
decide which the sponsor meant.

So this measures the stricter one instead of arguing about it. Same captures,
same detectors, same thresholds; the reverse direction is discarded before the
engine sees anything.

    python3 eval/degraded.py
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prahari.engine import Engine                       # noqa: E402
from prahari.generate import ALL_ATTACKS, TrafficGenerator   # noqa: E402
from prahari.visibility import DEGRADED, project_all    # noqa: E402

SEEDS = [2001, 2002, 2003, 2004, 2005]
JITTER = [0.15, 0.22, 0.30, 0.08, 0.40]


def run(flows) -> set[str]:
    return {a.threat_class for a in Engine(window=60.0).run(flows)}


def main() -> int:
    full: dict[str, int] = defaultdict(int)
    deg: dict[str, int] = defaultdict(int)

    for seed, jit in zip(SEEDS, JITTER):
        flows = TrafficGenerator(seed=seed, jitter=jit).capture(1800, classes=ALL_ATTACKS)
        for c in run(flows):
            full[c] += 1
        for c in run(project_all(flows)):
            deg[c] += 1
        print(f"  capture seed={seed} jitter={jit:.0%}  "
              f"both directions: {len(run(flows))}/7 classes  "
              f"one direction: {len(run(project_all(flows)))}/7")

    n = len(SEEDS)
    print("\n" + "-" * 94)
    print(f"{'threat class':22} {'both dirs':>10} {'one dir':>9}   what is lost when only one "
          f"direction is visible")
    print("-" * 94)
    for c in sorted(ALL_ATTACKS):
        print(f"{c:22} {full[c]:>7}/{n} {deg[c]:>7}/{n}   {DEGRADED.get(c, '')}")
    print("-" * 94)

    tf, td = sum(full.values()), sum(deg.values())
    print(f"\nDETECTION COVERAGE  both directions {tf}/{7 * n}   "
          f"one direction {td}/{7 * n}  ({td / max(tf, 1):.0%} retained)")
    print("\nThis is the answer to the ambiguity in the phrase 'unidirectional IP traffic'.")
    print("We assume a TAP copy of both directions crosses the diode. If the sponsor")
    print("means the stricter reading, the system still runs — it degrades in a way we")
    print("have measured and can name, rather than failing in a way we have not.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
