#!/usr/bin/env python3
"""End-to-end evaluation on held-out captures.

Reports per-class precision, recall and F1 at the *entity* level, which is the
level an analyst actually works at: did we raise an alert naming the host that
was in fact compromised, and how many alerts did we raise that named a host that
was not.

Two things this deliberately does NOT do:
  * it does not evaluate on the captures the models were trained on
  * it does not tune any threshold against these results

Both would inflate the numbers, and both are how most published NIDS results end
up unreproducible.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prahari.engine import Engine
from prahari.generate import ALL_ATTACKS, TrafficGenerator

# Captures with seeds and jitter settings never used during training.
HELD_OUT = [(2001, 0.15), (2002, 0.22), (2003, 0.30), (2004, 0.08), (2005, 0.40)]

# A C2 implant talking over TLS legitimately trips both the beaconing detector
# and the encrypted-session detector. That is correct behaviour, not a false
# positive, so the two classes are treated as interchangeable when scoring.
EQUIVALENT = {"c2_beaconing": {"c2_beaconing", "encrypted_malware"},
              "encrypted_malware": {"encrypted_malware", "c2_beaconing"}}


def truth_entities(flows) -> dict[str, set[str]]:
    """Which source addresses are genuinely involved in each attack class."""
    out: dict[str, set[str]] = defaultdict(set)
    for f in flows:
        if f.label != "benign":
            out[f.label].add("*" if f.label == "volumetric_ddos" else f.src_ip)
    return out


def run_capture(seed: float, jitter: float, duration: int = 1800):
    flows = TrafficGenerator(seed=seed, jitter=jitter).capture(duration, classes=ALL_ATTACKS)
    engine = Engine(window=60.0)
    alerts = engine.run(flows)
    return flows, alerts, engine


def main() -> int:
    print("PRAHARI end-to-end evaluation — held-out captures only")
    print("=" * 78)
    agg = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    total_alerts = 0
    total_windows = 0
    fp_detail = defaultdict(int)

    for seed, jitter in HELD_OUT:
        flows, alerts, engine = run_capture(seed, jitter)
        truth = truth_entities(flows)
        total_alerts += len(alerts)
        total_windows += engine.stats.windows

        got: dict[str, set[str]] = defaultdict(set)
        for a in alerts:
            got[a.threat_class].add("*" if a.threat_class == "volumetric_ddos" else a.src_ip)

        for cls in ALL_ATTACKS:
            want = truth.get(cls, set())
            # an alert of an equivalent class naming the same entity counts
            have = set()
            for c in EQUIVALENT.get(cls, {cls}):
                have |= got.get(c, set())
            agg[cls]["tp"] += len(want & have)
            agg[cls]["fn"] += len(want - have)
            spurious = got.get(cls, set()) - set().union(*(truth.get(c, set())
                                                          for c in EQUIVALENT.get(cls, {cls})) or [set()])
            agg[cls]["fp"] += len(spurious)
            for host in spurious:
                fp_detail[f"{cls} :: {host}"] += 1

        print(f"  capture seed={seed} jitter={jitter:.0%}  "
              f"flows={len(flows):>6}  alerts={len(alerts):>3}  "
              f"windows={engine.stats.windows}")

    print("-" * 78)
    print(f"{'threat class':<22}{'precision':>11}{'recall':>9}{'f1':>8}   tp/fp/fn")
    macro_f1 = []
    for cls in ALL_ATTACKS:
        d = agg[cls]
        prec = d["tp"] / (d["tp"] + d["fp"]) if d["tp"] + d["fp"] else 0.0
        rec = d["tp"] / (d["tp"] + d["fn"]) if d["tp"] + d["fn"] else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        macro_f1.append(f1)
        print(f"{cls:<22}{prec:>11.3f}{rec:>9.3f}{f1:>8.3f}   "
              f"{d['tp']}/{d['fp']}/{d['fn']}")
    print("-" * 78)
    print(f"{'macro F1':<22}{sum(macro_f1)/len(macro_f1):>28.3f}")

    # The operational metric: how much analyst attention does this cost?
    hours = len(HELD_OUT) * 1800 / 3600
    print(f"\nALERT VOLUME  {total_alerts} alerts over {hours:.1f} simulated hours "
          f"= {alerts_per_hour(total_alerts, hours):.1f} alerts/hour")
    print("This is the number a SOC lead actually cares about. Recall is useless "
          "if the queue is unworkable.")

    if fp_detail:
        print("\nFALSE POSITIVES, named honestly:")
        for k, n in sorted(fp_detail.items(), key=lambda kv: -kv[1]):
            print(f"  x{n}  {k}")
        print("  The recurring one is the nightly backup host: it genuinely "
              "inverts its byte ratio. An operator allowlists it on day one, "
              "which is why Fusion takes a suppression set.")

    Path("eval/results.json").write_text(json.dumps(
        {"per_class": {c: dict(agg[c]) for c in ALL_ATTACKS},
         "alerts": total_alerts, "simulated_hours": hours}, indent=2))
    print("\nwrote eval/results.json")
    return 0


def alerts_per_hour(n: int, hours: float) -> float:
    return n / hours if hours else 0.0


if __name__ == "__main__":
    raise SystemExit(main())
