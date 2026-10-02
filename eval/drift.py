#!/usr/bin/env python3
"""Concept-drift experiment — does the detector survive a network it was not
trained on, and traffic that changes over time?

A model fitted once on a fixed 'normal' profile is brittle: deploy it on a busier
or simply different network and its false-positive rate explodes, because the new
normal looks anomalous to the old model. PRAHARI's anomaly net defends against
this with an ADAPTIVE LOCAL BASELINE: it learns each network's own envelope live
and only alerts on a flow that is an outlier against BOTH the trained profile AND
the local one.

This measures the payoff. We shift the benign traffic's volume distribution away
from the training profile (benign_scale = 1.0 .. 3.0 — a different/evolving
network) and compare, on identical benign-only traffic:

  * STATIC  — the fixed synthetic-trained envelope alone (no local adaptation);
  * ADAPTIVE — the full detector, trained envelope AND the learned local baseline.

A trustworthy detector keeps its false-positive rate low as the network drifts.

    python3 eval/drift.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from prahari.detectors.anomaly import AnomalyDetector
from prahari.engine import Engine
from prahari.generate import TrafficGenerator
from eval.common import host_truth, host_pred  # noqa: E402

SEEDS = [7001, 7002, 7003]
SCALES = [1.0, 1.5, 2.2, 3.0]
CAPTURE_SECONDS = 1200


def benign_capture(seed: int, scale: float):
    g = TrafficGenerator(seed=seed)
    g.benign_scale = scale
    return g.capture(CAPTURE_SECONDS, classes=set())   # benign only


def static_fp_rate(flows) -> float:
    """What the fixed synthetic-trained envelope ALONE would flag — no local
    adaptation. Fraction of benign flows outside the trained envelope."""
    det = AnomalyDetector()
    if det.profile is None:
        return 0.0
    flagged = tot = 0
    for f in flows:
        vec = det.features(f)
        tot += 1
        if det._envelope_excess(vec) >= det.ENV_MARGIN:
            flagged += 1
    return flagged / tot if tot else 0.0


def adaptive_fp_rate(flows) -> tuple[float, int]:
    """The full detector on the same benign traffic: anomaly alerts per benign
    host (should stay near zero as the network drifts). Returns (host_fpr, alerts)."""
    alerts = Engine(window=60.0).run(flows)
    _, full_pred, _ = host_pred(alerts)
    truth = host_truth(flows)
    benign_hosts = [h for h, t in truth.items() if not t]
    flagged = sum(1 for h in benign_hosts if "anomalous_traffic" in full_pred.get(h, set()))
    return (flagged / len(benign_hosts) if benign_hosts else 0.0,
            sum(1 for a in alerts if a.threat_class == "anomalous_traffic"))


def main() -> int:
    print("PRAHARI concept-drift experiment — benign distribution shift")
    print("=" * 70)
    print(f"{'scale':>6} {'STATIC fp-rate':>16} {'ADAPTIVE host-fpr':>20} {'anomaly alerts':>16}")
    rows = []
    for scale in SCALES:
        s_rates, a_rates, a_counts = [], [], []
        for seed in SEEDS:
            flows = benign_capture(seed, scale)
            s_rates.append(static_fp_rate(flows))
            r, c = adaptive_fp_rate(flows)
            a_rates.append(r); a_counts.append(c)
        s = sum(s_rates) / len(s_rates)
        a = sum(a_rates) / len(a_rates)
        ac = sum(a_counts) / len(a_counts)
        print(f"{scale:>6.1f} {s:>15.1%} {a:>19.1%} {ac:>16.1f}")
        rows.append({"benign_scale": scale, "static_flow_fp_rate": round(s, 4),
                     "adaptive_host_fp_rate": round(a, 4), "adaptive_anomaly_alerts": round(ac, 1)})

    worst_static = max(r["static_flow_fp_rate"] for r in rows)
    worst_adaptive = max(r["adaptive_host_fp_rate"] for r in rows)
    print("\nAs the network drifts to 3x the training volume, the STATIC envelope's "
          f"false-positive rate climbs to {worst_static:.0%}, while the ADAPTIVE")
    print(f"detector holds host false-positives at {worst_adaptive:.0%}. The local "
          "baseline is what makes the model deployable on a network it never saw.")
    out = {"note": "benign-only traffic; static (trained envelope only) vs adaptive "
                   "(trained AND learned-local baseline) false positives under drift",
           "rows": rows}
    (ROOT / "eval" / "drift_report.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("\nwrote eval/drift_report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
