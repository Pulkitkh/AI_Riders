#!/usr/bin/env python3
"""Fit the two learned detectors and the bigram language model.

Training discipline that matters, and that most NIDS work gets wrong:

  * the split is TEMPORAL, never random. Flows from one attack burst are highly
    correlated; a random split puts them on both sides of the split, the model
    memorises the burst, and the reported accuracy is meaningless.
  * the held-out capture uses a different seed AND a different jitter setting,
    so we are measuring generalisation rather than recall of the training run.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prahari.detectors.beacon import FEATURES as BEACON_FEATURES, BeaconDetector
from prahari.detectors.dga import FEATURES as DGA_FEATURES
from prahari.features import bigram_table, lexical_features
from prahari.generate import ALL_ATTACKS, TrafficGenerator
from prahari.model import MODEL_DIR, LogisticRegression


def build_bigrams(flows) -> dict:
    """Language model over the domains this network normally resolves."""
    corpus = [f.dns_qname for f in flows if f.dns_qname and f.label == "benign"]
    print(f"  bigram corpus: {len(corpus)} benign domain names")
    return bigram_table(corpus)


def dga_dataset(flows, bigrams):
    X, y, ts = [], [], []
    for f in flows:
        if not f.dns_qname:
            continue
        X.append(lexical_features(f.dns_qname, bigrams))
        y.append(1 if f.label == "dga_resolution" else 0)
        ts.append(f.ts)
    return X, y, ts


def beacon_dataset(flows):
    """Per (src,dst) pair: timing features, labelled by whether the pair is C2.

    Destination prevalence is computed across the whole capture, exactly as the
    live detector computes it, so training and inference see the same feature.
    """
    # Captures are laid out 100_000 s apart, so the capture index is part of the
    # key. Without it the same (src, dst) pair from ten different captures
    # collapses into one training sample and the positive class all but vanishes.
    pairs = defaultdict(list)
    prevalence = defaultdict(set)
    for f in flows:
        if f.proto == "tcp" and f.syn:
            cap = int(f.ts // 100_000)
            pairs[(cap, f.src_ip, f.dst_ip)].append(f)
            prevalence[(cap, f.dst_ip)].add(f.src_ip)
    X, y, ts = [], [], []
    for (cap, src, dst), fl in pairs.items():
        if len(fl) < BeaconDetector.MIN_EVENTS:
            continue
        X.append(BeaconDetector.extract(fl, len(prevalence[(cap, dst)])))
        y.append(1 if sum(1 for f in fl if f.label == "c2_beaconing") > len(fl) / 2 else 0)
        ts.append(fl[0].ts)
    return X, y, ts


def temporal_split(X, y, ts, frac=0.7):
    order = sorted(range(len(ts)), key=lambda i: ts[i])
    cut = int(len(order) * frac)
    tr, te = order[:cut], order[cut:]
    return ([X[i] for i in tr], [y[i] for i in tr],
            [X[i] for i in te], [y[i] for i in te])


def report(model, X, y, name):
    tp = fp = fn = tn = 0
    thr = getattr(model, "threshold", 0.5)
    for xi, yi in zip(X, y):
        p = model.predict_proba(xi) >= thr
        if p and yi: tp += 1
        elif p and not yi: fp += 1
        elif not p and yi: fn += 1
        else: tn += 1
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    print(f"  {name:<24} precision {prec:.3f}  recall {rec:.3f}  f1 {f1:.3f}"
          f"   (tp {tp} fp {fp} fn {fn} tn {tn})  @t={thr:.2f}")
    return {"precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def main() -> int:
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    print("PRAHARI model training")
    print("=" * 62)

    # Split at CAPTURE level, not inside one capture. Six independent captures
    # with different seeds and jitter settings: four to train on, two held out.
    # Splitting inside a single capture would put an attack burst on both sides
    # of the boundary and quietly inflate every number below.
    print("generating six independent captures ...")
    train_flows, held_flows = [], []
    # The jitter range spans 0.00 to 0.45 on purpose. An earlier version trained
    # only on jittered beacons and learned "C2 means jittered", which the sweep
    # in eval/jitter_sweep.py caught as zero recall against a perfectly regular
    # implant. Covering the range is the fix.
    for i, (seed, jit) in enumerate([(11, 0.00), (23, 0.20), (37, 0.30), (41, 0.15),
                                     (53, 0.05), (67, 0.12), (71, 0.45), (83, 0.18),
                                     (89, 0.02), (97, 0.28), (101, 0.38), (103, 0.08)]):
        train_flows += TrafficGenerator(seed=seed, jitter=jit).capture(
            1800, t0=i * 100_000, classes=ALL_ATTACKS)
    for i, (seed, jit) in enumerate([(99, 0.33), (77, 0.24), (61, 0.17)]):
        held_flows += TrafficGenerator(seed=seed, jitter=jit).capture(
            1800, t0=(i + 10) * 100_000, classes=ALL_ATTACKS)
    print(f"  train {len(train_flows)} flows (10 captures) | "
          f"held-out {len(held_flows)} flows (3 captures)")

    # -- bigram language model ------------------------------------------------
    print("\nfitting bigram language model on benign domains ...")
    bigrams = build_bigrams(train_flows)
    (MODEL_DIR / "bigrams.json").write_text(json.dumps(bigrams))
    print(f"  wrote {len(bigrams)} bigram log-probabilities")

    metrics = {}

    # -- DGA ------------------------------------------------------------------
    print("\nfitting DGA lexical classifier ...")
    Xtr, ytr, _ = dga_dataset(train_flows, bigrams)
    Xh, yh, _ = dga_dataset(held_flows, bigrams)
    print(f"  train {len(Xtr)} samples ({sum(ytr)} positive) | "
          f"held-out {len(Xh)} ({sum(yh)} positive)")
    dga = LogisticRegression(DGA_FEATURES, lr=0.6, epochs=700).fit(Xtr, ytr)
    dga.choose_threshold(Xtr, ytr)
    metrics["dga_train"] = report(dga, Xtr, ytr, "DGA on training set")
    metrics["dga_held_out"] = report(dga, Xh, yh, "DGA HELD-OUT captures")
    dga.save("dga")

    # -- beaconing ------------------------------------------------------------
    print("\nfitting beaconing timing classifier ...")
    Xtr, ytr, _ = beacon_dataset(train_flows)
    Xh, yh, _ = beacon_dataset(held_flows)
    print(f"  train {len(Xtr)} pairs ({sum(ytr)} C2) | held-out {len(Xh)} ({sum(yh)} C2)")
    bea = LogisticRegression(BEACON_FEATURES, lr=0.5, epochs=900).fit(Xtr, ytr)
    bea.choose_threshold(Xtr, ytr)
    metrics["beacon_train"] = report(bea, Xtr, ytr, "beacon on training set")
    metrics["beacon_held_out"] = report(bea, Xh, yh, "beacon HELD-OUT captures")
    bea.save("beacon")

    (MODEL_DIR / "training_report.json").write_text(json.dumps(metrics, indent=2))
    print("\n" + "=" * 62)
    print(f"models written to {MODEL_DIR}")
    print("learned weights (standardised features):")
    print("  DGA   ", {k: round(v, 2) for k, v in dga.w.items()})
    print("  beacon", {k: round(v, 2) for k, v in bea.w.items()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
