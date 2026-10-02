#!/usr/bin/env python3
"""Validate PRAHARI on the UNSW-NB15 benchmark — the modern (2015) counterpart
to the NSL-KDD evaluation, on traffic from this decade rather than 1998 DARPA.

Same engine, same pure-Python models, same honest protocol as eval/nslkdd_eval.py:

  1. SUPERVISED detection (normal vs attack) — accuracy / precision / recall / F1
     / FPR, plus recall for each of the nine attack families.
  2. UNSUPERVISED anomaly detection — Isolation Forest fitted on NORMAL only.
     Because it never sees a single attack label, its per-family recall is a
     genuine ZERO-SHOT result for every family.
  3. DEEP baseline — the from-scratch autoencoder, compared head-to-head at an
     EQUAL false-positive operating point.

    python3 scripts/fetch_unsw.py && python3 eval/unsw_eval.py
"""
from __future__ import annotations

import json
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from prahari.anomaly import IsolationForest
from prahari.autoencoder import Autoencoder
from prahari.datasets import unsw
from prahari.model import LogisticRegression

DATA = ROOT / "data" / "unsw"
TRAIN_SUBSAMPLE = 25000
AE_TRAIN_SUBSAMPLE = 6000
TARGET_FPR = 0.10


def metrics(tp, fp, tn, fn):
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    acc = (tp + fp + tn + fn) and (tp + tn) / (tp + fp + tn + fn)
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"accuracy": round(acc, 4), "precision": round(prec, 4),
            "recall": round(rec, 4), "f1": round(f1, 4), "fpr": round(fpr, 4),
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def main() -> int:
    tr, te = DATA / "UNSW_NB15_training-set.csv", DATA / "UNSW_NB15_testing-set.csv"
    if not tr.exists() or not te.exists():
        print("UNSW-NB15 not found. Run:  python3 scripts/fetch_unsw.py", file=sys.stderr)
        return 2

    print("PRAHARI on the UNSW-NB15 benchmark — modern (2015) public data")
    print("=" * 70)
    train, test = unsw.load(tr), unsw.load(te)
    print(f"train {len(train):,} records  ·  test {len(test):,} records")

    # ---------- 1. supervised ----------
    rng = random.Random(1337)
    sub = rng.sample(train, min(TRAIN_SUBSAMPLE, len(train)))
    Xtr = [r.to_dict() for r in sub]
    ytr = [r.label for r in sub]
    feats = sorted({k for x in Xtr for k in x})
    print(f"\n[1] supervised classifier — {len(feats)} features, {len(sub):,} rows "
          f"({sum(ytr)} attack)")
    clf = LogisticRegression(feats, lr=0.5, epochs=200, l2=1e-3).fit(Xtr, ytr)
    clf.choose_threshold(Xtr, ytr)
    tp = fp = tn = fn = 0
    fam_total, fam_caught = Counter(), Counter()
    for r in test:
        pred = clf.predict_proba(r.to_dict()) >= clf.threshold
        if r.label:
            fam = unsw.category(r.attack)
            fam_total[fam] += 1
            if pred: tp += 1; fam_caught[fam] += 1
            else: fn += 1
        else:
            if pred: fp += 1
            else: tn += 1
    sup = metrics(tp, fp, tn, fn)
    print(f"    accuracy {sup['accuracy']:.3f} · precision {sup['precision']:.3f} · "
          f"recall {sup['recall']:.3f} · F1 {sup['f1']:.3f} · FPR {sup['fpr']:.3f}")
    fam_recall = {}
    print("    recall by attack family:")
    for fam in unsw.FAMILIES:
        n = fam_total.get(fam, 0)
        rc = fam_caught.get(fam, 0) / n if n else 0.0
        fam_recall[fam] = round(rc, 4)
        if n:
            print(f"      {fam:<16} {rc:6.1%}  ({fam_caught.get(fam,0)}/{n})")

    # ---------- 2. unsupervised Isolation Forest (normal-only) ----------
    print("\n[2] unsupervised anomaly detector — Isolation Forest on NORMAL only")
    normal_vecs = [r.to_vec() for r in train if r.label == 0]
    iso = IsolationForest(n_trees=120, sample_size=256, seed=7).fit(normal_vecs)

    def recall_at_fpr(score_fn):
        benign = sorted(score_fn(r) for r in test if r.label == 0)
        thr = benign[min(len(benign) - 1, int((1.0 - TARGET_FPR) * len(benign)))]
        tp = fn = fp = tn = 0
        fam_hit, fam_tot = Counter(), Counter()
        for r in test:
            hit = score_fn(r) >= thr
            if r.label:
                tp, fn = tp + hit, fn + (not hit)
                fam = unsw.category(r.attack); fam_tot[fam] += 1; fam_hit[fam] += hit
            else:
                fp, tn = fp + hit, tn + (not hit)
        zs = {f: round(fam_hit[f] / fam_tot[f], 4) for f in fam_tot if fam_tot[f]}
        return metrics(tp, fp, tn, fn), zs

    if_m, if_zero = recall_at_fpr(lambda r: iso.score(r.to_vec()))
    print(f"    detection rate (recall) {if_m['recall']:.3f} · FPR {if_m['fpr']:.3f} · "
          f"F1 {if_m['f1']:.3f}  @ {TARGET_FPR:.0%} FPR")
    print("    ZERO-SHOT recall per family (no attack labels seen at all):")
    for fam in unsw.FAMILIES:
        if fam in if_zero:
            print(f"      {fam:<16} {if_zero[fam]:6.1%}")

    # ---------- 2b. deep autoencoder baseline, matched FPR ----------
    print("\n[2b] deep baseline — pure-Python autoencoder on NORMAL only (no deps)")
    ae_train = rng.sample(normal_vecs, min(AE_TRAIN_SUBSAMPLE, len(normal_vecs)))
    ae = Autoencoder(dim=unsw.feature_dim(), hidden=16, bottleneck=8, seed=1337)
    ae.fit(ae_train, epochs=12, lr=0.05, batch=32)
    ae_m, _ = recall_at_fpr(lambda r: ae.reconstruction_error(r.to_vec()))
    gap = ae_m["recall"] - if_m["recall"]
    verdict = (f"explainable Isolation Forest within {gap:.1%} of the deep net"
               if gap > 0 else f"explainable Isolation Forest leads by {-gap:.1%}")
    print(f"    autoencoder recall {ae_m['recall']:.3f} · FPR {ae_m['fpr']:.3f}")
    print(f"    HEAD-TO-HEAD @ equal {TARGET_FPR:.0%} FPR: {verdict}.")

    out = {
        "dataset": {"name": "UNSW-NB15", "year": 2015,
                    "train": len(train), "test": len(test),
                    "families": list(unsw.FAMILIES)},
        "supervised": {**sup, "recall_by_family": fam_recall},
        "anomaly": {**if_m, "zero_shot_recall_by_family": if_zero},
        "deep_autoencoder": {**ae_m},
        "matched_comparison": {"target_fpr": TARGET_FPR,
                               "isolation_forest_recall": if_m["recall"],
                               "autoencoder_recall": ae_m["recall"]},
    }
    (ROOT / "eval" / "unsw_report.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("\nwrote eval/unsw_report.json")
    print("All numbers above are on UNSW-NB15 — a modern public benchmark we did "
          "not create, on its official train/test split.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
