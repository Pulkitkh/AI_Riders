#!/usr/bin/env python3
"""The evidence a senior jury asks for: dataset composition, an entity-level
confusion matrix, per-class precision / recall / false-positive rate, and the
operational cost — alerts per million flows.

Everything is computed on HELD-OUT captures (seeds and jitter never used in
training), at the entity level a SOC actually triages: did we correctly name
the host behind each attack, and how often did we flag a benign host.

    python3 eval/report.py           # prints the tables and writes eval/report.json
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prahari.engine import Engine
from prahari.generate import ALL_ATTACKS, TrafficGenerator
from prahari.schema import SEVERITY_BY_CLASS

HELD_OUT = [(2001, 0.15), (2002, 0.22), (2003, 0.30), (2004, 0.08), (2005, 0.40),
            (3007, 0.18), (3009, 0.27), (3011, 0.05)]
# a C2 implant legitimately trips both the beaconing and the encrypted-session
# detector; count either as correct for that host.
EQUIV = {"c2_beaconing": {"c2_beaconing", "encrypted_malware", "anomalous_traffic"},
         "encrypted_malware": {"encrypted_malware", "c2_beaconing", "anomalous_traffic"},
         "data_exfiltration": {"data_exfiltration", "anomalous_traffic"}}
DDOS_TARGET = "10.42.0.80"


SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def host_truth(flows):
    """Each host -> the SET of true attack classes it carries (a host can be
    multi-stage). The DDoS entity is its target, since the sources are spoofed."""
    truth = defaultdict(set)
    for f in flows:
        if f.label == "benign":
            truth[f.src_ip]                        # ensure benign hosts exist
        elif f.label == "volumetric_ddos":
            truth[DDOS_TARGET].add("volumetric_ddos")
        else:
            truth[f.src_ip].add(f.label)
    return truth


def host_pred(alerts):
    """Each host -> the SET of classes alerted on it, and its primary (highest
    severity, then confidence) prediction for the confusion matrix."""
    sets = defaultdict(set)
    best = {}
    for a in alerts:
        host = DDOS_TARGET if a.threat_class == "volumetric_ddos" else a.src_ip
        sets[host].add(a.threat_class)
        key = (SEV_RANK.get(a.severity, 0), a.confidence)
        if host not in best or key > best[host][1]:
            best[host] = (a.threat_class, key)
    primary = {h: c for h, (c, _) in best.items()}
    return sets, primary


def main() -> int:
    scored = sorted(ALL_ATTACKS)                # 8 ground-truth classes
    labels = scored + ["benign"]
    conf = defaultdict(Counter)                 # primary true -> Counter(primary pred)
    tpc = Counter(); fnc = Counter(); fpc = Counter()
    comp = Counter()
    total_flows = total_alerts = 0
    benign_hosts = benign_flagged = 0
    anom_on_attack = anom_on_benign = 0

    for seed, jitter in HELD_OUT:
        flows = TrafficGenerator(seed=seed, jitter=jitter).capture(1800, classes=ALL_ATTACKS)
        alerts = Engine(window=60.0).run(flows)
        total_flows += len(flows)
        total_alerts += len(alerts)
        for f in flows:
            comp[f.label] += 1
        truth, (pset, primary) = host_truth(flows), host_pred(alerts)

        for host, tset in truth.items():
            preds = pset.get(host, set())
            attack_pred = preds - {"anomalous_traffic"}
            if not tset:                                    # benign host
                benign_hosts += 1
                if attack_pred:
                    benign_flagged += 1
                    for p in attack_pred:
                        fpc[p] += 1
                if "anomalous_traffic" in preds:
                    anom_on_benign += 1
                continue
            # attack host — multi-label credit per true class
            for c in tset:
                if preds & EQUIV.get(c, {c}):
                    tpc[c] += 1
                else:
                    fnc[c] += 1
            if "anomalous_traffic" in preds:
                anom_on_attack += 1
            # confusion (primary-vs-primary) for the matrix
            t_primary = max(tset, key=lambda c: SEV_RANK.get(SEVERITY_BY_CLASS.get(c, "low"), 0))
            conf[t_primary][primary.get(host, "benign")] += 1

    rows, macro = {}, []
    for c in scored:
        tp, fn, fp = tpc[c], fnc[c], fpc[c]
        prec = tp / (tp + fp) if tp + fp else (1.0 if tp else 0.0)
        rec = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / benign_hosts if benign_hosts else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        macro.append(f1)
        rows[c] = {"tp": tp, "fp": fp, "fn": fn, "precision": round(prec, 3),
                   "recall": round(rec, 3), "f1": round(f1, 3), "fpr": round(fpr, 4)}

    fp_rate = benign_flagged / benign_hosts if benign_hosts else 0.0
    per_million = total_alerts / total_flows * 1e6 if total_flows else 0.0

    # ---- print ----
    print("PRAHARI evaluation report — held-out captures only")
    print("=" * 74)
    print(f"\nDATASET  {len(HELD_OUT)} captures · {total_flows:,} flows · "
          f"{comp['benign']:,} benign ({comp['benign']/total_flows:.1%}) · "
          f"{total_flows-comp['benign']:,} attack")
    print("  per class:", {k: v for k, v in sorted(comp.items())})

    print(f"\n{'class':<20}{'prec':>7}{'recall':>8}{'f1':>7}{'FPR':>8}   tp/fp/fn")
    for c in scored:
        r = rows[c]
        print(f"{c:<20}{r['precision']:>7.3f}{r['recall']:>8.3f}{r['f1']:>7.3f}"
              f"{r['fpr']:>8.3f}   {r['tp']}/{r['fp']}/{r['fn']}")
    print(f"\nmacro-F1 (8 named classes): {sum(macro)/len(macro):.3f}")
    print(f"false-positive rate (benign hosts flagged): {fp_rate:.2%} "
          f"({benign_flagged}/{benign_hosts})")
    print(f"alert volume: {per_million:.0f} alerts per million flows "
          f"({total_alerts} alerts / {total_flows:,} flows)")
    print(f"anomaly net (unsupervised): corroborated {anom_on_attack} attack hosts, "
          f"flagged {anom_on_benign} benign hosts")

    print("\nCONFUSION MATRIX  (rows = truth primary, cols = prediction primary)")
    hdr = "".join(f"{c[:8]:>9}" for c in labels)
    print(f"{'true/pred':<20}{hdr}")
    for t in labels:
        line = "".join(f"{conf[t][p]:>9}" for p in labels)
        print(f"{t:<20}{line}")

    out = {"dataset": {"captures": len(HELD_OUT), "flows": total_flows,
                       "benign": comp["benign"], "composition": dict(comp)},
           "per_class": rows,
           "macro_f1": round(sum(macro)/len(macro), 4),
           "false_positive_rate": round(fp_rate, 4),
           "benign_hosts": benign_hosts, "benign_flagged": benign_flagged,
           "alerts_per_million_flows": round(per_million, 1),
           "total_alerts": total_alerts,
           "anomaly_net": {"attack_hosts": anom_on_attack, "benign_hosts": anom_on_benign},
           "confusion": {t: dict(conf[t]) for t in labels},
           "labels": labels}
    (Path("eval") / "report.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("\nwrote eval/report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
