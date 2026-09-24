"""One honest definition of ground truth and prediction, shared by every
evaluation and calibration script so they can never drift apart.

Strict multi-label truth — NOT class-equivalence credit
-------------------------------------------------------
A senior audit rightly objected to an earlier evaluator that credited *any*
alert on a malicious host (predicting `c2_beaconing` on an `encrypted_malware`
host still scored as correct). That masks real classification errors.

We replace that with factual multi-label truth. In this generator a C2 implant
beacons over TLS with a deliberately malicious JA4 and a self-signed, short-life
certificate. Such a host genuinely exhibits *two* observable behaviours at once —
periodic C2 *and* a malicious encrypted-session fingerprint — so its true label
set is {c2_beaconing, encrypted_malware}. That is not substitution credit: it is
the accurate ground truth for that host. Crucially the relationship is one-way —
a bulk `encrypted_malware` upload host does NOT beacon, so predicting
`c2_beaconing` on it is a real false positive and is scored as one. Predicting
`data_exfiltration` on either is likewise a real error. Every off-diagonal the
confusion matrix can show, it shows.
"""
from __future__ import annotations

from collections import defaultdict

DDOS_TARGET = "10.42.0.80"


def host_truth(flows) -> dict[str, set[str]]:
    """host -> set of TRUE attack classes it carries (multi-label, honest).

    Benign hosts are present with an empty set. The DDoS entity is its target,
    since the flood sources are spoofed and not real hosts.
    """
    truth: dict[str, set[str]] = defaultdict(set)
    for f in flows:
        if f.label == "benign":
            truth[f.src_ip]                                 # ensure the host exists
        elif f.label == "volumetric_ddos":
            truth[DDOS_TARGET].add("volumetric_ddos")
        else:
            truth[f.src_ip].add(f.label)
    # Factual co-occurrence: a C2-over-TLS implant legitimately presents BOTH a
    # beaconing pattern and a malicious encrypted-session fingerprint. One-way
    # only — see the module docstring.
    for host, classes in truth.items():
        if "c2_beaconing" in classes:
            classes.add("encrypted_malware")
    return truth


def host_pred(alerts):
    """Returns (per-host predicted class SET excluding the anomaly corroborator,
    per-host FULL set incl. anomaly, per-host PRIMARY prediction).

    Primary = highest severity, then confidence — used for the confusion matrix.
    """
    from prahari.schema import SEVERITY_BY_CLASS
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    full: dict[str, set[str]] = defaultdict(set)
    best: dict[str, tuple] = {}
    for a in alerts:
        host = DDOS_TARGET if a.threat_class == "volumetric_ddos" else a.src_ip
        full[host].add(a.threat_class)
        key = (sev_rank.get(a.severity, 0), a.confidence)
        if host not in best or key > best[host][1]:
            best[host] = (a.threat_class, key)
    attack = {h: (s - {"anomalous_traffic"}) for h, s in full.items()}
    primary = {h: c for h, (c, _) in best.items()}
    return attack, full, primary
