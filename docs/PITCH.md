# PRAHARI — Cyber AI Hackathon 2026 (University of Derby) pitch

**Theme:** Cybersecurity & Digital Trust — *Detecting anomalies in network traffic using Intrusion Detection Systems (IDS).*

**One line:** An explainable, zero-dependency AI network IDS that learns what normal
looks like on a network and flags anomalies — including attacks it has never seen —
validated on the standard public NSL-KDD benchmark and on a multi-protocol synthetic
network, with every alert calibrated, explained, and recorded in a tamper-evident log.

---

## Why it wins on each scoring pointer

**Relevance to the problem statement.** It *is* the problem statement: a network
IDS whose core is unsupervised anomaly detection. On the official NSL-KDD test split
it detects **71% of attacks at a 3% false-positive rate** with no attack labels, and
**66% of attack families it was never trained on**. Direct, measured, on-theme.

**AI / technical merit.** Real machine learning built from first principles in pure
Python — a logistic-regression classifier, an Isolation-Forest anomaly detector with
an *adaptive local baseline* that learns each network's normal, and isotonic
confidence calibration. No scikit-learn, no TensorFlow, no GPU: it runs on an
air-gapped laptop and every line is auditable. Nine detectors span DDoS, C2
beaconing, DGA, DNS tunnelling, encrypted-session (TLS/JA4), reconnaissance,
exfiltration, OT/ICS and the anomaly net.

**Innovation.** (1) Anomaly detection that adapts to the live environment instead of
a fixed training set — so it works on real traffic, not just a lab. (2) Explainability
as a first-class feature: every alert carries a plain-English story, the exact
evidence, a calibrated probability and a MITRE ATT&CK technique. (3) Breadth into
OT/ICS most IDS projects ignore. (4) A read-only / passive design that can never
become an attack path itself.

**Digital Trust.** The "trust" half of the theme is built in: calibrated confidence
(a stated 0.9 really means ~90%), full explainability for every decision, a
tamper-evident SHA-256 hash-chained evidence ledger, and honest, reproducible
evaluation that discloses its own failure modes.

**Working prototype / demo.** Not slideware. A live dashboard taps a real interface,
assembles flows off the wire, and streams explained alerts in real time; a one-line
scan produces a live recon alert; the ledger tab lets a judge break a record and
watch it be caught. Also deploys as a shareable read-only link.

**Rigour / credibility.** Every number comes from one reproducible command. Strict
per-class scoring with a confusion matrix; two independent evaluations (real NSL-KDD +
synthetic multi-protocol); 59 automated tests; limitations stated openly.

**Impact.** A lightweight, explainable, trustworthy IDS any organisation can run on
commodity hardware — including the encrypted, OT, and resource-constrained settings
where heavyweight commercial tools struggle.

---

## 60-second demo script

1. **Overview** — one sentence: a passive AI IDS that detects anomalies and explains them.
2. **Live sensor** — Start sensor; run `python3 scripts/scan.py 127.0.0.1 1 1000`; a
   *Recon* alert appears. Click it → plain-English explanation + evidence + MITRE.
3. **Measured results** — the per-class table, strict confusion matrix, calibration.
4. **NSL-KDD** (terminal) — `python3 eval/nslkdd_eval.py`: real-data anomaly + 66%
   novel-attack detection.
5. **Ledger** — break a record; the chain names the tampered entry. *Digital trust.*
6. Close on one honest limitation and the roadmap — rigour, not bravado.

## Reproduce everything

```bash
python3 scripts/fetch_nslkdd.py && python3 eval/nslkdd_eval.py   # real public data
python3 eval/report.py                                          # synthetic multi-protocol
python3 tests/test_prahari.py && python3 tests/test_web.py       # 59 tests
python3 -m web.server                                           # the live dashboard
```
