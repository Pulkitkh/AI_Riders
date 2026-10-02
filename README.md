# PRAHARI — an AI network Intrusion Detection System

**P**assive **R**eal-time **A**nalysis of **H**ostile **A**ctivity over **R**ead-only **I**ngest

> *It only listens.*

**Cyber AI Hackathon 2026 · University of Derby, UK**
Theme: **Cybersecurity & Digital Trust** — *Detecting anomalies in network traffic using Intrusion Detection Systems (IDS).*
Team **AI Riders** · [github.com/Pulkitkh/PRAHARI](https://github.com/Pulkitkh/PRAHARI)

PRAHARI is a working, tested AI-based **network intrusion detection system**. It
reads a copy of network traffic from a passive tap (a SPAN/mirror port — it never
injects a packet), learns what *normal* looks like for that network, and raises
ranked, **explainable** alerts the moment traffic stops looking normal — including
attacks it has **never seen before**.

It is validated on the standard public **NSL-KDD** benchmark *and* on a rich
synthetic multi-protocol network, uses only pure-Python machine learning (**zero
third-party dependencies**), and every alert is calibrated, mapped to MITRE
ATT&CK, explained in plain English — with an exact **per-feature attribution** of
*why* the model fired — and written to a tamper-evident audit trail: the
*"digital trust"* half of the theme.

The design thesis is **trustworthy AI**: we benchmark our explainable model
head-to-head against a from-scratch **deep autoencoder** (also dependency-free) and
come within ~10 recall points of it at an equal false-positive rate while staying
auditable and ~1000× lighter; we show the detector **adapts to a network it was
never trained on** (concept drift) instead of drowning it in false positives; and
we publish an **adversarial-evasion** evaluation that measures exactly how each
signal degrades when an attacker hides. And we validate across a dataset decade:
NSL-KDD (2009) *and* the modern **UNSW-NB15** (2015), reporting the harder result
rather than the flattering one.

---

## Results first — on real, public data (NSL-KDD)

NSL-KDD is the de-facto academic benchmark for network intrusion detection. Its
held-out test set deliberately contains **17 attack types that appear in no
training record** — a built-in test of catching the unknown. PRAHARI's own
pure-Python models, trained on `KDDTrain+` and tested on `KDDTest+`:

| What | Result |
|---|---|
| **Unsupervised anomaly detection** (Isolation Forest, trained on *normal only*, no attack labels) | **71.1% of attacks detected at a 3.1% false-positive rate** |
| **Novel-attack / zero-day detection** (the 17 attack families unseen in training) | **66.3% caught** — with zero labels for those families |
| Supervised classifier (lightweight, explainable logistic model) | accuracy 0.76, **precision 0.91** on the official hard split; DoS recall 83%, Probe 78% |
| **Deep-learning baseline** — a from-scratch autoencoder (pure Python, normal-only), at an **equal 10% false-positive rate** | autoencoder recall ~0.89 vs the explainable Isolation Forest **0.80** — the explainable model is within ~10 points while being auditable and ~1000× lighter |

```bash
python3 scripts/fetch_nslkdd.py && python3 eval/nslkdd_eval.py   # reproduce in ~3 min
```

That last row is the honest answer to *"why not deep learning?"* — we built the
deep model, measured it on the same split at the same operating point, and chose
the explainable one with the trade-off in hand. PRAHARI ships both.

The anomaly detector — the part that matters for *"detecting anomalies"* — catches
**two-thirds of attack families it was never trained on**. That is the whole point
of an anomaly-based IDS, and we measure it on data we did not create. (R2L attacks,
which look almost identical to normal logins, are the known-hard class for every
method on NSL-KDD; we report them honestly rather than hide them.)

---

## What makes it stand out

- **Adaptive anomaly detection that learns *your* network.** The unsupervised
  detector builds a live baseline of what normal traffic looks like on the actual
  link and flags deviations from *that* — so it works on a real network, not just
  a lab, and keeps working as the network changes. Validated end-to-end on NSL-KDD.
- **Explainable by design (Digital Trust).** Every alert says, in plain English,
  *what* happened, *why* it matters, and *what to do* — next to the exact evidence
  and the MITRE ATT&CK technique. Confidence is **calibrated** (isotonic, all nine
  classes) and measured, not asserted: expected calibration error **0.07** on
  held-out captures, so 0.9 really does mean ~90%. Non-experts can read it;
  analysts can trust it.
- **Breadth.** Nine detectors covering volumetric DDoS, C2 beaconing, DGA malware
  domains, DNS tunnelling, suspicious encrypted (TLS) sessions, reconnaissance,
  data exfiltration, **OT/ICS** (Modbus/DNP3/IEC-104), and the unsupervised
  anomaly net for everything else.
- **Metadata-only, encryption-respecting.** It never decrypts payloads — it works
  from flow shape, timing, and TLS fingerprints (JA4) — so it is effective on
  today's ~95%-encrypted traffic and privacy-preserving by construction.
- **Tamper-evident audit trail.** Every alert is appended to a SHA-256
  hash-chained ledger; any edit breaks the chain and is detectable — the trust
  anchor for the evidence it produces.
- **Zero dependencies, runs anywhere.** Pure CPython — no scapy, numpy, sklearn or
  TensorFlow. Installs on an air-gapped box; every line is auditable; ~11k flows/s
  on a single CPU core, no GPU.
- **Honest evaluation.** One command produces every number; strict scoring with
  a confusion matrix; failure modes measured and disclosed, not hidden.

---

## Trustworthy AI, measured (not asserted)

Four experiments, each one command, each a property a judge can check:

| Property | What we measure | Result | Reproduce |
|---|---|---|---|
| **Competitive with deep learning** | our explainable Isolation Forest vs a from-scratch autoencoder on NSL-KDD, at an equal 10% FPR | IF recall **0.80** vs autoencoder **0.89** — within ~10 pts, auditable, ~1000× lighter | `python3 eval/nslkdd_eval.py` |
| **Explainable per decision** | exact per-feature attribution (the logit decomposition) on every model-backed alert | top contributors shown in the UI and the alert record | in the dashboard drawer |
| **Resilient to concept drift** | benign traffic shifted to 3× the training volume: static envelope vs adaptive local baseline | static FP **0.1%→28%**, adaptive holds at **0%** | `python3 eval/drift.py` |
| **Robust to evasion** | timing jitter, JA4 mimicry, dictionary-DGA — how each signal degrades | each evasion degrades one signal; the system still detects the host | `python3 eval/evasion.py` |

### Cross-dataset generalization — UNSW-NB15 (2015)

To answer *"does this still hold on traffic from this decade, not just 1998-derived
NSL-KDD?"* we ran the **same engine, same protocol** on the modern **UNSW-NB15**
benchmark (official 175,341 / 82,332 split). We report the result straight —
including where it is weaker:

| | Result on UNSW-NB15 |
|---|---|
| Supervised classifier, per-family recall | **90–100% on all nine families** (Generic 99.9%, DoS 98.7%, Exploits 98.2%, Reconnaissance 99.9%, Worms 100%); accuracy 0.81 |
| Supervised trade-off | high recall comes at a high false-positive rate here (precision 0.75) under the *identical, un-retuned* threshold rule — reported, not tuned away |
| Unsupervised anomaly net @ 10% FPR | recall **0.27** — markedly harder than NSL-KDD (0.80); UNSW is a well-known hard case for label-free methods, and the deep autoencoder only reaches 0.33 on it too |

```bash
python3 scripts/fetch_unsw.py && python3 eval/unsw_eval.py   # ~6 min; writes eval/unsw_report.json
```

The honest takeaway: the **supervised** detector generalizes across a 2009→2015
dataset gap with 90–100% per-family recall, while the **unsupervised** net is
dataset-sensitive — strong on NSL-KDD, weak on UNSW. We publish the benchmark that
does *not* flatter us rather than cherry-pick the one that does. (UNSW's CSVs are
large and usually LFS-hosted; `scripts/fetch_unsw.py` prints the public sources if
your network blocks the automatic download.)

---

## See it run (live demo)

A real-time dashboard backed by the same engine. On Linux it taps a real
interface, assembles flows off the wire, and streams alerts to the browser live.

```bash
# live sensor on a real NIC (needs root for raw capture)
sudo python3 -m web.server --live --iface eth0 --port 8000
#   self-contained single-machine demo: tap loopback and scan it
sudo python3 -m web.server --live --iface lo --port 8000
python3 scripts/scan.py 127.0.0.1 1 1000        # a 'Recon' alert appears in seconds
```

Open `http://<host>:8000`. Tabs: **Overview**, **Live sensor**, **Replay
scenarios**, **Measured results** (per-class table + strict confusion matrix +
calibration), **Tamper-evident ledger** (break a record, watch it get caught), and
**Read-only proof**. The static front end also deploys to any serverless host for
a shareable, read-only link (see [`docs/DEPLOY.md`](docs/DEPLOY.md)).

One-command container:

```bash
docker compose up --build      # open :8000
```

---

## Quick start

```bash
git clone https://github.com/Pulkitkh/PRAHARI && cd PRAHARI

python3 tests/test_prahari.py        # engine tests
python3 tests/test_web.py            # web tests
python3 scripts/fetch_nslkdd.py      # fetch the public NSL-KDD benchmark
python3 eval/nslkdd_eval.py          # REAL-DATA evaluation (anomaly + zero-day)
python3 eval/report.py               # synthetic multi-protocol evaluation
python3 eval/unseen_family.py        # the unseen-family (OOD) experiment
python3 -m prahari.cli selftest      # prove the read-only / integrity properties
python3 -m web.server                # the dashboard on http://localhost:8000
```

No `pip install` — there is nothing to install.

---

## How it works

```
 passive tap (SPAN/mirror)                          analyst
        │  copy of traffic                              ▲
        ▼                                               │ ranked, explained alerts
  flow assembly ─► passive metadata ─► 9 detectors ─► fuse + calibrate ─► tamper-evident
  (5-tuple, bytes,    (DNS, TLS/JA4,     (ML + stats +   (dedupe, correlate,   ledger
   packets, flags,     QUIC header,       anomaly net)    MITRE, confidence)
   timing)             OT/ICS headers)
```

- **Ingest** — offline PCAP, live `AF_PACKET` capture, or NetFlow v5. Read-only:
  the detection engine opens no sockets and has no transmit path (a self-test
  fails the build if any module imports one).
- **Detect** — three fitted logistic-regression models (beacon, DGA, exfil), an
  Isolation-Forest + adaptive-local-baseline anomaly detector, and explainable
  statistical detectors for DDoS, DNS tunnelling, TLS, recon and OT/ICS.
- **Fuse** — deduplicate floods, correlate a host's activity into one incident,
  calibrate confidence, stamp the MITRE ATT&CK technique.
- **Record** — append to the hash-chained ledger; render in the dashboard with a
  plain-English explanation.

Full detail: [`docs/WORKFLOW.md`](docs/WORKFLOW.md),
[`docs/COVERAGE.md`](docs/COVERAGE.md) (what it can/can't see and how it degrades),
[`docs/LEDGER.md`](docs/LEDGER.md) (the trust/audit model),
[`docs/SECURITY.md`](docs/SECURITY.md) (passive/read-only design).

---

## Two evaluations, both reproducible

**Real public data — NSL-KDD** (`eval/nslkdd_eval.py`): see the table above.

**Synthetic multi-protocol network** (`eval/report.py`): the synthetic generator
exercises the packet-level detectors NSL-KDD cannot (JA4 fingerprints, DNS names,
beacon timing, OT/ICS protocol semantics). On 8 held-out captures (97,172 flows;
seeds and jitter never used in training), scored strictly per class with no
equivalence credit: **macro-F1 0.993**, host-detection F1 1.000, **0 false
positives on 840 benign hosts** (the one residual error is a single
mis-classification, shown in the confusion matrix). An unseen-family experiment
(`eval/unseen_family.py`) excludes an entire attack family from training and shows
the anomaly net still catches it while every trained detector stays silent.

Every number comes from these commands — nothing is quoted by hand.

---

## Honest limitations

- NSL-KDD is a *summarised-connection* benchmark; our synthetic set covers the
  packet-level signals it cannot. Together they cover more than either alone, but
  neither is a live production network at national scale — real traffic is harder,
  and we say so.
- R2L attacks are near-indistinguishable from normal logins on connection
  metadata; the supervised model's recall there is **1.9%** (U2R 35.8%), as it is
  near-floor for most published NSL-KDD methods. This is exactly why the
  unsupervised anomaly net — not the supervised classifier — is our headline: it
  needs no attack labels and still catches 66% of families it never saw, R2L
  included. We report the weak per-category numbers rather than hide them.
- Encrypted DNS (DoH/DoT) and TLS 1.3 remove some metadata; the coverage matrix
  (`docs/COVERAGE.md`) states exactly what degrades and how.

We treat disclosing limits as part of *digital trust*, not a weakness.

---

## Repository

```
prahari/            the detection engine (pure Python, zero dependencies)
  detectors/        the nine detectors
  datasets/         NSL-KDD loader (real-data benchmark)
  anomaly.py        Isolation Forest   model.py  logistic regression + calibration
eval/               nslkdd_eval.py (real) · report.py (synthetic) · unseen_family.py
web/                the real-time dashboard + stateless API
sensor/             live AF_PACKET capture
scripts/            fetch_nslkdd, train, calibrate, scan, demo
tests/              automated tests (engine + web)
docs/               workflow, coverage, ledger, security, deploy, demo
```

Team **AI Riders** — Cyber AI Hackathon 2026, University of Derby.
