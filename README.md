# PRAHARI

**P**assive **R**eal-time **A**nalysis of **H**ostile **A**ctivity over **R**ead-only **I**ngest

> *It only listens.*

Smart India Hackathon 2026 · Problem Statement **SIH26145** · National Technical
Research Organisation · Team **AI Riders**

An AI/ML pipeline that ingests a one-directional copy of IP traffic inside an
isolated monitoring enclave and detects, classifies and scores six families of
cyber threat in near real time — using only passively observed packets, flow
records and derived metadata, with **no return path to the production network,
no active probing, and no payload decryption**.

---

## Run it in thirty seconds

No dependencies. Pure Python 3.11 standard library.

```bash
git clone <this repo> && cd AI_Riders

python3 -m prahari.cli selftest      # prove the read-only constraints
python3 -m prahari.cli replay        # replay a capture, watch alerts appear
python3 -m prahari.api               # dashboard on http://localhost:8000

python3 tests/test_prahari.py        # 12 tests
python3 eval/evaluate.py             # held-out evaluation
python3 eval/jitter_sweep.py         # the headline experiment
python3 scripts/train.py             # refit the models from scratch
```

Or `make demo`.

---

## What actually works right now

Everything below runs. Nothing here is a mock, a stub, or a screenshot.

| Capability | State |
|---|---|
| Labelled traffic generator, 7 classes, seeded and reproducible | working |
| Streaming engine, windowed, bounded latency | working |
| All six threat families detected | working |
| Two fitted ML models (logistic regression, in-repo, no sklearn) | working |
| Bigram language model over benign domains | working |
| Calibration, deduplication, incident correlation | working |
| SHA-256 hash-chained alert ledger with tamper detection | working |
| Live dashboard | working |
| Read-only self-test | working |
| Held-out evaluation + jitter sweep | working |
| **Live PCAP / Zeek ingest** | **not yet — see Honest limits** |

---

## Measured results

All numbers below are produced by the code in this repository. Re-run the
commands to reproduce them.

### Detection, on held-out captures (`python3 eval/evaluate.py`)

Five captures with seeds and jitter settings **never used in training**.

| Threat class | Precision | Recall | F1 |
|---|---:|---:|---:|
| Volumetric DDoS | 1.000 | 1.000 | 1.000 |
| C2 beaconing | 1.000 | 1.000 | 1.000 |
| DGA resolution | 1.000 | 1.000 | 1.000 |
| DNS tunnelling | 1.000 | 1.000 | 1.000 |
| Malware in TLS | 1.000 | 1.000 | 1.000 |
| Recon / scanning | 1.000 | 1.000 | 1.000 |
| **Data exfiltration** | **0.500** | 1.000 | 0.667 |
| **macro F1** | | | **0.952** |

The exfiltration number is the honest one. Its five false positives are all the
same host — the nightly backup server, which genuinely inverts its
outbound-to-inbound byte ratio. That is the hard negative the generator includes
on purpose, and it is why `Fusion` takes a suppression set an operator populates
on day one.

**Alert volume: ~87 alerts/hour.** This is the metric a SOC lead actually cares
about, and it is reported alongside recall because recall is useless if the
queue is unworkable.

### Throughput and latency (`python3 -m prahari.cli bench`)

```
flows_processed  85,367      flows_per_sec    14,387
windows             240      latency p50      31.7 s
alerts              442      latency p95      63.9 s
```

Latency is **bounded below by the window size**. A detector aggregating over 60
seconds cannot alert faster than 60 seconds, and claiming otherwise would be
incoherent. We publish the bound rather than a flattering single number.

### The jitter sweep (`python3 eval/jitter_sweep.py`)

Real C2 frameworks randomise their sleep interval specifically to defeat
periodicity detection. Recall across the range, three held-out captures per
point:

```
jitter    0%   5%  10%  15%  20%  25%  30%  35%  40%  45%  50%
recall  1.00 1.00 1.00 1.00 1.00 1.00 1.00 1.00 1.00 1.00 1.00
```

**This experiment earned its place by finding a real bug.** The first version
scored **0.00 recall at zero jitter** — the model had been trained only on
jittered beacons and had learned "C2 means jittered", so a perfectly regular
implant looked exactly like a monitoring poller. The fix was a `regularity`
feature that is high for anything repetitive plus training across the full
jitter range. The commit history shows both states.

---

## How it works

```
  PRODUCTION NETWORK  ──▶  DATA DIODE  ──▶  MONITORING ENCLAVE
                             ▲                  │
                             └── no path back ──┘        (PRAHARI runs here)

  ingest ─▶ decode ─▶ flow assembly ─▶ features ─▶ 7 detectors
                                                      │
                          fusion ◀─────────────────────┘
                            │
                            ├─▶ calibrate · deduplicate · correlate
                            └─▶ hash-chained ledger ─▶ dashboard
```

### The seven detectors

| Class | Signal read | Model |
|---|---|---|
| Volumetric DDoS | Windowed rate, SYN:SYN-ACK ratio, **Shannon entropy of source IPs** | CUSUM-style change detection |
| C2 beaconing | Interval **coefficient of variation**, regularity, byte variance, destination prevalence, external destination | Logistic regression (fitted) |
| DGA resolution | Character entropy, vowel ratio, consonant runs, **bigram log-likelihood**, NXDOMAIN rate | Logistic regression + bigram LM (fitted) |
| DNS tunnelling | Query-name length, unique subdomains per parent, TXT/NULL share | Statistical |
| Malware in TLS | **JA4 rarity**, self-signed certs, validity window, packet-size shape | Statistical, metadata only |
| Recon / scanning | Fan-out across ports and hosts, unanswered-attempt ratio | Threshold + rules |
| Data exfiltration | Out/in byte ratio vs the host's own EWMA baseline, destination novelty | Unsupervised baseline |

Three of these deliberately use statistics rather than deep learning. For rate
and fan-out problems a clean statistical detector is faster, explainable by
construction, and far easier to defend than a neural network doing the same job.

### The kill chain, correlated

Fusion links detections that share an entity. A single compromised host produces
one incident with a timeline rather than three unrelated alerts:

```
CORRELATED INCIDENTS
  10.42.1.19  severity=critical  score=1.00
              chain: encrypted_malware → c2_beaconing → data_exfiltration
```

---

## The five constraints NTRO set — and how this repo proves each

| # | Constraint | Proof |
|---|---|---|
| a | **Read-only ingest** | `python3 -m prahari.cli selftest` parses the AST of every module in the detection path and fails if any imports `socket`, `requests`, `urllib`, `httpx`, `scapy` or similar. The dashboard server is deliberately *outside* that path. |
| b | **No payload decryption** | No key material is ever provisioned. `Flow.pkt_sizes` holds sizes and directions; there is no field anywhere that holds payload bytes. |
| c | **Streaming, not batch** | `Engine.push()` processes one flow at a time and closes windows as the clock advances. `bench` reports measured p50/p95/p99. |
| d | **Stated throughput** | 14,387 flows/sec sustained, hardware and method in `cli.py bench`. |
| e | **Standardised alert schema** | `schema.Alert.to_record()` — versioned JSON, ECS-aligned field naming, with timestamp, flow ID, threat class, calibrated confidence, evidence, model version and hash-chain position. |

---

## Honest limits

A prototype that oversells itself loses the viva. These are the gaps.

1. **Traffic is synthetic.** The generator produces realistic *shapes* — and
   deliberately includes the hard negatives (monitoring agents that beacon,
   backup windows that invert byte ratios, asset scanners that fan out) — but it
   is not real capture. The next milestone is a `zeek`/`nfstream` reader feeding
   the same `Flow` record, which is a change to one module.

2. **Six of seven classes score 1.000. That will not survive real traffic.**
   Synthetic DGA names are random strings and so are cleanly separable;
   real *dictionary*-DGA families concatenate plausible words and would defeat
   the lexical features entirely. Treat these numbers as "the pipeline is
   wired correctly end to end", not as a claim about field performance.

3. **No real JA4 computation.** Fingerprints are carried as opaque strings from
   the generator. Computing a real JA4 needs a TLS ClientHello parser, which
   arrives with the PCAP reader.

4. **Exfiltration is genuinely weak** and is reported as such — it is positioned
   as a ranked lead for analyst review, not an oracle, and its score is capped
   below certainty in code (`SCORE_CEILING = 0.82`).

5. **~87 alerts/hour is too noisy for production.** The deduplication window
   needs tuning against real analyst feedback.

---

## Methodology notes

Things that are easy to get wrong and that this repo gets right on purpose:

- **Capture-level splits, never random.** Flows from one attack burst are
  highly correlated. A random split puts them on both sides, the model
  memorises the burst, and the accuracy is meaningless. Training uses twelve
  captures; evaluation uses separate ones with unseen seeds and jitter.
- **Thresholds are chosen on training data** (`LogisticRegression.choose_threshold`),
  never against the held-out results.
- **Class weights are capped.** An uncapped 265:1 ratio just flips the failure
  mode from "always benign" to "always malicious" — we hit that and capped it.
- **A leaky feature was removed.** The beacon model initially had
  `self_signed` available and learned to use it instead of timing. It belongs to
  the TLS detector; removing it forced the timing model to actually work.

---

## Layout

```
prahari/
  schema.py        Flow and Alert records; the alert schema for constraint (e)
  generate.py      labelled traffic generator, 7 classes, seeded
  features.py      entropy, CV, autocorrelation, bigram LM, lexical features
  model.py         logistic regression, calibration, threshold selection
  engine.py        the streaming pipeline
  fusion.py        dedupe, correlate into incidents, severity
  ledger.py        SHA-256 hash-chained append-only alert store
  selftest.py      read-only constraint proof
  api.py           dashboard server (outside the detection path, on purpose)
  cli.py           replay / selftest / bench
  detectors/       one module per threat family
dashboard/         live SOC view
eval/              held-out evaluation + jitter sweep
scripts/train.py   fits both models and the bigram table
tests/             12 tests
```

---

## Regulatory alignment

NCIIPC is a unit of NTRO, constituted under s.70A of the IT Act 2000. Design
choices that follow from the sponsor's own regulatory frame:

- alert timestamps assume **NPL-synchronised** enclave clocks
- the ledger defaults to **180-day retention** (CERT-In Directions, 2022)
- alerts are structured for export inside the **six-hour incident reporting**
  window those Directions require

**No blockchain.** The theme is called *Blockchain & Cybersecurity*, but the
problem statement never asks for one and it would not help. A SHA-256 hash chain
gives the same tamper-evidence at a fraction of the cost — see `ledger.py`.

---

Licensed for evaluation as part of Smart India Hackathon 2026.
