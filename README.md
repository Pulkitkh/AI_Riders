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

## Run it on real captured traffic

```bash
sudo tcpdump -i any -s 512 -w demo.pcap        # or use any .pcap you already have
python3 -m prahari.cli live --pcap demo.pcap
```

No capture handy, and no root on the machine in front of you? Build one:

```bash
python3 scripts/make_pcap.py --out data/demo.pcap --duration 1800
python3 -m prahari.cli live --pcap data/demo.pcap
python3 -m prahari.api --pcap data/demo.pcap   # the same capture, in the dashboard
```

**On Windows**, use `python` (or `py -3`) instead of `python3`, and skip `make`
entirely — it is not installed on a stock Windows box:

```powershell
python scripts\demo.py            # everything: tests, capture, analysis, eval
python scripts\demo.py --quick    # the same, minus the slow evaluation passes
```

`scripts/demo.py` is the cross-platform equivalent of `make demo` and invokes
whichever interpreter is running it, so it cannot pick the wrong Python.

`scripts/make_pcap.py` writes real frames — real Ethernet/IPv4/TCP headers, real
DNS wire encoding, a real TLS ClientHello, a real DER certificate — so Wireshark
opens the file and the reader is tested against bytes it did not itself produce.
The *contents* are generated; the format and the parsing are not.

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
| PCAP / PCAPNG reader — real packets to the same `Flow` record | working |
| Single-direction (one-way tap) degraded mode, measured | working |
| Real JA3 fingerprint + X.509 parsing from the handshake | working |

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

## What "unidirectional" means here

The problem statement says *unidirectional IP traffic*, and the phrase carries
two readings. **We assume a data diode carries a TAP copy of both directions of
each flow into the read-only enclave** — traffic crosses the boundary one way,
but each conversation is seen whole. The stricter reading is that only one
direction of any flow is ever observable, as with asymmetric routing or a
one-way tap on a single fibre.

We do not get to pick which one the sponsor meant, so we implemented the
stricter one and measured the cost:

```
python3 eval/degraded.py
```

| threat class | both dirs | one dir | what is lost |
|---|---|---|---|
| c2_beaconing | 5/5 | 5/5 | unaffected — timing is a client-side property |
| volumetric_ddos | 5/5 | 5/5 | unaffected — source entropy is client-side |
| dns_tunnelling | 5/5 | 5/5 | loses response size; query entropy and rate retained |
| recon_scanning | 5/5 | 5/5 | loses handshake completion; fan-out breadth retained |
| data_exfiltration | 5/5 | 5/5 | loses out/in ratio; absolute outbound volume retained |
| encrypted_malware | 5/5 | 5/5 | loses server cert and JA4S; JA3 + shape + rarity retained |
| dga_resolution | 5/5 | **4/5** | loses NXDOMAIN rate; lexical + burst retained |

**34 of 35 detections retained (97%).** Run it yourself, or add
`--single-direction` to `replay` or `live`.

The same mechanism answers a second question. TLS 1.3 encrypts the server
Certificate message, so self-signed status and validity window are unreadable
there too — identical loss, identical fallback. When the TLS detector scores
without server-side evidence it says so in the alert (`server_side_observed:
false`) and carries a caveat, rather than treating "not observed" as "observed
to be benign".

---

## Honest limits

A prototype that oversells itself loses the viva. These are the gaps.

1. **We can read real packets; we have not yet run on real operational
   traffic.** `prahari/pcapread.py` parses actual pcap/pcapng — Ethernet, Linux
   cooked SLL/SLL2, raw IP, VLAN unwrapping, IPv4/TCP/UDP, DNS question
   parsing, TLS ClientHello with a JA3 computed from the bytes, and X.509
   issuer/subject/validity from the Certificate message — and produces the same
   `Flow` record the generator does, so the whole pipeline runs on it unchanged.
   What we have not done is point it at a live NTRO-scale link. The *content* of
   our captures is still generated, so the traffic shapes are ours; only the
   wire format and the parsing of it are real.

2. **Six of seven classes score 1.000. That will not survive real traffic.**
   Synthetic DGA names are random strings and so are cleanly separable;
   real *dictionary*-DGA families concatenate plausible words and would defeat
   the lexical features entirely. Treat these numbers as "the pipeline is
   wired correctly end to end", not as a claim about field performance.

3. **JA3, not JA4, and TLS 1.3 hides the certificate.** The reader computes a
   real JA3 — the older, widely-tabulated fingerprint — from the ClientHello;
   JA4+ is a substitution of the same parsed fields and is not done yet.
   Certificate facts (self-signed, validity window) are readable only through
   TLS 1.2, because TLS 1.3 encrypts the Certificate message. On a 1.3-only
   link the encrypted-malware detector falls back to fingerprint rarity and
   packet shape, which is weaker, and Encrypted Client Hello removes SNI
   visibility as it rolls out.

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
  pcapread.py      pcap/pcapng -> Flow: real packet parsing, no scapy, no dpkt
  api.py           dashboard server (outside the detection path, on purpose)
  cli.py           live / replay / selftest / bench
  detectors/       one module per threat family
dashboard/         live SOC view
eval/              held-out evaluation, jitter sweep, degraded-mode measurement
scripts/train.py      fits both models and the bigram table
scripts/make_pcap.py  writes a genuine wire-format .pcap (round-trip test + demo)
scripts/demo.py       cross-platform `make demo`, for machines without make
docs/DEMO.md       the runbook for presenting this
tests/             21 tests
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
