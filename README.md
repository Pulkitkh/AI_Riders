# PRAHARI

**P**assive **R**eal-time **A**nalysis of **H**ostile **A**ctivity over **R**ead-only **I**ngest

> *It only listens.*

Smart India Hackathon 2026 · Problem Statement **SIH26145** · National Technical
Research Organisation · Team **AI Riders**

An AI/ML pipeline that ingests a one-directional copy of IP traffic inside an
isolated monitoring enclave and detects, classifies and scores six families of
cyber threat in near real time — using only passively observed packets, flow
records and derived metadata, with **no return path to the production network,
no active probing, and no session-payload decryption**. (The one cryptographic
operation anywhere is unwrapping a QUIC *Initial* with its published RFC 9001
salt — public keying, no secret — which reads a handshake that is cleartext over
TCP anyway; no session key is ever derived. See constraint b below.)

---

## The live web console

PRAHARI ships a real-time SOC dashboard backed by the same engine. It runs in
two forms, and the difference between them is honest, not cosmetic:

**Live sensor (a real server).** On a Linux host it taps a real interface with a
raw socket, assembles flows off the wire, runs the engine, and streams every
alert to the browser over Server-Sent Events as it happens. Real packets, real
capture, real-time detection.

```bash
sudo python3 -m web.server --live --iface eth0 --port 8000    # tap eth0
#   or, self-contained on any Linux box (needs root):
sudo python3 -m web.server --live --iface lo --port 8000
```

Open `http://<host>:8000`, press **Start sensor**, and — for a demo where no
real attacker is handy — press the attack buttons, which craft genuine attack
packets on the loopback interface for the sensor to catch. Nothing is mocked:
the packets travel, the sensor sniffs them, the dashboard lights up.

One command on a cloud VM:

```bash
docker compose up --build      # host networking + NET_RAW; open :8000
```

**Static viewer (shareable link).** For a URL the jury can just click, the same
front end deploys to any static/serverless host (Vercel, Netlify, GitHub
Pages). There it cannot tap a NIC — no serverless platform can — so live mode
stands down and the **Replay scenarios**, **one-way visibility**, **metrics**,
**ledger** and **read-only proof** tabs run instead, driven either by the
precomputed datasets or by the stateless serverless API. See
[`docs/DEPLOY.md`](docs/DEPLOY.md).

Why the split: live capture needs a raw socket, root, and a process that stays
alive. Serverless gives none of those. Rather than fake a live feed on a
platform that cannot produce one, PRAHARI runs the real sensor on a real host
and keeps the static viewer honestly read-only.

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
python3 -m web.server --pcap data/demo.pcap    # the same capture, in the dashboard
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
python3 -m web.server               # dashboard on http://localhost:8000

python3 tests/test_prahari.py        # 25 engine tests
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
| Three fitted ML models (logistic regression, in-repo, no sklearn) | working |
| Bigram language model over benign domains | working |
| Calibration, deduplication, incident correlation | working |
| SHA-256 hash-chained alert ledger with tamper detection | working |
| Live dashboard | working |
| Read-only self-test | working |
| Held-out evaluation + jitter sweep | working |
| PCAP / PCAPNG reader — real packets to the same `Flow` record | working |
| NetFlow v5 ingest — exported flow records to the same `Flow` | working |
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
| **Data exfiltration** | **1.000** | 0.800 | 0.889 |
| **macro F1** | | | **0.984** |

Exfiltration is the honest one, and it is now a **learned** detector. The hard
negative the generator includes on purpose is the nightly backup server, which
inverts its outbound-to-inbound byte ratio exactly like exfiltration — no
threshold on volume or ratio can separate the two. The fitted model separates
them on one feature a hand-set coefficient could never exploit: **`dst_external`**
— the backup sends its volume to an *internal* file server, real exfiltration
leaves the network. That took exfil precision from 0.50 (five false positives,
all that one host) to **1.00 with the backup no longer flagged**, trading a
little recall (one missed window) for a queue an analyst can actually work. The
benign-only negative control is now completely silent.

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
| Data exfiltration | Out/in byte ratio vs the host's own EWMA baseline, **destination locality** (internal vs external), volume, concentration, novelty | Logistic regression (fitted) |

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
| b | **No session-payload decryption** | No *session* key material is ever provisioned or derived; `Flow.pkt_sizes` holds sizes and directions, and no field anywhere holds session-payload bytes. The sole crypto operation is unwrapping a QUIC Initial with the **public** RFC 9001 salt (`quic_crypto.py`) — the same handshake ClientHello that is sent in the clear over TCP — to read its JA4/SNI. It reads a handshake, never a session: no 1-RTT key is computed, and the AEAD tag is not even verified. |
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

3. **JA3 and JA4 over both TCP and QUIC; TLS 1.3 hides the certificate.**
   The reader computes a real **JA3** and a real **JA4** (FoxIO spec — sorted
   cipher/extension lists, so it survives the client shuffling that defeats JA3)
   from the ClientHello. For **QUIC** it goes further than recognition: a v1/
   draft-29 Initial is decrypted with the *public* RFC 9001 salt (pure-Python
   AES-128 + HKDF, no OpenSSL, no session secret — `prahari/quic_crypto.py`), and
   the ClientHello inside yields a real **"q…" JA4** with SNI, exactly like the
   TCP path. `make quic` shows it end to end; the RFC 9001 Appendix A.1 key
   vectors and a FIPS-197 AES vector are asserted in the test suite. A later
   packet or an unknown version falls back to recognising the flow as QUIC so it
   is never invisible. Certificate facts (self-signed,
   validity window) are readable only through TLS 1.2, because TLS 1.3 encrypts
   the Certificate message; on a 1.3-only link the detector falls back to
   fingerprint rarity and packet shape, and Encrypted Client Hello removes SNI
   visibility as it rolls out.

4. **Exfiltration is the weakest signal** and is still positioned as a ranked
   lead for analyst review, not an oracle — its score stays capped below
   certainty in code (`SCORE_CEILING = 0.82`) even though it is now a fitted
   model. Learning `dst_external` removed the whole class of backup-host false
   positives, but a patient adversary moving modest volumes to a reputable
   external cloud endpoint still looks much like an employee using that service.

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
  pcapread.py      pcap/pcapng -> Flow: JA3/JA4 (TCP + QUIC) + X.509
  quic_crypto.py   pure-Python QUIC Initial decrypt (public salt) -> q-JA4
  netflow.py       NetFlow v5 -> Flow: exported flow-record ingest
  cli.py           live / replay / selftest / bench
  detectors/       one module per threat family
sensor/
  capture.py       AF_PACKET live capture -> Flow: real NIC tap, no libpcap
  attack.py        crafts real attack packets on the wire, for demo + tests
  live.py          continuous capture -> engine -> SSE event bus
web/
  service.py       every API answer as a plain dict (one implementation)
  router.py        one request router shared by the local server and Vercel
  server.py        local / on-server app: static + API + live SSE stream
  build.py         precomputes the demo datasets
  public/          the SOC dashboard (one HTML, one CSS, one JS; no CDN)
api/index.py       Vercel serverless entrypoint (stateless endpoints)
eval/              held-out evaluation, jitter sweep, degraded-mode measurement
scripts/train.py      fits both models and the bigram table
scripts/make_pcap.py  writes a genuine wire-format .pcap (round-trip test + demo)
scripts/demo.py       cross-platform `make demo`, for machines without make
docs/DEMO.md       the runbook for presenting this
docs/DEPLOY.md     live-sensor and static-viewer deployment
tests/             40 tests (25 engine + 15 web)
```

---

## Influences and prior art

A browser-based real-time flow console — an overview list that drills into
per-flow detail — is a well-trodden pattern; HoangNV2001's *Real-time-IDS* (an
academic Flask + Scapy + scikit-learn project) is one open example, and looking
at it helped shape our dashboard's overview-to-detail interaction. PRAHARI shares
none of its code. That project is an **active** Windows capture agent built on
third-party libraries; ours is a **passive, read-only, zero-dependency** engine
built around the diode constraint the problem statement sets — the opposite
architecture. The flow-feature taxonomy (packet-length and inter-arrival
statistics, TCP-flag counts) follows the CICFlowMeter conventions common across
the field.

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
