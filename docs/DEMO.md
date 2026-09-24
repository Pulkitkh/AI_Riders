# PRAHARI — demo runbook

For SIH26145, NTRO: *AI-Based Detection of Cyber Threats in Unidirectional IP Traffic*.

Read this once the night before. On the day, you will have somewhere between
**four and eight minutes** of a judge's attention, and they will have seen a
dozen dashboards already. What separates you is not the dashboard. It is that
you can be interrupted with a hard question and answer it by running something.

---

## 0. Before you leave the room

```bash
git clone <repo> && cd AI_Riders
python3 --version          # 3.10+; there are no other dependencies
python3 scripts/demo.py    # tests, capture, live analysis, selftest, eval, sweep
```

On **Windows PowerShell** it is the same file, with `python` in place of
`python3` and no `make` anywhere:

```powershell
python --version
python scripts\demo.py
```

`scripts/demo.py` takes about 80 seconds from cold and must end with
**all green**. If it does not, fix it before the event — never debug in front of
a judge. It builds `data/demo.pcap` on the way and reuses it if it is already
there, so run it once and the file stays.

> The step order matters and is deliberate: the capture is analysed *before* the
> self-test runs, so the alert ledger has records in it by the time the hash
> chain is verified. Run `selftest` on a fresh clone and it will correctly tell
> you the ledger is empty and there is nothing to verify — an empty chain
> verifies trivially and proves nothing, so we refuse to print it as a pass.

Copy the whole repo plus `data/demo.pcap` to a USB stick. Assume no internet,
no `pip`, no root on the machine you are given. The project has zero
third-party dependencies precisely so that this assumption costs you nothing.

---

## 1. The four-minute demo

Four terminal windows, opened in advance, commands typed but not run.

### Window 1 — the constraint, proved (30 seconds)

```bash
python3 -m prahari.cli replay --duration 300   # gives the ledger something to verify
python3 -m prahari.cli selftest
```

> "The problem statement says the sensor sits behind a data diode. Traffic comes
> in; nothing goes back. So before I show you any detection, here is the property
> everything else depends on. This walks the abstract syntax tree of every module
> in the detection path and fails the build if any of them imports a socket, an
> HTTP client, or scapy. It also counts the sockets this process holds. Zero.
> The dashboard binds a port — that is why the dashboard is a separate process
> and is excluded from the detection path by name."

This is the slide nobody else has. Lead with it.

### Window 2 — real packets (90 seconds)

```bash
python3 -m prahari.cli live --pcap data/demo.pcap
```

> "This is a pcap. Wireshark opens it. We parse it ourselves — Ethernet, VLAN
> tags, Linux cooked capture from `tcpdump -i any`, IPv4, TCP, UDP, DNS question
> sections, and the TLS ClientHello, from which we compute a JA3 fingerprint out
> of the actual cipher and extension bytes. No scapy, no dpkt, no libpcap.
> 297,000 packets, assembled into 10,671 bidirectional flows in about two
> seconds, and then every one of the seven threat classes comes out."

Let the alerts scroll. Then stop on one and read it aloud:

```
HIGH  c2_beaconing  conf 1.00  10.42.1.19 → 203.0.113.44
      interval_mean_s=60.4, interval_cv=0.143, jitter_band_fit=0.983
```

> "Every alert carries the evidence that produced it. This host called out
> every 60.4 seconds with a 14% coefficient of variation. Human browsing has a
> CV above 1. A cron job has a CV near zero. 14% is the band where implants
> live, because they add jitter to avoid looking like cron — and adding jitter
> is exactly what gives them away."

### Window 3 — the dashboard (60 seconds)

```bash
python3 -m web.server --pcap data/demo.pcap --port 8000
```

Open `http://localhost:8000`. The source chip in the header reads **real
capture — demo.pcap** in green. Alerts stream in as the engine raises them.

> "Same capture, same engine, streaming. The panel on the left is the read-only
> posture. The one at the bottom is incident correlation — when one host shows
> beaconing *and* an odd TLS fingerprint *and* a byte ratio inversion, that is
> not three alerts, that is one intrusion with three stages, and we rank it as
> one."

Click **verify hash chain**.

> "Every alert is appended to a SHA-256 hash-chained log. Change one byte of one
> past alert and verification names the record it broke. That is not a
> blockchain and we do not call it one — it is a chained digest, which is what
> CERT-In's 180-day retention direction actually needs."

### Window 4 — the numbers (60 seconds)

```bash
python3 eval/report.py
```

> "One command, one artifact — eval/report.json — and every number we show
> comes from it. Eight held-out captures the models never saw, split by capture
> and not at random, because splitting flows at random leaks an attack burst
> across both sides and inflates everything. Scoring is strict per class, no
> equivalence credit. STRICT macro-F1 0.993; host-detection F1 1.000 reported
> separately. Zero false positives on 840 benign hosts — the one residual error
> is a classification slip (a malware host scored as exfiltration), and it is
> right there in the confusion matrix. I want to be the one who tells you these
> numbers are on generated traffic: they prove the pipeline is correct and
> internally consistent, not that we get this on your link."

Then point at the hard negative we defeated with learning:

> "The classic exfiltration false positive is the nightly backup server — it
> sends tens of megabytes out and receives almost nothing back, the exact
> signature of data theft. No threshold on volume or ratio can tell them apart.
> So we made exfil a fitted model, and the feature that separates them is
> destination locality: the backup uploads to an internal file server, real
> exfiltration leaves the network. The backup host no longer alerts at all —
> zero false positives on 840 benign hosts. Exfil recall is 1.000 with one
> classification slip elsewhere (precision 0.889), and we show it in the
> confusion matrix rather than smoothing it away. Alert volume is ~3.6k per
> million flows — still to be tuned for a real SOC queue, and we say that too."

---

## 2. Making your own capture, live, on stage

If you have root on the demo machine, this is worth 30 seconds and it removes
every remaining doubt about whether the file is real:

```bash
sudo tcpdump -i any -s 512 -w /tmp/live.pcap &
# browse a few sites, run: dig example.com, curl https://www.nic.in
sleep 60 && sudo kill %1
python3 -m prahari.cli live --pcap /tmp/live.pcap
```

Say what you expect *before* you run it:

> "A minute of me browsing is not an attack, so the correct output is close to
> nothing. A detector that fires on this is worthless."

A prediction you make out loud and then meet is worth more than any number on a
slide. Be honest that a real desktop can still trip something — a sync client
that polls on a fixed interval looks like a beacon, which is the whole
difficulty of the problem — and if it does, that is the most interesting thing
that will happen in your demo. Read the evidence fields aloud and explain which
feature fired and why a real deployment would allowlist that host.

If you want the controlled version of this, which we have measured:

```bash
python3 scripts/make_pcap.py --out /tmp/clean.pcap --duration 300 --benign-only
python3 -m prahari.cli live --pcap /tmp/clean.pcap
```

1,187 benign flows and **zero** alerts — including the nightly backup host we
deliberately planted as a hard negative, which the learned exfil model now tells
apart from real exfiltration. Nothing fires.

---

## 3. The questions they will ask

**"Is this actually running or is it a video?"**
Hand them the keyboard. `python3 -m prahari.cli live --pcap <their own pcap>`.
It takes no arguments they need to understand and no network access.

**"You said unidirectional. How does the model get updated?"**
It does not, in place. Models are JSON files fitted offline on the trusted side
and carried in by the same physical process that carries in any other media.
Nothing on the sensor side can request an update, because there is no path back.
That is a real operational constraint, not a limitation we forgot.

**"Why not deep learning?"**
Three reasons, in this order. One, an alert must carry evidence an analyst can
act on in six hours — CERT-In's reporting window — and "the network said 0.93"
is not evidence. Two, the entire system runs on one CPU with no dependencies,
which is what actually gets installed in an air-gapped enclave. Three, we fitted
logistic regression *ourselves*, in-repo, with capped class weights and
threshold selection on the training set only; if we cannot justify every
coefficient we should not be shipping it.

**"What is your accuracy on CIC-IDS2017?"**
We deliberately did not report one. Engelen et al. (WTMC 2021) reconstructed
that dataset and found over 20% of traces mislabelled, plus a FIN-handling bug
in CICFlowMeter itself. Numbers on it are not comparable across papers. We would
rather show you a generator whose ground truth we control and whose hard
negatives we chose on purpose.

**"What breaks this?"**
A dictionary-DGA family that concatenates real words defeats our lexical
features entirely. A mature implant that mimics a Chrome JA3 defeats
fingerprint rarity. TLS 1.3 encrypts the certificate, so self-signed detection
goes away, and Encrypted Client Hello will take SNI with it. That is why timing
and packet-shape features carry more weight in our scoring than fingerprint
lookups do — they survive.

**"How fast is it?"**
`python3 -m prahari.cli bench` (or `eval/report.py`). Around 10–11k flows/sec
full-pipeline on one core — parse → detect → fuse → calibrate → ledger — at
~0.09 ms/flow compute (it varies with the machine; run it in front of them
rather than quoting ours).
Detection-window delay p50 is about 38 seconds at the 60 s batch window — and it *cannot* be lower than that,
because a detector that aggregates over a 60-second window cannot alert before
the window closes. The window is a deployment knob, not a constant — the live
sensor defaults to a 5-second window, so detection delay there is a few seconds.
Anyone claiming sub-second detection of a 60-second beacon interval is
describing something incoherent.

---

## 4. Things not to say

- Do not say "blockchain". It is a hash chain. Judges who know the difference
  will stop listening; judges who do not will ask the wrong follow-up.
- Do not say "99% accuracy". On a class-imbalanced problem accuracy is
  meaningless, and saying it signals you have not thought about it. Say
  precision, recall, and the alert volume per hour.
- Do not say "real-time" without the window caveat.
- Do not claim the traffic is real. Say: the *format* is real, the parsing is
  real, the contents are generated, and here is exactly what that means.

The strongest thing you have is not any single number. It is that when a judge
pushes on a claim, you reach for a terminal instead of a slide.

---

## 5. If something goes wrong

| Symptom | Do this |
|---|---|
| Building the capture is slow | ~25s, and it writes 140 MB. Build it beforehand and keep the file. |
| `data/demo.pcap` missing on the demo machine | `python3 scripts/make_pcap.py --out data/demo.pcap --duration 1800` rebuilds it deterministically — same seed, same bytes. |
| Dashboard port in use | `python3 -m web.server --pcap data/demo.pcap --port 8111` |
| No colour in the terminal | Harmless; it is ANSI escapes. |
| `python3` is 3.8 | The code uses `X | Y` type syntax under `from __future__ import annotations`; 3.10+ is required. Carry a 3.11 machine. |
| `make: command not found` (Windows) | Use `python scripts\demo.py`. `make` is a convenience, never a requirement. |
| `python3` not found (Windows) | Use `python`, or `py -3`. |
| Escape codes like `[1;31m` printed literally | An old console without VT processing. Set `NO_COLOR=1` and the output goes plain. |
| selftest says the ledger is empty | Correct on a fresh clone. Run `replay` or `live` first — see §0. |
| Laptop dies | The repo is the demo. Any machine with Python 3.10 runs `python3 scripts/demo.py` from a clean clone, Windows included. |
