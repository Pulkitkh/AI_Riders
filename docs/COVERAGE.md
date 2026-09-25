# PRAHARI — Coverage & Degradation Matrix

Honesty about what a passive, metadata-only sensor can and cannot see is a
strength, not a weakness. This is the precise scope, and how each detector
degrades when its evidence is unavailable.

## Ingest / traffic coverage

| Traffic | Status | Notes |
|---|---|---|
| IPv4 TCP/UDP | **Supported** | Full flow assembly and metadata. |
| IPv6 | **Recognised, scoped** | IPv6 packets are recognised and counted; full IPv6 flow features are a documented next step. We report the covered subset rather than silently dropping. |
| NetFlow v5 | **Supported** | Passive flow ingest. |
| IPFIX / NetFlow v9 | **Planned** | Template parsing is next; the PS lists these as possible sources. |
| ICMP / GRE / SCTP | **Out of scope (stated)** | Not decoded; listed here so it is never implied. |

## Application-metadata coverage & degradation

| Protocol | What we read (metadata only) | Degrades when… | Behaviour when degraded |
|---|---|---|---|
| DNS (UDP) | qname, qtype, rcode | DNS-over-TCP; compressed names; **DoH/DoT** hide queries entirely | Marked unavailable; DGA/tunnel lean on what remains; encrypted DNS is explicitly out of visibility |
| TLS | JA4/JA3, SNI, cert facts | **TLS 1.3** encrypts the Certificate; **ECH** hides SNI | Falls back to fingerprint rarity + packet-shape; alert flagged `degraded`, capped confidence |
| QUIC | public header (version, Initial) only — **no decryption** | always encrypted payload | Recognised as QUIC by header; scored on shape + destination rarity |
| Modbus/TCP | function code, unit id, write flag | — | Faithful (spec-fixed header) |
| IEC 60870-5-104 | APCI frame + **ASDU type id** | — | Control vs monitoring distinguished by type id, not "every I-frame" |
| DNP3 | **link-layer** control/addresses | app-layer control semantics | Scoped to "suspicious DNP3 control traffic"; app-layer decode is future work |

## Known detector blind spots (stated, not hidden)

- **Dictionary-DGA** families built from real concatenated words defeat the
  lexical/n-gram features; this is a known blind spot on the roadmap (word-
  segmentation + campaign features), not a solved case.
- **Legitimate external cloud transfer** (backup/replication/sync to a reputable
  external endpoint) can resemble exfiltration; we test internal-staging and
  cloud hard-negatives and report the residual failure mode.
- **One-way tap** hides every reverse direction: recon and TLS both detect this
  and degrade to fan-out / fingerprint-shape signals rather than scoring a
  missing feature as benign.

## Deployment scale: single-host vs multi-host

PRAHARI is designed for a **multi-host** CII enclave, where two of its strongest
legitimate/malicious separators are *cross-host* signals:

- **Destination popularity** — a service many internal hosts contact is
  infrastructure; a destination only one host beacons to is C2-like.
- **Fingerprint rarity** — a JA4 seen on one host among many is unusual.

On a **single-host tap** (e.g. one laptop for testing) both signals are
degenerate: every destination and every fingerprint is "seen by one host", so a
naive rarity rule would flag *all* normal browsing and *every* periodic
background service (OS/browser update, chat heartbeat) as a threat. The detectors
detect this case (fewer than 4 internal hosts) and adapt:

- the encrypted-session detector **switches off cross-host rarity** and scores
  only on host-independent evidence (self-signed/short-lived certs, strongly
  upload-shaped conversations) — normal download-shaped browsing stays silent;
- the beaconing detector **suppresses periodic traffic to recognised services**
  (a starter telemetry/update/CDN allowlist in `prahari.features`) since
  popularity cannot clear them there.

A real C2 to an unrecognised destination is still scored normally. Operators
extend the allowlist and use the auditable Fusion suppression set for their own
environment. This is why the reported synthetic metrics (a ~112-host network)
and single-host live behaviour differ — by design, and stated here.

## Robustness

- **Passive-capture imperfection** (loss, reordering, truncation): a fragmented
  ClientHello or split DNS message may not yield metadata within one segment;
  bounded TCP reassembly is scoped as future work and today's claims are limited
  to captures where the relevant handshake fits a segment.
- **Malformed / adversarial frames**: the custom parsers are exercised by fuzz
  tests in the suite; every parser returns `None` rather than raising on bad
  input, so a crafted frame cannot crash the pipeline.
