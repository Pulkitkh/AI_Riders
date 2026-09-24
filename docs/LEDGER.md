# PRAHARI — Evidence Ledger: scope, storage, and threat model

The alert ledger is a SHA-256 **hash-chained, append-only** record: each entry
carries the hash of the previous one, so any edit to a past record breaks the
chain and is detectable. We are precise about what that does and does not mean.

## What it is — and is not

| Property | Status | Note |
|---|---|---|
| Tamper-**evident** | **Yes** | Any modification of a past record is detectable by re-verifying the chain (`prahari.cli selftest`, or the dashboard's verify tab). |
| Tamper-**proof** / immutable | **No** | An insider with write access to the file can recompute the whole chain. Local hash chaining alone is not immutability. |
| Regulatory-certified | **No** | We say "tamper-evident hash-chained audit trail", never "CERT-In-grade". |
| Trusted timestamp / external anchor | **Planned** | Periodically anchoring the chain head to a WORM store or a trusted timestamp service (RFC 3161) gives chain-of-custody against a compromised host. This is future work and labelled as such. |
| Per-device signing | **Planned** | Signing each record with a per-appliance key (hardware/software trust anchor) attributes evidence to a specific sensor. |

## Threat model for the ledger

- **Read/observe attacker**: cannot alter records without detection (chain).
- **Local-write attacker (compromised sensor)**: can rewrite the *local* chain
  undetectably — which is exactly why chain-of-custody requires the planned
  external head-anchoring and per-device signing above. We do not claim the
  local chain defends against this today.
- **Evidence-availability**: the ledger is attached to the LIVE engine by
  default (`PRAHARI_LEDGER`), so operational alerts are chained as produced —
  not only in the separate tamper *demo*.

## Storage sizing (180-day retention)

The ledger stores alerts, not raw traffic. One alert record serialises to well
under 1 KB. A worked estimate at the evaluation alert rate:

| Quantity | Value | Basis |
|---|---|---|
| Alert record size | ~0.6–1.0 KB | JSON, ECS-shaped, evidence + MITRE + chain hash |
| Alert rate | ~3.6k / million flows | measured (`eval/report.py`) |
| Busy enclave flow rate | ~50M flows/day | planning assumption, adjust per site |
| Alerts/day | ~180k | 50M × 3.6k/1e6 |
| Bytes/day | ~140–180 MB | 180k × ~0.9 KB |
| **180-day trail** | **~25–32 GB** | before compression; JSONL compresses ~5–8× |
| Compressed 180-day | **~4–6 GB** | gzip/zstd on rotated segments |

Rotation is by day; each rotated segment carries the previous segment's head
hash so the chain spans segments. Sizing scales linearly with alert volume — the
number to watch is alerts/day, not flows/day, which is why alert-volume tuning
(dedup/correlation) is both a UX and a storage lever.

## Verification workflow

- On demand: `python3 -m prahari.cli selftest` re-verifies the whole chain.
- In the dashboard: the verify tab re-hashes every record and reports the first
  broken link if any (the tamper demo deliberately downgrades one record to show
  the break being caught).
- Model artifacts have their own integrity manifest (`scripts/sign_models.py`,
  checked by the self-test) so a swapped model is caught the same way.
