# PRAHARI — Evidence Ledger: scope, storage, and threat model

The alert ledger is a SHA-256 **hash-chained, append-only** record: each entry
carries the hash of the previous one, so any edit to a past record breaks the
chain and is detectable. We are precise about what that does and does not mean.

## What it is — and is not

| Property | Status | Note |
|---|---|---|
| Tamper-**evident** | **Yes** | Any modification of a past record is detectable by re-verifying the chain (`prahari.cli selftest`, or the dashboard's verify tab). |
| Tamper-**proof** without the key | **Yes, when keyed** | Set `PRAHARI_LEDGER_KEY` (or `PRAHARI_LEDGER_KEYFILE`) and each link is an HMAC-SHA256, not a bare hash. An insider who rewrites the whole file cannot forge a chain that verifies without the secret. Unkeyed, the chain is tamper-evident only (an attacker can recompute it). Each record records its `algo`, so old SHA-256 files keep verifying after a key is introduced. |
| Fail-closed on resume | **Yes** | Re-opening a ledger verifies the chain *before* trusting its tail; a broken chain raises `LedgerTampered` instead of silently resuming from a forged record. |
| Crash durability | **Yes** | Every append is `flush()` + `os.fsync()`, so an acknowledged alert survives power loss. |
| Regulatory-certified | **No** | We say "tamper-evident/-proof hash-chained audit trail", never "CERT-In-grade". |
| Trusted timestamp / external anchor | **Hook present** | `AlertLedger.head()` returns `{seq, sha256, algo}`; publishing it periodically to a WORM store or RFC-3161 timestamp service anchors the chain so even a full local rewrite is detectable. The hook is implemented; the external sink is a deployment choice. |

## Threat model for the ledger

- **Read/observe attacker**: cannot alter records without detection (chain).
- **Local-write attacker (compromised sensor)**: *unkeyed*, can rewrite the
  local chain undetectably; *keyed* (HMAC), cannot forge a verifying chain
  without the secret, and once a head is anchored externally even a full rewrite
  is detectable. The fail-closed resume means a tampered file is rejected at
  startup rather than quietly continued.
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
  HMAC-signed when `PRAHARI_MODEL_KEY` is set) and the engine **enforces** it at
  startup — a swapped or unsigned-under-key model makes the engine refuse to
  start (fail closed), not merely report a failed check.
