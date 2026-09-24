# PRAHARI — Security Architecture & the One-Way Argument

The core security proposition is that PRAHARI observes a *copy* of production-side
traffic through a one-way boundary and cannot create a path back into the
protected network. That claim is only as strong as the layer that enforces it, so
we state it as **three independent layers** and are explicit about what each one
does and does not prove. A senior jury is right to reject a single software check
presented as a complete boundary proof; this document is the honest version.

## The three layers of the one-way boundary

| Layer | Enforces | Proof / evidence | What it does NOT prove |
|---|---|---|---|
| **1. Physical** | Traffic can physically only flow one way into the sensor | A hardware data diode or a mirror/SPAN port with TX physically disconnected. Directionality is a property of the wire, not of software. | Nothing about what software on the sensor does with the copy. |
| **2. OS / network** | The sensor host has no route or egress toward the protected side | Capture bound to a single mirror-only interface; IP forwarding disabled (`net.ipv4.ip_forward=0`); egress firewall DROP toward the protected subnet; a separate management interface carries only the SOC/CERT-In feed. Show `ip route`, `iptables -S`, interface roles. | That the application itself never attempts to transmit. |
| **3. Application** | The detection code has no client/transmit capability | `prahari/selftest.py` parses the AST of every module in the detection path and fails the build if any imports `socket`, `requests`, `urllib`, `httpx`, `scapy`, etc. | It is a *software invariant check*, not an OS/hardware egress guarantee. A compromised process could in principle use another facility; that is why layers 1–2 exist. |

**Wording we use, and why.** We say *"Nothing can return to the protected
production network"* — not *"nothing leaves"*. The enclave deliberately DOES emit
outbound reporting to the SOC/CERT-In over the management interface; the invariant
is that no traffic returns to the protected side. The self-test is described as a
"read-only software invariant", never as proof of total egress impossibility.

## Management-plane isolation

The SOC/CERT-In reporting path is a **separate interface** from the capture path.
It must not become an accidental return path:

- capture interface: mirror-only, no IP address needed for L2 capture, no route
  to anything;
- management interface: routes ONLY to the SOC/CERT-In collector subnet;
- no bridge or forwarding between the two; `ip_forward` disabled;
- the two are shown as distinct roles in the deployment diagram, not one NIC.

## Demo vs hardened profiles

The repository ships a **demo/lab profile** and documents the **hardened
appliance** posture; they are not the same and we never present the demo as the
appliance:

| Concern | Demo/lab (this repo) | Hardened appliance |
|---|---|---|
| Attack injector (`/api/live/attack`) | Off by default; enable with `PRAHARI_DEMO=1`; localhost/token only | Absent from the build |
| Dashboard control endpoints | localhost, or `PRAHARI_API_TOKEN` | Authenticated + RBAC, audited |
| CORS | same-origin (no wildcard); `PRAHARI_CORS_ORIGIN` to allowlist | same-origin only |
| Errors | generic; tracebacks only under `PRAHARI_DEBUG` | generic only |
| Container | `cap_drop: ALL` + `NET_RAW`, `no-new-privileges`, read-only rootfs | + egress firewall, single capture NIC, seccomp |
| Model/software updates | JSON artifacts loaded directly | signed bundles, signature verified before activation, rollback |

## Threat model (including a compromised sensor)

- **Attacker on the production side** — cannot reach the sensor except by the
  one-way copy (layers 1–2). This is the primary design goal.
- **Attacker who compromises the monitoring enclave** — layers 1–2 still prevent
  a return path to the protected side. Evidence integrity, however, is only
  *tamper-evident* locally (the hash chain): an insider with write access can
  rewrite the whole chain, so chain-of-custody requires signing and external
  head-anchoring (WORM / trusted timestamp) — described as future work, not
  claimed as present. See `docs/LEDGER.md`.
- **Supply chain** — zero third-party Python runtime packages narrows the attack
  surface; the trade is that our own parsers must be fuzzed and maintained (we
  run parser fuzzing in the test suite).

## What the self-test proves, precisely

`python3 -m prahari.cli selftest` proves: (a) no module in the detection path
imports a network-client/transmit facility; (b) the alert hash chain verifies.
It does **not** prove physical directionality or OS-level egress denial — those
are layers 1–2 and are demonstrated with `ip route`/`iptables` and a physical
send-back test on jury day, not by the AST scan.
