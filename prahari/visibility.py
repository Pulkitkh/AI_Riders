"""Single-direction visibility — the degraded mode.

The problem statement says *unidirectional IP traffic*, and that phrase has two
readings. Ours is that a data diode carries a TAP copy of both directions of
each flow into a read-only enclave: traffic is one-way across the boundary, but
each conversation is still seen whole. The other reading is stricter — only one
direction of each flow is ever observable, as with asymmetric routing or a
one-way optical tap on a single fibre.

We do not get to choose which one the sponsor meant, so this module implements
the stricter reading and lets us measure what survives it. Everything here is a
projection applied to flows *before* the engine sees them; no detector is aware
that it is running degraded.

What breaks when the reverse direction is gone, and why:

  * SYN/SYN-ACK completion — the SYN-ACK is the server's packet. Recon scoring
    falls back to fan-out breadth alone (distinct destinations and ports), which
    is the dominant signal anyway.
  * out/in byte ratio — exfiltration loses its denominator. It falls back to
    absolute outbound volume against the host's own baseline, which is weaker
    and noisier, and we say so.
  * NXDOMAIN rate — the rcode lives in the DNS *response*. DGA detection falls
    back to lexical implausibility plus query-rate burst.
  * server certificate and JA4S — server-side handshake messages are gone.
    Encrypted-malware detection falls back to the client JA3, packet-size
    shape, timing and destination rarity.

What is unaffected, because it was only ever a property of the client side:
beacon interval regularity and jitter, DNS query-name entropy and length,
outbound fan-out, and source-IP entropy in a volumetric flood.
"""
from __future__ import annotations

from dataclasses import replace

from .schema import Flow

# Detector -> what it loses, for the honest version of the slide.
DEGRADED = {
    "recon_scanning":    "loses handshake completion; fan-out breadth retained",
    "data_exfiltration": "loses out/in ratio; absolute outbound volume retained",
    "dga_resolution":    "loses NXDOMAIN rate; lexical + burst retained",
    "encrypted_malware": "loses server cert and JA4S; JA3 + shape + rarity retained",
    "dns_tunnelling":    "loses response size; query entropy and rate retained",
    "c2_beaconing":      "unaffected — timing is a client-side property",
    "volumetric_ddos":   "unaffected — source entropy is client-side",
    "ics_intrusion":     "unaffected — the command direction is what we read",
    "anomalous_traffic": "unaffected — flow-shape features are client-side",
}


def project(flow: Flow) -> Flow:
    """Return the flow as a one-way tap would have seen it.

    Everything the reverse direction carried is removed rather than zeroed
    where the distinction matters, so a detector that checks `is None` can tell
    "not observed" from "observed to be zero" — a difference that decides
    whether a fallback is legitimate or a silent wrong answer.
    """
    return replace(
        flow,
        pkts_in=0,
        bytes_in=0,
        synack=0,                      # server's packet
        rst=0,                         # usually the server's, in a refused scan
        pkt_sizes=[s for s in flow.pkt_sizes if s > 0],
        dns_rcode=None,                # lives in the response
        tls_self_signed=False,         # server certificate is not observable
        tls_cert_days=None,
    )


def project_all(flows: list[Flow]) -> list[Flow]:
    return [project(f) for f in flows]
