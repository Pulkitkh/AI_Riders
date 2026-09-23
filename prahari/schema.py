"""Core records: flows in, alerts out.

The alert schema is the one the problem statement requires under constraint (e):
timestamp, flow identifier, threat class, confidence score, supporting evidence.
Field naming leans on Elastic Common Schema so alerts drop into existing SIEMs.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any

SCHEMA_VERSION = "1.0"

# The six threat classes named in SIH26145, plus the benign class.
CLASSES = (
    "benign",
    "volumetric_ddos",
    "c2_beaconing",
    "dga_resolution",
    "dns_tunnelling",
    "encrypted_malware",
    "recon_scanning",
    "data_exfiltration",
)

SEVERITY_BY_CLASS = {
    "volumetric_ddos": "high",
    "c2_beaconing": "high",
    "dga_resolution": "medium",
    "dns_tunnelling": "high",
    "encrypted_malware": "high",
    "recon_scanning": "low",
    "data_exfiltration": "critical",
}


@dataclass
class Flow:
    """One bidirectional flow record, the unit every detector consumes.

    This is deliberately shaped like what Zeek + nfstream would hand us from a
    real capture, so swapping the synthetic source for a live tap is a change of
    one module and nothing else.
    """
    ts: float                      # first-packet time, epoch seconds
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str = "tcp"

    duration: float = 0.0
    pkts_out: int = 0
    pkts_in: int = 0
    bytes_out: int = 0
    bytes_in: int = 0

    # TCP flag counters — what tells a completed handshake from a scan
    syn: int = 0
    synack: int = 0
    rst: int = 0
    fin: int = 0

    # Signed packet-size sequence: positive = outbound, negative = inbound.
    # This is the feature that survives encryption.
    pkt_sizes: list[int] = field(default_factory=list)

    # Application metadata, read passively — never payload.
    dns_qname: str | None = None
    dns_qtype: str | None = None
    dns_rcode: str | None = None
    tls_ja4: str | None = None
    tls_sni: str | None = None
    tls_self_signed: bool = False
    tls_cert_days: int | None = None

    # Ground truth. Present only in generated traffic; detectors never read it.
    label: str = "benign"

    @property
    def flow_id(self) -> str:
        raw = f"{self.ts:.3f}|{self.src_ip}:{self.src_port}|{self.dst_ip}:{self.dst_port}|{self.proto}"
        return "f-" + hashlib.sha256(raw.encode()).hexdigest()[:10]

    @property
    def completed(self) -> bool:
        return self.synack > 0

    @property
    def byte_ratio(self) -> float:
        """Outbound over inbound. A client that starts talking more than it
        listens has changed behaviour — the core exfiltration signal."""
        return self.bytes_out / max(self.bytes_in, 1)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Alert:
    """A finding, with the evidence that produced it."""
    alert_id: str
    ts_event: float          # when the triggering traffic was observed
    ts_emitted: float        # when we raised the alert
    threat_class: str
    severity: str
    confidence: float        # calibrated, not a raw model score
    src_ip: str
    dst_ip: str | None
    detector: str
    model_version: str
    evidence: dict[str, Any]
    flow_ids: list[str] = field(default_factory=list)
    observed_flows: int = 1
    reverse_direction_visible: bool = True
    caveat: str | None = None

    @property
    def latency_ms(self) -> float:
        return (self.ts_emitted - self.ts_event) * 1000.0

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "alert_id": self.alert_id,
            "@timestamp": self.ts_event,
            "detected_at": self.ts_emitted,
            "detection_latency_ms": round(self.latency_ms, 1),
            "threat": {
                "class": self.threat_class,
                "severity": self.severity,
                "confidence": round(self.confidence, 3),
            },
            "flow": {
                "ids": self.flow_ids[:8],
                "source": {"ip": self.src_ip},
                "destination": {"ip": self.dst_ip},
                "observed_flows": self.observed_flows,
            },
            "evidence": {
                **self.evidence,
                "reverse_direction_visible": self.reverse_direction_visible,
            },
            "model": {"detector": self.detector, "version": self.model_version},
            **({"caveat": self.caveat} if self.caveat else {}),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_record(), separators=(",", ":"), sort_keys=True)


# Plain-language intelligence for each threat class — written for a non-expert.
# The dashboard shows this so anyone, technical or not, understands every alert:
# what it is, why it matters, and what an operator would do. Kept in the schema
# so there is one source of truth the API and UI both read.
THREAT_INFO = {
    "volumetric_ddos": {
        "title": "Volumetric DDoS",
        "plain": "A flood of traffic from many fake addresses trying to overwhelm a "
                 "server so real users cannot reach it.",
        "analogy": "Like thousands of hoax callers jamming a helpline so genuine "
                   "callers get a busy tone.",
        "why": "Can knock a public service — a bank portal, a power dashboard — "
               "offline for everyone.",
        "action": "Rate-limit or block the source ranges upstream; alert the ISP.",
    },
    "c2_beaconing": {
        "title": "C2 Beaconing",
        "plain": "A device on the network is quietly checking in with an attacker's "
                 "server at regular intervals, waiting for orders.",
        "analogy": "Like a planted spy calling their handler at the same time every "
                   "hour to receive instructions.",
        "why": "It is the heartbeat of an active intrusion — the attacker already "
               "has a foothold inside.",
        "action": "Isolate the device, capture the destination, hunt for how it got in.",
    },
    "dga_resolution": {
        "title": "DGA Resolution",
        "plain": "A device is looking up lots of random-looking website names — the "
                 "way malware finds its command server when fixed addresses are blocked.",
        "analogy": "Like a courier dialling hundreds of random numbers until the boss "
                   "picks up.",
        "why": "A strong sign of malware trying to reach its operator resiliently.",
        "action": "Block the domains, quarantine the host, identify the malware family.",
    },
    "dns_tunnelling": {
        "title": "DNS Tunnelling",
        "plain": "Data is being smuggled out hidden inside ordinary-looking DNS "
                 "lookups — a channel that often slips past firewalls.",
        "analogy": "Like sneaking documents out of a building folded inside routine "
                   "mail that nobody inspects.",
        "why": "A covert exit route for stolen data or remote control.",
        "action": "Block the domain, inspect the host, tighten DNS egress rules.",
    },
    "encrypted_malware": {
        "title": "Malware in Encrypted Traffic",
        "plain": "An encrypted connection whose software fingerprint matches malware, "
                 "not a normal browser — spotted without decrypting anything.",
        "analogy": "Like recognising a burglar by their gait on CCTV without ever "
                   "opening the bag they carry.",
        "why": "Modern malware hides inside HTTPS; the fingerprint gives it away.",
        "action": "Investigate the host and destination; the payload was never opened.",
    },
    "recon_scanning": {
        "title": "Reconnaissance / Port Scan",
        "plain": "Someone is probing many ports on the network to map which doors "
                 "are open — usually the first step before an attack.",
        "analogy": "Like a burglar walking down a street trying every door and window "
                   "to see which is unlocked.",
        "why": "Early warning: an attacker is planning their way in.",
        "action": "Note the source, review exposed services, watch for a follow-up.",
    },
    "data_exfiltration": {
        "title": "Data Exfiltration",
        "plain": "A device is sending out far more data than it receives, to a place "
                 "it never talked to before — the shape of data being stolen.",
        "analogy": "Like an employee who suddenly carries out boxes of files every "
                   "night to an address the company has no dealings with.",
        "why": "This is the theft itself — intellectual property or citizen data leaving.",
        "action": "Cut the connection, preserve evidence, begin incident response.",
    },
    "benign": {
        "title": "Benign",
        "plain": "Normal, expected traffic. No action needed.",
        "analogy": "",
        "why": "",
        "action": "",
    },
}
