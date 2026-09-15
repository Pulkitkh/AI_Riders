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
