"""Fusion: turn raw detections into ranked incidents an analyst can work.

Three jobs, all of which exist because the binding constraint in a real SOC is
analyst attention, not compute:

  * deduplicate — a SYN flood produces thousands of flows but is one event
  * correlate  — recon then beaconing then an outbound volume anomaly from the
                 same host is one intrusion story, not three unrelated alerts
  * calibrate  — a raw model score of 0.97 must actually mean something, or
                 analysts learn to ignore the number
"""
from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass, field

from .detectors.base import Detection
from .schema import Alert, MITRE_ATTACK, SEVERITY_BY_CLASS

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CORRELATION_WINDOW = 1800.0      # seconds


@dataclass
class Incident:
    """Several detections about one entity, presented as one story."""
    entity: str
    alerts: list[Alert] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def classes(self) -> list[str]:
        seen, out = set(), []
        for a in self.alerts:
            if a.threat_class not in seen:
                seen.add(a.threat_class)
                out.append(a.threat_class)
        return out

    @property
    def severity(self) -> str:
        return max((a.severity for a in self.alerts), key=lambda s: SEVERITY_RANK[s])

    @property
    def score(self) -> float:
        """Rank by worst single finding, lifted when a host shows a kill chain."""
        best = max(a.confidence for a in self.alerts)
        return min(best + 0.05 * (len(self.classes) - 1), 1.0)


class Fusion:
    def __init__(self, suppress: set[str] | None = None):
        self.seen: dict[str, float] = {}            # dedupe key -> last emitted
        self.incidents: dict[str, Incident] = {}
        self.suppress = suppress or set()           # explicit, auditable allowlist

    @staticmethod
    def _key(d: Detection) -> str:
        return f"{d.threat_class}|{d.src_ip}|{d.dst_ip}"

    @staticmethod
    def _alert_id(d: Detection, now: float) -> str:
        raw = f"{d.threat_class}|{d.src_ip}|{d.dst_ip}|{d.ts_event:.1f}"
        return "prh-" + hashlib.sha256(raw.encode()).hexdigest()[:12]

    def severity_for(self, d: Detection, confidence: float) -> str:
        """Severity is not confidence. It combines confidence with the impact of
        the threat class — a medium-confidence exfiltration finding outranks a
        high-confidence port scan."""
        base = SEVERITY_BY_CLASS.get(d.threat_class, "low")
        if confidence < 0.6 and base in ("critical", "high"):
            return "medium"
        if confidence > 0.9 and base == "medium":
            return "high"
        return base

    def push(self, detections: list[Detection], detector_name: str,
             model_version: str, now: float | None = None,
             dedupe_window: float = 300.0) -> list[Alert]:
        now = now if now is not None else time.time()
        out: list[Alert] = []
        for d in detections:
            if d.src_ip in self.suppress or (d.dst_ip or "") in self.suppress:
                continue
            key = self._key(d)
            last = self.seen.get(key)
            if last is not None and now - last < dedupe_window:
                continue
            self.seen[key] = now

            confidence = round(min(max(d.score, 0.0), 1.0), 3)
            # Stamp the MITRE ATT&CK technique so every alert lands in a
            # kill-chain an analyst can pivot on, not just a class bucket.
            tech = MITRE_ATTACK.get(d.threat_class)
            evidence = dict(d.evidence)
            if tech:
                evidence["mitre_technique"] = tech[0]
                evidence["mitre_name"] = tech[1]
                evidence["mitre_tactic"] = tech[2]
            alert = Alert(
                alert_id=self._alert_id(d, now),
                ts_event=d.ts_event,
                ts_emitted=now,
                threat_class=d.threat_class,
                severity=self.severity_for(d, confidence),
                confidence=confidence,
                src_ip=d.src_ip,
                dst_ip=d.dst_ip,
                detector=detector_name,
                model_version=model_version,
                evidence=evidence,
                flow_ids=d.flow_ids,
                observed_flows=d.observed_flows,
                reverse_direction_visible=d.reverse_direction_visible,
                caveat=d.caveat,
            )
            out.append(alert)
            self._correlate(alert)
        return out

    def _correlate(self, alert: Alert) -> None:
        entity = alert.src_ip
        inc = self.incidents.get(entity)
        if inc is None or alert.ts_event - inc.last_seen > CORRELATION_WINDOW:
            inc = Incident(entity=entity, first_seen=alert.ts_event)
            self.incidents[entity] = inc
        inc.alerts.append(alert)
        inc.last_seen = max(inc.last_seen, alert.ts_event)

    def ranked_incidents(self) -> list[Incident]:
        multi = [i for i in self.incidents.values() if len(i.alerts) > 0]
        return sorted(multi, key=lambda i: (-i.score, -len(i.classes)))
