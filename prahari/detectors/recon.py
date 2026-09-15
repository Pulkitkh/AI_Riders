"""(e) Reconnaissance and port scanning.

Signal: fan-out from a single source across many destination ports or hosts,
with most attempts getting no answer. Another case where a clean statistical
detector beats a model — it is explainable by construction, and an operator can
read the evidence and agree or disagree immediately.
"""
from __future__ import annotations

from collections import defaultdict

from ..schema import Flow
from .base import Detection, Detector


class ReconDetector(Detector):
    name = "recon-fanout"
    model_version = "0.3.0"
    threat_class = "recon_scanning"

    MIN_TARGETS = 40            # distinct (host, port) pairs in the window
    UNANSWERED_FLOOR = 0.85

    def __init__(self) -> None:
        self.by_src: dict[str, list[Flow]] = defaultdict(list)

    def observe(self, flow: Flow) -> None:
        if flow.proto == "tcp" and flow.syn:
            self.by_src[flow.src_ip].append(flow)

    def evaluate(self, window_end: float) -> list[Detection]:
        out: list[Detection] = []
        for src, flows in self.by_src.items():
            ports = {f.dst_port for f in flows}
            hosts = {f.dst_ip for f in flows}
            targets = len({(f.dst_ip, f.dst_port) for f in flows})
            if targets < self.MIN_TARGETS:
                continue
            unanswered = sum(1 for f in flows if not f.completed) / len(flows)
            if unanswered < self.UNANSWERED_FLOOR:
                continue

            score = min(targets / 300.0, 1.0) * 0.55 + unanswered * 0.45
            score = min(score, 1.0)
            if score >= self.threshold:
                out.append(Detection(
                    threat_class=self.threat_class,
                    src_ip=src,
                    dst_ip=f"{len(hosts)} hosts",
                    score=score,
                    ts_event=min(f.ts for f in flows),
                    observed_flows=len(flows),
                    flow_ids=[f.flow_id for f in flows[:8]],
                    evidence={
                        "distinct_ports": len(ports),
                        "distinct_hosts": len(hosts),
                        "distinct_targets": targets,
                        "unanswered_ratio": round(unanswered, 3),
                    },
                ))
        return out

    def reset_window(self) -> None:
        self.by_src.clear()
