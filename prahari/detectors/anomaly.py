"""(h) Unknown / zero-day behaviour — unsupervised anomaly detection.

The other detectors are trained or tuned to catch threats we can name. This one
catches what we cannot: a flow far from everything the network normally does,
flagged by an Isolation Forest (prahari.anomaly) that was fitted on benign
traffic only. It is the safety net for a novel attack that matches no signature
and no learned class — the case a signature-only IDS is blind to.

It reports a separate, deliberately non-alarming class ("anomalous_traffic",
medium severity) so it augments the specific detectors rather than drowning
them: a lead that says "this host is behaving unlike the baseline", with the
features that made it stand out.
"""
from __future__ import annotations

import math
from collections import defaultdict

from ..anomaly import IsolationForest
from ..schema import Flow
from .base import Detection, Detector

_PORTS = (80, 443, 53, 22, 502, 20000, 2404)


class AnomalyDetector(Detector):
    name = "anomaly-iforest"
    model_version = "0.1.0"
    threat_class = "anomalous_traffic"
    threshold = 0.5

    FLAG_SCORE = 0.62         # a flow this isolated is worth a look
    MIN_ANOM = 9              # cumulative anomalous flows to clear the benign hard-negatives
    HORIZON = 1800.0          # rolling memory, seconds

    def __init__(self) -> None:
        self.by_src: dict[str, list[tuple[float, Flow, float]]] = defaultdict(list)
        self.model = IsolationForest.load("anomaly")

    @staticmethod
    def features(f: Flow) -> list[float]:
        """A fixed numeric fingerprint of a flow — the shape of its behaviour,
        not its content. Same vector at training and inference."""
        br = f.bytes_out / max(f.bytes_in, 1)
        vec = [
            math.log10(f.bytes_out + 1.0),
            math.log10(f.bytes_in + 1.0),
            math.log10(br + 0.01),
            math.log10(f.duration + 0.01),
            math.log10(f.pkts_out + 1.0),
            math.log10(f.pkts_in + 1.0),
            float(f.syn), float(f.synack), float(f.rst), float(f.fin),
            1.0 if f.proto == "udp" else 0.0,
            1.0 if f.ics_proto else 0.0,
        ]
        vec += [1.0 if f.dst_port == p else 0.0 for p in _PORTS]
        return vec

    def observe(self, flow: Flow) -> None:
        if self.model is None:
            return
        s = self.model.score(self.features(flow))
        if s >= self.FLAG_SCORE:
            self.by_src[flow.src_ip].append((flow.ts, flow, s))

    def evaluate(self, window_end: float) -> list[Detection]:
        out: list[Detection] = []
        for src in list(self.by_src.keys()):
            hits = [h for h in self.by_src[src] if h[0] >= window_end - self.HORIZON]
            self.by_src[src] = hits
            if len(hits) < self.MIN_ANOM:
                continue
            top = max(s for _, _, s in hits)
            # confidence from how isolated the peak flow is AND how much of this
            # host's session is off-baseline — a lone outlier is a maybe, a host
            # persistently far from normal is a lead.
            score = (min(max((top - 0.60) / 0.05, 0.0), 1.0) * 0.45
                     + min(len(hits) / 20.0, 1.0) * 0.45)
            score = min(score, 0.90)
            if score < self.threshold:
                continue
            worst = max(hits, key=lambda h: h[2])[1]
            out.append(Detection(
                threat_class=self.threat_class,
                src_ip=src, dst_ip=worst.dst_ip, score=score,
                ts_event=min(t for t, _, _ in hits),
                observed_flows=len(hits),
                flow_ids=[f.flow_id for _, f, _ in hits[:8]],
                evidence={
                    "anomaly_score": round(top, 3),
                    "method": "isolation_forest",
                    "anomalous_flows": len(hits),
                    "peak_dst_port": worst.dst_port,
                    "peak_proto": worst.ics_proto or worst.proto,
                    "note": "unsupervised — matches no signature or trained class",
                },
                caveat="zero-day candidate — behaviour far from the benign baseline",
            ))
        return out

    def reset_window(self) -> None:
        pass       # anomaly memory persists across windows; the horizon prunes it
