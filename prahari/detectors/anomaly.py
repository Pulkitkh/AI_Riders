"""(h) Unknown / previously-unseen behaviour — unsupervised anomaly detection.

The other detectors are trained or tuned to catch threats we can name. This one
catches what we cannot: a flow far from everything the network normally does. It
is deliberately a CORROBORATING net for previously-unseen behaviour, not a proven
zero-day oracle — see eval/unseen_family.py for the honest out-of-distribution
experiment behind that wording.

Two unsupervised signals, ensembled — the standard way to cover each other's
blind spots:
  * an Isolation Forest (prahari.anomaly) fitted on benign traffic only, which
    isolates points in sparse regions of the benign distribution; and
  * a robust per-feature outlier gate (median/MAD profile of benign traffic),
    which catches a flow that is extreme on a single axis — e.g. a connection
    held open for minutes — a case vanilla Isolation Forest handles poorly
    because such a point sits OUTSIDE the benign range rather than inside a gap.

It reports a separate, deliberately non-alarming class ("anomalous_traffic",
medium severity) so it augments the specific detectors rather than drowning them.
"""
from __future__ import annotations

import json
import math
from collections import defaultdict
from pathlib import Path

from ..anomaly import IsolationForest
from ..schema import Flow
from .base import Detection, Detector

_PORTS = (80, 443, 53, 22, 502, 20000, 2404)
_PROFILE = Path(__file__).resolve().parents[1] / "models" / "anomaly_profile.json"


class AnomalyDetector(Detector):
    name = "anomaly-iforest"
    model_version = "0.2.0"
    threat_class = "anomalous_traffic"
    threshold = 0.5

    FLAG_SCORE = 0.62         # Isolation-Forest score: a flow this isolated is a look
    ENV_MARGIN = 0.25         # log-units a continuous feature must clear the benign envelope
    MIN_ANOM = 8              # SUSTAINED anomalous flows required — a one-off benign
                              # backup window (byte-ratio inversion, ~6 flows) must not
                              # alarm; a persistent covert channel (many flows) does
    HORIZON = 1800.0          # rolling memory, seconds
    RECENT = 120.0            # only alert while anomalous activity is fresh (bounds latency)

    def __init__(self) -> None:
        self.by_src: dict[str, list[tuple[float, Flow, float]]] = defaultdict(list)
        self.model = IsolationForest.load("anomaly")
        self.profile = self._load_profile()

    @staticmethod
    def _load_profile() -> dict:
        try:
            return json.loads(_PROFILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

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

    def _envelope_excess(self, vec: list[float]) -> float:
        """How far, in log-units, the worst continuous feature sits OUTSIDE the
        benign 0.1/99.9th-percentile envelope (0.0 if inside on every axis)."""
        p_lo = self.profile.get("p_lo"); p_hi = self.profile.get("p_hi")
        cont = self.profile.get("continuous")
        if not p_lo or not p_hi or not cont:
            return 0.0
        worst = 0.0
        for i in cont:
            x = vec[i]
            excess = max(x - p_hi[i], p_lo[i] - x, 0.0)
            if excess > worst:
                worst = excess
        return worst

    def observe(self, flow: Flow) -> None:
        if self.model is None:
            return
        vec = self.features(flow)
        s = self.model.score(vec)
        excess = self._envelope_excess(vec)
        # Ensemble: an Isolation-Forest score, OR a flow beyond the benign
        # envelope on a continuous axis by a clear margin, mapped onto the same
        # [0,1] scale so both unsupervised signals feed one number.
        s_eff = s
        if excess >= self.ENV_MARGIN:
            s_eff = max(s, min(0.62 + (excess - self.ENV_MARGIN) * 0.20, 0.95))
        if s_eff >= self.FLAG_SCORE:
            self.by_src[flow.src_ip].append((flow.ts, flow, s_eff))

    def evaluate(self, window_end: float) -> list[Detection]:
        out: list[Detection] = []
        for src in list(self.by_src.keys()):
            hits = [h for h in self.by_src[src] if h[0] >= window_end - self.HORIZON]
            self.by_src[src] = hits
            if len(hits) < self.MIN_ANOM:
                continue
            # Only alert while the host is ACTIVELY anomalous. Without this a host
            # whose anomalous burst ended keeps re-alerting every dedupe window as
            # long as stale hits sit inside the horizon, and its "detection delay"
            # grows without bound. Require fresh evidence in the last two windows.
            newest = max(t for t, _, _ in hits)
            if window_end - newest > self.RECENT:
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
                # the alert is about ongoing behaviour, raised at window close:
                # date it to the most-recent contributing flow, so detection
                # latency reflects the window delay, not the whole horizon.
                ts_event=max(t for t, _, _ in hits),
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
