"""(f) Data exfiltration.

Signal: asymmetric flow-volume anomalies and unusual outbound-to-inbound byte
ratios. Most clients receive far more than they send; a host that inverts that
against *its own* baseline has changed behaviour.

This is the weakest of the six from passive metadata alone, and we say so rather
than tuning the threshold until the number looks good. A patient adversary
moving modest volumes to a reputable cloud endpoint over TLS during working
hours is close to indistinguishable from an employee using that same service.
The detector is positioned as a ranked lead generator for analyst review, not
an oracle — which is why its scores are deliberately capped below certainty.
"""
from __future__ import annotations

from collections import defaultdict

from ..schema import Flow
from .base import Detection, Detector

SCORE_CEILING = 0.82        # we never claim certainty on this class


class ExfilDetector(Detector):
    name = "exfil-baseline"
    model_version = "0.3.0"
    threat_class = "data_exfiltration"
    threshold = 0.55

    MIN_BYTES = 200_000         # ignore trivial transfers
    ALPHA = 0.25                # EWMA rate for the per-host baseline

    def __init__(self) -> None:
        self.by_src: dict[str, list[Flow]] = defaultdict(list)
        self.baseline_ratio: dict[str, float] = {}
        self.known_dsts: dict[str, set[str]] = defaultdict(set)

    def observe(self, flow: Flow) -> None:
        if flow.proto == "tcp":
            self.by_src[flow.src_ip].append(flow)

    def evaluate(self, window_end: float) -> list[Detection]:
        out: list[Detection] = []
        for src, flows in self.by_src.items():
            up = sum(f.bytes_out for f in flows)
            down = sum(f.bytes_in for f in flows)
            ratio = up / max(down, 1)
            base = self.baseline_ratio.get(src)
            self.baseline_ratio[src] = (ratio if base is None
                                        else (1 - self.ALPHA) * base + self.ALPHA * ratio)

            if base is None or up < self.MIN_BYTES:
                for f in flows:
                    self.known_dsts[src].add(f.dst_ip)
                continue

            # which destination carries the outbound volume?
            by_dst: dict[str, int] = defaultdict(int)
            for f in flows:
                by_dst[f.dst_ip] += f.bytes_out
            top_dst = max(by_dst, key=by_dst.get)
            novel = top_dst not in self.known_dsts[src]
            for f in flows:
                self.known_dsts[src].add(f.dst_ip)

            deviation = ratio / max(base, 0.2)
            score = 0.0
            if ratio > 3.0:
                score += min(ratio / 20.0, 1.0) * 0.40
            if deviation > 3.0:
                score += min((deviation - 3.0) / 8.0, 1.0) * 0.30
            if novel:
                score += 0.20
            if up > 5_000_000:
                score += 0.10
            score = min(score, SCORE_CEILING)

            if score >= self.threshold:
                out.append(Detection(
                    threat_class=self.threat_class,
                    src_ip=src, dst_ip=top_dst, score=score,
                    ts_event=min(f.ts for f in flows),
                    observed_flows=len(flows),
                    flow_ids=[f.flow_id for f in flows[:8]],
                    evidence={
                        "bytes_out": up, "bytes_in": down,
                        "out_in_ratio": round(ratio, 2),
                        "host_baseline_ratio": round(base, 2),
                        "deviation_vs_baseline": round(deviation, 2),
                        "top_destination": top_dst,
                        "destination_is_new_for_host": novel,
                    },
                    caveat="lead for analyst review — exfiltration has the weakest passive signal",
                ))
        return out

    def reset_window(self) -> None:
        self.by_src.clear()
