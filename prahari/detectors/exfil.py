"""(f) Data exfiltration.

Signal: asymmetric flow-volume anomalies and unusual outbound-to-inbound byte
ratios. Most clients receive far more than they send; a host that inverts that
against *its own* baseline has changed behaviour.

This is the weakest of the six from passive metadata alone, and we say so rather
than tuning a threshold until the number looks good. A patient adversary moving
modest volumes to a reputable cloud endpoint over TLS during working hours is
close to indistinguishable from an employee using that same service. The
detector is a ranked lead generator for analyst review, not an oracle — which is
why its scores are deliberately capped below certainty.

The scoring is a fitted logistic regression (`prahari.model`) over eight
features, trained by `scripts/train.py` on temporally split captures. The single
feature that a hand-tuned threshold could never use well is `dst_external`: the
nightly-backup host that inverts its byte ratio — the classic exfil false
positive — sends its volume to an *internal* file server, while real exfiltration
leaves the network. The model learns that separation from labelled data instead
of us guessing a coefficient for it. A clean checkout with no trained model
falls back to the previous hand-set heuristic so the detector still runs.
"""
from __future__ import annotations

import math
from collections import defaultdict

from ..features import is_benign_service_sni, is_rfc1918
from ..model import LogisticRegression
from ..schema import Flow
from .base import Detection, Detector

SCORE_CEILING = 0.82        # we never claim certainty on this class

# dst_external is the feature a threshold cannot exploit: the benign backup host
# inverts its byte ratio exactly like exfiltration, but to an INTERNAL target.
FEATURES = ["out_in_ratio", "deviation", "log_bytes_out", "dst_concentration",
            "dst_novelty", "dst_external", "out_share", "n_flows"]


class ExfilDetector(Detector):
    name = "exfil-logreg"
    model_version = "0.4.0"
    threat_class = "data_exfiltration"
    threshold = 0.55

    MIN_BYTES = 200_000         # ignore trivial transfers
    ALPHA = 0.25                # EWMA rate for the per-host baseline
    MIN_HOSTS_FOR_RARITY = 4    # below this, suppress uploads to recognised services

    def __init__(self) -> None:
        self.by_src: dict[str, list[Flow]] = defaultdict(list)
        self.baseline_ratio: dict[str, float] = {}
        self.known_dsts: dict[str, set[str]] = defaultdict(set)
        self.dst_sni: dict[str, str] = {}          # last SNI seen per destination
        self.src_hosts: set[str] = set()           # internal hosts (rarity population)
        self.model = LogisticRegression.load("exfil")
        if self.model:
            self.threshold = self.model.threshold
        # Set by scripts/train.py to tap every gated window's feature vector so
        # training sees exactly what inference computes. None in production.
        self._sink: list | None = None

    def observe(self, flow: Flow) -> None:
        if flow.proto == "tcp" and not flow.ics_proto:
            self.by_src[flow.src_ip].append(flow)
            if flow.tls_sni:
                self.dst_sni[flow.dst_ip] = flow.tls_sni
            if is_rfc1918(flow.src_ip):
                self.src_hosts.add(flow.src_ip)

    @staticmethod
    def features(up: float, down: float, ratio: float, base: float | None,
                 top_share: float, novel: bool, external: bool,
                 n_flows: int) -> dict[str, float]:
        """One feature vector for a (source, window) aggregate.

        Clipped where a raw value has a long tail (a pure upload gives an
        unbounded ratio) so one outlier cannot dominate standardisation; the
        model standardises internally regardless.
        """
        dev = min(ratio / max(base, 0.2), 30.0) if base is not None else 1.0
        return {
            "out_in_ratio": min(ratio, 50.0),
            "deviation": dev,
            "log_bytes_out": math.log10(up + 1.0),
            "dst_concentration": top_share,          # 1.0 = all volume to one dst
            "dst_novelty": 1.0 if novel else 0.0,
            "dst_external": 1.0 if external else 0.0,
            "out_share": up / max(up + down, 1.0),
            "n_flows": float(n_flows),
        }

    @staticmethod
    def _heuristic(f: dict[str, float]) -> float:
        """Hand-set fallback for a checkout with no trained model. Same shape as
        the pre-learning detector, expressed over the feature vector."""
        ratio, dev = f["out_in_ratio"], f["deviation"]
        up = 10 ** f["log_bytes_out"]
        s = 0.0
        if ratio > 3.0:
            s += min(ratio / 20.0, 1.0) * 0.40
        if dev > 3.0:
            s += min((dev - 3.0) / 8.0, 1.0) * 0.30
        if f["dst_novelty"] > 0.5:
            s += 0.20
        if up > 5_000_000:
            s += 0.10
        return s

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

            by_dst: dict[str, int] = defaultdict(int)
            for f in flows:
                by_dst[f.dst_ip] += f.bytes_out
            top_dst = max(by_dst, key=by_dst.get)
            top_share = by_dst[top_dst] / max(up, 1)
            novel = top_dst not in self.known_dsts[src]
            external = not is_rfc1918(top_dst)
            for f in flows:
                self.known_dsts[src].add(f.dst_ip)

            # Single-user tap: a large upload to a RECOGNISED cloud service
            # (Drive / iCloud / Dropbox / photo backup) is ordinary, and without a
            # multi-host baseline we cannot tell it from exfil, so we suppress it
            # rather than cry wolf. A multi-host CII network keeps flagging it —
            # insider-to-cloud exfil is a real concern there for an analyst to review.
            if (len(self.src_hosts) < self.MIN_HOSTS_FOR_RARITY
                    and is_benign_service_sni(self.dst_sni.get(top_dst))):
                continue

            feats = self.features(up, down, ratio, base, top_share, novel,
                                  external, len(flows))
            if self._sink is not None:
                self._sink.append((min(f.ts for f in flows), src, feats))

            raw = self.model.predict_proba(feats) if self.model else self._heuristic(feats)
            score = min(raw, SCORE_CEILING)         # never claim certainty here

            if score >= self.threshold:
                deviation = ratio / max(base, 0.2)
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
                        "destination_external": external,
                        "destination_is_new_for_host": novel,
                        "scored_by": "model" if self.model else "heuristic",
                    },
                    caveat="lead for analyst review — exfiltration has the weakest passive signal",
                ))
        return out

    def reset_window(self) -> None:
        self.by_src.clear()
