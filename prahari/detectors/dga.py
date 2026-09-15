"""(c) DGA domain resolution.

Signal: entropy and n-gram analysis of query names, plus the NXDOMAIN walk an
implant produces while it works through its candidate list.

Two models cooperate. A bigram language model fitted on the domains this network
normally resolves scores how plausible a name is; a logistic regression over
lexical features turns that plus entropy, vowel ratio and consonant runs into a
probability. Dictionary-based DGA families remain the honest hard case — their
names look like words — which is why the per-host NXDOMAIN rate carries weight
independently of how the name reads.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from ..features import lexical_features, mean
from ..model import LogisticRegression, MODEL_DIR
from ..schema import Flow
from .base import Detection, Detector

FEATURES = ["length", "entropy", "vowel_ratio", "digit_ratio", "consonant_run",
            "bigram_ll", "n_labels"]


def load_bigrams() -> dict[str, float]:
    p = MODEL_DIR / "bigrams.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


class DGADetector(Detector):
    name = "dga-lexical-logreg"
    model_version = "0.5.0"
    threat_class = "dga_resolution"
    threshold = 0.55

    MIN_QUERIES = 8

    def __init__(self) -> None:
        self.by_src: dict[str, list[Flow]] = defaultdict(list)
        self.model = LogisticRegression.load("dga")
        self.bigrams = load_bigrams()

    def observe(self, flow: Flow) -> None:
        if flow.dns_qname:
            self.by_src[flow.src_ip].append(flow)

    def score_name(self, qname: str) -> float:
        feats = lexical_features(qname, self.bigrams)
        if self.model:
            return self.model.predict_proba(feats)
        # dependency-free fallback before training has been run
        s = 0.0
        if feats["entropy"] > 3.2:
            s += 0.4
        if feats["vowel_ratio"] < 0.30:
            s += 0.3
        if feats["consonant_run"] >= 4:
            s += 0.3
        return min(s, 1.0)

    def evaluate(self, window_end: float) -> list[Detection]:
        out: list[Detection] = []
        for src, flows in self.by_src.items():
            if len(flows) < self.MIN_QUERIES:
                continue
            scores = [self.score_name(f.dns_qname) for f in flows]
            nx = sum(1 for f in flows if f.dns_rcode == "NXDOMAIN") / len(flows)
            suspicious = sum(1 for s in scores if s > 0.5) / len(scores)

            # The NXDOMAIN walk is often a stronger signal than any single name.
            score = 0.55 * suspicious + 0.45 * min(nx * 1.6, 1.0)
            if score >= self.threshold:
                worst = sorted(zip(scores, flows), key=lambda p: -p[0])[:3]
                out.append(Detection(
                    threat_class=self.threat_class,
                    src_ip=src, dst_ip=flows[0].dst_ip, score=min(score, 1.0),
                    ts_event=min(f.ts for f in flows),
                    observed_flows=len(flows),
                    flow_ids=[f.flow_id for f in flows[:8]],
                    evidence={
                        "queries_in_window": len(flows),
                        "nxdomain_rate": round(nx, 3),
                        "suspicious_name_rate": round(suspicious, 3),
                        "mean_name_score": round(mean(scores), 3),
                        "examples": [f.dns_qname for _, f in worst],
                    },
                ))
        return out

    def reset_window(self) -> None:
        self.by_src.clear()
