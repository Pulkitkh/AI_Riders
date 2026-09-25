"""(b) Botnet command-and-control beaconing.

Signal: periodicity and inter-arrival analysis on flows repeating toward a small
set of destinations. The hard part is jitter — real C2 frameworks randomise the
sleep interval by 10-40% precisely to defeat naive periodicity tests.

Our answer is to test the *shape of the interval distribution* rather than
demanding near-perfect regularity. A jittered beacon still produces a tight,
bounded, unimodal distribution; human-driven traffic is heavy-tailed and bursty.
The recall-versus-jitter curve this produces is measured in eval/jitter_sweep.py.
"""
from __future__ import annotations

from collections import defaultdict

from ..features import (autocorrelation_peak, coefficient_of_variation, intervals,
                        is_benign_service_sni, is_rfc1918, jitter_band, mad, mean,
                        median, regularity, stdev)
from ..model import LogisticRegression
from ..schema import Flow
from .base import Detection, Detector

# Deliberately NOT included: whether the certificate is self-signed. That is a
# real signal, but it belongs to the encrypted-session detector. Leaving it here
# let the model take a shortcut and stop learning from timing at all — which is
# the kind of leakage that produces a beautiful number and a useless detector.
FEATURES = ["regularity", "jitter_band", "interval_cv", "mad_ratio", "byte_cv",
            "n_events", "dst_prevalence", "dst_external"]


class BeaconDetector(Detector):
    name = "beacon-logreg"
    model_version = "0.5.0"
    threat_class = "c2_beaconing"
    threshold = 0.6

    MIN_EVENTS = 6          # need enough check-ins for the interval stats to mean anything
    HORIZON = 3600.0        # rolling memory, seconds
    # Below this many internal hosts, destination popularity cannot separate C2
    # from a monitoring agent (every destination is talked to by one host), so on
    # a single-user tap we suppress beaconing to RECOGNISED services — otherwise
    # every OS/browser/chat heartbeat looks like C2. Multi-host networks are
    # unaffected: popularity does the work there, exactly as before.
    MIN_HOSTS_FOR_RARITY = 4

    def __init__(self) -> None:
        self.history: dict[tuple[str, str], list[Flow]] = defaultdict(list)
        self.model = LogisticRegression.load("beacon")
        if self.model:
            self.threshold = self.model.threshold
        # Prevalence: a pattern shared by many hosts is infrastructure, not C2.
        self.dst_popularity: dict[str, set[str]] = defaultdict(set)
        self.src_hosts: set[str] = set()             # internal hosts (rarity population)

    def observe(self, flow: Flow) -> None:
        if flow.proto != "tcp" or not flow.syn or flow.ics_proto:
            return
        key = (flow.src_ip, flow.dst_ip)
        self.history[key].append(flow)
        self.dst_popularity[flow.dst_ip].add(flow.src_ip)
        if is_rfc1918(flow.src_ip):
            self.src_hosts.add(flow.src_ip)

    @staticmethod
    def extract(flows: list[Flow], dst_prevalence: int = 1) -> dict[str, float]:
        """Timing statistics for one (source, destination) pair.

        `dst_prevalence` — how many internal hosts talk to this destination — is
        the feature that separates C2 from a monitoring agent. Both beacon on a
        tight interval; only one of them does it from a single host to a
        destination nobody else in the environment contacts.
        """
        ts = [f.ts for f in flows]
        iv = intervals(ts)
        byts = [f.bytes_out for f in flows]
        m = median(iv) or 1.0
        cv = coefficient_of_variation(iv)
        return {
            "regularity": regularity(cv),
            "jitter_band": jitter_band(cv),
            "interval_cv": cv,
            "mad_ratio": mad(iv) / m,
            "byte_cv": coefficient_of_variation(byts),
            "n_events": float(len(flows)),
            "dst_prevalence": float(dst_prevalence),
            "dst_external": 0.0 if is_rfc1918(flows[-1].dst_ip) else 1.0,
        }

    def _heuristic(self, f: dict[str, float]) -> float:
        """Fallback used when no trained model is present, so the detector still
        works on a clean checkout before `make train` has been run."""
        s = 0.0
        if f["interval_cv"] < 0.45:
            s += (1.0 - f["interval_cv"] / 0.45) * 0.5
        if f["mad_ratio"] < 0.35:
            s += (1.0 - f["mad_ratio"] / 0.35) * 0.25
        if f["byte_cv"] < 0.25:
            s += (1.0 - f["byte_cv"] / 0.25) * 0.25
        return min(s, 1.0)

    def evaluate(self, window_end: float) -> list[Detection]:
        out: list[Detection] = []
        for (src, dst), flows in self.history.items():
            flows = [f for f in flows if f.ts >= window_end - self.HORIZON]
            self.history[(src, dst)] = flows
            if len(flows) < self.MIN_EVENTS:
                continue

            popularity = len(self.dst_popularity[dst])
            # Single-user tap: popularity is degenerate, so a periodic flow to a
            # recognised service (google/microsoft/apple/… update & telemetry) is
            # background noise, not C2. Suppress it rather than spam the operator.
            single_host = len(self.src_hosts) < self.MIN_HOSTS_FOR_RARITY
            if single_host and is_benign_service_sni(flows[-1].tls_sni):
                continue
            feats = self.extract(flows, popularity)
            score = self.model.predict_proba(feats) if self.model else self._heuristic(feats)
            if not self.model and popularity >= 3:
                score *= 0.25       # heuristic fallback needs the penalty explicitly

            if score >= self.threshold:
                out.append(Detection(
                    threat_class=self.threat_class,
                    src_ip=src, dst_ip=dst, score=min(score, 1.0),
                    ts_event=flows[-1].ts,
                    observed_flows=len(flows),
                    flow_ids=[f.flow_id for f in flows[-8:]],
                    evidence={
                        "interval_mean_s": round(mean(intervals([f.ts for f in flows])), 1),
                        "interval_cv": round(feats["interval_cv"], 3),
                        "jitter_band_fit": round(feats["jitter_band"], 3),
                        "mad_ratio": round(feats["mad_ratio"], 3),
                        "byte_cv": round(feats["byte_cv"], 3),
                        "check_ins": len(flows),
                        "dest_prevalence_hosts": popularity,
                        "destination_external": bool(feats["dst_external"]),
                        "ja4": flows[-1].tls_ja4,
                    },
                ))
        return out

    def reset_window(self) -> None:
        pass        # beaconing needs memory across windows; the horizon prunes it
