"""(a) Volumetric and protocol DDoS.

Signal the problem statement points at: flow-level rate statistics and
source-IP entropy. A spoofed flood randomises source addresses, so the entropy
of the source distribution toward one destination jumps away from that
destination's own baseline, while the handshake completion ratio collapses.

Deliberately statistical, not deep learning: it is faster, explainable, and far
easier to defend in a viva than a neural network would be for the same job.
"""
from __future__ import annotations

from collections import defaultdict

from ..features import shannon_entropy
from ..schema import Flow
from .base import Detection, Detector


class DDoSDetector(Detector):
    name = "ddos-entropy-cusum"
    model_version = "0.4.0"
    threat_class = "volumetric_ddos"

    MIN_FLOWS = 150             # below this a burst is not volumetric
    ENTROPY_FLOOR = 6.0         # bits, over source addresses
    COMPLETION_CEIL = 0.20      # fraction of SYNs that got a SYN-ACK
    # Ports that answer a small query with a large reply — the reflectors used
    # in amplification floods (DNS, NTP, SSDP, memcached, chargen, LDAP).
    AMPLIFIER_PORTS = {53, 123, 1900, 11211, 19, 389, 137, 161}
    AMPLIFY_SIZE = 600          # bytes; a reply this large from a reflector is suspect

    def __init__(self) -> None:
        self.by_dst: dict[str, list[Flow]] = defaultdict(list)
        self.baseline_rate: dict[str, float] = {}     # EWMA flows/window per dst

    def observe(self, flow: Flow) -> None:
        if flow.syn or flow.proto == "udp":
            self.by_dst[flow.dst_ip].append(flow)

    def evaluate(self, window_end: float) -> list[Detection]:
        out: list[Detection] = []
        for dst, flows in self.by_dst.items():
            n = len(flows)
            base = self.baseline_rate.get(dst, 0.0)
            self.baseline_rate[dst] = 0.8 * base + 0.2 * n      # update after use

            if n < self.MIN_FLOWS:
                continue
            srcs = [f.src_ip for f in flows]
            ent = shannon_entropy(srcs)
            uniq = len(set(srcs))
            # The handshake-completion feature only means anything for TCP.
            # UDP has no handshake, so applying it there marked every busy DNS
            # resolver as a flood — a real bug this caught, and the reason the
            # component is now gated on the protocol mix.
            # Reflection/amplification: large UDP replies arriving from known
            # reflector source ports are the tell — a spoofed victim is being
            # drowned in responses it never asked for.
            udp = [f for f in flows if f.proto == "udp"]
            reflections = [f for f in udp
                           if f.src_port in self.AMPLIFIER_PORTS
                           and (f.bytes_out / max(f.pkts_out, 1)) >= self.AMPLIFY_SIZE]
            amplification = len(reflections) >= max(0.3 * len(udp), 20) if udp else False

            tcp = [f for f in flows if f.proto == "tcp"]
            has_handshake = len(tcp) >= 0.5 * len(flows)
            syns = sum(f.syn for f in tcp) or 1
            completion = (sum(f.synack for f in tcp) / syns) if has_handshake else None
            # CUSUM-style: how far above its own baseline has this destination gone?
            surge = n / max(base, 1.0)

            score = 0.0
            if ent >= self.ENTROPY_FLOOR:
                score += min((ent - self.ENTROPY_FLOOR) / 4.0, 1.0) * 0.45
            if completion is not None and completion <= self.COMPLETION_CEIL:
                score += (1.0 - completion / max(self.COMPLETION_CEIL, 1e-9)) * 0.35
            elif completion is None:
                # No handshake signal available: lean harder on the rate surge,
                # and require a bigger one before calling it a flood.
                score += min(max(surge - 5.0, 0.0) / 10.0, 1.0) * 0.35
            if surge > 3.0:
                score += min((surge - 3.0) / 10.0, 1.0) * 0.20
            if amplification:
                score += 0.25          # a clear reflector signature
            score = min(score, 1.0)

            if score >= self.threshold:
                out.append(Detection(
                    threat_class=self.threat_class,
                    src_ip=f"{uniq} sources",
                    dst_ip=dst,
                    score=score,
                    ts_event=min(f.ts for f in flows),
                    observed_flows=n,
                    flow_ids=[f.flow_id for f in flows[:8]],
                    evidence={
                        "source_ip_entropy_bits": round(ent, 2),
                        "distinct_sources": uniq,
                        "flows_in_window": n,
                        "handshake_completion_ratio":
                            round(completion, 3) if completion is not None else "n/a (udp)",
                        "surge_vs_baseline": round(surge, 1),
                        "attack_kind": ("udp_reflection_amplification" if amplification
                                        else "spoofed_flood" if ent >= self.ENTROPY_FLOOR
                                        else "protocol_flood"),
                        "reflector_replies": len(reflections),
                    },
                ))
        return out

    def reset_window(self) -> None:
        self.by_dst.clear()
