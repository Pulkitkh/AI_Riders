"""(d) Malware inside encrypted sessions.

Signal: TLS/QUIC metadata alone — fingerprints, packet-size and timing
sequences — with no decryption. Constraint (b) forbids decryption and we never
provision key material, so every feature here is something visible in passing.

What survives encryption:
  * the handshake itself is not encrypted, so cipher and extension lists are
    observable, and the JA4 fingerprint derived from them identifies the client
    software stack. Malware built on a non-browser TLS library simply does not
    look like Chrome.
  * certificate metadata: self-signed status, validity window, whether the
    subject matches the SNI.
  * the *shape* of the conversation. A file upload, an interactive shell and a
    page load have different packet-size and direction signatures even when
    every byte is opaque.

Honest limit: mature implants mimic browser fingerprints, and Encrypted Client
Hello removes SNI visibility entirely as it rolls out. That is why rarity and
sequence shape carry more weight over time than the fingerprint lookup does.
"""
from __future__ import annotations

from collections import defaultdict

from ..features import mean, stdev
from ..schema import Flow
from .base import Detection, Detector


class EncryptedMalwareDetector(Detector):
    name = "tls-metadata"
    model_version = "0.4.0"
    threat_class = "encrypted_malware"
    threshold = 0.55

    def __init__(self) -> None:
        self.ja4_hosts: dict[str, set[str]] = defaultdict(set)   # environment-wide rarity
        self.by_pair: dict[tuple[str, str], list[Flow]] = defaultdict(list)

    def observe(self, flow: Flow) -> None:
        if not flow.tls_ja4:
            return
        self.ja4_hosts[flow.tls_ja4].add(flow.src_ip)
        self.by_pair[(flow.src_ip, flow.dst_ip)].append(flow)

    @staticmethod
    def shape_features(flows: list[Flow]) -> dict[str, float]:
        """Direction and size statistics over the packet-size sequence."""
        seq = [s for f in flows for s in f.pkt_sizes]
        if not seq:
            return {"out_share": 0.0, "size_mean": 0.0, "size_sd": 0.0}
        out = [s for s in seq if s > 0]
        return {
            "out_share": len(out) / len(seq),
            "size_mean": mean([abs(s) for s in seq]),
            "size_sd": stdev([abs(s) for s in seq]),
        }

    def evaluate(self, window_end: float) -> list[Detection]:
        out: list[Detection] = []
        for (src, dst), flows in self.by_pair.items():
            ja4 = flows[-1].tls_ja4
            prevalence = len(self.ja4_hosts.get(ja4, ()))
            self_signed = any(f.tls_self_signed for f in flows)
            short_cert = any((f.tls_cert_days or 999) <= 30 for f in flows)
            no_sni = all(not f.tls_sni for f in flows)
            shape = self.shape_features(flows)

            score = 0.0
            if prevalence <= 1:
                score += 0.35                       # fingerprint seen on one host only
            if self_signed:
                score += 0.25
            if short_cert:
                score += 0.20
            if no_sni:
                score += 0.10
            if shape["out_share"] > 0.6:            # upload-shaped, not page-load-shaped
                score += 0.10
            score = min(score, 1.0)

            if score >= self.threshold:
                out.append(Detection(
                    threat_class=self.threat_class,
                    src_ip=src, dst_ip=dst, score=score,
                    ts_event=min(f.ts for f in flows),
                    observed_flows=len(flows),
                    flow_ids=[f.flow_id for f in flows[:8]],
                    evidence={
                        "ja4": ja4,
                        "ja4_host_prevalence": prevalence,
                        "self_signed_cert": self_signed,
                        "min_cert_validity_days": min((f.tls_cert_days or 999) for f in flows),
                        "sni_present": not no_sni,
                        "outbound_packet_share": round(shape["out_share"], 3),
                        "mean_packet_size": round(shape["size_mean"], 1),
                    },
                    caveat="metadata only — no payload was decrypted",
                ))
        return out

    def reset_window(self) -> None:
        self.by_pair.clear()
