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

Two situations remove the server side of the handshake entirely:

  * **TLS 1.3** encrypts the Certificate message (RFC 8446 moves it inside the
    encrypted handshake), so self-signed status and validity window are simply
    not observable. They were readable through TLS 1.2 and are not here.
  * **Single-direction visibility** — if the tap carries only one direction of
    each flow, every server-side message is gone for the same reason.

Both land in the same place: no certificate facts, no JA4S. So rather than
scoring low and silently missing, the detector switches to a documented
fallback that renormalises over what remains observable from the client side —
JA3 rarity, *destination* rarity, externality and conversation shape — and
marks every alert it raises that way. A detector that cannot observe a feature
should say so, not quietly treat "not observed" as "observed to be benign".

Honest limit: mature implants mimic browser fingerprints, and Encrypted Client
Hello removes SNI visibility entirely as it rolls out. That is why rarity and
sequence shape carry more weight over time than the fingerprint lookup does.
"""
from __future__ import annotations

from collections import defaultdict

from ..features import is_rfc1918, mean, stdev
from ..schema import Flow
from .base import Detection, Detector


class EncryptedMalwareDetector(Detector):
    name = "tls-metadata"
    model_version = "0.4.0"
    threat_class = "encrypted_malware"
    threshold = 0.55

    # Ceiling for the degraded path: weaker evidence must not reach the same
    # confidence as the full-visibility path, or the score stops meaning anything.
    DEGRADED_CEILING = 0.85

    # "Rarity" (a fingerprint/destination seen by only one host) is only a signal
    # when there are ENOUGH hosts for one-of-many to be unusual. On a single-user
    # tap (one laptop) every fingerprint and every external site is seen by
    # exactly one host, so rarity carries no information and must not fire — that
    # is what made normal browsing raise alerts. Below this many distinct internal
    # hosts, rarity is switched off and the detector relies only on host-
    # independent evidence (self-signed / short-lived certs, strongly upload-
    # shaped conversations).
    MIN_HOSTS_FOR_RARITY = 4

    def __init__(self) -> None:
        self.ja4_hosts: dict[str, set[str]] = defaultdict(set)   # environment-wide rarity
        self.dst_hosts: dict[str, set[str]] = defaultdict(set)   # who talks to this dst
        self.src_hosts: set[str] = set()                         # internal hosts (rarity population)
        self.by_pair: dict[tuple[str, str], list[Flow]] = defaultdict(list)

    def observe(self, flow: Flow) -> None:
        if not flow.tls_ja4:
            return
        self.ja4_hosts[flow.tls_ja4].add(flow.src_ip)
        self.dst_hosts[flow.dst_ip].add(flow.src_ip)
        if is_rfc1918(flow.src_ip):
            self.src_hosts.add(flow.src_ip)
        self.by_pair[(flow.src_ip, flow.dst_ip)].append(flow)

    @property
    def rarity_meaningful(self) -> bool:
        return len(self.src_hosts) >= self.MIN_HOSTS_FOR_RARITY

    def _degraded_score(self, dst: str, ja4: str, prevalence: int,
                        no_sni: bool, shape: dict[str, float]) -> tuple[float, dict]:
        """Score without any server-side evidence.

        Weights are redistributed onto client-observable signals rather than
        left on the floor. Destination rarity does most of the work the
        certificate used to: a host reached by exactly one machine in the
        environment is interesting regardless of what its certificate said.
        """
        dst_prevalence = len(self.dst_hosts.get(dst, ()))
        score = 0.0
        rarity = self.rarity_meaningful
        if rarity:
            # host-relative rarity — only when there are enough hosts to compare
            if prevalence <= 1:
                score += 0.30
            elif prevalence <= 3:
                score += 0.15
            if dst_prevalence <= 1:
                score += 0.25
            elif dst_prevalence <= 3:
                score += 0.12
            if not is_rfc1918(dst):
                score += 0.10
            if no_sni:
                score += 0.10
        # Host-INDEPENDENT signal, valid even on a single-user tap: a strongly
        # upload-shaped encrypted session is not a page load. Normal browsing is
        # download-shaped (out_share well below 0.5), so it scores ~0 here.
        if shape["out_share"] > 0.6:
            score += 0.30 if not rarity else 0.15
        if shape["out_share"] > 0.85:
            score += 0.15
        return min(score, self.DEGRADED_CEILING), {
            "dst_host_prevalence": dst_prevalence,
            "rarity_applied": rarity,
            "internal_hosts_seen": len(self.src_hosts)}

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

            # Was the server side observable at all? TLS 1.3 and a one-way tap
            # both answer no, and both must take the fallback rather than score
            # a missing feature as a benign one.
            cert_seen = any(f.tls_cert_days is not None for f in flows)
            extra: dict = {}
            if cert_seen:
                score = 0.0
                if self.rarity_meaningful and prevalence <= 1:
                    score += 0.35                   # fingerprint on one host only — only if rarity means something
                if self_signed:
                    score += 0.25                   # host-independent, strong
                if short_cert:
                    score += 0.20                   # host-independent, strong
                if no_sni:
                    score += 0.10
                if shape["out_share"] > 0.6:        # upload-shaped, not page-load-shaped
                    score += 0.10
                score = min(score, 1.0)
            else:
                score, extra = self._degraded_score(dst, ja4, prevalence, no_sni, shape)

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
                        "server_side_observed": cert_seen,
                        **({"self_signed_cert": self_signed,
                            "min_cert_validity_days":
                                min((f.tls_cert_days or 999) for f in flows)}
                           if cert_seen else extra),
                        "sni_present": not no_sni,
                        "outbound_packet_share": round(shape["out_share"], 3),
                        "mean_packet_size": round(shape["size_mean"], 1),
                    },
                    caveat=("metadata only — no payload was decrypted" if cert_seen else
                            "degraded: server-side handshake not observed "
                            "(TLS 1.3 or single-direction tap); scored on "
                            "client-side evidence only"),
                ))
        return out

    def reset_window(self) -> None:
        self.by_pair.clear()
