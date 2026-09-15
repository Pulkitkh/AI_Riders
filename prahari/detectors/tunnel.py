"""(c) DNS tunnelling.

Signal: query-length and record-type anomalies. A tunnel encodes an outbound
channel into subdomain labels under one parent it controls, so the giveaway is a
large number of unique, unusually long subdomains under a single registrable
domain, with a record-type mix skewed to TXT/NULL rather than A/AAAA.
"""
from __future__ import annotations

from collections import defaultdict

from ..features import domain_labels, mean, registrable_part
from ..schema import Flow
from .base import Detection, Detector


class TunnelDetector(Detector):
    name = "dns-tunnel-stats"
    model_version = "0.4.0"
    threat_class = "dns_tunnelling"
    threshold = 0.6

    MIN_QUERIES = 15
    LONG_NAME = 50              # characters in the query name

    def __init__(self) -> None:
        self.by_parent: dict[tuple[str, str], list[Flow]] = defaultdict(list)

    def observe(self, flow: Flow) -> None:
        if flow.dns_qname:
            self.by_parent[(flow.src_ip, registrable_part(flow.dns_qname))].append(flow)

    def evaluate(self, window_end: float) -> list[Detection]:
        out: list[Detection] = []
        for (src, parent), flows in self.by_parent.items():
            if len(flows) < self.MIN_QUERIES:
                continue
            lens = [len(f.dns_qname) for f in flows]
            subs = {f.dns_qname for f in flows}
            odd_types = sum(1 for f in flows if f.dns_qtype in ("TXT", "NULL", "CNAME"))
            long_rate = sum(1 for l in lens if l >= self.LONG_NAME) / len(lens)
            uniq_rate = len(subs) / len(flows)
            type_rate = odd_types / len(flows)
            up = sum(f.bytes_out for f in flows)
            down = sum(f.bytes_in for f in flows)

            score = 0.40 * long_rate + 0.25 * type_rate + 0.20 * uniq_rate
            if len(flows) > 60:
                score += 0.15
            if score >= self.threshold:
                out.append(Detection(
                    threat_class=self.threat_class,
                    src_ip=src, dst_ip=parent, score=min(score, 1.0),
                    ts_event=min(f.ts for f in flows),
                    observed_flows=len(flows),
                    flow_ids=[f.flow_id for f in flows[:8]],
                    evidence={
                        "parent_domain": parent,
                        "queries": len(flows),
                        "unique_subdomains": len(subs),
                        "mean_qname_length": round(mean(lens), 1),
                        "long_name_rate": round(long_rate, 3),
                        "txt_null_cname_rate": round(type_rate, 3),
                        "bytes_up": up, "bytes_down": down,
                    },
                ))
        return out

    def reset_window(self) -> None:
        self.by_parent.clear()
