"""(g) OT / ICS intrusion — the plant-floor threat NTRO and NCIIPC guard.

Signal: a control network is the most predictable traffic in existence. A given
HMI polls a given PLC with one or two Modbus function codes, forever. Three
things break that pattern and each is an attack:

  * an **unauthorised WRITE** — a state-changing command (open a breaker, change
    a setpoint) from a host that is not the established poller of that controller;
  * **function-code / unit-id enumeration** — a source sweeping many function
    codes or unit ids to map the controller before acting;
  * an **illegal function code** — a code outside the protocol's valid set,
    the fingerprint of a fuzzing or exploitation attempt.

The detector reads only the protocol header (see prahari.icsparse) — function
code, unit id, whether the command writes — never the payload. It learns which
hosts legitimately poll each controller from the traffic itself, so "unauthorised"
means "not the host that normally reads this PLC", with no configuration.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from ..schema import Flow
from .base import Detection, Detector


class ICSDetector(Detector):
    name = "ics-guard"
    model_version = "0.2.0"
    threat_class = "ics_intrusion"
    threshold = 0.55

    FUNC_SCAN = 5              # distinct function codes from one source = enumeration
    POLLER_READS = 3          # reads before a host is trusted as a controller's poller

    def __init__(self) -> None:
        self.by_src: dict[str, list[Flow]] = defaultdict(list)
        # persistent across windows: who legitimately polls each controller
        self.reads_to: dict[str, Counter] = defaultdict(Counter)   # dst -> Counter(src)

    def observe(self, flow: Flow) -> None:
        if flow.ics_proto:
            self.by_src[flow.src_ip].append(flow)

    def _established_pollers(self, controller: str) -> set[str]:
        # only hosts that polled this controller in PRIOR windows count as
        # legitimate — a host's own recon reads this window do not legitimise
        # the writes it issues in the same window.
        return {s for s, n in self.reads_to[controller].items() if n >= self.POLLER_READS}

    def evaluate(self, window_end: float) -> list[Detection]:
        out: list[Detection] = []
        for src, flows in self.by_src.items():
            funcs = {f.ics_func for f in flows if f.ics_func is not None}
            controllers = {f.dst_ip for f in flows}
            writes = [f for f in flows if f.ics_write]
            illegal = [f for f in flows if f.ics_illegal]
            proto = flows[-1].ics_proto

            # an unauthorised writer is one issuing commands to a controller it
            # is not an established poller of
            unauth = [f for f in writes if src not in self._established_pollers(f.dst_ip)]

            score = 0.0
            reasons = []
            if len(funcs) >= self.FUNC_SCAN:
                score += min(len(funcs) / 7.0, 1.0) * 0.62
                reasons.append("function_code_enumeration")
            if unauth:
                score += 0.55
                reasons.append("unauthorised_write")
            if illegal:
                score += 0.40
                reasons.append("illegal_function_code")
            if len(controllers) >= 3 and writes:
                score += 0.15
                reasons.append("multi_controller_commands")
            score = min(score, 1.0)

            if score >= self.threshold and reasons:
                top = max(controllers, key=lambda c: sum(1 for f in flows if f.dst_ip == c))
                out.append(Detection(
                    threat_class=self.threat_class,
                    src_ip=src,
                    dst_ip=top,
                    score=score,
                    ts_event=min(f.ts for f in flows),
                    observed_flows=len(flows),
                    flow_ids=[f.flow_id for f in flows[:8]],
                    evidence={
                        "ot_protocol": proto,
                        "attack_kind": reasons[0],
                        "reasons": reasons,
                        "distinct_function_codes": len(funcs),
                        "function_codes": sorted(f for f in funcs)[:12],
                        "write_commands": len(writes),
                        "unauthorised_writes": len(unauth),
                        "illegal_codes": len(illegal),
                        "controllers_touched": len(controllers),
                        "established_poller": src in self._established_pollers(top),
                    },
                    caveat="OT command traffic — header only, no payload or setpoint read",
                ))
        return out

    def reset_window(self) -> None:
        # commit this window's benign reads to the persistent poller memory,
        # so a host is only "established" from windows that already closed.
        for flows in self.by_src.values():
            for f in flows:
                if not f.ics_write and not f.ics_illegal and f.ics_func is not None:
                    self.reads_to[f.dst_ip][f.src_ip] += 1
        self.by_src.clear()
