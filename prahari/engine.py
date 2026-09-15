"""The streaming engine.

Constraint (c) of SIH26145 asks for incremental processing with bounded latency,
not an end-of-run report. The engine advances a window clock as flows arrive,
evaluates every detector at each window boundary, and emits alerts immediately.

Constraint (a) — read-only — is enforced structurally, not by convention: this
process opens no sockets toward the traffic source, performs no live enrichment
lookups, and has no code path that transmits. `prahari/selftest.py` asserts it.

Latency is measured, never asserted: every alert records the time between the
triggering traffic being observed and the alert being raised.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .detectors import all_detectors
from .detectors.base import Detector
from .fusion import Fusion
from .ledger import AlertLedger
from .schema import Alert, Flow

DEFAULT_WINDOW = 60.0       # seconds; also the worst-case latency floor


@dataclass
class EngineStats:
    flows: int = 0
    windows: int = 0
    alerts: int = 0
    wall_start: float = 0.0
    wall_end: float = 0.0
    latencies_ms: list[float] = field(default_factory=list)

    @property
    def wall_seconds(self) -> float:
        return max(self.wall_end - self.wall_start, 1e-9)

    @property
    def flows_per_sec(self) -> float:
        return self.flows / self.wall_seconds

    def percentile(self, p: float) -> float:
        if not self.latencies_ms:
            return 0.0
        xs = sorted(self.latencies_ms)
        k = min(int(round(p / 100.0 * (len(xs) - 1))), len(xs) - 1)
        return xs[k]

    def summary(self) -> dict:
        return {
            "flows_processed": self.flows,
            "windows": self.windows,
            "alerts": self.alerts,
            "wall_seconds": round(self.wall_seconds, 3),
            "flows_per_sec": round(self.flows_per_sec, 1),
            "latency_p50_ms": round(self.percentile(50), 1),
            "latency_p95_ms": round(self.percentile(95), 1),
            "latency_p99_ms": round(self.percentile(99), 1),
        }


class Engine:
    MAX_CATCHUP = 10        # empty windows to walk before realigning the clock

    def __init__(self, window: float = DEFAULT_WINDOW,
                 ledger: AlertLedger | None = None,
                 detectors: list[Detector] | None = None,
                 on_alert=None):
        self.window = window
        self.detectors = detectors if detectors is not None else all_detectors()
        self.fusion = Fusion()
        self.ledger = ledger
        self.on_alert = on_alert
        self.stats = EngineStats()
        self._window_end: float | None = None

    # -- streaming ------------------------------------------------------------
    def _close_window(self, window_end: float) -> list[Alert]:
        alerts: list[Alert] = []
        for det in self.detectors:
            detections = det.evaluate(window_end)
            if detections:
                alerts += self.fusion.push(detections, det.name, det.model_version,
                                           now=window_end)
            det.reset_window()
        self.stats.windows += 1
        for a in alerts:
            self.stats.alerts += 1
            self.stats.latencies_ms.append(a.latency_ms)
            if self.ledger:
                self.ledger.append(a.to_record())
            if self.on_alert:
                self.on_alert(a)
        return alerts

    def push(self, flow: Flow) -> list[Alert]:
        """Feed one flow. Returns any alerts this flow's arrival caused."""
        emitted: list[Alert] = []
        if self._window_end is None:
            self._window_end = flow.ts + self.window
            self.stats.wall_start = time.perf_counter()
        # Close windows up to this flow's arrival. If the stream jumps forward
        # by a long idle gap (or we are replaying several captures back to back)
        # there is no value in grinding through thousands of empty windows —
        # close one, then realign. Without this the engine spends its time
        # evaluating nothing and both throughput and p95 latency look terrible.
        if flow.ts - self._window_end > self.MAX_CATCHUP * self.window:
            emitted += self._close_window(self._window_end)
            self._window_end = flow.ts + self.window
        else:
            while flow.ts >= self._window_end:
                emitted += self._close_window(self._window_end)
                self._window_end += self.window
        for det in self.detectors:
            det.observe(flow)
        self.stats.flows += 1
        self.stats.wall_end = time.perf_counter()
        return emitted

    def run(self, flows, progress=None) -> list[Alert]:
        """Replay a whole capture. Flows must be time-ordered."""
        out: list[Alert] = []
        for i, f in enumerate(flows):
            out += self.push(f)
            if progress and i % 2000 == 0:
                progress(i)
        if self._window_end is not None:
            out += self._close_window(self._window_end)
        self.stats.wall_end = time.perf_counter()
        return out
