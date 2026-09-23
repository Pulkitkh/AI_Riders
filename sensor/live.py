"""The live detection loop and the real-time event bus.

A background thread taps the interface, assembles flows, and pushes them through
the real engine. Every alert, incident and stats tick is published to an
in-process bus; the HTTP layer relays that bus to browsers over Server-Sent
Events. No websocket library, no message broker — the standard library streams
events to any number of watchers.

The engine here is the same `prahari.engine.Engine` used everywhere else. This
module supplies it flows and drains its alerts; it makes no detection decision
of its own.
"""
from __future__ import annotations

import json
import queue
import threading
import time
from collections import deque
from typing import Any

from prahari.engine import Engine
from prahari.schema import Flow

from .capture import LiveCapture


class EventBus:
    """Fan-out of JSON events to every subscribed SSE client.

    Each subscriber gets its own bounded queue; a slow browser drops its own
    oldest events and never stalls the capture thread. Thread-safe.
    """

    def __init__(self, backlog: int = 200):
        self._subs: set[queue.Queue] = set()
        self._lock = threading.Lock()
        self._recent: deque = deque(maxlen=backlog)
        self._seq = 0

    def publish(self, kind: str, data: Any) -> None:
        with self._lock:
            self._seq += 1
            evt = {"seq": self._seq, "kind": kind, "t": time.time(), "data": data}
            self._recent.append(evt)
            dead = []
            for q in self._subs:
                try:
                    q.put_nowait(evt)
                except queue.Full:
                    try:
                        q.get_nowait()
                        q.put_nowait(evt)
                    except queue.Empty:
                        pass
                except Exception:
                    dead.append(q)
            for q in dead:
                self._subs.discard(q)

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=500)
        with self._lock:
            for evt in self._recent:            # replay backlog so a new tab is not blank
                try:
                    q.put_nowait(evt)
                except queue.Full:
                    break
            self._subs.add(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            self._subs.discard(q)

    @property
    def clients(self) -> int:
        with self._lock:
            return len(self._subs)


class LiveSensor:
    """Owns the capture thread, the engine, and the running statistics."""

    def __init__(self, iface: str = "lo", window: float = 5.0, bus: EventBus | None = None):
        self.iface = iface
        self.window = window
        self.bus = bus or EventBus()
        self.engine = Engine(window=window, on_alert=self._on_alert)
        self.capture = LiveCapture(iface=iface)
        self._thread: threading.Thread | None = None
        self._running = False
        self._lock = threading.Lock()
        self.started_at = 0.0

        # running totals, published on every tick
        self.flows_total = 0
        self.packets_total = 0
        self.alerts_total = 0
        self.by_class: dict[str, int] = {}
        self.recent_alerts: deque = deque(maxlen=200)
        self.recent_incidents: dict[str, dict] = {}

    # -- lifecycle ---------------------------------------------------------
    @staticmethod
    def available(iface: str | None = None):
        return LiveCapture.available(iface)

    def start(self) -> bool:
        with self._lock:
            if self._running:
                return True
            ok, _ = LiveCapture.available(self.iface if self.iface != "any" else None)
            if not ok:
                return False
            self._running = True
            self.started_at = time.time()
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
            self._heart = threading.Thread(target=self._heartbeat, daemon=True)
            self._heart.start()
            self.bus.publish("status", self.status())
            return True

    def replay_pcap(self, path, speed: float = 60.0) -> bool:
        """Replay a capture file into the live dashboard.

        Reads a pcap into flows and pushes them through the same engine and bus
        the live tap uses, time-scaled so a 30-minute capture animates in about
        30 seconds. The dashboard cannot tell this from a live feed — it is the
        same pipeline — which is the point: replay and live differ only in where
        the flows come from.
        """
        from prahari.pcapread import flows_from_capture
        import threading, time as _t
        try:
            flows = flows_from_capture(path)
        except OSError:
            return False
        if not flows:
            return False

        def worker():
            with self._lock:
                self._running = True
                self.started_at = _t.time()
            self.bus.publish("status", self.status())
            t_prev = flows[0].ts
            for f in flows:
                if not self._running:
                    break
                gap = (f.ts - t_prev) / speed if speed > 0 else 0
                if gap > 0.002:
                    _t.sleep(min(gap, 0.2))
                t_prev = f.ts
                self.flows_total += 1
                self.engine.push(f)
                if self.flows_total % 40 == 0:
                    # Advance on the CAPTURE clock, not wall-clock: replayed
                    # flows carry the timestamps they had on the wire, so the
                    # engine must close windows in capture time or every window
                    # ends before its flows arrive and nothing ever alerts.
                    self.engine.advance(f.ts)
                    self._flush_tick()
            self.engine.advance(flows[-1].ts + self.window)
            self._flush_tick()
            with self._lock:
                self._running = False
            self.bus.publish("status", self.status())

        self._thread = threading.Thread(target=worker, daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        with self._lock:
            self._running = False
        self.capture.close()
        if self._thread:
            self._thread.join(timeout=2.0)
        self.bus.publish("status", self.status())

    def running(self) -> bool:
        return self._running

    def _heartbeat(self) -> None:
        """Close elapsed windows and publish a stats tick once a second.

        Detection must not depend on new packets arriving: a burst followed by
        silence still has to alert, and the console still has to show a live
        clock. This drives both, independent of the capture thread.
        """
        while self._running:
            time.sleep(1.0)
            try:
                self.engine.advance(time.time())
            except Exception:
                pass
            self._flush_tick()

    # -- the loop ----------------------------------------------------------
    def _loop(self) -> None:
        try:
            self.capture.open()
        except OSError as exc:
            self.bus.publish("error", {"message": f"cannot open {self.iface}: {exc}"})
            self._running = False
            return

        last_tick = time.time()
        while self._running:
            self.capture.run(self._ingest, should_stop=lambda: not self._running)
            break
        # capture.run only returns when stopped
        self._flush_tick()

    def _ingest(self, flows: list[Flow]) -> None:
        self.flows_total += len(flows)
        for f in flows:
            self.engine.push(f)
        # Close any window that has ended in wall-clock time, so a burst that is
        # followed by quiet still alerts instead of waiting for the next flow.
        self.engine.advance(time.time())
        # incidents refresh on each batch
        for inc in self.engine.fusion.ranked_incidents():
            if len(inc.classes) > 1:
                self.recent_incidents[inc.entity] = {
                    "entity": inc.entity, "severity": inc.severity,
                    "score": round(inc.score, 3), "classes": inc.classes,
                    "alerts": len(inc.alerts), "last_seen": inc.last_seen,
                }
        self._flush_tick()

    def _on_alert(self, alert) -> None:
        self.alerts_total += 1
        self.by_class[alert.threat_class] = self.by_class.get(alert.threat_class, 0) + 1
        view = self._alert_view(alert)
        self.recent_alerts.appendleft(view)
        self.bus.publish("alert", view)

    def _flush_tick(self) -> None:
        self.bus.publish("stats", self.status())
        if self.recent_incidents:
            self.bus.publish("incidents", list(self.recent_incidents.values())[:10])

    # -- views -------------------------------------------------------------
    def _alert_view(self, a) -> dict:
        return {
            "id": a.alert_id, "ts": a.ts_event, "threat_class": a.threat_class,
            "severity": a.severity, "confidence": round(a.confidence, 3),
            "src_ip": a.src_ip, "dst_ip": a.dst_ip, "detector": a.detector,
            "observed_flows": a.observed_flows,
            "evidence": {k: _json(v) for k, v in list(a.evidence.items())[:6]},
            "caveat": a.caveat,
        }

    def status(self) -> dict:
        st = self.engine.stats.summary() if self.alerts_total or self.flows_total else {}
        return {
            "running": self._running,
            "iface": self.iface,
            "uptime": round(time.time() - self.started_at, 1) if self.started_at else 0,
            "flows_total": self.flows_total,
            "alerts_total": self.alerts_total,
            "by_class": dict(self.by_class),
            "clients": self.bus.clients,
            "engine": st,
        }

    def snapshot(self) -> dict:
        return {
            "status": self.status(),
            "alerts": list(self.recent_alerts)[:100],
            "incidents": list(self.recent_incidents.values())[:10],
        }


def _json(v):
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    if isinstance(v, (list, tuple)):
        return [_json(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _json(x) for k, x in v.items()}
    return str(v)


def sse_format(evt: dict) -> bytes:
    """One event, in the text/event-stream wire format."""
    return (f"id: {evt['seq']}\nevent: {evt['kind']}\n"
            f"data: {json.dumps(evt['data'], allow_nan=False)}\n\n").encode("utf-8")
