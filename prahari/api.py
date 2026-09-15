"""Dashboard server.

Deliberately OUTSIDE the detection path. `prahari/selftest.py` asserts that no
module the engine or detectors import touches a network client; this file does
bind a socket, which is exactly why it is a separate process serving a read-only
view of the alert ledger rather than part of the pipeline.

    python -m prahari.api --port 8000
"""
from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .engine import Engine
from .generate import ALL_ATTACKS, TrafficGenerator
from .ledger import AlertLedger

ROOT = Path(__file__).resolve().parents[1]
DASH = ROOT / "dashboard" / "index.html"

STATE: dict = {"alerts": [], "stats": {}, "incidents": [], "running": False}
LOCK = threading.Lock()


def replay_worker(duration: int, jitter: float, seed: int, speed: float) -> None:
    """Replay a capture in wall-clock-scaled time so the dashboard animates."""
    with LOCK:
        STATE.update(alerts=[], stats={}, incidents=[], running=True)
    flows = TrafficGenerator(seed=seed, jitter=jitter).capture(duration, classes=ALL_ATTACKS)
    ledger = AlertLedger(ROOT / "data" / "alerts.jsonl")

    def on_alert(a):
        with LOCK:
            STATE["alerts"].insert(0, a.to_record())
            del STATE["alerts"][200:]

    engine = Engine(window=60.0, ledger=ledger, on_alert=on_alert)
    t_prev = flows[0].ts
    for f in flows:
        if speed > 0:
            gap = (f.ts - t_prev) / speed
            if gap > 0.001:
                time.sleep(min(gap, 0.25))
        t_prev = f.ts
        engine.push(f)
        with LOCK:
            STATE["stats"] = {**engine.stats.summary(), "sim_time": round(f.ts, 1)}
    engine._close_window(engine._window_end or t_prev)
    with LOCK:
        STATE["incidents"] = [
            {"entity": i.entity, "severity": i.severity, "score": round(i.score, 2),
             "chain": i.classes, "alerts": len(i.alerts)}
            for i in engine.fusion.ranked_incidents() if len(i.classes) > 1
        ][:6]
        STATE["stats"] = engine.stats.summary()
        STATE["running"] = False


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):        # keep the demo console clean
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            self._send(200, DASH.read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/state":
            with LOCK:
                payload = json.dumps(STATE).encode()
            self._send(200, payload, "application/json")
        elif self.path.startswith("/api/replay"):
            if not STATE["running"]:
                threading.Thread(target=replay_worker, args=(1800, 0.20, 1337, 120.0),
                                 daemon=True).start()
            self._send(200, b'{"ok":true}', "application/json")
        elif self.path == "/api/verify":
            ok, n, bad = AlertLedger(ROOT / "data" / "alerts.jsonl").verify()
            self._send(200, json.dumps({"ok": ok, "records": n, "bad": bad}).encode(),
                       "application/json")
        else:
            self._send(404, b"not found", "text/plain")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-autostart", action="store_true")
    args = ap.parse_args()
    if not args.no_autostart:
        threading.Thread(target=replay_worker, args=(1800, 0.20, 1337, 120.0),
                         daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"PRAHARI dashboard on http://localhost:{args.port}")
    print("replaying a capture; alerts will appear as the engine raises them")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
