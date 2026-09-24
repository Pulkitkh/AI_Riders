"""Local / on-server application — the same router the hosted viewer uses, plus
the live sensor the hosted viewer cannot run.

    python3 -m web.server --port 8000            # replay + static viewer
    sudo python3 -m web.server --live --iface lo # add the real-time sensor
    python3 -m web.server --pcap demo.pcap       # replay a capture in the dashboard

The stateless endpoints (scenarios, replay, selftest, ledger, metrics) are
served by `web.router`, exactly as they are on Vercel, so that deployment and
this one cannot diverge. The live endpoints — capture control and the
Server-Sent-Events stream — exist ONLY here, because they need a privileged raw
socket and a process that stays alive, which serverless does not provide. That
split is honest: the shareable link is read-only; the live console runs on a
real host.

This module binds sockets, which is why it lives outside `prahari/` and is
excluded by name from the read-only self-test.
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from web.router import CORS_ORIGIN, MAX_UPLOAD, dispatch      # noqa: E402

PUBLIC = Path(__file__).resolve().parent / "public"

# Demo controls (live capture start/stop and — most sensitively — attack traffic
# injection) are DISABLED unless explicitly enabled, and even then are limited to
# localhost callers or callers presenting a shared token. A production sensor
# ships with neither set, so the injector is simply unreachable.
DEMO_MODE = os.environ.get("PRAHARI_DEMO", "").lower() in ("1", "true", "yes", "on")
API_TOKEN = os.environ.get("PRAHARI_API_TOKEN", "").strip()

mimetypes.add_type("application/json", ".json")
mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("image/svg+xml", ".svg")

# The live sensor is created on demand so a plain `python -m web.server` with no
# privilege still serves the replay viewer without touching a raw socket.
SENSOR = None
SENSOR_IFACE = "lo"


def _get_sensor(autostart: bool = False):
    global SENSOR
    if SENSOR is None:
        from sensor.live import LiveSensor
        ledger_path = os.environ.get("PRAHARI_LEDGER", "data/live_alerts.jsonl")
        SENSOR = LiveSensor(iface=SENSOR_IFACE, ledger_path=ledger_path or None)
        if autostart:
            SENSOR.start()
    return SENSOR


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "PRAHARI"

    def log_message(self, fmt, *args):
        if getattr(self.server, "verbose", False):
            sys.stderr.write(f"  {self.command} {self.path}\n")

    # -- helpers -----------------------------------------------------------
    def _send(self, status: int, headers: dict, body: bytes) -> None:
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, status: int = 200) -> None:
        raw = json.dumps(obj, allow_nan=False).encode("utf-8")
        headers = {"Content-Type": "application/json; charset=utf-8",
                   "Content-Length": str(len(raw)), "Cache-Control": "no-store",
                   "X-Content-Type-Options": "nosniff"}
        if CORS_ORIGIN:
            headers["Access-Control-Allow-Origin"] = CORS_ORIGIN
            headers["Vary"] = "Origin"
        self._send(status, headers, raw)

    # -- authorization for control-plane endpoints -------------------------
    def _client_is_local(self) -> bool:
        ip = self.client_address[0] if self.client_address else ""
        return ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost")

    def _control_allowed(self, injection: bool = False) -> tuple[bool, str]:
        """Start/stop/attack are control-plane actions. Require localhost OR a
        valid token; attack injection additionally requires demo mode. A
        production sensor (no PRAHARI_DEMO, no token) exposes none of them."""
        if injection and not DEMO_MODE:
            return False, "attack injection is disabled (set PRAHARI_DEMO=1 for a demo build)"
        if API_TOKEN:
            tok = self.headers.get("X-PRAHARI-Token", "")
            if tok != API_TOKEN:
                return False, "missing or invalid X-PRAHARI-Token"
            return True, ""
        if self._client_is_local():
            return True, ""
        return False, "control endpoints are restricted to localhost; set PRAHARI_API_TOKEN to allow remote control"

    # -- live endpoints (server only) --------------------------------------
    def _live(self, path: str, query: dict, body: bytes) -> bool:
        from sensor import attack

        if path == "/api/live/status":
            s = _get_sensor()
            ok, why = s.available(SENSOR_IFACE if SENSOR_IFACE != "any" else None)
            atk_ok, atk_why = attack.available()
            self._json({"capture_available": ok, "capture_reason": why,
                        "attack_available": atk_ok, "attack_reason": atk_why,
                        "interfaces": s.capture.interfaces(),
                        "status": s.status()})
            return True

        if path == "/api/live/start":
            ok, why = self._control_allowed()
            if not ok:
                self._json({"started": False, "reason": why}, 403)
                return True
            s = _get_sensor()
            started = s.start()
            self._json({"started": started, "status": s.status()},
                       200 if started else 503)
            return True

        if path == "/api/live/stop":
            ok, why = self._control_allowed()
            if not ok:
                self._json({"stopped": False, "reason": why}, 403)
                return True
            s = _get_sensor()
            s.stop()
            self._json({"stopped": True, "status": s.status()})
            return True

        if path == "/api/live/snapshot":
            self._json(_get_sensor().snapshot())
            return True

        if path == "/api/live/attack":
            allowed, why = self._control_allowed(injection=True)
            if not allowed:
                self._json({"launched": False, "reason": why}, 403)
                return True
            name = query.get("name", "")
            ok, why = attack.available()
            if not ok:
                self._json({"launched": False, "reason": why}, 503)
                return True
            if name not in attack.ATTACKS + ("benign",):
                self._json({"launched": False, "reason": f"unknown attack {name!r}",
                            "available": list(attack.ATTACKS)}, 400)
                return True
            attack.launch_async(name)
            self._json({"launched": True, "attack": name})
            return True

        if path == "/api/live/stream":
            self._stream()
            return True

        return False

    def _stream(self) -> None:
        """Server-Sent Events: hold the connection open and relay the bus."""
        from sensor.live import sse_format
        sensor = _get_sensor(autostart=True)
        q = sensor.bus.subscribe()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        if CORS_ORIGIN:
            self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
            self.send_header("Vary", "Origin")
        self.end_headers()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            last = time.time()
            while True:
                try:
                    evt = q.get(timeout=1.0)
                    self.wfile.write(sse_format(evt))
                    self.wfile.flush()
                except Exception:
                    # comment ping keeps proxies from closing an idle stream
                    if time.time() - last > 15:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                        last = time.time()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            sensor.bus.unsubscribe(q)

    # -- stateless API (shared with Vercel) --------------------------------
    def _api(self, body: bytes = b"") -> None:
        path, _, query = self.path.partition("?")
        self._send(*dispatch(self.command, path, query, body))

    # -- static ------------------------------------------------------------
    def _static(self) -> None:
        path, _, _ = self.path.partition("?")
        rel = path.strip("/") or "index.html"
        target = (PUBLIC / rel).resolve()
        if not str(target).startswith(str(PUBLIC.resolve())) or not target.is_file():
            target = PUBLIC / "index.html"
            if not target.is_file():
                self._send(404, {"Content-Type": "text/plain", "Content-Length": "9"},
                           b"not found")
                return
        raw = target.read_bytes()
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith(("text/", "application/json", "text/javascript")):
            ctype += "; charset=utf-8"
        self._send(200, {"Content-Type": ctype, "Content-Length": str(len(raw)),
                         "Cache-Control": "no-store"}, raw)

    def _query(self) -> dict:
        from urllib.parse import parse_qs
        _, _, q = self.path.partition("?")
        return {k: v[0] for k, v in parse_qs(q).items() if v}

    # -- verbs -------------------------------------------------------------
    def do_GET(self):
        path = self.path.partition("?")[0]
        if path.startswith("/api/live/"):
            self._live(path, self._query(), b"")
        elif path.startswith("/api"):
            self._api()
        else:
            self._static()

    do_HEAD = do_GET

    def do_OPTIONS(self):
        self._api()

    def do_POST(self):
        path = self.path.partition("?")[0]
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(n, MAX_UPLOAD + 1)) if n else b""
        if path.startswith("/api/live/"):
            self._live(path, self._query(), body)
        else:
            self._api(body)


def main(argv=None) -> int:
    global SENSOR_IFACE
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--iface", default="lo", help="interface to tap in live mode")
    ap.add_argument("--live", action="store_true", help="start the sensor at boot")
    ap.add_argument("--pcap", help="replay this capture into the live dashboard at boot")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    SENSOR_IFACE = a.iface

    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    srv.verbose = a.verbose                        # type: ignore[attr-defined]
    srv.daemon_threads = True

    print(f"PRAHARI   http://{a.host}:{a.port}")
    if a.pcap:
        s = _get_sensor()
        if s.replay_pcap(a.pcap):
            print(f"replaying {a.pcap} into the live dashboard")
        else:
            print(f"could not replay {a.pcap} (empty or unreadable)")
    elif a.live:
        s = _get_sensor(autostart=True)
        ok, why = s.available(a.iface if a.iface != "any" else None)
        print(f"live sensor on {a.iface}: {'RUNNING' if s.running() else 'unavailable — ' + why}")
    else:
        print("replay + static viewer; POST /api/live/start to tap a NIC (needs root)")
    print("the detection engine runs in-process; no third-party package is loaded")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
        if SENSOR:
            SENSOR.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
