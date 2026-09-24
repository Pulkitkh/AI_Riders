"""One request router, two deployments.

The local development server and the Vercel serverless function both call
`dispatch()`. Neither owns any routing logic of its own, so the demo a judge
opens on the internet and the one running on your laptop cannot answer
differently.
"""
from __future__ import annotations

import json
import os
import traceback
from typing import Any
from urllib.parse import parse_qs

from . import service

MAX_UPLOAD = 4 * 1024 * 1024        # Vercel caps request bodies at ~4.5 MB

JSON = "application/json; charset=utf-8"

# Security posture (all opt-in; safe defaults):
#   PRAHARI_DEBUG       — include exception tracebacks in error responses (dev only)
#   PRAHARI_CORS_ORIGIN — explicit allowed origin; unset means SAME-ORIGIN only
#                         (no Access-Control-Allow-Origin header, not a wildcard)
DEBUG = os.environ.get("PRAHARI_DEBUG", "").lower() in ("1", "true", "yes", "on")
CORS_ORIGIN = os.environ.get("PRAHARI_CORS_ORIGIN", "").strip()


def _b(v: Any, default: bool = False) -> bool:
    if v is None:
        return default
    return str(v).lower() in ("1", "true", "yes", "on")


def _f(v: Any, default: float) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _i(v: Any, default: int | None) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _q(query: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(query or "").items() if v}


def dispatch(method: str, path: str, query: str = "",
             body: bytes = b"") -> tuple[int, dict[str, str], bytes]:
    """Return (status, headers, body). Never raises — a 500 is still a response."""
    path = "/" + path.strip("/")
    for prefix in ("/api/index", "/api"):
        if path.startswith(prefix):
            path = path[len(prefix):] or "/"
            break
    q = _q(query)

    try:
        payload, status = _route(method, path, q, body)
    except Exception as exc:                         # noqa: BLE001 - boundary
        # Never leak internal paths / tracebacks to clients in production.
        traceback.print_exc()                        # server-side log only
        payload = {"error": "internal error"}
        if DEBUG:
            payload = {"error": type(exc).__name__, "message": str(exc),
                       "trace": traceback.format_exc()[-1200:]}
        status = 500

    raw = json.dumps(payload, allow_nan=False).encode("utf-8")
    headers = {
        "Content-Type": JSON,
        "Content-Length": str(len(raw)),
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }
    # Same-origin by default: only emit CORS headers when an origin is explicitly
    # allowlisted. A security console should not be openly cross-origin callable.
    if CORS_ORIGIN:
        headers["Access-Control-Allow-Origin"] = CORS_ORIGIN
        headers["Vary"] = "Origin"
        headers["Access-Control-Allow-Headers"] = "Content-Type, X-PRAHARI-Token"
        headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return status, headers, raw


def _route(method: str, path: str, q: dict[str, str],
           body: bytes) -> tuple[dict, int]:
    if method == "OPTIONS":
        return {}, 204

    if path in ("/", "/health"):
        return service.health(), 200

    if path == "/scenarios":
        return service.list_scenarios(), 200

    if path == "/analyze":
        if method == "POST" and body:
            try:
                q = {**q, **json.loads(body.decode("utf-8"))}
            except ValueError:
                return {"error": "body was not valid JSON"}, 400
        return service.analyze(
            scenario=str(q.get("scenario", "full")),
            jitter=_f(q.get("jitter"), 0.20),
            seed=_i(q.get("seed"), None),
            duration=_i(q.get("duration"), None),
            single_direction=_b(q.get("single_direction")),
        ), 200

    if path == "/pcap":
        if method != "POST":
            return {"error": "POST a capture file as the request body"}, 405
        if not body:
            return {"error": "empty body"}, 400
        if len(body) > MAX_UPLOAD:
            return {"error": "capture too large",
                    "limit_bytes": MAX_UPLOAD, "got_bytes": len(body),
                    "hint": "Serverless request bodies cap at ~4.5 MB. Split the "
                            "capture, or run the CLI locally for a large one."}, 413
        return service.analyze_pcap(
            body, single_direction=_b(q.get("single_direction"))), 200

    if path == "/selftest":
        return service.selftest(), 200

    if path == "/degraded":
        n = max(1, min(_i(q.get("seeds"), 3) or 3, 5))
        return service.degraded(
            scenario=str(q.get("scenario", "full")),
            seeds=tuple(2000 + i for i in range(1, n + 1)),
            duration=_i(q.get("duration"), 1800) or 1800,
        ), 200

    if path == "/verify":
        return service.verify_ledger(tamper=_b(q.get("tamper"))), 200

    if path == "/metrics":
        return service.metrics(), 200

    return {"error": "not found", "path": path,
            "routes": ["/health", "/scenarios", "/analyze", "/pcap", "/selftest",
                       "/degraded", "/verify", "/metrics"]}, 404
