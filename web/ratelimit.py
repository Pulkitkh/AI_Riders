"""Resource-abuse protection for the public analysis endpoints.

`/analyze`, `/pcap` and `/degraded` each spin up the full detection engine, which
is CPU- and memory-bound. On a public demo that is a denial-of-service lever: a
handful of parallel requests, or a tight loop from one client, can saturate the
box and take the console down for everyone. Two cheap, in-process controls close
that without any external dependency (the engine ships none):

  * a **global concurrency gate** — only so many heavy requests run at once; the
    rest get 503 + Retry-After instead of piling onto an already-busy CPU;
  * a **per-client token bucket** — a steady rate with a small burst, so one
    client cannot monopolise the service; over-rate requests get 429.

All limits are env-tunable with safe defaults. State is per process, which is
the right scope for the single-box demo and for each Vercel lambda instance;
a multi-replica production deployment would move the bucket to a shared store.
"""
from __future__ import annotations

import os
import threading
import time


def _int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, "")))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return max(0.01, float(os.environ.get(name, "")))
    except (TypeError, ValueError):
        return default


class _Bucket:
    __slots__ = ("tokens", "last")

    def __init__(self, tokens: float, last: float):
        self.tokens = tokens
        self.last = last


class RateLimiter:
    def __init__(self, rate: float, burst: int, max_concurrency: int):
        self.rate = rate                 # tokens refilled per second, per client
        self.burst = burst               # bucket capacity (max burst)
        self.max_concurrency = max_concurrency
        self._buckets: dict[str, _Bucket] = {}
        self._active = 0
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        # Bound memory: forget clients whose bucket has fully refilled (idle).
        if len(self._buckets) <= 1024:
            return
        stale = [c for c, b in self._buckets.items()
                 if now - b.last > self.burst / self.rate + 60]
        for c in stale:
            self._buckets.pop(c, None)

    def acquire(self, client: str) -> tuple[bool, int, int]:
        """Try to admit one expensive request.

        Returns (allowed, http_status, retry_after_seconds). On allowed=True the
        caller MUST call release() when the request finishes.
        """
        now = time.monotonic()
        with self._lock:
            if self._active >= self.max_concurrency:
                return False, 503, 1
            key = client or "_global"
            b = self._buckets.get(key)
            if b is None:
                b = self._buckets[key] = _Bucket(self.burst, now)
            else:
                b.tokens = min(self.burst, b.tokens + (now - b.last) * self.rate)
                b.last = now
            if b.tokens < 1.0:
                retry = max(1, int((1.0 - b.tokens) / self.rate) + 1)
                return False, 429, retry
            b.tokens -= 1.0
            self._active += 1
            self._prune(now)
            return True, 200, 0

    def release(self) -> None:
        with self._lock:
            if self._active > 0:
                self._active -= 1


# Defaults: 1 heavy req/sec steady, burst of 5, at most 4 running concurrently.
limiter = RateLimiter(
    rate=_float("PRAHARI_RL_RATE", 1.0),
    burst=_int("PRAHARI_RL_BURST", 5),
    max_concurrency=_int("PRAHARI_MAX_CONCURRENCY", 4),
)
