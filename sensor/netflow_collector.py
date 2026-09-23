"""Receive a live NetFlow v5 feed and drive the engine with it.

This is the second live ingest path, beside packet capture: a router or a
software exporter (nfcapd, softflowd, `nfreplay`) sends NetFlow v5 datagrams
over UDP, and this collector decodes each one into `Flow` records and pushes
them through the same real-time engine. It demonstrates the problem statement's
"exported flow records" source directly.

Binding a UDP socket to receive the feed is why this lives in `sensor/`, outside
the read-only detection path. The socket only receives; the enclave still sends
nothing back — a NetFlow feed is inherently one-directional, which is the whole
point of the exercise.
"""
from __future__ import annotations

import socket
import threading
import time
from typing import Callable

from prahari.netflow import parse_v5
from prahari.schema import Flow

DEFAULT_PORT = 2055        # the conventional NetFlow collector port


def available(port: int = DEFAULT_PORT) -> tuple[bool, str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.close()
        return True, "UDP collector available"
    except OSError as exc:
        return False, str(exc)


class NetFlowCollector:
    """Listen for NetFlow v5 datagrams and hand assembled flows to a callback."""

    def __init__(self, host: str = "0.0.0.0", port: int = DEFAULT_PORT):
        self.host, self.port = host, port
        self._sock: socket.socket | None = None
        self._running = False
        self.datagrams = 0
        self.records = 0

    def open(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.settimeout(0.5)
        self._sock = s

    def close(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def run(self, on_flows: Callable[[list[Flow]], None],
            should_stop: Callable[[], bool] | None = None) -> None:
        if self._sock is None:
            self.open()
        assert self._sock is not None
        self._running = True
        while self._running and not (should_stop and should_stop()):
            try:
                data, _ = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            flows = parse_v5(data)
            if flows:
                self.datagrams += 1
                self.records += len(flows)
                on_flows(flows)


def send_demo_feed(host: str = "127.0.0.1", port: int = DEFAULT_PORT) -> int:
    """Emit a short NetFlow v5 feed containing a port scan, for a self-contained
    demo of the NetFlow ingest path. Returns records sent."""
    from prahari.netflow import build_v5
    recs = [{"src_ip": "203.0.113.9", "dst_ip": "10.0.0.20", "src_port": 40000 + i,
             "dst_port": p, "proto": "tcp", "bytes": 60, "pkts": 1, "flags": 0x02}
            for i, p in enumerate(range(1, 401))]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    for i in range(0, len(recs), 30):           # ~30 records per datagram, like a real exporter
        s.sendto(build_v5(recs[i:i + 30], secs=int(time.time())), (host, port))
        sent += len(recs[i:i + 30])
    s.close()
    return sent
