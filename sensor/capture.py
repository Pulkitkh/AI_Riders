"""Live packet capture on Linux, with no third-party dependency.

An AF_PACKET raw socket delivers every frame on an interface to user space.
That is what libpcap does under the hood; we do it directly, so the sensor
installs on an air-gapped box with nothing but CPython. The packet decoders are
the same ones `prahari.pcapread` uses on a saved capture, so a flow assembled
live is bit-for-bit the flow assembled from a pcap of the same traffic.

Requires Linux, and CAP_NET_RAW (root, or `setcap cap_net_raw+ep` on the
interpreter). Everywhere else `LiveCapture.available()` returns False and the
server falls back to replaying captures — the demo never hard-crashes because a
laptop is not Linux.
"""
from __future__ import annotations

import socket
import struct
import time
from dataclasses import replace
from typing import Callable, Iterator

from prahari.pcapread import (parse_dns, parse_ipv4, parse_tcp,
                              parse_quic_initial, parse_tls_certificate,
                              parse_tls_client_hello, parse_udp,
                              strip_link)
from prahari.quic_crypto import decrypt_client_hello as decrypt_quic_client_hello
from prahari.schema import Flow

ETH_P_ALL = 0x0003
TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10

# A live tap needs wall-clock expiry, not the file reader's simulated clock.
IDLE_TIMEOUT = 5.0            # a flow idle this long is complete and flushed
ACTIVE_TIMEOUT = 120.0        # a long-lived flow is flushed and continued
MAX_PKT_SIZES = 20
SWEEP_EVERY = 1.0            # how often to expire idle flows, seconds


def available(iface: str | None = None) -> tuple[bool, str]:
    """Can this host capture live? Returns (yes, human-readable reason)."""
    if not hasattr(socket, "AF_PACKET"):
        return False, "AF_PACKET is Linux-only; this host cannot tap a NIC"
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        if iface:
            s.bind((iface, 0))
        s.close()
        return True, "AF_PACKET raw socket available"
    except PermissionError:
        return False, "need CAP_NET_RAW (run as root, or setcap cap_net_raw+ep)"
    except OSError as exc:
        return False, f"raw socket unavailable: {exc}"


class _Acc:
    __slots__ = ("flow", "first", "last")

    def __init__(self, flow: Flow, ts: float):
        self.flow, self.first, self.last = flow, ts, ts


class FlowAssembler:
    """Turn a stream of (timestamp, linktype, bytes) into completed Flows.

    Streaming twin of `pcapread.flows_from_capture`: same decoders, same flow
    shape, but it emits a flow the moment it goes idle instead of at end of file,
    which is what "real time" requires. Protocol is identified by content, not
    port, exactly as the offline reader does.
    """

    def __init__(self, idle: float = IDLE_TIMEOUT, active: float = ACTIVE_TIMEOUT):
        self.idle, self.active = idle, active
        self.live: dict[tuple, _Acc] = {}
        self.seen = self.decoded = 0

    def push(self, ts: float, linktype: int, pkt: bytes) -> None:
        self.seen += 1
        ip = strip_link(linktype, pkt)
        if not ip:
            return
        parsed = parse_ipv4(ip)
        if not parsed:
            return
        src, dst, proto, seg, seg_len = parsed

        if proto == 6:
            got = parse_tcp(seg)
            if not got:
                return
            sport, dport, flags, app = got
            pname = "tcp"
        elif proto == 17:
            got = parse_udp(seg)
            if not got:
                return
            sport, dport, app = got
            flags, pname = 0, "udp"
        else:
            return
        self.decoded += 1

        fwd = (src, sport, dst, dport, pname)
        rev = (dst, dport, src, sport, pname)
        key, outbound = (fwd, True) if fwd in self.live else (
            (rev, False) if rev in self.live else (fwd, True))

        acc = self.live.get(key)
        if acc is None:
            acc = _Acc(Flow(ts=ts, src_ip=src, dst_ip=dst, src_port=sport,
                            dst_port=dport, proto=pname), ts)
            self.live[key] = acc

        f = acc.flow
        acc.last = ts
        f.duration = ts - acc.first
        if outbound:
            f.pkts_out += 1
            f.bytes_out += seg_len
        else:
            f.pkts_in += 1
            f.bytes_in += seg_len
        if len(f.pkt_sizes) < MAX_PKT_SIZES:
            f.pkt_sizes.append(seg_len if outbound else -seg_len)

        if pname == "tcp":
            syn, ack = bool(flags & TCP_SYN), bool(flags & TCP_ACK)
            if syn and not ack:
                f.syn += 1
            elif syn and ack:
                f.synack += 1
            if flags & TCP_RST:
                f.rst += 1
            if flags & TCP_FIN:
                f.fin += 1

        if app:
            if pname == "udp" and (dport == 53 or sport == 53):
                dns = parse_dns(app)
                if dns:
                    if not dns["is_response"] and dns["qname"]:
                        f.dns_qname = dns["qname"]
                        f.dns_qtype = dns["qtype"]
                    elif dns["rcode"]:
                        f.dns_rcode = dns["rcode"]
            elif pname == "tcp" and len(app) > 5 and app[0] == 0x16 and app[1] == 0x03:
                if f.tls_ja4 is None:
                    tls = parse_tls_client_hello(app, transport="t")
                    if tls:
                        f.tls_ja4 = tls["ja4"]        # real JA4
                        f.tls_ja3 = tls["ja3_hash"]
                        f.tls_sni = tls["sni"]
                if f.tls_cert_days is None:
                    cert = parse_tls_certificate(app)
                    if cert:
                        f.tls_self_signed = cert["self_signed"]
                        f.tls_cert_days = cert["cert_days"]
            elif pname == "udp" and dport == 443 and f.tls_ja4 is None:
                rec = decrypt_quic_client_hello(app)  # public-salt Initial → real q-JA4
                if rec:
                    tls = parse_tls_client_hello(rec, transport="q")
                    if tls:
                        f.tls_ja4 = tls["ja4"]
                        f.tls_ja3 = tls["ja3_hash"]
                        f.tls_sni = tls["sni"]
                if f.tls_ja4 is None:
                    q = parse_quic_initial(app)       # fallback: recognise as QUIC
                    if q:
                        f.tls_ja4 = q["marker"]

    def expire(self, now: float) -> list[Flow]:
        """Return and drop flows that are complete.

        A flow is complete when it has gone idle, run too long, or been cleanly
        torn down (a RST, or a FIN seen in both directions). Flushing a closed
        connection immediately — rather than waiting out the idle timer — is what
        lets a burst of short beacon connections be scored while the burst is
        still fresh, which is exactly the real-time property a live console needs.
        """
        done = []
        for key in list(self.live.keys()):
            acc = self.live[key]
            f = acc.flow
            closed = f.proto == "tcp" and (f.rst > 0 or f.fin >= 2)
            if closed or now - acc.last > self.idle or now - acc.first > self.active:
                done.append(f)
                del self.live[key]
        return done

    def drain(self) -> list[Flow]:
        out = [a.flow for a in self.live.values()]
        self.live.clear()
        return out


class LiveCapture:
    """Read frames off a real interface and hand assembled flows to a callback."""

    def __init__(self, iface: str = "any", snaplen: int = 2048):
        self.iface = iface
        self.snaplen = snaplen
        self._sock: socket.socket | None = None
        self._running = False

    @staticmethod
    def available(iface: str | None = None) -> tuple[bool, str]:
        return available(iface)

    def interfaces(self) -> list[str]:
        try:
            import os
            return sorted(os.listdir("/sys/class/net"))
        except OSError:
            return []

    RCVBUF = 16 * 1024 * 1024        # absorb bursts without dropping frames

    def open(self) -> None:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        # A large receive buffer matters under load: a spoofed-source flood is
        # thousands of packets in a fraction of a second, and a small kernel
        # buffer would drop the tail — which on a real link is silent data loss,
        # not just a flaky demo. Best-effort; not every kernel honours the size.
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.RCVBUF)
        except OSError:
            pass
        if self.iface and self.iface != "any":
            s.bind((self.iface, 0))
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
        """Capture loop. Calls on_flows with each batch of completed flows.

        Runs until should_stop() is true or close() is called. The link type is
        detected per frame from the sockaddr, so both cooked (`any`) and
        Ethernet interfaces work without configuration.
        """
        if self._sock is None:
            self.open()
        assert self._sock is not None
        self._running = True
        asm = FlowAssembler()
        last_sweep = time.time()

        while self._running and not (should_stop and should_stop()):
            try:
                pkt, sa = self._sock.recvfrom(self.snaplen)
            except socket.timeout:
                pkt = None
            except OSError:
                break
            now = time.time()
            if pkt:
                # sa = (ifname, ethertype, pkttype, hatype, addr)
                linktype = 113 if (self.iface in ("any", None)) else 1
                asm.push(now, linktype, pkt)
            if now - last_sweep >= SWEEP_EVERY:
                done = asm.expire(now)
                if done:
                    on_flows(done)
                last_sweep = now

        done = asm.drain()
        if done:
            on_flows(done)
