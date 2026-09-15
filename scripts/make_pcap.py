"""Write a real wire-format .pcap from the synthetic generator.

This exists for two reasons.

1. It verifies `prahari.pcapread` end to end. The reader is only trustworthy if
   something independent produced the bytes it parses, so this module builds
   genuine Ethernet/IPv4/TCP/UDP frames — real headers, real checksums-free but
   structurally valid, real DNS wire encoding, a real TLS ClientHello — and the
   test suite asserts the flows that come back out match the flows that went in.

2. It gives you a capture file to demo with when you cannot run tcpdump on the
   machine in front of you (no root, no interface, a locked-down lab PC). The
   file is a normal .pcap: Wireshark opens it, and so does anything else.

    python3 scripts/make_pcap.py --out data/demo.pcap --duration 1800
    python3 -m prahari.cli live --pcap data/demo.pcap
"""
from __future__ import annotations

import argparse
import datetime
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prahari.generate import ALL_ATTACKS, TrafficGenerator   # noqa: E402
from prahari.schema import Flow                              # noqa: E402

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10
MSS_SEG = 1480              # 1460 payload + 20 bytes of TCP header
MAX_FILL_PACKETS = 4000     # keeps a pathological flow from eating the file


# =============================================================================
# header builders
# =============================================================================
def _mac(ip: str) -> bytes:
    """A stable synthetic MAC per host, so captures look like one L2 segment."""
    octets = [int(x) & 0xFF for x in ip.split(".")]
    return bytes([0x02, 0x00] + octets)


def eth(src_ip: str, dst_ip: str, payload: bytes) -> bytes:
    return _mac(dst_ip) + _mac(src_ip) + struct.pack("!H", 0x0800) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int = 0) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, total, ident & 0xFFFF, 0x4000, 64, proto, 0,
        bytes(int(x) for x in src.split(".")),
        bytes(int(x) for x in dst.split(".")),
    )
    return hdr + payload


def tcp(sport: int, dport: int, flags: int, payload: bytes = b"",
        seq: int = 1, ack: int = 1) -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                      5 << 4, flags, 65535, 0, 0)
    return hdr + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


# =============================================================================
# application payloads
# =============================================================================
def dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii", "replace")[:63]
    return out + b"\x00"


TYPE_CODES = {"A": 1, "AAAA": 28, "TXT": 16, "NULL": 10, "CNAME": 5, "MX": 15}
RCODES = {"NOERROR": 0, "NXDOMAIN": 3, "SERVFAIL": 2, "REFUSED": 5}


def dns_query(txid: int, qname: str, qtype: str = "A") -> bytes:
    return (struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
            + dns_name(qname) + struct.pack("!HH", TYPE_CODES.get(qtype, 1), 1))


def dns_response(txid: int, qname: str, qtype: str, rcode: str, pad: int = 0) -> bytes:
    flags = 0x8180 | (RCODES.get(rcode, 0) & 0x0F)
    body = (struct.pack("!HHHHHH", txid, flags, 1, 1 if rcode == "NOERROR" else 0, 0, 0)
            + dns_name(qname) + struct.pack("!HH", TYPE_CODES.get(qtype, 1), 1))
    if rcode == "NOERROR":
        body += (b"\xc0\x0c" + struct.pack("!HHIH", TYPE_CODES.get(qtype, 1), 1, 300, 4)
                 + bytes([93, 184, 216, 34]))
    return body + b"\x00" * pad


def tls_client_hello(sni: str | None, ciphers: list[int], exts: list[int],
                     curves: list[int]) -> bytes:
    """A structurally valid TLS 1.2 ClientHello record.

    Real bytes in real order — which is the point: `pcapread` computes a JA3
    from this, and the test asserts the JA3 it computes is the one these lists
    imply. A fake fingerprint would not survive that.
    """
    body = b""
    for etype in exts:
        if etype == 0x0000 and sni:
            host = sni.encode()
            ext = struct.pack("!HBH", len(host) + 3, 0, len(host)) + host
        elif etype == 0x000a:
            g = b"".join(struct.pack("!H", c) for c in curves)
            ext = struct.pack("!H", len(g)) + g
        elif etype == 0x000b:
            ext = bytes([1, 0])
        else:
            ext = b""
        body += struct.pack("!HH", etype, len(ext)) + ext

    hello = (struct.pack("!H", 0x0303) + bytes(range(32))
             + b"\x00"                                        # session id
             + struct.pack("!H", len(ciphers) * 2)
             + b"".join(struct.pack("!H", c) for c in ciphers)
             + b"\x01\x00"                                    # compression
             + struct.pack("!H", len(body)) + body)
    handshake = b"\x01" + struct.pack("!I", len(hello))[1:] + hello
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


# --- a real DER certificate, so the X.509 parser has something to parse ------
def _tlv(tag: int, content: bytes) -> bytes:
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    n = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(n)]) + n + content


def _name(cn: str) -> bytes:
    attr = _tlv(0x30, _tlv(0x06, b"\x55\x04\x03") + _tlv(0x13, cn.encode()))
    return _tlv(0x30, _tlv(0x31, attr))


def _utctime(y: int, m: int, d: int) -> bytes:
    return _tlv(0x17, f"{y % 100:02d}{m:02d}{d:02d}000000Z".encode())


def x509(subject_cn: str, issuer_cn: str, not_before: tuple[int, int, int],
         not_after: tuple[int, int, int]) -> bytes:
    """A structurally valid DER certificate.

    Not cryptographically meaningful — the signature is filler — but the fields
    the detector reads (issuer, subject, validity) are encoded exactly as a real
    CA encodes them, so `parse_x509` is tested against real DER, not a stub.
    """
    alg = _tlv(0x30, _tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b") + _tlv(0x05, b""))
    spki = _tlv(0x30, _tlv(0x30, _tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01")
                           + _tlv(0x05, b"")) + _tlv(0x03, b"\x00" + b"\x01" * 64))
    tbs = _tlv(0x30,
               _tlv(0xA0, _tlv(0x02, b"\x02"))
               + _tlv(0x02, b"\x10\x2f")
               + alg
               + _name(issuer_cn)
               + _tlv(0x30, _utctime(*not_before) + _utctime(*not_after))
               + _name(subject_cn)
               + spki)
    return _tlv(0x30, tbs + alg + _tlv(0x03, b"\x00" + b"\x42" * 64))


def tls_server_certificate(subject_cn: str, issuer_cn: str,
                           not_before: tuple[int, int, int],
                           not_after: tuple[int, int, int]) -> bytes:
    """A TLS record carrying a Certificate handshake message."""
    der = x509(subject_cn, issuer_cn, not_before, not_after)
    entry = len(der).to_bytes(3, "big") + der
    msg = len(entry).to_bytes(3, "big") + entry
    handshake = b"\x0b" + len(msg).to_bytes(3, "big") + msg
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


DEFAULT_CIPHERS = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0x009e]
DEFAULT_EXTS = [0x0000, 0x0017, 0x000a, 0x000b, 0x0010, 0x000d, 0x002b, 0x0033]
DEFAULT_CURVES = [0x001d, 0x0017, 0x0018]
# A client that offers a short, dated cipher list — the shape malware TLS stacks
# tend to have, because they link an old library and never update it.
ODD_CIPHERS = [0xc014, 0xc013, 0x0035, 0x002f, 0x000a]
ODD_EXTS = [0x0000, 0x000b, 0x000a, 0x0023, 0x000d]


# =============================================================================
# flow -> packets
# =============================================================================
def flow_to_packets(f: Flow, rng: random.Random) -> list[tuple[float, bytes]]:
    """Expand one flow record into the frames that would have carried it.

    The expansion is lossy on purpose — a flow record does not remember every
    packet — but it preserves what the detectors read: handshake outcome, packet
    size sequence, direction, timing, and the DNS/TLS fields seen in passing.
    """
    pkts: list[tuple[float, bytes]] = []
    t = f.ts
    step = max(f.duration / max(len(f.pkt_sizes) + 3, 4), 1e-4)

    def out(payload: bytes, proto: int, at: float) -> None:
        pkts.append((at, eth(f.src_ip, f.dst_ip,
                             ipv4(f.src_ip, f.dst_ip, proto, payload,
                                  rng.randrange(65536)))))

    def inn(payload: bytes, proto: int, at: float) -> None:
        pkts.append((at, eth(f.dst_ip, f.src_ip,
                             ipv4(f.dst_ip, f.src_ip, proto, payload,
                                  rng.randrange(65536)))))

    if f.proto == "udp":
        txid = rng.randrange(65536)
        if f.dns_qname:
            out(udp(f.src_port, f.dst_port,
                    dns_query(txid, f.dns_qname, f.dns_qtype or "A")), 17, t)
            if f.pkts_in:
                pad = max(0, (f.bytes_in // max(f.pkts_in, 1)) - 60)
                inn(udp(f.dst_port, f.src_port,
                        dns_response(txid, f.dns_qname, f.dns_qtype or "A",
                                     f.dns_rcode or "NOERROR", pad)), 17, t + step)
        else:
            for i, size in enumerate(f.pkt_sizes or [f.bytes_out]):
                body = bytes(rng.randrange(256) for _ in range(min(abs(size), 1400)))
                (out if size >= 0 else inn)(
                    udp(f.src_port if size >= 0 else f.dst_port,
                        f.dst_port if size >= 0 else f.src_port, body), 17, t + i * step)
        return pkts

    # --- TCP ---
    seq = 1
    out(tcp(f.src_port, f.dst_port, TCP_SYN, seq=seq), 6, t)
    t += step
    if f.synack:
        inn(tcp(f.dst_port, f.src_port, TCP_SYN | TCP_ACK), 6, t)
        t += step
        out(tcp(f.src_port, f.dst_port, TCP_ACK), 6, t)
        t += step

    if f.synack and (f.tls_ja4 is not None or f.dst_port == 443):
        odd = f.tls_self_signed or f.label == "encrypted_malware"
        hello = tls_client_hello(
            f.tls_sni,
            ODD_CIPHERS if odd else DEFAULT_CIPHERS,
            ODD_EXTS if odd else DEFAULT_EXTS,
            DEFAULT_CURVES if not odd else [0x0017, 0x0018])
        out(tcp(f.src_port, f.dst_port, TCP_PSH | TCP_ACK, hello), 6, t)
        t += step
        cn = f.tls_sni or f.dst_ip
        days = f.tls_cert_days if f.tls_cert_days is not None else 365
        issuer = cn if f.tls_self_signed else "DigiCert TLS RSA SHA256 2020 CA1"
        start = datetime.date(2026, 1, 1)
        end = start + datetime.timedelta(days=max(days, 1))
        nb, na = (start.year, start.month, start.day), (end.year, end.month, end.day)
        inn(tcp(f.dst_port, f.src_port, TCP_PSH | TCP_ACK,
                tls_server_certificate(cn, issuer, nb, na)), 6, t)
        t += step

    sent_out = sent_in = 0
    for size in f.pkt_sizes:
        n = max(0, min(abs(size) - 20, 1400))       # TCP header is 20 of the segment
        body = bytes(rng.randrange(256) for _ in range(n))
        if size >= 0:
            out(tcp(f.src_port, f.dst_port, TCP_PSH | TCP_ACK, body), 6, t)
            sent_out += 20 + n
        else:
            inn(tcp(f.dst_port, f.src_port, TCP_PSH | TCP_ACK, body), 6, t)
            sent_in += 20 + n
        t += step

    # The flow record remembers a byte total but only the first few packet
    # sizes. Make up the difference at MSS, the way a bulk transfer actually
    # looks on the wire, so volume-based detectors see the volume that the
    # record claims rather than the 20-packet sample.
    for target, already, direction, sport, dport in (
            (f.bytes_out, sent_out, out, f.src_port, f.dst_port),
            (f.bytes_in, sent_in, inn, f.dst_port, f.src_port)):
        remaining = target - already
        n_pkts = min(remaining // MSS_SEG, MAX_FILL_PACKETS)
        if n_pkts <= 0:
            continue
        fill = max(f.duration - (t - f.ts), 0.0) / max(n_pkts, 1) or 1e-5
        body = bytes(rng.randrange(256) for _ in range(MSS_SEG - 20))
        for _ in range(int(n_pkts)):
            direction(tcp(sport, dport, TCP_PSH | TCP_ACK, body), 6, t)
            t += fill

    if f.rst:
        inn(tcp(f.dst_port, f.src_port, TCP_RST | TCP_ACK), 6, t)
    elif f.fin:
        out(tcp(f.src_port, f.dst_port, TCP_FIN | TCP_ACK), 6, t)
        t += step
        inn(tcp(f.dst_port, f.src_port, TCP_FIN | TCP_ACK), 6, t)
    return pkts


# =============================================================================
# file writer
# =============================================================================
def write_pcap(path: str | Path, packets: list[tuple[float, bytes]],
               linktype: int = 1, snaplen: int = 512) -> int:
    """Classic pcap, little-endian, microsecond resolution.

    Records are truncated to `snaplen` with the original length preserved in the
    header — exactly what `tcpdump -s 512` produces, and what a passive tap
    normally stores, because keeping full payload off a 10G link is neither
    affordable nor, for a metadata-only system, useful.
    """
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype)]
    for ts, raw in sorted(packets, key=lambda p: p[0]):
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        out.append(struct.pack("<IIII", sec, usec, min(len(raw), snaplen), len(raw))
                   + raw[:snaplen])
    blob = b"".join(out)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(blob)
    return len(blob)


def build(duration: int = 1800, seed: int = 1337, jitter: float = 0.20,
          t0: float = 1_757_900_000.0,
          benign_only: bool = False) -> tuple[list[Flow], list[tuple[float, bytes]]]:
    gen = TrafficGenerator(seed=seed, jitter=jitter)
    flows = gen.capture(duration, t0=t0,
                        classes=set() if benign_only else ALL_ATTACKS)
    rng = random.Random(seed)
    packets: list[tuple[float, bytes]] = []
    for f in flows:
        packets += flow_to_packets(f, rng)
    return flows, packets


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="data/demo.pcap")
    ap.add_argument("--duration", type=int, default=1800)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--jitter", type=float, default=0.20)
    ap.add_argument("--snaplen", type=int, default=512,
                    help="bytes kept per packet, as tcpdump -s (0 = full)")
    ap.add_argument("--benign-only", action="store_true",
                    help="no attacks at all — the negative control for a demo")
    a = ap.parse_args(argv)

    flows, packets = build(a.duration, a.seed, a.jitter, benign_only=a.benign_only)
    n = write_pcap(a.out, packets, snaplen=a.snaplen or 262144)
    print(f"{len(flows)} flows -> {len(packets)} packets -> {a.out} ({n/1e6:.1f} MB)")
    print("open it in Wireshark, or run:")
    print(f"  python3 -m prahari.cli live --pcap {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
