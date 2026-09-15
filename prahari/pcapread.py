"""Read real captured traffic.

Turns a .pcap or .pcapng file into the same `Flow` records the synthetic
generator produces, so every detector, the engine, fusion and the dashboard all
work unchanged on real traffic. This is the module that closes the gap between
"works on our generator" and "works on what came off the wire".

Pure standard library — no scapy, no dpkt, no libpcap binding. It reads a file;
it never opens a socket, which is why the read-only self-test still passes with
this module present.

Supported link types: Ethernet, Linux "cooked" SLL and SLL2 (what
`tcpdump -i any` produces), raw IP, and BSD loopback.

    sudo tcpdump -i any -w demo.pcap        # make a capture
    python3 -m prahari.cli live --pcap demo.pcap
"""
from __future__ import annotations

import hashlib
import struct
from collections import defaultdict
from pathlib import Path
from typing import Iterator

from .schema import Flow

# --- link types --------------------------------------------------------------
LINKTYPE_NULL, LINKTYPE_ETHERNET = 0, 1
LINKTYPE_RAW, LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2 = 101, 113, 276

TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
             16: "TXT", 10: "NULL", 28: "AAAA", 33: "SRV", 255: "ANY"}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}

# TLS extensions that carry no information for fingerprinting because clients
# insert them at random positions (RFC 8701 GREASE).
GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
          0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}


# =============================================================================
# capture file readers
# =============================================================================
def _read_pcap(data: bytes) -> Iterator[tuple[float, int, bytes]]:
    magic = data[:4]
    if magic == b"\xa1\xb2\xc3\xd4":
        endian, frac = ">", 1e-6
    elif magic == b"\xd4\xc3\xb2\xa1":
        endian, frac = "<", 1e-6
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, frac = ">", 1e-9
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, frac = "<", 1e-9
    else:
        raise ValueError("not a classic pcap file")

    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        if len(pkt) < incl:
            break
        yield ts_sec + ts_frac * frac, linktype, pkt


def _read_pcapng(data: bytes) -> Iterator[tuple[float, int, bytes]]:
    off = 0
    endian = "<"
    linktypes: dict[int, int] = {}
    tsresol: dict[int, float] = {}
    iface = 0
    while off + 12 <= len(data):
        btype = struct.unpack(endian + "I", data[off:off + 4])[0]
        if btype == 0x0A0D0D0A:                       # section header
            bom = data[off + 8:off + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            btype = 0x0A0D0D0A
            linktypes, tsresol, iface = {}, {}, 0
        blen = struct.unpack(endian + "I", data[off + 4:off + 8])[0]
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8:off + blen - 4]

        if btype == 0x00000001:                       # interface description
            lt = struct.unpack(endian + "H", body[0:2])[0]
            idx = len(linktypes)
            linktypes[idx] = lt
            tsresol[idx] = 1e-6
            # walk options for if_tsresol (code 9)
            o = 8
            while o + 4 <= len(body):
                code, olen = struct.unpack(endian + "HH", body[o:o + 4])
                val = body[o + 4:o + 4 + olen]
                if code == 0:
                    break
                if code == 9 and olen >= 1:
                    r = val[0]
                    tsresol[idx] = (1.0 / (2 ** (r & 0x7F))) if r & 0x80 else (10.0 ** -r)
                o += 4 + olen + ((4 - olen % 4) % 4)
        elif btype == 0x00000006:                     # enhanced packet block
            iface, ts_hi, ts_lo, cap_len, _orig = struct.unpack(endian + "IIIII", body[:20])
            ts = ((ts_hi << 32) | ts_lo) * tsresol.get(iface, 1e-6)
            yield ts, linktypes.get(iface, LINKTYPE_ETHERNET), body[20:20 + cap_len]
        off += blen


def read_capture(path: str | Path) -> Iterator[tuple[float, int, bytes]]:
    data = Path(path).read_bytes()
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        yield from _read_pcapng(data)
    else:
        yield from _read_pcap(data)


# =============================================================================
# packet decode
# =============================================================================
def strip_link(linktype: int, pkt: bytes) -> bytes | None:
    """Return the IPv4 payload, or None if this is not IPv4."""
    if linktype == LINKTYPE_ETHERNET:
        if len(pkt) < 14:
            return None
        et = struct.unpack("!H", pkt[12:14])[0]
        off = 14
        while et in (0x8100, 0x88A8) and len(pkt) >= off + 4:   # VLAN tags
            et = struct.unpack("!H", pkt[off + 2:off + 4])[0]
            off += 4
        return pkt[off:] if et == 0x0800 else None
    if linktype == LINKTYPE_LINUX_SLL:
        if len(pkt) < 16:
            return None
        return pkt[16:] if struct.unpack("!H", pkt[14:16])[0] == 0x0800 else None
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(pkt) < 20:
            return None
        return pkt[20:] if struct.unpack("!H", pkt[0:2])[0] == 0x0800 else None
    if linktype == LINKTYPE_RAW:
        return pkt
    if linktype == LINKTYPE_NULL:
        if len(pkt) < 4:
            return None
        fam = struct.unpack("<I", pkt[:4])[0]
        return pkt[4:] if fam == 2 else None
    return None


def parse_ipv4(ip: bytes):
    """Decode an IPv4 header.

    Returns the captured L4 bytes *and* the L4 length the header declares. The
    two differ whenever the capture was taken with a snaplen — the usual case
    for a passive tap, where you keep headers and throw payload away. Byte
    counters must follow the declared length or every volume-based detector
    silently under-reads on a truncated capture; parsers must follow the
    captured bytes. Keeping both is the difference between a tool that works on
    a lab capture and one that works on a tap.
    """
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    proto = ip[9]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    seg = ip[ihl:total] if total >= ihl else ip[ihl:]
    # total == 0 means segmentation offload handed us a super-frame; fall back.
    seg_len = (total - ihl) if total > ihl else len(ip[ihl:])
    return src, dst, proto, seg, seg_len


def parse_tcp(seg: bytes):
    if len(seg) < 20:
        return None
    sport, dport = struct.unpack("!HH", seg[0:4])
    doff = (seg[12] >> 4) * 4
    flags = seg[13]
    return sport, dport, flags, seg[doff:] if len(seg) >= doff else b""


def parse_udp(seg: bytes):
    if len(seg) < 8:
        return None
    sport, dport, length = struct.unpack("!HHH", seg[0:6])
    return sport, dport, seg[8:max(length, 8)]


# --- application metadata ----------------------------------------------------
def parse_dns(payload: bytes):
    """Query name, type and response code — the fields the DGA and tunnelling
    detectors consume. We read the question section only; no payload is stored."""
    if len(payload) < 12:
        return None
    flags, qd = struct.unpack("!HH", payload[2:6])
    if qd < 1:
        return None
    labels, off = [], 12
    while off < len(payload):
        n = payload[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0:                   # compression pointer
            off += 2
            break
        labels.append(payload[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
        if len(labels) > 40:
            break
    qtype = struct.unpack("!H", payload[off:off + 2])[0] if off + 2 <= len(payload) else 0
    return {
        "qname": ".".join(labels),
        "qtype": DNS_TYPES.get(qtype, str(qtype)),
        "rcode": DNS_RCODES.get(flags & 0x0F, str(flags & 0x0F)) if flags & 0x8000 else None,
        "is_response": bool(flags & 0x8000),
    }


def parse_tls_client_hello(payload: bytes):
    """SNI plus a JA3-style fingerprint, computed from the ClientHello.

    The handshake is not encrypted, so cipher and extension lists are observable
    in passing. Nothing here decrypts anything — constraint (b) holds.
    """
    if len(payload) < 45 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    try:
        off = 9
        ver = struct.unpack("!H", payload[off:off + 2])[0]
        off += 2 + 32                                   # version + random
        sid_len = payload[off]; off += 1 + sid_len
        cs_len = struct.unpack("!H", payload[off:off + 2])[0]; off += 2
        ciphers = [struct.unpack("!H", payload[off + i:off + i + 2])[0]
                   for i in range(0, cs_len, 2)]
        off += cs_len
        comp_len = payload[off]; off += 1 + comp_len

        sni, exts, curves, formats = None, [], [], []
        if off + 2 <= len(payload):
            ext_total = struct.unpack("!H", payload[off:off + 2])[0]
            off += 2
            end = min(off + ext_total, len(payload))
            while off + 4 <= end:
                etype, elen = struct.unpack("!HH", payload[off:off + 4])
                body = payload[off + 4:off + 4 + elen]
                off += 4 + elen
                if etype in GREASE:
                    continue
                exts.append(etype)
                if etype == 0x0000 and len(body) >= 5:          # server_name
                    nlen = struct.unpack("!H", body[3:5])[0]
                    sni = body[5:5 + nlen].decode("ascii", "replace")
                elif etype == 0x000a and len(body) >= 2:        # supported_groups
                    glen = struct.unpack("!H", body[0:2])[0]
                    curves = [struct.unpack("!H", body[2 + i:4 + i])[0]
                              for i in range(0, glen, 2)]
                elif etype == 0x000b and len(body) >= 1:        # ec_point_formats
                    formats = list(body[1:1 + body[0]])

        ja3 = ",".join([
            str(ver),
            "-".join(str(c) for c in ciphers if c not in GREASE),
            "-".join(str(e) for e in exts),
            "-".join(str(c) for c in curves if c not in GREASE),
            "-".join(str(f) for f in formats),
        ])
        return {"sni": sni,
                "ja3": ja3,
                "ja3_hash": hashlib.md5(ja3.encode()).hexdigest()}
    except (struct.error, IndexError):
        return None


# --- X.509, read from the handshake ------------------------------------------
def _der(buf: bytes, off: int):
    """Return (tag, content_bytes, next_offset) for one DER element."""
    if off + 2 > len(buf):
        raise ValueError("truncated DER")
    tag = buf[off]
    n = buf[off + 1]
    off += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or off + k > len(buf):
            raise ValueError("bad DER length")
        n = int.from_bytes(buf[off:off + k], "big")
        off += k
    return tag, buf[off:off + n], off + n


def _der_time(raw: bytes) -> tuple[int, int, int]:
    """UTCTime (YYMMDD...) or GeneralizedTime (YYYYMMDD...) -> (y, m, d)."""
    t = raw.decode("ascii", "replace")
    if len(t) >= 13 and t[-1] == "Z" and len(t) == 13:      # UTCTime
        yy = int(t[0:2])
        return (2000 + yy if yy < 50 else 1900 + yy), int(t[2:4]), int(t[4:6])
    return int(t[0:4]), int(t[4:6]), int(t[6:8])


def _days(a: tuple[int, int, int], b: tuple[int, int, int]) -> int:
    import datetime
    return (datetime.date(*b) - datetime.date(*a)).days


def parse_x509(der: bytes):
    """Issuer/subject equality and the validity window — nothing more.

    These two facts are what the TLS detector consumes, and both are readable
    without any key material: the server's certificate travels in the clear in
    TLS 1.2 and below. In TLS 1.3 it is encrypted, so this returns None there
    and the detector falls back to fingerprint rarity and packet shape. That
    limit is real and we state it rather than paper over it.
    """
    try:
        _, tbs_outer, _ = _der(der, 0)                    # Certificate SEQUENCE
        tag, tbs, _ = _der(tbs_outer, 0)                  # tbsCertificate SEQUENCE
        off = 0
        tag, _, off = _der(tbs, off)
        if tag == 0xA0:                                   # [0] EXPLICIT version
            tag, _, off = _der(tbs, off)                  # serialNumber
        tag, _, off = _der(tbs, off)                      # signature AlgorithmIdentifier
        _, issuer, nxt = _der(tbs, off)                   # issuer Name
        off = nxt
        _, validity, nxt = _der(tbs, off)                 # validity SEQUENCE
        off = nxt
        _, subject, _ = _der(tbs, off)                    # subject Name

        _, nb, v2 = _der(validity, 0)
        _, na, _ = _der(validity, v2)
        return {"self_signed": issuer == subject,
                "cert_days": _days(_der_time(nb), _der_time(na))}
    except (ValueError, IndexError, struct.error):
        return None


def parse_tls_certificate(payload: bytes):
    """Find the first Certificate handshake message in a server record."""
    off = 0
    while off + 5 <= len(payload):
        if payload[off] != 0x16:                          # handshake record
            return None
        rec_len = struct.unpack("!H", payload[off + 3:off + 5])[0]
        body = payload[off + 5:off + 5 + rec_len]
        off += 5 + rec_len
        h = 0
        while h + 4 <= len(body):
            htype = body[h]
            hlen = int.from_bytes(body[h + 1:h + 4], "big")
            msg = body[h + 4:h + 4 + hlen]
            h += 4 + hlen
            if htype == 0x0B and len(msg) >= 6:           # Certificate
                clen = int.from_bytes(msg[3:6], "big")
                return parse_x509(msg[6:6 + clen])
    return None


# =============================================================================
# flow assembly
# =============================================================================
IDLE_TIMEOUT = 60.0
ACTIVE_TIMEOUT = 180.0
MAX_PKT_SIZES = 20


class _Acc:
    __slots__ = ("flow", "last", "first")

    def __init__(self, flow: Flow, ts: float):
        self.flow, self.first, self.last = flow, ts, ts


def flows_from_capture(path: str | Path, verbose: bool = False) -> list[Flow]:
    """Assemble bidirectional flows from a capture file.

    Direction is fixed by whichever side sent the first packet, matching how
    nfstream and Zeek canonicalise a connection.
    """
    live: dict[tuple, _Acc] = {}
    done: list[Flow] = []
    seen = decoded = 0

    for ts, linktype, pkt in read_capture(path):
        seen += 1
        ip = strip_link(linktype, pkt)
        if not ip:
            continue
        parsed = parse_ipv4(ip)
        if not parsed:
            continue
        src, dst, proto, seg, seg_len = parsed

        if proto == 6:
            got = parse_tcp(seg)
            if not got:
                continue
            sport, dport, flags, app = got
            pname = "tcp"
        elif proto == 17:
            got = parse_udp(seg)
            if not got:
                continue
            sport, dport, app = got
            flags, pname = 0, "udp"
        else:
            continue
        decoded += 1

        fwd = (src, sport, dst, dport, pname)
        rev = (dst, dport, src, sport, pname)
        key, outbound = (fwd, True) if fwd in live else (
            (rev, False) if rev in live else (fwd, True))

        acc = live.get(key)
        if acc and (ts - acc.last > IDLE_TIMEOUT or ts - acc.first > ACTIVE_TIMEOUT):
            done.append(acc.flow)
            del live[key]
            acc = None
        if acc is None:
            acc = _Acc(Flow(ts=ts, src_ip=src, dst_ip=dst, src_port=sport,
                            dst_port=dport, proto=pname), ts)
            live[key] = acc

        f = acc.flow
        acc.last = ts
        f.duration = ts - acc.first
        size = seg_len
        if outbound:
            f.pkts_out += 1
            f.bytes_out += size
        else:
            f.pkts_in += 1
            f.bytes_in += size
        if len(f.pkt_sizes) < MAX_PKT_SIZES:
            f.pkt_sizes.append(size if outbound else -size)

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

        # Application metadata, read in passing. Protocol is identified by
        # content, not by port number — the way Zeek's dynamic protocol
        # detection does it — so TLS on 8443 or 514 is still seen as TLS and a
        # plaintext service parked on 443 is not mistaken for it.
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
                    tls = parse_tls_client_hello(app)
                    if tls:
                        f.tls_ja4 = tls["ja3_hash"]   # real fingerprint, computed here
                        f.tls_sni = tls["sni"]
                if f.tls_cert_days is None:
                    cert = parse_tls_certificate(app)
                    if cert:
                        f.tls_self_signed = cert["self_signed"]
                        f.tls_cert_days = cert["cert_days"]

    done.extend(a.flow for a in live.values())
    done.sort(key=lambda x: x.ts)
    if verbose:
        print(f"  read {seen} packets, decoded {decoded} IPv4 TCP/UDP, "
              f"assembled {len(done)} flows")
    return done
