"""Ingest exported flow records — NetFlow v5.

The problem statement names "exported flow records (NetFlow/IPFIX/sFlow)" as one
of the passive data sources a monitoring enclave sees. This reads NetFlow v5,
the most widely deployed of them, and maps each record onto the same `Flow` the
rest of the pipeline consumes — so a NetFlow feed is detected by exactly the same
engine as a packet capture, with no other change.

NetFlow is a natural fit for this problem in a second way: each v5 record
describes ONE direction of a conversation. That is the unidirectional-visibility
case the problem statement is about, arriving natively — there is no reverse
direction to assume, so the degraded-mode features are what run.

Pure byte parsing, no socket. The live collector that receives these datagrams
over UDP lives in `sensor/` (which is allowed to bind a socket); this module
only decodes bytes, so it stays inside the read-only detection path.

Reference: Cisco NetFlow v5 — 24-byte header, then `count` 48-byte records.
IPFIX/NetFlow v9 are template-driven and are the documented next step; their
records map onto the same `Flow`, only the parsing of the wire format differs.
"""
from __future__ import annotations

import struct
from typing import Iterator

from .schema import Flow

TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10
_HEADER = struct.Struct("!HHIIIIBBH")     # 24 bytes
_RECORD = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")   # 48 bytes


def _ip(v: int) -> str:
    return f"{(v >> 24) & 0xFF}.{(v >> 16) & 0xFF}.{(v >> 8) & 0xFF}.{v & 0xFF}"


def parse_v5(datagram: bytes) -> list[Flow]:
    """Decode one NetFlow v5 export datagram into Flow records.

    Timestamps come from the header's wall clock plus each record's switch
    uptime, so flows land on the same real-time axis the engine expects.
    """
    if len(datagram) < _HEADER.size:
        return []
    version, count, sys_uptime, secs, nsecs, _seq, _et, _eid, _smp = \
        _HEADER.unpack_from(datagram, 0)
    if version != 5:
        return []
    boot = secs + nsecs / 1e9 - sys_uptime / 1000.0     # switch boot, epoch seconds
    out: list[Flow] = []
    off = _HEADER.size
    for _ in range(min(count, (len(datagram) - _HEADER.size) // _RECORD.size)):
        (src, dst, _nh, _in, _out, pkts, octets, first, last,
         sport, dport, _pad, flags, proto, _tos, _sas, _das,
         _sm, _dm, _pad2) = _RECORD.unpack_from(datagram, off)
        off += _RECORD.size

        pname = "tcp" if proto == 6 else "udp" if proto == 17 else None
        if pname is None:
            continue
        f = Flow(
            ts=boot + first / 1000.0,
            src_ip=_ip(src), dst_ip=_ip(dst),
            src_port=sport, dst_port=dport, proto=pname,
            duration=max(0.0, (last - first) / 1000.0),
            pkts_out=pkts, bytes_out=octets,     # v5 records are one-directional
        )
        if pname == "tcp":
            # NetFlow reports the OR of all flags seen in the flow.
            if flags & TCP_SYN:
                f.syn = 1
                if flags & TCP_ACK:
                    f.synack = 1
            if flags & TCP_RST:
                f.rst = 1
            if flags & TCP_FIN:
                f.fin = 1
        out.append(f)
    return out


def flows_from_datagrams(datagrams: Iterator[bytes]) -> list[Flow]:
    flows: list[Flow] = []
    for d in datagrams:
        flows.extend(parse_v5(d))
    flows.sort(key=lambda f: f.ts)
    return flows


# --- helper to build a v5 datagram (used by the test and the demo sender) -----
def build_v5(records: list[dict], secs: int = 1_757_900_000, sys_uptime: int = 100_000) -> bytes:
    """Assemble a NetFlow v5 datagram from simple record dicts.

    Exists so the reader is tested against bytes it did not itself produce, and
    so a demo can replay a flow feed without a real NetFlow exporter.
    """
    hdr = _HEADER.pack(5, len(records), sys_uptime, secs, 0, 0, 0, 0, 0)
    body = b""
    for r in records:
        def ip2int(s):
            a, b, c, d = (int(x) for x in s.split("."))
            return (a << 24) | (b << 16) | (c << 8) | d
        proto = 6 if r.get("proto", "tcp") == "tcp" else 17
        body += _RECORD.pack(
            ip2int(r["src_ip"]), ip2int(r["dst_ip"]), 0, 0, 0,
            r.get("pkts", 1), r.get("bytes", 100),
            r.get("first", 1000), r.get("last", 1200),
            r.get("src_port", 1234), r.get("dst_port", 80),
            0, r.get("flags", 0), proto, 0, 0, 0, 0, 0, 0)
    return hdr + body
