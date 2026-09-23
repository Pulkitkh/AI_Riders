#!/usr/bin/env python3
"""Show, reproducibly, that PRAHARI reads a QUIC ClientHello with no secret.

It writes a small pcap of genuine QUIC v1 Initial packets — sealed exactly as an
endpoint would, header-protected and AEAD-encrypted — then reads that pcap back
through the SAME offline path the engine uses on real traffic, and prints the
"q…" JA4 and SNI it recovered from inside each encrypted Initial.

The only key material involved is the published RFC 9001 salt. Nothing here
holds a session secret; this is observation of a handshake that travels in the
clear under public keying, not interception of a session. Run it:

    python3 scripts/quic_demo.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from make_pcap import (DEFAULT_CIPHERS, DEFAULT_CURVES, DEFAULT_EXTS, eth,
                       ipv4, tls_client_hello, udp, write_pcap)
from prahari.pcapread import flows_from_capture
from prahari.quic_crypto import build_initial

# A few realistic HTTP/3 destinations a browser would reach over QUIC.
SITES = [
    ("cdn.example-video.net", "10.0.0.21", "198.51.100.10", 54100),
    ("chat.example-app.com", "10.0.0.21", "203.0.113.7", 54101),
    ("api.example-cloud.io", "10.0.0.22", "192.0.2.44", 54102),
]
DCID = bytes.fromhex("8394c8f03e515708")


def main() -> int:
    packets = []
    t = 1_757_900_000.0
    for i, (sni, src, dst, sport) in enumerate(SITES):
        record = tls_client_hello(sni, DEFAULT_CIPHERS, DEFAULT_EXTS, DEFAULT_CURVES)
        initial = build_initial(DCID, record[5:])          # strip TLS record header
        frame = eth(src, dst, ipv4(src, dst, 17, udp(sport, 443, initial), 1000 + i))
        packets.append((t + i * 0.2, frame))
        # a small server response so the flow has both directions
        packets.append((t + i * 0.2 + 0.05,
                        eth(dst, src, ipv4(dst, src, 17, udp(443, sport, b"\x00" * 64), 2000 + i))))

    out = Path(__file__).resolve().parents[1] / "data" / "quic_demo.pcap"
    out.parent.mkdir(exist_ok=True)
    write_pcap(out, packets, snaplen=262144)               # full frames, like tcpdump -s0

    print(f"wrote {len(packets)} packets of genuine QUIC v1 Initials -> {out}\n")
    print("reading it back through the ordinary offline path "
          "(prahari.pcapread.flows_from_capture):\n")
    flows = [f for f in flows_from_capture(out) if f.dst_port == 443 and f.proto == "udp"]
    ok = 0
    for f in flows:
        ja4 = f.tls_ja4 or "(none)"
        decrypted = ja4.startswith("q") and "quic-v" not in ja4
        ok += decrypted
        tag = "decrypted" if decrypted else "recognised"
        print(f"  {f.src_ip:>11} -> {f.dst_ip:<13}  {tag:10}  "
              f"JA4 {ja4}   SNI {f.tls_sni or '-'}")
    print(f"\n{ok}/{len(flows)} QUIC Initials decrypted to a real q-JA4, "
          f"using only the public RFC 9001 salt.")
    return 0 if ok == len(SITES) else 1


if __name__ == "__main__":
    raise SystemExit(main())
