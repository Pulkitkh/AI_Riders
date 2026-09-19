"""Live capture and real-time serving for PRAHARI.

This package binds sockets: an AF_PACKET receive socket to tap the wire, and it
feeds a live HTTP stream. It is deliberately OUTSIDE the `prahari` package so
the read-only self-test — which scans only the detection path — stays true. The
engine it drives never learns that packets arrived from a NIC rather than a file.

A raw receive socket is the software realisation of the passive tap the problem
statement assumes: it can read frames off the interface but the detection path
that consumes them holds no socket and can transmit nothing. Capture and
detection are separate processes of thought, and this package is the capture one.
"""
