"""A tiny TCP port scanner — for testing PRAHARI against a real external attack.

Run this from a DIFFERENT machine (your laptop) against the server PRAHARI is
watching. It opens a real TCP connection to each port in a range: the SYNs land
on the server's interface, the sensor tapping that interface assembles them into
flows, and the recon detector fires on the fan-out. This is the honest end-to-end
test — a real scan, from a real remote host, detected live.

    python3 scripts/scan.py <server-ip> [start-port] [end-port]
    python3 scripts/scan.py 203.0.113.10 1 1000

Only scan a host you are authorised to test — here, your own server. Needs no
root and no dependencies; it is an ordinary connect scan.
"""
from __future__ import annotations

import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor


def probe(host: str, port: int, timeout: float = 0.4) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        open_ = s.connect_ex((host, port)) == 0
    except OSError:
        open_ = False
    finally:
        s.close()
    return open_


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    if not argv:
        print(__doc__)
        return 2
    host = argv[0]
    start = int(argv[1]) if len(argv) > 1 else 1
    end = int(argv[2]) if len(argv) > 2 else 1000
    ports = range(start, end + 1)

    print(f"scanning {host} ports {start}-{end} ...")
    t0 = time.time()
    open_ports = []
    with ThreadPoolExecutor(max_workers=200) as pool:
        for port, is_open in zip(ports, pool.map(lambda p: probe(host, p), ports)):
            if is_open:
                open_ports.append(port)
    dt = time.time() - t0
    print(f"done in {dt:.1f}s — {len(list(ports))} ports probed")
    print(f"open: {open_ports or 'none'}")
    print("\nIf PRAHARI is watching this host's interface, a 'Recon scanning'")
    print("alert should now be on its Live tab, naming this machine as the source.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
