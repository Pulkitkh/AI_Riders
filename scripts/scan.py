"""A tiny TCP port scanner — for testing PRAHARI against a real external attack.

The sensor only sees traffic on the interface it TAPS. So the scan must cross
that interface, or the sensor never sees it and no alert fires. Two correct ways:

  1. Single machine (easiest): tell the sensor to tap loopback and scan loopback.
         sudo python3 -m web.server --live --iface lo
         python3 scripts/scan.py 127.0.0.1 1 1000
     (Scanning 127.0.0.1 while the sensor taps your LAN NIC will NOT be seen —
     loopback traffic never touches the LAN card. That is the usual surprise.)

  2. Two machines (most realistic): run the sensor on the server's LAN NIC and
     run this scanner from a DIFFERENT machine against the server's LAN IP.
         # on the server:  sudo python3 -m web.server --live --iface eth0
         # on your laptop:  python3 scripts/scan.py <server-LAN-ip> 1 1000

The recon detector fires on the fan-out (many ports, few answered) a few seconds
after the scan, once the flows expire and the window closes.

    python3 scripts/scan.py <target-ip> [start-port] [end-port]

Only scan a host you are authorised to test. Needs no root and no dependencies;
it is an ordinary connect scan.
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
    loopback = host in ("127.0.0.1", "localhost", "::1")
    print("\nA 'Recon scanning' alert should appear on the Live tab within a few")
    print("seconds — IF the sensor is tapping the interface this scan crossed.")
    if loopback:
        print("You scanned LOOPBACK (127.0.0.1). The sensor must be tapping 'lo' to")
        print("see it:  sudo python3 -m web.server --live --iface lo")
        print("If it is tapping your LAN NIC (eth0/wlan0) it will NOT see this scan —")
        print("scan the machine's LAN IP from another host instead.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
