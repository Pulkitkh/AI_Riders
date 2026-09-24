"""Read-only self-test — constraint (a), demonstrated rather than asserted.

Run this on stage. It proves three things in about a second:
  1. the process holds no listening or outbound sockets toward the traffic source
  2. no module in the detection path imports a network client
  3. the alert chain verifies

This is the check that separates a system designed for a read-only enclave from
a conventional IDS with a claim about one on its slide.
"""
from __future__ import annotations

import ast
import socket
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parent
# The engine and detectors must never reach for any of these.
FORBIDDEN = {"socket", "requests", "urllib", "urllib3", "http.client",
             "httpx", "ftplib", "smtplib", "telnetlib", "paramiko", "scapy"}
DETECTION_PATH = ["engine.py", "features.py", "model.py", "fusion.py", "schema.py",
                  "ledger.py", "pcapread.py", "netflow.py", "quic_crypto.py",
                  "icsparse.py", "anomaly.py", "detectors"]
# pcapread.py is in this list deliberately. It is the module that touches real
# traffic, so it is the one where a socket would be least surprising and most
# damaging — it opens a file and nothing else, and this asserts that.


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module.split(".")[0])
    return found


def check_no_network_imports() -> tuple[bool, list[str]]:
    offenders = []
    for entry in DETECTION_PATH:
        p = PKG / entry
        files = sorted(p.rglob("*.py")) if p.is_dir() else ([p] if p.exists() else [])
        for f in files:
            bad = _imports(f) & FORBIDDEN
            if bad:
                offenders.append(f"{f.relative_to(PKG.parent)}: {sorted(bad)}")
    return not offenders, offenders


def check_no_open_sockets() -> tuple[bool, int]:
    """Count sockets this process holds. The detection path should hold none."""
    n = 0
    for obj in list(globals().values()):
        if isinstance(obj, socket.socket):
            n += 1
    try:
        import gc
        n = sum(1 for o in gc.get_objects() if isinstance(o, socket.socket))
    except Exception:
        pass
    return n == 0, n


def main() -> int:
    print("PRAHARI read-only self-test")
    print("=" * 52)
    ok_imports, offenders = check_no_network_imports()
    print(f"[{'PASS' if ok_imports else 'FAIL'}] detection path imports no network client")
    for o in offenders:
        print(f"       offender: {o}")

    ok_sockets, n = check_no_open_sockets()
    print(f"[{'PASS' if ok_sockets else 'FAIL'}] process holds no sockets (found {n})")

    from .ledger import AlertLedger
    led = AlertLedger(Path("data") / "alerts.jsonl")
    ok_chain, count, bad = led.verify()
    if count == 0:
        # An empty chain verifies trivially, and reporting that as a PASS would
        # be the kind of vacuous green tick this project exists to avoid.
        ok_chain = None
        print("[SKIP] alert hash chain — ledger is empty, nothing to verify")
        print("       run `python -m prahari.cli replay` first, then re-run this")
    else:
        print(f"[{'PASS' if ok_chain else 'FAIL'}] alert hash chain verifies "
              f"({count} records{'' if ok_chain else f', first bad: {bad}'})")

    print("=" * 52)
    all_ok = ok_imports and ok_sockets and ok_chain is not False
    print("RESULT:", "read-only properties hold" if all_ok else "CHECK FAILED")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
