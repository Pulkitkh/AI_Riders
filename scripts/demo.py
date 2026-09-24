"""Everything a judge needs to see, on any operating system.

`make` is not installed on a stock Windows machine, and the demo laptop is not
always the one you prepared. This runs the same sequence the Makefile does,
using nothing but the Python that is already running it.

    python scripts/demo.py            # the full sequence, about three minutes
    python scripts/demo.py --quick    # skip the slow evaluation passes
    python scripts/demo.py --list     # just show what it would run
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable          # the interpreter running this, not a guess at one

sys.path.insert(0, str(ROOT))
from prahari.cli import COLOUR   # noqa: E402  (same terminal check the CLI uses)

BOLD = "\033[1m" if COLOUR else ""
GREEN = "\033[32m" if COLOUR else ""
RED = "\033[31m" if COLOUR else ""
OFF = "\033[0m" if COLOUR else ""

PCAP = "data/demo.pcap"

STEPS: list[tuple[str, list[str], bool]] = [
    # label, argv after the interpreter, slow?
    ("engine tests", ["tests/test_prahari.py"], False),
    ("web tests", ["tests/test_web.py"], False),
    ("build a real capture", ["scripts/make_pcap.py", "--out", PCAP,
                              "--duration", "1800"], True),
    ("analyse real packets", ["-m", "prahari.cli", "live", "--pcap", PCAP], False),
    ("read-only self-test", ["-m", "prahari.cli", "selftest"], False),
    ("canonical evaluation", ["eval/report.py"], True),
    ("unseen-family (OOD) experiment", ["eval/unseen_family.py"], True),
    ("jitter sweep", ["eval/jitter_sweep.py"], True),
]


def run(label: str, argv: list[str]) -> bool:
    print(f"\n{BOLD}=== {label} " + "=" * max(4, 66 - len(label)) + OFF, flush=True)
    t = time.time()
    rc = subprocess.run([PY] + argv, cwd=ROOT).returncode
    mark = f"{GREEN}ok{OFF}" if rc == 0 else f"{RED}FAILED (exit {rc}){OFF}"
    print(f"--- {label}: {mark} in {time.time() - t:.1f}s", flush=True)
    return rc == 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="skip the slow steps")
    ap.add_argument("--list", action="store_true", help="print the steps and exit")
    a = ap.parse_args(argv)

    steps = [s for s in STEPS if not (a.quick and s[2])]
    if a.list:
        for label, args, slow in steps:
            print(f"  {label:24} {PY} {' '.join(args)}{'   (slow)' if slow else ''}")
        return 0

    # The capture is expensive and deterministic, so keep one if it is there.
    if (ROOT / PCAP).exists():
        steps = [s for s in steps if s[0] != "build a real capture"]
        print(f"using the existing {PCAP} "
              f"({(ROOT / PCAP).stat().st_size / 1e6:.0f} MB)")

    failed = [label for label, args, _ in steps if not run(label, args)]
    print("\n" + "=" * 70)
    if failed:
        print(f"{RED}{len(failed)} step(s) failed: {', '.join(failed)}{OFF}")
        print("Do not demo until this is green. Fix it now, not on the day.")
        return 1
    print(f"{GREEN}all green{OFF} — see docs/DEMO.md for how to present this")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
