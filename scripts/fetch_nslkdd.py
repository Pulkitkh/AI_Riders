#!/usr/bin/env python3
"""Download the NSL-KDD benchmark into data/nslkdd/ so eval/nslkdd_eval.py can
run on real public data. The dataset is NOT committed to the repo (it is public
and ~21 MB); this fetches it on demand, with only the standard library.

    python3 scripts/fetch_nslkdd.py
"""
from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

BASE = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master"
FILES = {"KDDTrain+.txt": "KDDTrain%2B.txt", "KDDTest+.txt": "KDDTest%2B.txt"}
OUT = Path(__file__).resolve().parents[1] / "data" / "nslkdd"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for local, remote in FILES.items():
        dst = OUT / local
        if dst.exists() and dst.stat().st_size > 1000:
            print(f"  have {local} ({dst.stat().st_size:,} B)")
            continue
        url = f"{BASE}/{remote}"
        print(f"  fetching {local} from {url} ...")
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                dst.write_bytes(r.read())
        except Exception as e:                       # noqa: BLE001
            print(f"  ERROR: {e}\n  Download {local} manually into {OUT}/", file=sys.stderr)
            return 1
        print(f"    wrote {dst.stat().st_size:,} B")
    print(f"\nNSL-KDD ready in {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
