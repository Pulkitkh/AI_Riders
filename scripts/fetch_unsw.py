#!/usr/bin/env python3
"""Fetch the UNSW-NB15 pre-split benchmark into data/unsw/ for eval/unsw_eval.py.

UNSW-NB15's official partition is two CSVs — UNSW_NB15_training-set.csv (~82k
flows) and UNSW_NB15_testing-set.csv (~175k flows). They are public but large
(15-32 MB) and are almost always stored via git-LFS or on hosts that a locked-down
build environment blocks, so — unlike NSL-KDD — a single guaranteed raw URL does
not exist. This script tries a list of candidate mirrors with the standard library
only, and if none is reachable it tells you exactly where to drop the files.

    python3 scripts/fetch_unsw.py

The data is NOT committed to the repo (public, and gitignored under data/).
"""
from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "data" / "unsw"
FILES = ("UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv")

# Candidate mirrors, tried in order. Add your own first if you have a reachable
# one. These are best-effort: LFS-backed copies will return a pointer, not data,
# and the script detects and rejects that.
MIRRORS = (
    "https://raw.githubusercontent.com/Gwlz/project35_backend_dashboard/main",
    "https://raw.githubusercontent.com/jamshaid120/UNSW_NB15-Complete-dataset/main",
)


def _looks_like_lfs_pointer(data: bytes) -> bool:
    return data[:100].lstrip().startswith(b"version https://git-lfs")


def _valid_csv(data: bytes) -> bool:
    head = data[:200].lstrip(b"\xef\xbb\xbf").lower()
    # a real file starts with the header and is clearly larger than a sample
    return head.startswith(b"id,dur,proto") and len(data) > 1_000_000


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    ok = True
    for fname in FILES:
        dst = OUT / fname
        if dst.exists() and dst.stat().st_size > 1_000_000:
            print(f"  have {fname} ({dst.stat().st_size:,} B)")
            continue
        got = False
        for base in MIRRORS:
            url = f"{base}/{fname}"
            try:
                with urllib.request.urlopen(url, timeout=60) as r:
                    data = r.read()
                if _looks_like_lfs_pointer(data) or not _valid_csv(data):
                    continue
                dst.write_bytes(data)
                print(f"  fetched {fname} ({len(data):,} B) from {base}")
                got = True
                break
            except Exception:                                   # noqa: BLE001
                continue
        if not got:
            ok = False
            print(f"  could NOT fetch {fname}", file=sys.stderr)

    if not ok:
        print(
            "\nUNSW-NB15 could not be downloaded automatically in this environment.\n"
            "It is public — get the two official CSVs from any of:\n"
            "  * Kaggle: 'UNSW-NB15' (mrwellsdavid / dhoogla) — the *-set.csv pair\n"
            "  * https://research.unsw.edu.au/projects/unsw-nb15-dataset (CSV Files/\n"
            "    'a part of training and testing set')\n"
            f"and place them here:\n  {OUT}/UNSW_NB15_training-set.csv\n"
            f"  {OUT}/UNSW_NB15_testing-set.csv\n"
            "Then re-run:  python3 eval/unsw_eval.py", file=sys.stderr)
        return 1
    print(f"\nUNSW-NB15 ready in {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
