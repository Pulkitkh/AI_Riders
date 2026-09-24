#!/usr/bin/env python3
"""Write an integrity manifest for the model artifacts.

An attacker who can modify the appliance filesystem could swap a model JSON and
silently blind a detector without touching a line of code. As a prototype-level
integrity control we record a SHA-256 of every model artifact in a signed-by-
convention manifest; the self-test verifies the live files against it before the
engine is trusted. A production appliance would extend this to a real signature
(an offline key + verification before activation) and a rollback path — this is
the mechanism, stated honestly at the maturity we have implemented.

    python3 scripts/sign_models.py      # regenerate prahari/models/MANIFEST.json
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

MODELS = Path(__file__).resolve().parents[1] / "prahari" / "models"
MANIFEST = MODELS / "MANIFEST.json"


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def build() -> dict:
    files = {}
    for p in sorted(MODELS.glob("*.json")):
        if p.name == MANIFEST.name:
            continue
        files[p.name] = {"sha256": sha256(p), "bytes": p.stat().st_size}
    return {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "algorithm": "sha256", "files": files}


def main() -> int:
    m = build()
    MANIFEST.write_text(json.dumps(m, indent=2), encoding="utf-8")
    print(f"wrote {MANIFEST} ({len(m['files'])} model artifacts)")
    for name, info in m["files"].items():
        print(f"  {name:<22} {info['sha256'][:16]}…  {info['bytes']:>7} B")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
