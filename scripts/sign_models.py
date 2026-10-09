#!/usr/bin/env python3
"""Write an integrity manifest for the model artifacts.

An attacker who can modify the appliance filesystem could swap a model JSON and
silently blind a detector without touching a line of code. We record a SHA-256
of every model artifact in a manifest, and — when a signing key is configured —
HMAC-sign the manifest itself so the attacker cannot simply regenerate a fresh
consistent manifest to match a swapped model. The self-test verifies the live
files against the manifest, and the manifest against the key, before the engine
is trusted; `prahari.selftest.enforce_model_integrity()` makes that a hard gate
at engine startup (fail closed).

    # tamper-evident only (no key): records hashes, manifest is unsigned
    python3 scripts/sign_models.py

    # tamper-proof: sign the manifest so it cannot be forged without the key
    PRAHARI_MODEL_KEYFILE=/etc/prahari/model.key python3 scripts/sign_models.py

A production appliance would move the key to an HSM / offline signer and add a
rollback path — this is the same mechanism at the maturity we have implemented.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from prahari.selftest import (canonical_manifest_bytes, model_key,  # noqa: E402
                              sha256_file)

MODELS = ROOT / "prahari" / "models"
MANIFEST = MODELS / "MANIFEST.json"


def build() -> dict:
    files = {}
    for p in sorted(MODELS.glob("*.json")):
        if p.name == MANIFEST.name:
            continue
        files[p.name] = {"sha256": sha256_file(p), "bytes": p.stat().st_size}
    m = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "algorithm": "sha256", "files": files}
    key = model_key()
    if key:
        import hashlib
        import hmac
        sig = hmac.new(key, canonical_manifest_bytes(m), hashlib.sha256).hexdigest()
        m["signature"] = {"algo": "hmac-sha256", "value": sig}
    return m


def main() -> int:
    m = build()
    MANIFEST.write_text(json.dumps(m, indent=2), encoding="utf-8")
    signed = "signature" in m
    print(f"wrote {MANIFEST} ({len(m['files'])} model artifacts, "
          f"{'HMAC-signed' if signed else 'UNSIGNED — set PRAHARI_MODEL_KEY to sign'})")
    for name, info in m["files"].items():
        print(f"  {name:<22} {info['sha256'][:16]}…  {info['bytes']:>7} B")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
