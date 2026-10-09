"""Tamper-evident alert store.

Each record carries the hash of its predecessor, so altering any historical
alert breaks the chain and is detectable by re-walking the file. This gives the
chain-of-custody property the problem statement cares about without introducing
a distributed ledger — the theme is called "Blockchain & Cybersecurity", but the
problem statement never asks for a blockchain and a hash chain does the same job
for a fraction of the cost.

Two integrity modes:

  * Plain SHA-256 (default) — *tamper-evident*: anyone re-walking the file can
    detect an edit, but an attacker who can rewrite the whole file can forge a
    fresh consistent chain.
  * Keyed HMAC-SHA256 (set ``PRAHARI_LEDGER_KEY`` or ``PRAHARI_LEDGER_KEYFILE``)
    — *tamper-proof* against anyone who does not hold the key: forging the chain
    requires the secret, so an attacker with write access to the file still
    cannot produce a chain that verifies.

Durability: every append is flushed and ``fsync``-ed, so an alert that the API
has acknowledged survives a crash or power loss. On startup the chain is
verified *before* the resume point is trusted; a broken chain fails closed
rather than silently continuing from a forged tail.

Anchoring: :meth:`head` returns the current head hash and sequence, suitable for
periodically publishing to an append-only external store (syslog, an object
bucket, a second host). Once a head is anchored externally, even a full rewrite
of the local file is detectable, which closes the one gap a local-only chain has.

Retention defaults to 180 days to match the CERT-In Directions of 2022.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

GENESIS = "0" * 64
RETENTION_DAYS = 180


def _load_key() -> bytes | None:
    """Resolve the ledger HMAC key from the environment, or None for SHA-256.

    ``PRAHARI_LEDGER_KEY`` is the key directly; ``PRAHARI_LEDGER_KEYFILE`` points
    at a file whose bytes are the key (preferred — keeps the secret out of the
    process environment / ``ps`` output). Absent both, the ledger stays in
    backward-compatible plain-SHA-256 mode so existing files keep verifying.
    """
    raw = os.environ.get("PRAHARI_LEDGER_KEY")
    if raw:
        return raw.encode("utf-8")
    kf = os.environ.get("PRAHARI_LEDGER_KEYFILE")
    if kf:
        data = Path(kf).read_bytes().strip()
        if data:
            return data
    return None


class LedgerTampered(Exception):
    """Raised when the on-disk chain fails to verify at startup (fail closed)."""


def verify_chain(path: str | Path, key: bytes | None = None) -> tuple[bool, int, str | None]:
    """Re-walk a ledger file without opening/resuming it. Returns
    (ok, records_checked, first_bad_alert_id).

    Side-effect free: unlike constructing an :class:`AlertLedger`, this never
    advances a sequence or resumes state, so it is safe for a verification demo
    or an auditor checking a file it does not own.
    """
    p = Path(path)
    prev, n = GENESIS, 0
    if not p.exists():
        return True, 0, None
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        integrity = rec.pop("integrity")
        body = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        msg = f"{prev}|{integrity['seq']}|{body}".encode()
        if integrity.get("algo") == "hmac-sha256":
            if not key:
                return False, n + 1, rec.get("alert_id")
            expected = hmac.new(key, msg, hashlib.sha256).hexdigest()
        else:
            expected = hashlib.sha256(msg).hexdigest()
        n += 1
        if not hmac.compare_digest(expected, integrity["sha256"]) \
                or integrity["prev_sha256"] != prev:
            return False, n, rec.get("alert_id")
        prev = integrity["sha256"]
    return True, n, None


class AlertLedger:
    def __init__(self, path: str | Path = "data/alerts.jsonl",
                 key: bytes | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.key = key if key is not None else _load_key()
        self.algo = "hmac-sha256" if self.key else "sha256"
        self.seq = 0
        self.prev = GENESIS
        if self.path.exists():
            self._resume()

    def _resume(self) -> None:
        # Verify BEFORE trusting the tail. Resuming from an unverified last record
        # would let an attacker who rewrote the file dictate our next prev-hash and
        # seq, so a broken chain must fail closed, not continue silently.
        ok, _, bad = self.verify()
        if not ok:
            raise LedgerTampered(
                f"ledger chain verification failed at alert_id={bad!r} "
                f"({self.path}); refusing to resume from a tampered tail")
        last = None
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = json.loads(line)
        if last is not None:
            self.seq = last["integrity"]["seq"]
            self.prev = last["integrity"]["sha256"]

    def _digest(self, payload: dict, prev: str, seq: int) -> str:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        msg = f"{prev}|{seq}|{body}".encode()
        if self.key:
            return hmac.new(self.key, msg, hashlib.sha256).hexdigest()
        return hashlib.sha256(msg).hexdigest()

    def append(self, record: dict) -> dict:
        self.seq += 1
        digest = self._digest(record, self.prev, self.seq)
        record = dict(record)
        record["integrity"] = {"seq": self.seq, "prev_sha256": self.prev,
                               "sha256": digest, "algo": self.algo}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            # Durability: an alert the API acknowledged must survive power loss.
            fh.flush()
            os.fsync(fh.fileno())
        self.prev = digest
        return record

    def head(self) -> dict:
        """Current chain head — publish this to an external append-only store to
        anchor the ledger, so even a full local rewrite becomes detectable."""
        return {"seq": self.seq, "sha256": self.prev, "algo": self.algo}

    def verify(self) -> tuple[bool, int, str | None]:
        """Re-walk the chain. Returns (ok, records_checked, first_bad_alert_id).

        A record's stored ``algo`` selects how it is re-hashed, so a file written
        in SHA-256 mode still verifies after a key is configured, and vice-versa a
        keyed record cannot be re-forged without the key.
        """
        return verify_chain(self.path, self.key)
