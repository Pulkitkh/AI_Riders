"""Tamper-evident alert store.

Each record carries the SHA-256 of its predecessor, so altering any historical
alert breaks the chain and is detectable by re-walking the file. This gives the
chain-of-custody property the problem statement cares about without introducing
a distributed ledger — the theme is called "Blockchain & Cybersecurity", but the
problem statement never asks for a blockchain and a hash chain does the same job
for a fraction of the cost.

Retention defaults to 180 days to match the CERT-In Directions of 2022.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS = "0" * 64
RETENTION_DAYS = 180


class AlertLedger:
    def __init__(self, path: str | Path = "data/alerts.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.seq = 0
        self.prev = GENESIS
        if self.path.exists():
            self._resume()

    def _resume(self) -> None:
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            self.seq = rec["integrity"]["seq"]
            self.prev = rec["integrity"]["sha256"]

    @staticmethod
    def _digest(payload: dict, prev: str, seq: int) -> str:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(f"{prev}|{seq}|{body}".encode()).hexdigest()

    def append(self, record: dict) -> dict:
        self.seq += 1
        digest = self._digest(record, self.prev, self.seq)
        record = dict(record)
        record["integrity"] = {"seq": self.seq, "prev_sha256": self.prev, "sha256": digest}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        self.prev = digest
        return record

    def verify(self) -> tuple[bool, int, str | None]:
        """Re-walk the chain. Returns (ok, records_checked, first_bad_alert_id)."""
        prev, n = GENESIS, 0
        if not self.path.exists():
            return True, 0, None
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            integrity = rec.pop("integrity")
            expected = self._digest(rec, prev, integrity["seq"])
            n += 1
            if expected != integrity["sha256"] or integrity["prev_sha256"] != prev:
                return False, n, rec.get("alert_id")
            prev = integrity["sha256"]
        return True, n, None
