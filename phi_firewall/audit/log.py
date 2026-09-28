"""Tamper-evident audit log (a mini blockchain in a JSONL file).

Every record stores the hash of the previous record. If someone edits or
deletes a line, every hash after it stops matching and `verify_chain` points
at the first broken line. HIPAA requires audit controls (45 CFR 164.312(b));
this is a simple, dependency-free way to make logs trustworthy.

We NEVER log PHI values — only counts per entity type.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path

GENESIS = "0" * 64


def _hash(prev: str, body: dict) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + canonical).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.last_hash = GENESIS
        if self.path.exists():
            lines = self.path.read_text().strip().splitlines()
            if lines:
                self.last_hash = json.loads(lines[-1])["hash"]

    def write(self, event: str, **fields) -> dict:
        with self.lock:
            body = {"ts": round(time.time(), 3), "event": event, **fields}
            record = {**body, "prev": self.last_hash, "hash": _hash(self.last_hash, body)}
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, sort_keys=True) + "\n")
            self.last_hash = record["hash"]
            return record


def verify_chain(path: str | Path) -> tuple[bool, int | None]:
    """Return (ok, first_bad_line_number)."""
    prev = GENESIS
    p = Path(path)
    if not p.exists():
        return True, None
    for i, line in enumerate(p.read_text().splitlines(), start=1):
        rec = json.loads(line)
        body = {k: v for k, v in rec.items() if k not in ("prev", "hash")}
        if rec["prev"] != prev or rec["hash"] != _hash(prev, body):
            return False, i
        prev = rec["hash"]
    return True, None
