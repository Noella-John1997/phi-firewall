"""Token vault: remembers which token stands for which (encrypted) value.

Stored in SQLite so it survives restarts and works across uvicorn workers on
one machine. Swap for Redis/DynamoDB when you scale out. Entries expire after
`ttl_seconds` - the firewall only needs them for the life of one LLM call.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time

from .crypto import EnvelopeCipher


class TokenVault:
    def __init__(self, cipher: EnvelopeCipher, path: str = ":memory:", ttl_seconds: int = 900):
        self.cipher = cipher
        self.ttl = ttl_seconds
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("""CREATE TABLE IF NOT EXISTS vault (
            request_id TEXT PRIMARY KEY, blob TEXT NOT NULL, expires_at REAL NOT NULL)""")
        self.db.commit()

    def put(self, request_id: str, mapping: dict[str, str]) -> None:
        """Encrypt the whole token->value map for one request."""
        blob = self.cipher.encrypt(json.dumps(mapping).encode(), aad=request_id.encode())
        with self.lock:
            self.db.execute("REPLACE INTO vault VALUES (?, ?, ?)", (request_id, blob, time.time() + self.ttl))
            self.db.commit()

    def get(self, request_id: str) -> dict[str, str] | None:
        with self.lock:
            row = self.db.execute("SELECT blob, expires_at FROM vault WHERE request_id=?",
                                  (request_id,)).fetchone()
        if not row or row[1] < time.time():
            return None
        return json.loads(self.cipher.decrypt(row[0], aad=request_id.encode()))

    def delete(self, request_id: str) -> None:
        with self.lock:
            self.db.execute("DELETE FROM vault WHERE request_id=?", (request_id,))
            self.db.commit()

    def purge_expired(self) -> int:
        with self.lock:
            cur = self.db.execute("DELETE FROM vault WHERE expires_at < ?", (time.time(),))
            self.db.commit()
            return cur.rowcount
