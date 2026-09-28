"""AES-256-GCM envelope encryption for small secrets (the PHI values)."""
from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keys import KeyProvider


class EnvelopeCipher:
    """Each call to encrypt() makes a fresh data key and a fresh 96-bit nonce.

    Why GCM? It is *authenticated*: if anyone flips a bit in the stored
    ciphertext, decryption fails loudly instead of returning garbage.
    `aad` (associated data) binds the ciphertext to its context, e.g. the
    request id, so a record can't be copied into another request.
    """

    def __init__(self, keys: KeyProvider):
        self.keys = keys

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> str:
        data_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        ct = AESGCM(data_key).encrypt(nonce, plaintext, aad)
        kid, wrapped = self.keys.wrap(data_key)
        blob = {"v": 1, "kid": kid, "wk": base64.b64encode(wrapped).decode(),
                "n": base64.b64encode(nonce).decode(), "ct": base64.b64encode(ct).decode()}
        return json.dumps(blob, separators=(",", ":"))

    def decrypt(self, blob: str, aad: bytes = b"") -> bytes:
        d = json.loads(blob)
        data_key = self.keys.unwrap(d["kid"], base64.b64decode(d["wk"]))
        return AESGCM(data_key).decrypt(base64.b64decode(d["n"]), base64.b64decode(d["ct"]), aad)
