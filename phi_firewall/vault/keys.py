"""Key providers: where master keys live.

Envelope encryption in one picture:

    master key (KMS / env)  --wraps-->  data key (random, per record)  --encrypts-->  PHI

The master key never touches the data directly and can be rotated without
re-encrypting every record: old wrapped data keys stay readable because we
keep old master keys for *decryption only*.
"""
from __future__ import annotations

import base64
import os
import warnings
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key() -> str:
    """A new random 256-bit key, base64 encoded."""
    return base64.b64encode(AESGCM.generate_key(bit_length=256)).decode()


class KeyProvider(Protocol):
    active_key_id: str

    def wrap(self, data_key: bytes) -> tuple[str, bytes]:
        """Encrypt a data key with the active master key. Returns (key_id, wrapped)."""

    def unwrap(self, key_id: str, wrapped: bytes) -> bytes:
        """Decrypt a data key with the master key it was wrapped by."""


class LocalKeyProvider:
    """Master keys from an env string like 'k2:BASE64,k1:BASE64' (first = active).

    Good for local dev and small deployments. In production use a KMS
    (see AwsKmsKeyProvider) so keys never sit in the app's memory or env.
    """

    def __init__(self, spec: str = ""):
        self.keys: dict[str, bytes] = {}
        order: list[str] = []
        for part in [p for p in spec.split(",") if p.strip()]:
            kid, b64 = part.strip().split(":", 1)
            key = base64.b64decode(b64)
            if len(key) != 32:
                raise ValueError(f"master key {kid} must be 32 bytes (got {len(key)})")
            self.keys[kid] = key
            order.append(kid)
        if not order:
            warnings.warn("PHI_FIREWALL_MASTER_KEYS not set: using a temporary key. "
                          "Vault data will be unreadable after restart.", stacklevel=2)
            self.keys["ephemeral"] = AESGCM.generate_key(bit_length=256)
            order.append("ephemeral")
        self.active_key_id = order[0]

    def wrap(self, data_key: bytes) -> tuple[str, bytes]:
        nonce = os.urandom(12)
        wrapped = AESGCM(self.keys[self.active_key_id]).encrypt(nonce, data_key, b"data-key")
        return self.active_key_id, nonce + wrapped

    def unwrap(self, key_id: str, wrapped: bytes) -> bytes:
        if key_id not in self.keys:
            raise KeyError(f"unknown master key id '{key_id}' (was it removed after rotation?)")
        return AESGCM(self.keys[key_id]).decrypt(wrapped[:12], wrapped[12:], b"data-key")


class AwsKmsKeyProvider:
    """Uses AWS KMS to wrap/unwrap data keys. Needs `pip install phi-firewall[aws]`.

    Not exercised by the test suite (needs an AWS account).
    """

    def __init__(self, key_arn: str, region: str | None = None):
        import boto3
        self.kms = boto3.client("kms", region_name=region)
        self.active_key_id = key_arn

    def wrap(self, data_key: bytes) -> tuple[str, bytes]:
        resp = self.kms.encrypt(KeyId=self.active_key_id, Plaintext=data_key)
        return self.active_key_id, resp["CiphertextBlob"]

    def unwrap(self, key_id: str, wrapped: bytes) -> bytes:
        return self.kms.decrypt(CiphertextBlob=wrapped, KeyId=key_id)["Plaintext"]
