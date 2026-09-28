import base64
import os

import pytest
from cryptography.exceptions import InvalidTag

from phi_firewall.vault import EnvelopeCipher, LocalKeyProvider, TokenVault


def _key():
    return base64.b64encode(os.urandom(32)).decode()


def test_encrypt_decrypt_round_trip():
    c = EnvelopeCipher(LocalKeyProvider(f"k1:{_key()}"))
    blob = c.encrypt(b"jane@x.com", aad=b"req-1")
    assert b"jane" not in blob.encode()
    assert c.decrypt(blob, aad=b"req-1") == b"jane@x.com"


def test_wrong_aad_fails():
    c = EnvelopeCipher(LocalKeyProvider(f"k1:{_key()}"))
    blob = c.encrypt(b"secret", aad=b"req-1")
    with pytest.raises(InvalidTag):
        c.decrypt(blob, aad=b"req-2")


def test_key_rotation_old_data_still_readable():
    k1, k2 = _key(), _key()
    old = EnvelopeCipher(LocalKeyProvider(f"k1:{k1}")).encrypt(b"old secret")
    rotated = EnvelopeCipher(LocalKeyProvider(f"k2:{k2},k1:{k1}"))  # k2 active, k1 kept
    assert rotated.decrypt(old) == b"old secret"
    assert '"kid":"k2"' in rotated.encrypt(b"new")


def test_bad_key_length_rejected():
    with pytest.raises(ValueError):
        LocalKeyProvider("k1:" + base64.b64encode(b"short").decode())


def test_vault_ttl_expiry(tmp_path):
    v = TokenVault(EnvelopeCipher(LocalKeyProvider(f"k1:{_key()}")), str(tmp_path / "v.db"), ttl_seconds=-1)
    v.put("r1", {"EMAIL_1": "a@b.com"})
    assert v.get("r1") is None
    assert v.purge_expired() == 1


def test_vault_is_encrypted_on_disk(tmp_path):
    path = tmp_path / "v.db"
    v = TokenVault(EnvelopeCipher(LocalKeyProvider(f"k1:{_key()}")), str(path))
    v.put("r1", {"EMAIL_1": "jane.doe@gmail.com"})
    assert v.get("r1") == {"EMAIL_1": "jane.doe@gmail.com"}
    assert b"jane.doe" not in path.read_bytes()
