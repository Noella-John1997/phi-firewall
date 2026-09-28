# `vault/` — encrypted storage for token maps

The mapping `{"PERSON_1": "Jane Doe", ...}` *is* PHI, so it must be encrypted at rest.

## Envelope encryption (simple version)

```
master key  ──wraps──►  data key (new random key per record)  ──encrypts──►  the mapping
(env or KMS)
```

- Every record gets its **own random data key** and **nonce**, so two identical maps encrypt differently.
- Only the small data key is encrypted with the master key. With AWS KMS, the master key **never leaves KMS**.
- **AES-256-GCM** is *authenticated*: any change to the stored bytes makes decryption fail.
- The `request_id` is passed as **associated data (AAD)**, so a record can't be copied into another request.

## Key rotation

`PHI_FIREWALL_MASTER_KEYS="k2:NEW,k1:OLD"` → new data is wrapped with `k2`, old data is still
readable with `k1`. Remove `k1` once old records have expired (TTL).

## Files

| File | Purpose |
| --- | --- |
| `keys.py` | `LocalKeyProvider` (env keys), `AwsKmsKeyProvider` (optional), `generate_key()` |
| `crypto.py` | `EnvelopeCipher.encrypt()` / `decrypt()` |
| `store.py` | `TokenVault`: SQLite table `request_id → encrypted blob` with expiry |
