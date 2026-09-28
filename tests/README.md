# `tests/` - automated tests

```bash
pytest -q
```

| File | What it proves |
| --- | --- |
| `test_validators.py` | Luhn, Verhoeff (Aadhaar), SSN, PAN and NPI rules accept valid and reject invalid numbers |
| `test_redaction.py` | All entities are found, no false positives on plain clinical text, tokens are consistent, round-trip works, block/allow policies work |
| `test_vault.py` | Encryption round-trip, wrong AAD fails, **key rotation**, TTL expiry, **nothing readable on disk** |
| `test_audit.py` | Hash chain verifies, **edited and deleted lines are detected**, chain survives restarts |
| `test_proxy.py` | **The LLM never receives the raw PHI** but the user gets it back, multi-part messages, 422 blocking, redact/rehydrate API, API-key auth, **no PHI in the audit log** |
| `test_proxy.py` (web part) | Demo page loads, `/v1/scan` spans and blocking, policy endpoint, audit tail has no values, input size limit |
| `conftest.py` | Shared fixtures: temp settings, mock upstream, sample note |
