# `phi_firewall/` — the package

| File / folder | Purpose |
| --- | --- |
| `cli.py` | `phi-firewall serve`, `scan`, `gen-key`, `verify-audit` |
| `config.py` | Reads settings from environment variables |
| `detectors/` | Finds sensitive values in text |
| `policy/` | Decides what to do with each kind of value |
| `redaction/` | Replaces values with tokens and restores them |
| `vault/` | Encrypts and stores token maps |
| `audit/` | Tamper-evident log of every request |
| `proxy/` | The FastAPI web service |

**Request flow:** `proxy` receives a chat request → `redaction` asks `detectors` for spans and
`policy` for actions → token map goes into the encrypted `vault` → cleaned request goes upstream →
answer is rehydrated → an `audit` record is written.
