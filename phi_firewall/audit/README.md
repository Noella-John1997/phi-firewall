# `audit/` - a log you can trust

HIPAA requires audit controls: a record of who accessed what, when. A plain log file can be
edited quietly. This one can't - not without being caught.

## How the hash chain works

Each line stores:

- the event (`chat`, `redact`, `rehydrate`, `blocked`, …), time, client hash, entity **counts**
- `prev` - the hash of the line before it
- `hash` - SHA-256 of `prev` + this line's content

Change one character in line 40 and its hash no longer matches, and line 41's `prev` no longer
matches either. `verify_chain()` returns the first broken line.

```bash
phi-firewall verify-audit audit.jsonl
# {"ok": true, "first_bad_line": null}
```

**No PHI is ever written here** - only how many of each entity type were found. There's a test for that.
