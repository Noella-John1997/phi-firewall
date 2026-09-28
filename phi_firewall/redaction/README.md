# `redaction/` — tokens in, values back out

`redactor.py` has two jobs.

### 1. `Redactor.redact(text, mapping)`

Replaces each detected value according to the policy:

| Action | Result | Reversible? |
| --- | --- | --- |
| tokenize | `[[EMAIL_1]]` | Yes, via the mapping |
| mask | `[AADHAAR]` | No |
| block | raises `BlockedContent` → HTTP 422 | — |
| allow | unchanged | — |

The **same value gets the same token** across all messages in a request, so the LLM can still tell
"the same patient" apart from "a different patient".

### 2. `rehydrate(text, mapping)`

Finds `[[TOKEN]]` patterns in the LLM's answer and swaps the real values back in. Tokens that
aren't in the mapping are left untouched (never guessed).

**Why double square brackets?** Models copy them reliably and they almost never appear in normal text.
