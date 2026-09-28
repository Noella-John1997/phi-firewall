# `proxy/` - the web service

| File | Purpose |
| --- | --- |
| `app.py` | `create_app(settings, upstream)` builds the FastAPI app with all endpoints |
| `upstream.py` | `OpenAICompatibleUpstream` (real LLM) and `MockUpstream` (echo, for demos/tests) |

## `/v1/chat/completions` step by step

1. Check `X-Firewall-Key` if client keys are configured.
2. Reject `stream: true` (not supported yet).
3. Redact every message (plain string content and multi-part `text` parts), sharing one token map.
4. Save the map in the encrypted vault.
5. Forward the cleaned request upstream. Upstream failure → HTTP 502 + audit record.
6. Rehydrate tokens in every choice's `message.content`.
7. Delete the vault entry, write an audit record, return the response with `X-PHI-Entities`.

Run it: `phi-firewall serve` or
`uvicorn phi_firewall.proxy.app:app --factory --port 8000`.
