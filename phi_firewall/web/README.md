# `web/` — the browser demo

The UI is served by the same FastAPI app as the proxy (`create_app(serve_ui=True)`), at `/`.
It only uses the public API, so it also shows how a client integrates:

| Endpoint used | Why |
| --- | --- |
| `POST /v1/scan` | Positions and actions of every detected value, to highlight the text (nothing stored) |
| `POST /v1/chat/completions` | The real round trip through the mock LLM |
| `GET /v1/policy` | Shows the active policy as chips |
| `GET /v1/audit/tail`, `GET /v1/audit/verify` | Audit log viewer and hash-chain check |

Inputs are limited to 20,000 characters. If `FIREWALL_API_KEYS` is set, the audit panel shows
"needs API key" because the browser does not send one.

- [`static/`](static/) — the HTML, CSS and JS files.
