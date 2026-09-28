"""End-to-end demo. Start the firewall first:

    export PHI_FIREWALL_MASTER_KEYS=$(phi-firewall gen-key)
    phi-firewall serve

then in another terminal:

    python examples/demo_client.py
"""
from pathlib import Path

import httpx

BASE = "http://127.0.0.1:8000"
note = Path(__file__).with_name("sample_note.txt").read_text()

print("=== 1. What the LLM will see ===")
r = httpx.post(f"{BASE}/v1/redact", json={"text": note}).json()
print(r["redacted"])
print("entities:", r["entities"])

print("\n=== 2. Full chat call through the firewall ===")
resp = httpx.post(f"{BASE}/v1/chat/completions", json={
    "model": "gpt-4o-mini",
    "messages": [{"role": "system", "content": "Summarize this discharge note in 3 bullet points."},
                 {"role": "user", "content": note}],
}, timeout=60)
print("entities header:", resp.headers.get("X-PHI-Entities"))
print(resp.json()["choices"][0]["message"]["content"])

print("\n=== 3. Card numbers are blocked ===")
blocked = httpx.post(f"{BASE}/v1/chat/completions", json={
    "model": "m", "messages": [{"role": "user", "content": "Bill card 4111 1111 1111 1111"}]})
print(blocked.status_code, blocked.json())

print("\n=== 4. Audit log integrity ===")
print(httpx.get(f"{BASE}/v1/audit/verify").json())
