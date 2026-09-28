"""Point the official OpenAI SDK at the firewall - no other code changes.

    pip install openai
    export UPSTREAM_BASE_URL=https://api.openai.com/v1 UPSTREAM_API_KEY=sk-...
    export PHI_FIREWALL_MASTER_KEYS=$(phi-firewall gen-key)
    phi-firewall serve
    python examples/use_with_openai_sdk.py
"""
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8000/v1", api_key="not-used-by-firewall")
out = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Write a short appointment reminder for Patient: Jane Doe, phone +91 98765 43210."}],
)
print(out.choices[0].message.content)  # contains the real name and phone, restored by the firewall
