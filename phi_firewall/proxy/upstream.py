"""Where cleaned requests go: a real OpenAI-compatible API, or a mock."""
from __future__ import annotations

import time
from typing import Protocol

import httpx


class Upstream(Protocol):
    async def chat(self, payload: dict) -> dict: ...


class OpenAICompatibleUpstream:
    """Forwards to any /chat/completions API (OpenAI, Azure, Groq, vLLM, Ollama...)."""

    def __init__(self, base_url: str, api_key: str, timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.client = httpx.AsyncClient(timeout=timeout)

    async def chat(self, payload: dict) -> dict:
        r = await self.client.post(f"{self.base_url}/chat/completions", json=payload,
                                   headers={"Authorization": f"Bearer {self.api_key}"})
        r.raise_for_status()
        return r.json()


class MockUpstream:
    """Pretends to be an LLM. It repeats what it received, so you can SEE that
    the model only ever gets tokens — and that the firewall restores them."""

    def __init__(self):
        self.last_payload: dict | None = None

    async def chat(self, payload: dict) -> dict:
        self.last_payload = payload
        user_msgs = [m for m in payload.get("messages", []) if m.get("role") == "user"]
        last = user_msgs[-1]["content"] if user_msgs else ""
        if isinstance(last, list):
            last = " ".join(p.get("text", "") for p in last if isinstance(p, dict))
        return {
            "id": "mock-1", "object": "chat.completion", "created": int(time.time()),
            "model": payload.get("model", "mock"),
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": f"Summary (mock LLM saw): {last}"}}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }


def upstream_from_url(base_url: str, api_key: str) -> Upstream:
    return MockUpstream() if base_url == "mock" else OpenAICompatibleUpstream(base_url, api_key)
