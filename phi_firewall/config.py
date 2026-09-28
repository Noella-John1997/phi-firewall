"""All settings come from environment variables (12-factor style)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _list(name: str) -> list[str]:
    return [x.strip() for x in os.getenv(name, "").split(",") if x.strip()]


@dataclass
class Settings:
    master_keys: str = field(default_factory=lambda: os.getenv("PHI_FIREWALL_MASTER_KEYS", ""))
    upstream_base_url: str = field(default_factory=lambda: os.getenv("UPSTREAM_BASE_URL", "mock"))
    upstream_api_key: str = field(default_factory=lambda: os.getenv("UPSTREAM_API_KEY", ""))
    firewall_api_keys: list[str] = field(default_factory=lambda: _list("FIREWALL_API_KEYS"))
    vault_path: str = field(default_factory=lambda: os.getenv("VAULT_PATH", "vault.db"))
    vault_ttl_seconds: int = field(default_factory=lambda: int(os.getenv("VAULT_TTL_SECONDS", "900")))
    audit_log_path: str = field(default_factory=lambda: os.getenv("AUDIT_LOG_PATH", "audit.jsonl"))
    policy_path: str | None = field(default_factory=lambda: os.getenv("POLICY_PATH") or None)
