import base64
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phi_firewall.config import Settings  # noqa: E402
from phi_firewall.proxy.upstream import MockUpstream  # noqa: E402

KEY = base64.b64encode(os.urandom(32)).decode()

NOTE = ("Patient: Jane Doe, DOB: 04/12/1987, MRN: AB123456. Email jane.doe@gmail.com, "
        "phone +91 98765 43210, Aadhaar 2345 6789 0124, PAN ABCPE1234F.")


@pytest.fixture
def settings(tmp_path):
    return Settings(master_keys=f"k1:{KEY}", upstream_base_url="mock", upstream_api_key="",
                    firewall_api_keys=[], vault_path=str(tmp_path / "vault.db"),
                    vault_ttl_seconds=60, audit_log_path=str(tmp_path / "audit.jsonl"), policy_path=None)


@pytest.fixture
def mock_upstream():
    return MockUpstream()
