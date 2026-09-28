from pathlib import Path

from fastapi.testclient import TestClient

from phi_firewall.proxy import create_app

from conftest import NOTE


def _client(settings, upstream):
    return TestClient(create_app(settings, upstream))


def test_chat_llm_never_sees_phi_but_user_gets_it_back(settings, mock_upstream):
    c = _client(settings, mock_upstream)
    r = c.post("/v1/chat/completions", json={"model": "gpt-x", "messages": [
        {"role": "system", "content": "You are a clinical scribe."},
        {"role": "user", "content": NOTE}]})
    assert r.status_code == 200
    sent = str(mock_upstream.last_payload)
    for secret in ["Jane Doe", "jane.doe@gmail.com", "AB123456", "2345 6789 0124"]:
        assert secret not in sent, f"{secret} leaked to the LLM"
    answer = r.json()["choices"][0]["message"]["content"]
    assert "Jane Doe" in answer and "jane.doe@gmail.com" in answer
    assert "PERSON=1" in r.headers["X-PHI-Entities"]


def test_multipart_content(settings, mock_upstream):
    c = _client(settings, mock_upstream)
    c.post("/v1/chat/completions", json={"model": "m", "messages": [
        {"role": "user", "content": [{"type": "text", "text": "email jane.doe@gmail.com"}]}]})
    assert "jane.doe@gmail.com" not in str(mock_upstream.last_payload)


def test_blocked_request_returns_422(settings, mock_upstream):
    c = _client(settings, mock_upstream)
    r = c.post("/v1/chat/completions", json={"model": "m", "messages": [
        {"role": "user", "content": "charge card 4111 1111 1111 1111"}]})
    assert r.status_code == 422
    assert r.json()["entities"] == ["CREDIT_CARD"]
    assert mock_upstream.last_payload is None  # never forwarded


def test_redact_then_rehydrate(settings, mock_upstream):
    c = _client(settings, mock_upstream)
    r = c.post("/v1/redact", json={"text": "Patient: Jane Doe"}).json()
    assert r["redacted"] == "Patient: [[PERSON_1]]"
    back = c.post("/v1/rehydrate", json={"request_id": r["request_id"],
                                          "text": "Call [[PERSON_1]] tomorrow"}).json()
    assert back["text"] == "Call Jane Doe tomorrow"


def test_api_key_required_when_configured(settings, mock_upstream):
    settings.firewall_api_keys = ["secret-1"]
    c = _client(settings, mock_upstream)
    assert c.post("/v1/redact", json={"text": "x"}).status_code == 401
    assert c.post("/v1/redact", json={"text": "x"}, headers={"X-Firewall-Key": "secret-1"}).status_code == 200


def test_audit_log_has_no_phi_and_verifies(settings, mock_upstream):
    c = _client(settings, mock_upstream)
    c.post("/v1/chat/completions", json={"model": "m", "messages": [{"role": "user", "content": NOTE}]})
    log = Path(settings.audit_log_path).read_text()
    assert "Jane" not in log and "gmail" not in log
    assert c.get("/v1/audit/verify").json() == {"ok": True, "first_bad_line": None}


def test_streaming_rejected(settings, mock_upstream):
    c = _client(settings, mock_upstream)
    assert c.post("/v1/chat/completions", json={"stream": True, "messages": []}).status_code == 400
