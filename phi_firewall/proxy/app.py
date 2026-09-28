"""The FastAPI service.

Endpoints
---------
POST /v1/chat/completions   OpenAI-compatible. Redact -> forward -> rehydrate.
POST /v1/redact             Redact text, keep the mapping in the vault, return a request_id.
POST /v1/rehydrate          Restore tokens in text using a request_id.
GET  /v1/audit/verify       Check the audit log hash chain.
GET  /health
"""
from __future__ import annotations

import hashlib
import time
import uuid
from collections import Counter

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ..audit import AuditLog, verify_chain
from ..config import Settings
from ..detectors import DetectionEngine
from ..policy import load_policy
from ..redaction import BlockedContent, Redactor, rehydrate
from ..vault import EnvelopeCipher, LocalKeyProvider, TokenVault
from .upstream import Upstream, upstream_from_url


class RedactBody(BaseModel):
    text: str


class RehydrateBody(BaseModel):
    request_id: str
    text: str


def _counts_header(c: Counter) -> str:
    return ",".join(f"{k}={v}" for k, v in sorted(c.items())) or "none"


def create_app(settings: Settings | None = None, upstream: Upstream | None = None) -> FastAPI:
    s = settings or Settings()
    redactor = Redactor(DetectionEngine(), load_policy(s.policy_path))
    vault = TokenVault(EnvelopeCipher(LocalKeyProvider(s.master_keys)), s.vault_path, s.vault_ttl_seconds)
    audit = AuditLog(s.audit_log_path)
    up = upstream or upstream_from_url(s.upstream_base_url, s.upstream_api_key)

    app = FastAPI(title="PHI Firewall", version="0.1.0",
                  description="Strips PHI/PII from LLM traffic and restores it in responses.")
    app.state.upstream = up
    app.state.vault = vault

    def client_id(x_firewall_key: str | None = Header(default=None)) -> str:
        if s.firewall_api_keys and x_firewall_key not in s.firewall_api_keys:
            raise HTTPException(401, "missing or invalid X-Firewall-Key")
        # Log a short hash of the key, never the key itself.
        return hashlib.sha256((x_firewall_key or "anonymous").encode()).hexdigest()[:12]

    @app.exception_handler(BlockedContent)
    async def _blocked(_: Request, exc: BlockedContent):
        audit.write("blocked", entities=sorted(set(exc.entities)))
        return JSONResponse(status_code=422, content={"error": "blocked_by_policy",
                                                      "entities": sorted(set(exc.entities))})

    @app.get("/health")
    def health():
        return {"ok": True, "upstream": s.upstream_base_url}

    @app.post("/v1/redact")
    def redact(body: RedactBody, cid: str = Depends(client_id)):
        rid = uuid.uuid4().hex
        res = redactor.redact(body.text)
        vault.put(rid, res.mapping)
        audit.write("redact", request_id=rid, client=cid, entities=dict(res.counts))
        return {"request_id": rid, "redacted": res.text, "entities": dict(res.counts)}

    @app.post("/v1/rehydrate")
    def rehydrate_ep(body: RehydrateBody, cid: str = Depends(client_id)):
        mapping = vault.get(body.request_id)
        if mapping is None:
            raise HTTPException(404, "unknown or expired request_id")
        audit.write("rehydrate", request_id=body.request_id, client=cid)
        return {"text": rehydrate(body.text, mapping)}

    @app.post("/v1/chat/completions")
    async def chat(payload: dict, cid: str = Depends(client_id)):
        if payload.get("stream"):
            raise HTTPException(400, "streaming is not supported yet (see README roadmap)")
        t0 = time.perf_counter()
        rid = uuid.uuid4().hex
        mapping: dict[str, str] = {}
        counts: Counter = Counter()

        clean_messages = []
        for m in payload.get("messages", []):
            m = dict(m)
            if isinstance(m.get("content"), str):
                m["content"] = redactor.redact(m["content"], mapping, counts).text
            elif isinstance(m.get("content"), list):  # multi-part content
                parts = []
                for p in m["content"]:
                    if isinstance(p, dict) and p.get("type") == "text":
                        p = {**p, "text": redactor.redact(p["text"], mapping, counts).text}
                    parts.append(p)
                m["content"] = parts
            clean_messages.append(m)

        vault.put(rid, mapping)
        try:
            resp = await up.chat({**payload, "messages": clean_messages})
        except Exception as e:  # upstream down / bad key
            audit.write("upstream_error", request_id=rid, client=cid, error=type(e).__name__)
            raise HTTPException(502, f"upstream error: {type(e).__name__}")

        restored = vault.get(rid) or mapping
        for ch in resp.get("choices", []):
            msg = ch.get("message") or {}
            if isinstance(msg.get("content"), str):
                msg["content"] = rehydrate(msg["content"], restored)
        vault.delete(rid)  # nothing to keep once the answer is back

        ms = round((time.perf_counter() - t0) * 1000, 1)
        audit.write("chat", request_id=rid, client=cid, model=payload.get("model"),
                    entities=dict(counts), overhead_ms=ms)
        return JSONResponse(resp, headers={"X-PHI-Firewall-Request-Id": rid,
                                           "X-PHI-Entities": _counts_header(counts)})

    @app.get("/v1/audit/verify")
    def audit_verify(cid: str = Depends(client_id)):
        ok, bad = verify_chain(s.audit_log_path)
        return {"ok": ok, "first_bad_line": bad}

    return app


app = create_app  # `uvicorn phi_firewall.proxy.app:app --factory`
