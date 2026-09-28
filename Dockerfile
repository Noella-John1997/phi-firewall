FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY phi_firewall ./phi_firewall
RUN pip install --no-cache-dir . && useradd -m app
USER app
# Public demo defaults: mock LLM, files in /tmp. Set PHI_FIREWALL_MASTER_KEYS for a stable key.
ENV UPSTREAM_BASE_URL=mock VAULT_PATH=/tmp/vault.db AUDIT_LOG_PATH=/tmp/audit.jsonl PORT=8000
EXPOSE 8000
CMD ["sh", "-c", "uvicorn phi_firewall.proxy.app:app --factory --host 0.0.0.0 --port ${PORT}"]
