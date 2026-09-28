FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY phi_firewall ./phi_firewall
RUN pip install --no-cache-dir . && useradd -m firewall
USER firewall
ENV VAULT_PATH=/tmp/vault.db AUDIT_LOG_PATH=/tmp/audit.jsonl
EXPOSE 8000
CMD ["uvicorn", "phi_firewall.proxy.app:app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
