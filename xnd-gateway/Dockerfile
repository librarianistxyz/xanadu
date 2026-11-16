FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn cryptography

COPY xnd-hub/p2p_discovery.py /app/xnd-hub/p2p_discovery.py
COPY xnd-hub/abuse_guard.py /app/xnd-hub/abuse_guard.py
COPY xnd-gateway/gateway.py /app/xnd-gateway/gateway.py

ENV XND_GATEWAY_PORT=8780
ENV XND_GATEWAY_RATE_PER_MIN=60
EXPOSE 8780

CMD ["python3", "/app/xnd-gateway/gateway.py"]
