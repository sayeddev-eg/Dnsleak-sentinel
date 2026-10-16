# DNSLeak Sentinel - Backend (FastAPI) container
# Ready for Hugging Face Spaces (port 7860, non-root user) and any Docker host ($PORT)
FROM python:3.11-slim

WORKDIR /app

# libgomp1 is required by xgboost on slim Debian images
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY ai_core /app/ai_core
COPY cyber /app/cyber
COPY backend /app/backend

RUN chmod -R 777 /app/backend

WORKDIR /app/backend
ENV PYTHONUNBUFFERED=1
ENV SENTINEL_DB=/tmp/dnsleak_alerts.db
EXPOSE 7860

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-7860}"]
