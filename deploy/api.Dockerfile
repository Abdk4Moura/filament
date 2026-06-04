# Filament signaling API — production image.
# Build context is the REPO ROOT (see docker-compose.yml), so paths are backend/*.
FROM python:3.12-slim

WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

# Native WebSockets via eventlet; single worker because the room registry is
# in-memory (see deploy/README.md → "Scaling").
ENV FIL_ASYNC_MODE=eventlet PORT=8000
EXPOSE 8000
CMD ["gunicorn", "-k", "eventlet", "-w", "1", "-b", "0.0.0.0:8000", "app:app"]
