FROM python:3.13-slim AS base

# Build layer: compile wheels in a throwaway stage so the final image
# doesn't carry a C compiler or build headers.
FROM base AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM base
WORKDIR /app

# Runs as a dedicated non-root user; no shell, no home directory beyond
# what's needed. The app never needs root, so it never runs as root.
RUN useradd --system --no-create-home --uid 10001 eljefe
COPY --from=builder /install /usr/local
COPY app/ ./app/

ENV ELJEFE_DB_PATH=/data/eljefe.db \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# SQLite file lives on a mounted/created volume the app user can write to;
# the application code itself stays read-only.
RUN mkdir -p /data && chown eljefe:eljefe /data

USER eljefe
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD python -c "import httpx; httpx.get('http://127.0.0.1:8000/docs', timeout=2).raise_for_status()" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
