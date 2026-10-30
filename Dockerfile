FROM python:3.13-slim

# Single stage, deliberately: none of this project's dependencies need a
# compiler to install (all have prebuilt wheels for this platform), so a
# multi-stage copy-the-wheels split would add complexity for no benefit
# — and it previously caused a real bug: copying a separate stage's
# site-packages over this base image's own pre-installed setuptools left
# the old version's dist-info metadata on disk alongside the new one,
# which Trivy's container scan (correctly) flagged as a stale, vulnerable
# version still present in the image. Installing directly into this one
# environment lets pip manage the upgrade (and removal of the old
# dist-info) properly.
WORKDIR /app

RUN useradd --system --no-create-home --uid 10001 eljefe

COPY requirements.txt .
# pip is uninstalled after the install step: it's pure build tooling, the
# running app never imports it, and pip bundles its own internal vendored
# copies of urllib3/msgpack (at whatever version pip itself shipped with)
# which a container scanner correctly flags as present in the image even
# though this app never calls them. Removing pip removes that noise along
# with the tool itself.
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip uninstall --yes --no-input pip

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
