# syntax=docker/dockerfile:1.7
#
# Container image for DigitalOcean App Platform (or any container host).
# Runs gunicorn directly — Whitenoise serves the collected static files
# from inside the same process, so there is no separate web server.
#
# Signing keys are NOT baked in. They must be mounted at runtime via
# SKEY_PATH / VKEY_PATH (e.g. DO App Platform secret files at /run/...,
# or a mounted volume). The ApiConfig.ready() check at startup will
# refuse to boot if they are missing.

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# libsodium isn't strictly required (PyNaCl bundles its own), but build-essential
# would only be needed if a wheel were missing — every dep in requirements.txt
# ships manylinux wheels for cpython 3.12, so we can skip the toolchain.
# curl stays in the image for the health check / smoke test.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Run as a non-root user. App Platform doesn't strictly require it, but it's
# cheap defence-in-depth: a code-execution bug shouldn't have root inside the
# container.
RUN useradd --system --create-home --uid 10001 app

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

# Project layout: manage.py lives at /app/collateral_provider/manage.py.
# Everything else (known.hosts.json, etc.) lives at /app/.
COPY . /app/

# Static files for the landing page + DRF browsable API. Collectstatic
# needs settings.py to import successfully, which means PKH/SECRET_KEY/etc.
# must parse — pass throwaway values via env (apps.py skips key validation
# during collectstatic so the dummy SKEY/VKEY paths are fine).
RUN set -eux; \
    export PKH=0000000000000000000000000000000000000000000000000000000000000000 \
           DJANGO_SECRET_KEY=build-time-only-not-a-real-secret \
           ENVIRONMENT=development \
           PREPROD_TXID=0000000000000000000000000000000000000000000000000000000000000000 \
           PREPROD_TXIDX=0 \
           "PREPROD_NETWORK=--testnet-magic 1" \
           MAINNET_TXID=0000000000000000000000000000000000000000000000000000000000000000 \
           MAINNET_TXIDX=0 \
           MAINNET_NETWORK=--mainnet; \
    python collateral_provider/manage.py collectstatic --noinput

# Cache directory for the file-based throttle. Has to be writable at runtime.
# /app is owned by root after COPY; chown the slots that need writes.
# Pre-create /run/keys for the entrypoint's signing-key materialization
# (the app user can't mkdir under /run, which is root-owned).
RUN mkdir -p /app/collateral_provider/.cache /app/collateral_provider/staticfiles /run/keys \
    && chown -R app:app /app/collateral_provider/.cache /app/collateral_provider/staticfiles /run/keys \
    && chmod 700 /run/keys

USER app

WORKDIR /app/collateral_provider

EXPOSE 8080

# Entrypoint materializes SKEY_CONTENTS / VKEY_CONTENTS env vars to
# tmpfs files (/run/keys/) before exec'ing gunicorn. Operators using a
# mounted volume for keys can simply leave those env vars unset — the
# entrypoint skips the materialization and gunicorn picks up whatever
# SKEY_PATH / VKEY_PATH point to.
ENTRYPOINT ["/app/docker-entrypoint.sh"]

# Workers: 2-3 is appropriate for a single small instance. The file-based
# cache backend shares throttle counters across workers on the same host.
# Bind to 8080 because that's the port DO App Platform's HTTP router expects.
CMD ["gunicorn", "collateral_provider.wsgi:application", \
     "--bind", "0.0.0.0:8080", \
     "--workers", "2", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
