# syntax=docker/dockerfile:1.7
#
# Container image for DigitalOcean App Platform (or any container host).
# Runs gunicorn directly — Whitenoise serves the collected static files
# from inside the same process, so there is no separate web server.
#
# Signing keys are NOT baked in. On App Platform they arrive as encrypted
# env vars (SKEY_CONTENTS / VKEY_CONTENTS) which the entrypoint materializes
# under /run/keys; that platform offers neither secret files nor volumes. On
# runtimes that do provide a mount, point SKEY_PATH / VKEY_PATH at it, or a mounted volume). The ApiConfig.ready() check at startup will
# refuse to boot if they are missing.

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    # In a container the default file-based debug.log is wrong. Select the
    # console handler explicitly so no file is opened; the platform captures
    # stderr and retains it independently of the ephemeral container.
    LOG_TO_CONSOLE=True \
    LOG_FORMAT=json

# libsodium isn't strictly required (PyNaCl bundles its own), but build-essential
# would only be needed if a wheel were missing — every dep in requirements.txt
# ships manylinux wheels for cpython 3.12, so we can skip the toolchain.
# curl stays in the image for manual diagnosis from inside a container.
# App Platform probes /healthz over HTTP from its own router, so it does not
# need curl present.
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

# Static files for the landing page. Collectstatic needs settings.py to
# import successfully, which means PKH/SECRET_KEY/etc. must parse — pass
# throwaway values via env (apps.py skips key validation during collectstatic
# so the dummy SKEY/VKEY paths are fine).
#
# PKH is a 28-byte Blake2b-224 key hash, so its placeholder is 56 hex
# characters, not the 64 used for the 32-byte transaction ids below. Settings
# now enforces that length, which is what caught this.
RUN set -eux; \
    export PKH=00000000000000000000000000000000000000000000000000000000 \
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

# Entrypoint materializes SKEY_CONTENTS / VKEY_CONTENTS env vars on the
# container's ephemeral writable layer at /run/keys before exec'ing gunicorn.
# On a runtime that supports it, mount /run/keys as tmpfs for memory-backed
# key storage. App Platform does not; its filesystem is ephemeral but
# disk-backed, and is wiped on every deploy.
# Operators using a mounted volume for keys can leave those env vars unset;
# gunicorn then reads whatever SKEY_PATH / VKEY_PATH point to.
ENTRYPOINT ["/app/docker-entrypoint.sh"]

# Workers + threads. The whole product is a thin wrapper around a Koios
# HTTP call (~hundreds of ms p50, up to 5s read timeout). Sync workers
# would block one request per worker for the whole RTT — gthread lets
# each process juggle multiple in-flight requests while waiting on the
# network, so concurrent capacity ≈ workers * threads. 2 * 8 = 16 is
# plenty for a basic-xxs DO instance and uses negligible extra memory.
# The file-based cache backend shares throttle counters across workers
# on the same host. Bind to 8080 — the port DO App Platform expects.
#
# --keep-alive 75 holds the LB↔gunicorn TCP connection open between
# requests (gunicorn defaults to 2s, which forces a fresh accept() on
# every cold hit). --timeout 60 makes the worker timeout explicit so a
# hung Koios call doesn't get silently killed at the 30s default.
CMD ["gunicorn", "collateral_provider.wsgi:application", \
     "--bind", "0.0.0.0:8080", \
     "--worker-class", "gthread", \
     "--workers", "2", \
     "--threads", "8", \
     "--timeout", "60", \
     "--graceful-timeout", "30", \
     "--keep-alive", "75", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
