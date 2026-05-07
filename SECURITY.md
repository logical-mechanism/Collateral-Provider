# Security Policy

## Reporting a vulnerability

If you believe you've found a security issue in this collateral provider,
please report it privately to **support@logicalmechanism.io** rather than
opening a public GitHub issue.

A useful report includes:

- A clear description of the issue and what you can do with it.
- Steps to reproduce, or a proof-of-concept transaction CBOR if one is needed.
- Whether you believe a fix needs to be coordinated with anyone else (e.g. an
  upstream Cardano library).

We aim to acknowledge reports within 3 business days.

## Scope

In scope:

- Anything that causes the service to sign a transaction that violates the
  collateral-usage contract documented in [README.md](README.md) (collateral
  consumed, signature on a tx the user shouldn't be able to obtain, etc.).
- Anything that exfiltrates the signing key material from a running instance.
- Authentication / authorization bypasses on the open endpoints.
- Supply-chain risks (vulnerable transitive dependency, typo-squat, etc.).
- Denial-of-service vectors that go beyond exhausting the documented per-IP
  rate limit (e.g. a single small request that costs the server a
  disproportionate amount of CPU, memory, or upstream cost).

Out of scope:

- Hitting the rate limit. The 60/min/IP limit is documented and intentional.
- Reports that depend on running the service with `DEBUG=True` or with secrets
  committed to the repo.
- Self-XSS on the public landing page (the page is static).
- Lack of features that aren't part of this project (e.g. no audit logging
  beyond the request-id-correlated app log; no per-tx receipts).

## Supported versions

This is a single-product repository — only the tip of `main` is "supported"
in the security sense. Operators are expected to deploy a recent commit.

## Operator hardening checklist

If you're running this service:

- [ ] Keep `payment.skey` outside the repo on production hosts; configure
      `SKEY_PATH` via the `.env` file to point at it.
- [ ] Set `ALLOWED_HOSTS` to your real domain(s); the service refuses to
      start in non-development mode if it's empty.
- [ ] Run gunicorn behind a TLS-terminating reverse proxy. The service trusts
      `X-Forwarded-Proto` from the proxy via `SECURE_PROXY_SSL_HEADER`.
- [ ] Make sure the proxy strips/rewrites `X-Forwarded-For` so an external
      client can't spoof their source IP and bypass the per-IP throttle.
      As a code-level safeguard, the service only honors `X-Forwarded-For`
      when the immediate peer (`REMOTE_ADDR`) is in `TRUSTED_PROXY_IPS`
      (default: `127.0.0.1`, `::1`). Set this list to your real proxy
      egress IPs (or CIDR blocks) in multi-host deploys.
- [ ] Subscribe to the GitHub repository's Dependabot/security alerts.
- [ ] Pin to a known-good commit (don't deploy from `main` without review).
- [ ] Probe `/healthz` from your load balancer; it returns 503 if the keys
      become unreadable so traffic gets routed away from a broken host.

### Container-platform deploys (DigitalOcean App Platform, Fly, Render, ...)

If you're using the [DigitalOcean App Platform deploy](docs/DEPLOY.md)
(or another platform that runs the bundled `Dockerfile`), additional
hardening:

- [ ] Signing keys must enter the runtime via `SKEY_CONTENTS` /
      `VKEY_CONTENTS` SECRET env vars (or a mounted volume). They must
      **never** be baked into the image — `.dockerignore` excludes
      `api/key/` for exactly this reason. The entrypoint writes them
      to `/run/keys/` (tmpfs) and unsets the env vars before exec'ing
      gunicorn.
- [ ] `DJANGO_SECRET_KEY` must be a real ≥50-char random string set as
      a SECRET env var; never reuse the dev or CI value in production.
- [ ] `TRUSTED_PROXY_IPS` must list the platform's load-balancer source
      ranges (CIDR is supported). Leaving the default (`127.0.0.1`,
      `::1`) means every request appears to come from the LB's single
      private IP, which collapses the per-IP throttle into a global
      throttle — easy to miss, very bad. The bundled `.do/app.yaml`
      sets the standard RFC1918 ranges, which is correct for App
      Platform.
- [ ] `ALLOWED_HOSTS` must include the platform-issued hostname plus
      your custom domain. An overly permissive value (e.g. `*`) opens
      Host-header injection.
- [ ] Verify `/metrics` is either off (default) or restricted to a
      specific scraper IP via `METRICS_ALLOW_IPS`. The endpoint exposes
      aggregate request counts and Koios outcomes — not per-user data,
      but still implementation detail you don't want public.
- [ ] If you scale beyond `instance_count: 1`, the file-based throttle
      cache no longer shares state between instances. The throttle
      becomes per-instance (effective rate = `N * COLLATERAL_THROTTLE_RATE`).
      Either keep `instance_count: 1` or wire in a shared cache (e.g.
      DO Managed Redis + `django-redis`) before scaling.
