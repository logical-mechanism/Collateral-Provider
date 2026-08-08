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
- [ ] Use a dedicated payment key controlling exactly the advertised
      collateral UTxO. Never receive ordinary funds at, or reuse the key hash
      for, another payment address, stake credential, native policy, or
      governance credential. The returned witness authorizes the whole body.
- [ ] Treat the full advertised UTxO as operationally at risk unless callers
      use CIP-40 collateral return to an address controlled by the provider
      key. The API intentionally does not require `collateral_return` /
      `total_collateral` so wallet builders can integrate without
      provider-specific balancing rules.
- [ ] Do not add a pass-through for Ogmios `additionalUtxo`. The service
      rejects every non-empty caller-supplied UTxO set because a reference to
      an unsubmitted parent cannot authenticate the output value/datum/script
      the parent will actually create. Safe support requires verifying the
      complete parent transaction or consulting an authoritative mempool.
- [ ] Treat the configured Ogmios/Koios endpoint as a funds-at-risk trust
      dependency. Local response correlation, script-data-hash verification,
      and budget comparison do not stop an evaluator from lying that a
      phase-2-failing script succeeded. For mainnet, self-host the evaluator
      beside a node you control or use an independently trusted service.
- [ ] Set `ALLOWED_HOSTS` to your real domain(s); the service refuses to
      start in non-development mode if it's empty.
- [ ] Run gunicorn behind a TLS-terminating reverse proxy. The service trusts
      `X-Forwarded-Proto` from the proxy via `SECURE_PROXY_SSL_HEADER`.
- [ ] Make sure the proxy replaces `X-Forwarded-For` or appends the actual
      client address correctly, and prevent direct public access to gunicorn.
      As a code-level safeguard, the service only honors the header when the
      immediate peer (`REMOTE_ADDR`) is in `TRUSTED_PROXY_IPS`, then validates
      and walks the chain right-to-left until it reaches the first untrusted
      address. Set this list to actual proxy egress IPs or narrowly scoped
      CIDRs—never arbitrary client networks.
- [ ] Subscribe to the GitHub repository's Dependabot/security alerts.
- [ ] Pin to a known-good commit (don't deploy from `main` without review).
- [ ] Probe `/healthz` from your load balancer; it returns 503 if the keys
      become unreadable so traffic gets routed away from a broken host.
- [ ] Protect operational logs. The application deliberately omits raw client
      IPs from request records and transaction hashes from success records,
      but reverse-proxy and gunicorn access logs may have their own policies.
      Under systemd or a container runtime, configure journal/runtime retention
      and access controls. In file mode, restrict `LOG_FILE` to the service user.

### Ubuntu/systemd deploys

The canonical single-host deployment is documented in
[docs/UBUNTU_DEPLOY.md](docs/UBUNTU_DEPLOY.md). Keep the deployment identity
separate from the runtime identity: the deploy account may write versioned
code releases and may reset failure state, restart, or stop only
`collateral-provider.service`, while only the runtime account can read the
application environment and signing keys. The stop is used only when a failed
first deploy has no prior version to restore. Pin the server host key in
GitHub; do not discover it with `ssh-keyscan` inside CI.
Protect the GitHub `production` environment with required review and a
`production`-only deployment-branch rule.

### Container-platform deploys (DigitalOcean App Platform, Fly, Render, ...)

If you're using the [DigitalOcean App Platform deploy](docs/DEPLOY.md)
(or another platform that runs the bundled `Dockerfile`), additional
hardening:

- [ ] Signing keys must enter the runtime via `SKEY_CONTENTS` /
      `VKEY_CONTENTS` SECRET env vars (or a mounted volume). They must
      **never** be baked into the image — `.dockerignore` excludes
      `api/key/` for exactly this reason. The entrypoint writes them
      to `/run/keys/` on the container's ephemeral writable layer and unsets
      the env vars before exec'ing gunicorn. Mount `/run/keys` as tmpfs when
      the platform supports it if disk-backed ephemeral storage is not
      acceptable.
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
- [ ] Concurrency math: gunicorn runs `gthread` workers, so a single
      instance can hold roughly `workers * threads` requests in flight
      (default `2 * 8 = 16`). The bottleneck per request is the Koios
      RTT — most requests finish in well under a second, but a slow
      Koios spell can pin threads. Bump `--threads` (cheap) before
      `--workers` (more memory) if `/metrics` shows the duration
      histogram drifting up.
