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
      egress IPs in multi-host deploys.
- [ ] Subscribe to the GitHub repository's Dependabot/security alerts.
- [ ] Pin to a known-good commit (don't deploy from `main` without review).
- [ ] Probe `/healthz` from your load balancer; it returns 503 if the keys
      become unreadable so traffic gets routed away from a broken host.
