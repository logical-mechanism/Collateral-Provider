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

- Hitting the rate limit. The per-IP limit (default `300/min`, see
  `COLLATERAL_THROTTLE_RATE`) is documented and intentional.
- Reports that depend on running the service with `DEBUG=True` or with secrets
  committed to the repo.
- Self-XSS on the public landing page (the page is static).
- Lack of features that aren't part of this project (e.g. no audit logging
  beyond the request-id-correlated app log; no per-tx receipts).

## Hard forks: rotate the collateral UTxO before every protocol-version bump

This is a scheduled operator duty, not an optional one. It closes the only
structural path by which an already-issued witness can end up consuming the
collateral.

**Why.** Phase-2 script evaluation is a function of the script, its arguments,
the committed execution units, the cost models, the transaction context, and
the **major protocol version**. A transaction commits to the cost models
through the script-data hash in body field 11 — change them and the ledger
rejects it at phase 1 with `PPViewHashesDontMatch`, before phase 2 runs. It
cannot commit to the protocol version, and Plutus keys both builtin semantics
and UPLC decoder strictness on that value. At `vanRossemPV` (major version 11)
`ensurable` switched roughly forty builtins to bounds-checked arguments for all
three ledger languages, and `maxBoundsByPV` tightened the decoder's type-header
and constructor limits. Neither change requires a cost-model update, so the
phase-1 hash check does not fire.

Nothing forces cost models to change at a fork either: when the on-chain
parameter list is shorter than expected the ledger fills the remainder with
`maxBound` and warns rather than rejecting, and `HardForkInitiation` and
`ParameterChange` are independent governance actions with independent
enactment epochs. On mainnet the Plutus cost-model change was enacted on
2026-06-18 and protocol version 11 activated on 2026-07-18, leaving a month in
which a witness issued beforehand stayed valid straight across the boundary.

**The window.** An attacker would need to obtain a witness for a transaction
that succeeds under the current semantics and fails under the next, hold it
across the fork, keep its inputs unspent, and submit afterwards with
`is_valid=false`. Narrow, but it re-arms at every future fork.

**The procedure.** A `HardForkInitiation` action is ratified an epoch before it
enacts, so there is always advance notice.

1. Watch for a ratified `HardForkInitiation` on each network you serve.
2. Before the enactment epoch boundary, spend the advertised collateral UTxO
   back to the same provider address, creating a new `txid#ix`.
3. Update `*_TXID` / `*_TXIDX` wherever this deployment holds configuration.
   On DigitalOcean App Platform that means editing the **live** spec
   (`doctl apps spec get <app-id>` → edit → `doctl apps update`), which rolls
   a new container automatically; there is no environment file and nothing to
   restart by hand. On a self-hosted host it means
   `/etc/collateral-provider/environment` plus
   `systemctl restart collateral-provider.service`.
4. Update `known.hosts.json`. Note this file is baked into the image on App
   Platform, so publishing the new reference is a commit and a deploy, not an
   edit in place — sequence it so the advertised UTxO is never stale for long.
5. Confirm `/healthz` is green and the landing page shows the new reference.

Spending the old UTxO makes every outstanding witness that references it
phase-1 invalid via `BadInputsUTxO`, so no signature issued before the fork can
be redeemed after it. Rotating is also the correct response to any suspected
compromise of the evaluator.

This service deliberately does **not** require a short `invalid_hereafter` to
achieve the same bound. Many Plutus contracts constrain their own validity
interval, and forcing a short TTL would lock out exactly the transactions that
most need shared collateral.

## Supported versions

This is a single-product repository — only the tip of `main` is "supported"
in the security sense. Operators are expected to deploy a recent commit.

## Operator hardening checklist

If you're running this service:

- [ ] Never let signing keys reach the repo or a container image. How they
      are supplied depends on the deployment: App Platform injects them as
      encrypted `SKEY_CONTENTS` / `VKEY_CONTENTS` env vars that the entrypoint
      materializes under `/run/keys`, while a self-hosted host keeps them
      outside the checkout and points `SKEY_PATH` / `VKEY_PATH` at them. A
      `.env` file is a local-development convenience only; production reads
      process environment variables.
- [ ] Use a dedicated payment key controlling exactly the advertised
      collateral UTxO. Never receive ordinary funds at, or reuse the key hash
      for, another payment address, stake credential, native policy, or
      governance credential. The returned witness authorizes the whole body.
- [ ] Treat the full advertised UTxO as operationally at risk unless callers
      use CIP-40 collateral return. The API does not *require*
      `collateral_return` / `total_collateral`, so wallet builders can
      integrate without provider-specific balancing rules — but when a caller
      does supply `collateral_return` it is validated to pay this provider's
      own payment key hash, so an attacker cannot redirect the remainder to
      themselves and profit from burning the UTxO.
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

### Self-hosted Ubuntu/systemd deploys

The single-host self-hosting path is documented in
[docs/UBUNTU_DEPLOY.md](docs/UBUNTU_DEPLOY.md). It is not what the reference
provider runs, but if you choose it: keep the deployment identity separate
from the runtime identity. The deploy account may write versioned code
releases and may reset failure state, restart, or stop only
`collateral-provider.service`, while only the runtime account can read the
application environment and signing keys. The stop is used only when a failed
first deploy has no prior version to restore. Pin the server host key in
GitHub; do not discover it with `ssh-keyscan` inside CI.
Protect the GitHub `production` environment with required review and a
`production`-only deployment-branch rule.

### Container-platform deploys (DigitalOcean App Platform, Fly, Render, ...)

This is how the reference provider runs. If you deploy the bundled
`Dockerfile` on a platform, additional hardening:

- [ ] Know whether your platform auto-deploys. The reference deployment has
      `deploy_on_push: true` on `main`, so **merging a pull request ships to
      production**, and the platform builds from GitHub independently of
      GitHub Actions — a red CI run does not stop a release. Protect the
      deployed branch with required status checks, or set
      `deploy_on_push: false` and deploy explicitly.

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
- [ ] `ALLOWED_HOSTS` must list your real hostnames and **must not contain a
      bare `*`**. Check this specifically rather than assuming — a wildcard
      added while bootstrapping (before the platform-issued hostname is known)
      is easy to leave behind, and one `*` silently voids every other entry in
      the list. Django then accepts any Host header, the `DisallowedHost`
      handler becomes unreachable, and a caller controls the `servers` block
      drf-spectacular renders into `/api/schema/`.

      Django's leading-dot form covers the issued hostname without a wildcard,
      so `www.example.com,example.com,.ondigitalocean.app` is the shape you
      want. Removing a wildcard is safe to try on App Platform: the platform
      keeps the current deployment serving until the new one passes its health
      check, so if the probe's Host header turns out not to match, the change
      simply fails to roll out rather than taking the service down.
- [ ] Verify `/metrics` is either off (default) or restricted to a
      specific scraper IP via `METRICS_ALLOW_IPS`. The endpoint exposes
      aggregate request counts and Koios outcomes — not per-user data,
      but still implementation detail you don't want public.
- [ ] If you scale beyond `instance_count: 1`, the file-based throttle
      cache no longer shares state between instances. The throttle
      becomes per-instance (effective rate = `N * COLLATERAL_THROTTLE_RATE`).
      Either keep `instance_count: 1` or wire in a shared cache (e.g.
      DO Managed Redis + `django-redis`) before scaling.
- [ ] Concurrency math: there are two distinct ceilings, and only the
      second one moves throughput. A single instance holds roughly
      `workers * threads` HTTP requests in flight (default `2 * 8 = 16`),
      but concurrent *upstream* calls are capped separately at
      `workers * KOIOS_MAX_IN_FLIGHT` (default `2 * 4 = 8`). Since every
      signing request makes an upstream call, sustained throughput is
      `workers * KOIOS_MAX_IN_FLIGHT / koios_latency` — about 16 rps at a
      500 ms RTT — and requests above that budget are shed as 503 rather
      than queued. Raising `--threads` therefore cannot increase
      throughput; raise `KOIOS_MAX_IN_FLIGHT` (and keep it at or below
      the adapter's `pool_maxsize` of 16) or reduce upstream latency by
      self-hosting the evaluator.
