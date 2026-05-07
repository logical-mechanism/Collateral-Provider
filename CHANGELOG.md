# Changelog

All notable, externally-visible changes go here. The single source of truth
for the version number is [`collateral_provider/api/__init__.py`](collateral_provider/api/__init__.py)
(`__version__`); the OpenAPI schema and `/healthz` both read from it.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and we aim to follow [Semantic Versioning](https://semver.org/) for the public
HTTP contract:

- **MAJOR** when a request/response shape changes incompatibly (e.g. a
  required field is renamed without a deprecation window).
- **MINOR** when we add an endpoint, an optional request field, or a
  response field that existing clients can ignore.
- **PATCH** for bug fixes that don't change the contract.

## [Unreleased]

### Added

- **Optional `additional_utxos` request field.** Forwarded to Ogmios as
  [`additionalUtxo`](https://ogmios.dev/mini-protocols/local-tx-submission/#additional-utxo-set)
  on the `evaluateTransaction` call, so callers can splice in
  `[txin, txout]` pairs that don't yet exist on chain (chained-tx /
  future-input scenarios). Missing or empty is skipped silently;
  non-empty is forwarded verbatim — the inner Ogmios UTxO shape isn't
  mirrored here, so a malformed entry surfaces as the standard
  `Transaction Fails Validation` 400 from Koios's verdict, not as our
  bug.

### Added

- **Container-platform deploy shape.** [`Dockerfile`](Dockerfile),
  [`docker-entrypoint.sh`](docker-entrypoint.sh), and
  [`.do/app.yaml`](.do/app.yaml) bundle a one-command DigitalOcean App
  Platform deploy: push to `main` → DO rebuilds the image and rolls it
  out behind their TLS-terminating router. Signing keys enter the
  runtime via `SKEY_CONTENTS` / `VKEY_CONTENTS` SECRET env vars (or a
  mounted volume); the entrypoint materializes them to `/run/keys/`
  (tmpfs) before exec'ing gunicorn so the existing `ApiConfig.ready()`
  signing-key check is satisfied. Operator runbook in
  [`docs/DEPLOY.md`](docs/DEPLOY.md).
- **`whitenoise`** dependency for in-process static-file serving so
  the deployed container needs no separate web server. Picked the
  non-manifest variant — the manifest one breaks template rendering
  whenever `collectstatic` hasn't run yet, which includes the test
  suite.
- **CIDR support in `TRUSTED_PROXY_IPS`.** Each entry is parsed via
  `ipaddress.ip_network` so single hosts (`127.0.0.1`) and blocks
  (`10.0.0.0/8`) both work. Container platforms that don't pin a
  single LB egress IP need this; without it the per-IP throttle would
  collapse into a global one.
- **CI Docker smoke test.** A second job in the workflow builds the
  image, boots the container with synthetic env, and curls `/healthz`
  + `/`. Catches Dockerfile / entrypoint / collectstatic / static-
  serving regressions the unit tests can't.

### Changed

- **`settings.py` no longer hard-fails when `.env` is missing.**
  Container-platform deploys inject configuration via `os.environ`;
  there is no file. `django-environ` reads from the process env when
  no file is present. The required-vars check below still fails loudly
  if anything actually needed is unset.

## [1.2.0] — 2026-05-06

A second polish pass focused on observability, 12-factor configuration,
and operator self-service. Fully backward-compatible with 1.1: every
existing client request and response shape is still honored.

### Added

- **Single `__version__` constant** in `collateral_provider/api/__init__.py`.
  Both the OpenAPI schema (`SPECTACULAR_SETTINGS['VERSION']`) and the
  `/healthz` response read from it. One bump location, no drift.
- **JSON logging** (`LOG_FORMAT=json`). Stdlib-only formatter at
  `api.log_format.JsonFormatter` emits one JSON object per record with
  `level`, `time`, `logger`, `module`, `message`, `request_id`, plus
  any `extra={...}` kwargs as top-level keys. Default stays `text` so
  existing log scraping is unaffected.
- **Prometheus `/metrics`** endpoint. Off by default
  (`METRICS_ENABLED=False` → 404); when on, restricted to
  `METRICS_ALLOW_IPS` (default `127.0.0.1`, `::1`). Metrics are
  aggregated and low-cardinality (no per-IP / per-PKH / per-tx labels)
  in line with the privacy goal:
    - `collateral_http_requests_total{environment, status}`
    - `collateral_http_request_duration_seconds{environment}`
    - `collateral_koios_requests_total{environment, outcome}` —
      outcomes: `success`, `tx_invalid`, `timeout`, `request_error`,
      `http_error`, `invalid_json`
    - `collateral_koios_request_duration_seconds{environment}`
- **Hot-reloadable JSON data files** for ban list and known-hosts
  registry. `bans.json` (path: `BANS_PATH`) and `known.hosts.json`
  (path: `KNOWN_HOSTS_PATH`) are re-read on the next request after
  the file's mtime advances — operators can update them without
  bouncing the service. Atomic write-tmp-then-rename is the expected
  edit workflow. `bans.json.example` checked in with the canonical
  shape; the real file is gitignored.
- **`tx` request field** as the canonical name on the collateral
  endpoint. The legacy field name `tx_body` was misleading (the value
  is the whole transaction CBOR, not just the body) and is now a
  deprecated alias that still works for one transition release.
  Sending both `tx` and `tx_body` is rejected.
- **`TRUSTED_PROXY_IPS` allowlist** for X-Forwarded-For. The service
  only honors XFF when the immediate peer is in the list (default
  `127.0.0.1`, `::1`). A misconfigured deploy where gunicorn is
  reachable directly can no longer be tricked into accepting a
  spoofed source IP via XFF. Empty list disables XFF entirely.

### Changed

- `_load_known_hosts` no longer uses `lru_cache(maxsize=1)`. The cache
  was effectively forever; reloading required a process restart. Now
  uses the same mtime-aware loader as the ban list.
- The DRF default throttle classes setting was removed (had been a
  global default that any new endpoint would inherit). Endpoints now
  state their throttle explicitly. `/metrics` and `/healthz` opt out
  via `@throttle_classes([])`.
- `landing_page` and `known_hosts_view` no longer have FileNotFoundError
  branches; the loader returns `{}` for a missing file, which is the
  same shape as an empty registry.

### Security

- `_client_ip` now refuses to honor X-Forwarded-For from untrusted
  peers. Documented in `SECURITY.md` under the operator hardening
  checklist.
- `/metrics` is not exposed unless explicitly enabled, and even then
  only to allow-listed IPs — implementation-detail observability
  data should not be world-readable.

### Removed

- Stale `captcha/` directory (only contained `__pycache__` from a
  long-removed feature). Added `__pycache__/` and `*.pyc` to the
  root `.gitignore` so the same accident can't recur.
- `lru_cache` import from `views.py` (no longer needed after the
  known-hosts refactor).

## [1.1.0] — 2026-05-06

This release is the result of a substantial cleanup pass on top of the
1.0 production codebase. The HTTP contract is fully backward-compatible
with 1.0; everything below is either additive or an internal change.

### Added

- `GET /healthz` — liveness/readiness probe. Returns `200 {"status": "ok",
  "version": "..."}` when signing keys and `known.hosts.json` are readable;
  `503 {"status": "error", "problems": [...]}` otherwise. Not rate-limited.
- `X-Request-ID` response header on every request. The id is also stamped
  on every log line emitted during the request, for log-correlation.
  Honors a client-supplied `X-Request-ID` (capped at 64 chars) if sent.
- OpenAPI 3 schema at `/api/schema/`, Swagger UI at `/api/docs/`, ReDoc at
  `/api/redoc/`.
- Configuration via `.env` for nearly every operational knob: `SKEY_PATH`,
  `VKEY_PATH`, `COLLATERAL_THROTTLE_RATE`, `LOG_LEVEL`, `LOG_FILE`,
  `CACHE_DIR`, `PREPROD_KOIOS_URL`, `MAINNET_KOIOS_URL`. See
  [`collateral_provider/sample.env`](collateral_provider/sample.env).
- CI on GitHub Actions: ruff, tests, coverage, OpenAPI schema validation,
  pip-audit. See [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
- [`SECURITY.md`](SECURITY.md) with vulnerability reporting and operator
  hardening checklist.

### Changed

- Every 4xx/5xx response now uses the same shape: `{"detail": "<message>"}`.
  Previously the API returned `{"tx_body": ["..."]}` for validator errors,
  `{"error": "..."}` for invalid environment, and `{"detail": "..."}` for
  everything else. Internal serializer field names no longer leak.
- Koios calls now have a `(3s connect, 5s read)` timeout. Network failures
  surface as `503 Validation Service Unavailable` rather than masquerading
  as `400 Transaction Fails Validation` (which previously misled users
  about whether their transaction was bad).
- The `/<env>/collateral/` rate limit is configurable via the
  `COLLATERAL_THROTTLE_RATE` env var (default `60/min`).
- The throttle now uses a file-based cache backend (`.cache/` by default,
  overridable via `CACHE_DIR`) so multi-worker gunicorn shares per-IP
  counters.
- Log levels normalized: 4xx events are `WARNING`, not `ERROR`. The error
  log is now actionable instead of full of routine user-input rejections.

### Removed

- `pycardano` dependency (was being used for one symbol, `OrderedSet`,
  which dragged in 30+ transitive deps including `blockfrost-python`,
  `cardano-tools`, `ogmios`, `cose`, `mnemonic`). Replaced with
  `cbor2.CBORTag(258, sorted(...))` — byte-equivalent encoding, no
  transitives.
- `HandleDisallowedHostMiddleware` — was duplicating Django's built-in
  `ALLOWED_HOSTS` check and silently rejecting Django's test client
  (which made several of the test cases pass for the wrong reason).
- `DEFAULT_THROTTLE_CLASSES` global — was a footgun where any new
  endpoint would inherit a `1/min` rate. Endpoints now opt in
  explicitly to the throttle they want.

### Fixed

- 14 tests in `test_cbor.py` had `assertIn(...)` calls placed inside
  `with self.assertRaises(...)` blocks, after the line that raised.
  They were never executing, so the asserted error messages were never
  checked. Moved out of the `with` block; updated the messages to match
  the actual Title-Case strings the validator emits.
- Patched a class of pre-existing test bugs where the host middleware
  was rejecting Django's default `Host: testserver` and tests that
  expected `400` from the validators were getting `400 Invalid Host
  Header` from the middleware. View tests now use
  `@override_settings(ALLOWED_HOSTS=["testserver"])` so they exercise
  the actual validation pipeline.

### Security

- 32 known dependabot CVEs at the start of this release → **0** at the
  end, via dropping unused deps and bumping the rest to current
  patches.
- HTTPS posture: removed dead `SECURE_*` settings that were setting
  things to their Django defaults (and one was strictly worse — the
  explicit `SECURE_HSTS_SECONDS = 0` in the production block disabled
  HSTS where Django's default behavior would have respected the
  proxy). Added `SECURE_PROXY_SSL_HEADER` so `request.is_secure()`
  works behind a TLS-terminating reverse proxy.
- Signing keys are read once at startup via
  `api.apps.ApiConfig.ready()`. A misconfigured deploy (missing or
  unreadable `payment.skey` / `payment.vkey`) now fails to start
  rather than 500'ing on the first POST.

## [1.0.0] — pre-2026-05-06

Initial production release. See git history before commit `1e19a15`
for the full pre-1.1 history.
