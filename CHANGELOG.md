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
