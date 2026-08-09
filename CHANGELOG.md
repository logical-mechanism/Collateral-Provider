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

## [1.3.0] — 2026-08-08

### Added

- **Both Conway `set` encodings are accepted** for body fields 0, 13 and 14.
  Conway's CDDL is `set<a0> = #6.258([* a0]) / [* a0]`; cbor2 decodes the
  tagged form to a `set` of tuples and the untagged form to a `list` of lists,
  so the previous `isinstance(x, set)` gate rejected a legal encoding and would
  refuse transactions from any builder that omits tag 258.
- **`collateral_return` validation.** When body field 16 is present its payment
  credential must be the provider's own key hash, and script addresses are
  refused. The field decides who receives the collateral remainder on the
  phase-2-invalid branch; leaving it unchecked let a third party profit from
  burning the provider's UTxO. Omitting the field is still allowed.
- **Readiness covers the throttle cache.** `/healthz` now round-trips the
  configured cache backend. A deployment whose `CACHE_DIR` is unwritable —
  the default path sits inside the release tree, which `ProtectSystem=strict`
  mounts read-only — previously reported healthy, satisfied the deploy
  script's readiness gate, and then returned 500 on every collateral request.
- **`handler500` and a JSON `handler400`.** Errors that escape DRF's exception
  handler, and `DisallowedHost` rejections, now use the same
  `{"detail": "..."}` envelope as everything else.
- **Pre-hard-fork rotation runbook** in [SECURITY.md](SECURITY.md). A
  transaction commits to the cost models through field 11 but cannot commit to
  the major protocol version, which Plutus uses to select builtin semantics and
  UPLC decoder bounds. Rotating the advertised collateral UTxO before a fork
  invalidates every outstanding witness via `BadInputsUTxO`.
- **Script-execution binding.** Before evaluation, the provider recomputes
  body field 11 from the exact submitted redeemer/datum CBOR bytes and current
  protocol cost models. After evaluation, the returned redeemer pointers must
  exactly match the submitted set and every execution budget committed in the
  witness set must cover the evaluated requirement. This closes mutable-witness
  and intentionally under-budget phase-2-invalid paths.
- **Privacy-safe request logging.** Application request records no longer
  persist raw client IPs. Successful witness issuance records the environment,
  duration, and request ID but not the transaction hash. This avoids creating
  a durable mapping from a network identity to an on-chain transaction while
  preserving operational correlation and latency data.
- **Console/journald logging mode.** `LOG_TO_CONSOLE=True` sends all app and
  Django logs to stderr and does not instantiate the rotating file handler.
  File logging remains the default. Both modes use one consistent destination
  per logger, eliminating duplicate and error-only console records.
- **Container-platform deploy shape.** [`Dockerfile`](Dockerfile),
  [`docker-entrypoint.sh`](docker-entrypoint.sh), and
  [`.do/app.yaml`](.do/app.yaml) describe the DigitalOcean App Platform
  deployment, which is what the reference provider runs: App Platform builds
  the image and deploys on every push to the tracked branch. Signing keys
  enter the runtime via `SKEY_CONTENTS` / `VKEY_CONTENTS` SECRET env vars;
  the entrypoint materializes them to `/run/keys/` on the container's
  ephemeral writable layer before exec'ing gunicorn, so the existing
  `ApiConfig.ready()` signing-key check is satisfied. App Platform supports
  neither volumes nor tmpfs mounts, so encrypted env vars are the only key
  delivery mechanism there. Operator runbook in
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
- **Dependabot config** for `pip` and `github-actions` ecosystems.
  Weekly schedule, security updates grouped.
- **Self-hosted Ubuntu deployment path.** A `workflow_dispatch`-only GitHub
  workflow reruns CI for the selected commit, streams that exact Git archive
  over pinned native OpenSSH, and performs a public readiness smoke test.
  This is for operators running their own host; it is not how the reference
  provider deploys. The server helper installs an immutable versioned release,
  atomically switches `current`, restarts the systemd service, and rolls back
  on failed local readiness. Application configuration and signing keys remain
  only on the server.

### Changed

- **Responses are always JSON.** DRF's browsable-API renderer was active, so a
  client sending `Accept: text/html` received an HTML page instead of the
  documented envelope, on success as well as on error. Rendering is now pinned
  to JSON and content negotiation never returns 406. Parser negotiation is
  unchanged, so a form-encoded body still gets 415.
- **JSON-RPC protocol faults from the evaluator now return 503, not 400.**
  Ogmios reports transaction verdicts with its own codes in the 3000s; the
  reserved `-32768..-32000` range means the request itself was rejected — a
  `KOIOS_URL` pointing at a build without `evaluateTransaction` answers
  `-32601` over HTTP 200. Reporting that as 400 told every wallet its
  transaction was bad while the service was the broken party. An error we
  cannot classify also fails closed to 503.
- **An unrecognized Plutus cost-model language is skipped rather than fatal.**
  A hard fork introducing `plutus:v5` previously made every request 503,
  including transactions using only languages already understood. The service
  now logs and ignores unknown languages, failing only when none remain.
- **A mistyped API path returns a JSON 404** instead of redirecting to the
  landing page. Because mainstream HTTP clients follow redirects by default,
  the old behaviour showed integrators a 200 and an HTML body for a request
  that never reached the endpoint. Browser navigation still redirects home.
- **A request without `Content-Length` returns 411.** Django bounds the
  request stream by that header, so a chunked body read as empty and the
  caller was told `Missing required field: 'tx'` for a request they had sent
  correctly. Note the reference deployment runs gunicorn behind DigitalOcean's
  router with no nginx of our own, so this can be reached there; the nginx
  template shipped for self-hosters sets `proxy_request_buffering on` and
  therefore hides it.
- **Default per-IP throttle raised from `60/min` to `300/min`**, and the
  throttle cache no longer discards counters. Django's `FileBasedCache`
  defaults (`MAX_ENTRIES=300`, `CULL_FREQUENCY=3`) deleted a random third of
  all entries on every write once 300 client IPs had been seen, so the only
  abuse control degraded under exactly the load it exists to bound. The key is
  a single source IP, so an integrator proxying its users spends the whole
  budget from one address — see [docs/WALLET_INTEGRATION.md](docs/WALLET_INTEGRATION.md).
- **`PKH` and the network TXIDs are canonicalized at settings load.**
  `bytes.fromhex` tolerates uppercase and whitespace, but every request-time
  comparison is an exact lowercase match, so an uppercase value produced a
  service that reported itself healthy and rejected 100% of transactions with
  a message blaming the caller. A non-hex or wrong-length `PKH` now refuses to
  start.
- **The systemd unit provides a writable `CACHE_DIR` by default** via
  `CacheDirectory=`, declared before `EnvironmentFile=` so an operator setting
  still wins. `docs/UBUNTU_DEPLOY.md` additionally documents `BANS_PATH`,
  without which the ban list silently never loads on a self-hosted install.
  On App Platform the ban list never loads at all: `bans.json` is gitignored
  and excluded by `.dockerignore`, and the platform has no persistent volume
  to supply one.
- Caller-supplied `additional_utxos` can no longer be enabled or forwarded.
  Missing and empty values remain harmless compatibility inputs; every
  non-empty value returns 400. A future parent reference cannot authenticate
  the output that parent will create, so safe support requires complete parent
  CBOR verification or an authoritative mempool rather than a gREST race check.
- The collateral throttle now uses the same trusted-proxy-aware client
  identity as bans and metrics authorization, preventing forged
  `X-Forwarded-For` values from creating fresh rate-limit buckets.
- Trusted-proxy client detection now validates IP syntax and walks
  `X-Forwarded-For` from right to left, skipping only configured proxy hops.
  A caller-prefixed leftmost value is no longer treated as authoritative;
  malformed chains fail closed to the immediate peer.
- Client-supplied `X-Request-ID` values are accepted only when they are 1–64
  safe ASCII characters (`A-Z`, `a-z`, `0-9`, `.`, `_`, `:`, `-`). Unsafe
  or overlong values are replaced with a freshly generated ID instead of
  being reflected into response headers and logs.
- Invalid `/<environment>/collateral/` route values now share the bounded
  Prometheus label `environment="unknown"`, preventing attacker-controlled
  metric-series cardinality.
- Hot-reload caches for JSON registries and signing keys now compare
  `(mtime_ns, size, inode)` rather than requiring mtime to increase. Atomic
  replacements reload even with equal or older timestamps, and readiness sees
  such key rotations immediately.
- Witness creation now derives the returned public key from the exact signing
  key snapshot used for the signature and rechecks its configured PKH. A
  two-file key replacement can fail transiently with 503 but cannot emit a
  signature/public-key pair assembled from different identities.
- `known.hosts.json` is validated before publication: PKHs and public keys must
  be canonical and cryptographically consistent; network names, transaction
  IDs, indices, and HTTPS `/<network>/collateral/` endpoints must match the
  wallet-facing schema. Invalid updates retain the last valid registry.
- Startup now verifies the signing key, verification key, PKH, collateral
  transaction IDs, and indices are internally consistent.
- Transaction and Koios envelopes fail closed: exactly four transaction
  elements, no trailing CBOR, a map-shaped witness set, and a JSON-RPC 2.0
  evaluation-result list are required before signing.
- `GET /livez` now provides network-free process liveness, while `/healthz`
  cryptographically revalidates the current skey/vkey/PKH on every readiness
  probe. The public known-hosts registry is no longer treated as a signing
  dependency.
- Outbound Koios calls use a configurable nonblocking per-process admission
  budget (`KOIOS_MAX_IN_FLIGHT`, default 4), preserving worker capacity and
  returning a fast 503 during upstream saturation.
- Successful evaluation must contain at least one well-formed Plutus redeemer
  budget; an empty result can no longer use the service as a general signing
  oracle.
- Protocol-parameter and evaluation calls use unique JSON-RPC IDs, exact method
  correlation, bounded streamed responses, and strict schemas. Current cost
  models are cached for five minutes per environment/upstream URL, with
  single-flight refresh so concurrent cold-cache requests do not stampede the
  evaluator.
- The collateral safety boundary is now explicit: the witness binds only the
  body, CIP-40 return fields remain optional for builder compatibility, and
  operators must use a dedicated key controlling only the advertised UTxO.
- Added a wallet integration contract covering provider discovery, transaction
  construction, finalized script-data/budget requirements, local witness
  verification, byte-preserving witness insertion, error handling, and
  multi-provider retry behavior.

- **JSON-only request bodies on `/<env>/collateral/`.** DRF's default
  also accepted form-encoded and multipart, which was undocumented
  surface area. Non-JSON content types now return 415.
- **Body-size cap dropped from Django's 2.5 MiB default** to a value
  derived from `MAX_TX_SIZE` (≈ 36 KiB by default). The protocol caps a
  tx at 16 KiB binary (32 KiB hex); the derived cap leaves room for the
  JSON envelope while making oversized junk cheap to reject. A dedicated
  pre-parser middleware reads at most the cap plus one byte, including when
  `Content-Length` is absent, and returns the documented JSON 413 response
  before the view runs.
- **`MAX_TX_SIZE` is now env-overridable** so a future hard fork that bumps
  the protocol parameter does not require a code deploy.
- **Validation orchestration moved out of the serializer** into
  `api.services.collateral.issue_witness`. The serializer is now
  shape-only; the service runs the validator chain, calls Koios, and
  returns `(witness_hex, tx_hash_hex)`. No external behavior change.
- **gunicorn switched from sync workers to `gthread`** (2 workers ×
  8 threads). The whole product is IO-bound on Koios; the previous
  2-sync-workers shape blocked one request per worker for the full
  upstream RTT.
- **Trailing slash now optional** on `/api/docs`, `/api/schema`, and
  `/api/redoc`. Both `/api/docs` and `/api/docs/` resolve directly.
- **`/healthz` and `/known_hosts/` now set `Cache-Control: no-store`**
  so an upstream proxy can't serve a stale "ok" after the keys go
  missing or a stale registry after an operator edit.
- **`/healthz` 503 body no longer leaks signing-key paths.** Public
  `problems` list is label-only (`"skey unreadable"`); the path stays
  in the WARNING-level log line for operator debug.
- **Landing page and `/known_hosts/` are now GET-only.** A POST to
  either previously returned 200; now returns 405.
- **`settings.py` no longer hard-fails when `.env` is missing.**
  Container-platform deploys inject configuration via `os.environ`;
  there is no file. `django-environ` reads from the process env when
  no file is present. The required-vars check below still fails loudly
  if anything actually needed is unset.
- **CI `pip-audit` now also audits `requirements-dev.txt`.**

### Removed

- **Legacy `tx_body` request field.** The transition release that
  accepted both `tx` and `tx_body` is over. Clients must send `tx`.
  Sending `tx_body` now returns a 400 (`tx` field required).

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

- Every 4xx/5xx response from the collateral endpoint now uses the same shape:
  `{"detail": "<message>"}`. Previously it returned `{"tx_body": ["..."]}` for validator errors,
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
