# CLAUDE.md

Notes for Claude Code working in this repo. Keep this terse and current — update when something here drifts from reality.

## What this is

A Django + DRF service that takes a Cardano transaction CBOR from a user, validates it satisfies the rules for using a shared collateral UTxO, and returns a witness (signature) for that transaction. One key, one collateral UTxO per network, shared across many users so they don't have to set up collateral in their own wallet.

The whole product is one main endpoint plus operational extras:

```
POST /<environment>/collateral/   body: { "tx": "<hex cbor>", "additional_utxos"?: [<[txin,txout] pair | flat Utxo>, ...] }   -> { "witness": "<hex cbor>" }
GET  /healthz                                                          -> { "status": "ok", "version": "..." }
GET  /known_hosts/                                                     -> registry JSON
GET  /                                                                 -> landing HTML
GET  /api/{schema,docs,redoc}/                                          -> OpenAPI surface
```

## Repo layout

- [collateral_provider/](collateral_provider/) — Django project root (`manage.py` lives here)
  - [collateral_provider/collateral_provider/](collateral_provider/collateral_provider/) — Django settings/urls/wsgi
  - [collateral_provider/api/](collateral_provider/api/) — the only app; all the real logic
    - [apps.py](collateral_provider/api/apps.py) — `ApiConfig.ready()` validates signing keys at process start
    - [views.py](collateral_provider/api/views.py) — `ProvideCollateralView`, `healthz_view`, landing page, `known_hosts`
    - [serializers.py](collateral_provider/api/serializers.py) — orchestrates validation in cheap-to-expensive order
    - [validators/](collateral_provider/api/validators/) — module-level functions (no classes); cbor / environment / transaction
    - [signature.py](collateral_provider/api/signature.py) — Ed25519 via PyNaCl, tx hashing, witness CBOR; `get_key_from_file` is `lru_cache`d
    - [simulate.py](collateral_provider/api/simulate.py) — calls Koios `evaluateTransaction`. URL per env from `settings.ENVIRONMENTS[<env>]['KOIOS_URL']`
    - [middleware.py](collateral_provider/api/middleware.py) — `RequestIDMiddleware` + `RequestIDLogFilter`
    - [tx_fields.py](collateral_provider/api/tx_fields.py) — Cardano body-field index constants and `SET_TAG = 258`
    - [ban_list.py](collateral_provider/api/ban_list.py) — banned addresses + IPs
    - [util.py](collateral_provider/api/util.py) — `raise_validation_error` and `normalize_error_response` (DRF exception handler)
    - [key/](collateral_provider/api/key/) — dev `payment.skey` / `payment.vkey`. Production overrides via `SKEY_PATH` / `VKEY_PATH` env vars.
    - [templates/api/landing.html](collateral_provider/api/templates/api/landing.html) — landing page template
    - [tests/](collateral_provider/api/tests/) — Django tests; fixtures in `test_data.py` / `test_big_data.py`
  - [collateral_provider/sample.env](collateral_provider/sample.env) — copy to `.env` and fill in
- [known.hosts.json](known.hosts.json) — public registry of known providers, keyed by collateral PKH; surfaced on the landing page
- [scripts/](scripts/) — helper scripts (curl + python clients, locust stress test)
- [guides/](guides/) — server setup notes
- [.github/workflows/ci.yml](.github/workflows/ci.yml) — CI: ruff, tests, coverage, OpenAPI validate, pip-audit
- [pyproject.toml](pyproject.toml) — ruff and coverage config
- [requirements.in](requirements.in) / [requirements-dev.in](requirements-dev.in) — direct deps; `*.txt` files are pip-compile lockfiles
- [SECURITY.md](SECURITY.md) — vuln reporting policy and operator hardening checklist

## Request flow (the part Claude needs to know cold)

`POST /<env>/collateral/` → [ProvideCollateralView.post](collateral_provider/api/views.py) →
[ProvideCollateralSerializer.validate_tx_body](collateral_provider/api/serializers.py) runs these
free functions in cheap-to-expensive order; the first failure raises and short-circuits the rest:

1. `validators.environment.check_ip_address` — reject banned IPs
2. `validators.environment.check_environment` — env must be one of `settings.ENVIRONMENTS`
3. `validators.cbor.check_cbor_hex` — hex-decodable, ≤ 16 KiB
4. `validators.cbor.check_tx_body` — top-level CBOR is `[body, witnesses, valid_bool, aux]`; `valid_bool` must be True
5. `validators.cbor.check_inputs` — collateral UTxO must NOT be in inputs (would spend it)
6. `validators.cbor.check_outputs` — every output address must not be in `banned_addresses`
7. `validators.cbor.check_collateral` — collateral UTxO MUST be in `body[13]` (collateral inputs)
8. `validators.cbor.check_signers` — our PKH MUST be in `body[14]` (required signers)
9. `validators.transaction.check_valid_tx` — require a well-formed Koios/Ogmios JSON-RPC phase-2 evaluation result

Only after all of that does [signature.witness_tx_cbor](collateral_provider/api/signature.py) compute the body hash (Blake2b-256, with `cbor2.CBORTag(258, ...)` reordering for inputs/certs/collateral/required-signers/reference-inputs/proposal-procedures) and produce the witness.

Validation errors propagate as `ValidationError`; `views.py` calls `is_valid(raise_exception=True)` so they flow through `util.normalize_error_response` (registered as `REST_FRAMEWORK['EXCEPTION_HANDLER']`) and emerge as `{"detail": "<message>"}`. **Every** 4xx/5xx body uses that shape — `{"tx_body": [...]}` should never appear in a response.

`UpstreamUnavailable` from `simulate.py` is caught in `validators.transaction.check_valid_tx` and re-raised as `UpstreamServiceUnavailable` (status 503). Don't let it become a 400 — that misleads the user about whether their tx is bad.

## Cardano CBOR conventions used here

Transaction body field indices (Conway era) referenced by the validators:

| idx | meaning              |
|-----|----------------------|
| 0   | inputs (set)         |
| 1   | outputs (list)       |
| 4   | certificates         |
| 13  | collateral inputs    |
| 14  | required signers     |
| 18  | reference inputs     |
| 20  | proposal procedures  |

The witness CBOR returned is `cbor([0, [pubkey_bytes, signature_bytes]])` — Cardano's vkey-witness shape.

## Running it

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp collateral_provider/sample.env collateral_provider/.env  # then fill in PKH, keys, txids, etc
cd collateral_provider
python3 manage.py runserver
python3 manage.py test                  # runs the api app's tests
```

`settings.py` `sys.exit(1)`s if `.env` is missing — by design.

## Operational extras

- **Request correlation:** every request gets a 12-char hex `X-Request-ID` (or echoes a client-supplied one, capped at 64 chars). The id is set on a `contextvars.ContextVar` by [middleware.RequestIDMiddleware](collateral_provider/api/middleware.py) and pulled onto every log record by `RequestIDLogFilter`. Log lines emitted outside any request show `[-]` in the request_id slot.
- **Health check:** `GET /healthz` returns 200 when both signing keys and `known.hosts.json` are readable, 503 otherwise with a list of specific problems. Not throttled (`@throttle_classes([])`). Useful for load-balancer health probes.
- **Throttling:** `ProvideCollateralThrottle` extends `AnonRateThrottle` and reads `settings.COLLATERAL_THROTTLE_RATE` (default `60/min`). The cache backend is file-based (`django.core.cache.backends.filebased.FileBasedCache`) so multi-worker gunicorn shares the count.
- **Error shape:** every error body is `{"detail": <string>}`. The flattening lives in `api.util.normalize_error_response`, wired via `REST_FRAMEWORK['EXCEPTION_HANDLER']`. A view returning `Response(serializer.errors, ...)` directly would bypass it — use `is_valid(raise_exception=True)`.

## Gotchas / non-obvious things

- **DB is `:memory:`.** [settings.py](collateral_provider/collateral_provider/settings.py) hardcodes sqlite in-memory. There are no migrations or models in this app — Django's ORM is effectively unused. If you ever see a stray `db.sqlite3` it's from `manage.py` commands defaulting to file-based; it's gitignored.
- **No native CSRF/auth.** It's an open POST API. Throttling is the only abuse control: `ProvideCollateralThrottle` (default `60/min` per IP, env-overridable via `COLLATERAL_THROTTLE_RATE`).
- **Koios is the only upstream.** [simulate.py](collateral_provider/api/simulate.py) reads the URL from `settings.ENVIRONMENTS[<env>]['KOIOS_URL']` (defaults to `https://{preprod|api}.koios.rest/api/v1/ogmios`, overridable per network). Has a `(3s, 5s)` connect/read timeout. On any timeout/network/non-2xx/non-JSON failure it raises `UpstreamUnavailable`, which becomes a 503 to the user — distinct from a 400 "Transaction Fails Validation" (which means Koios actually said the tx was bad).
- **Signing is PyNaCl Ed25519, not cardano-cli.** Keys in `api/key/payment.{skey,vkey}` are Cardano CLI JSON (`{"cborHex": "..."}`); `get_key_from_file` strips the first 4 hex chars and caches by path + mtime. Startup verifies the skey, vkey, and PKH are one identity.
- **Startup validation:** [api/apps.py](collateral_provider/api/apps.py) `ApiConfig.ready()` validates the keys at process start (skipped for `collectstatic` / `makemigrations` / `test`). A misconfigured deploy fails in the logs rather than 500ing on the first POST.
- **Tx hashing preserves wire bytes.** [signature.tx_id](collateral_provider/api/signature.py) hashes the exact body-byte slice from the submitted transaction. Never re-serialize first: valid CBOR encoding choices affect the transaction ID.
- **HTTPS is the proxy's job.** No `SECURE_SSL_REDIRECT` / `SECURE_HSTS_SECONDS` settings — production is expected behind a TLS-terminating proxy that handles HSTS and HTTP→HTTPS redirects. We set `SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')` so `request.is_secure()` works behind the proxy.
- **`banned_addresses` matches on raw output bytes hex** (full address bytes), not bech32. When adding a ban, hex-encode the binary address.
- **Logging writes to `LOG_FILE`** (default `./debug.log`) with rotation (1 MiB × 3). Gitignored. Every line includes the request id, e.g. `INFO 2026-... [a1b2c3d4e5f6] views Witnessed tx: ip=...`. Outside requests the id is `-`.
- **Custom DRF exception handler** [util.normalize_error_response](collateral_provider/api/util.py) flattens DRF's `{field: [messages]}` to `{"detail": "<first message>"}`. Returning `Response(serializer.errors, ...)` from a view bypasses it — use `is_valid(raise_exception=True)` so the handler kicks in.
- **/healthz is unthrottled** by `@throttle_classes([])`. New endpoints inherit no global throttle (we deliberately removed `DEFAULT_THROTTLE_CLASSES`), so they must opt in with `throttle_classes` — easier to forget than to mis-set.

## Branch state

`production` is the deployed branch and may lag `main`. Don't assume they match. The remote `main` is the integration branch — PR there.

## Style this repo prefers

- Validators are module-level functions (no classes); raise `serializers.ValidationError` via `util.raise_validation_error` so the message logs at WARNING and surfaces to the client. Use ERROR only for things that should page on-call.
- Title Case error strings ("Tx Is Too Large") — PR #7 standardized this.
- One Django app (`api`). Resist adding more.
- One error response shape: `{"detail": "<message>"}` on every 4xx/5xx. The success shape is endpoint-specific.
- `%`-style log args (`logger.info("foo %s", x)`) so the formatting cost is paid only when the level is actually emitted.
