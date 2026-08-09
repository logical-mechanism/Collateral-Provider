# CLAUDE.md

Notes for Claude Code working in this repo. Keep this terse and current — update when something here drifts from reality.

## What this is

A Django + DRF service that takes a Cardano transaction CBOR from a user, validates it satisfies the rules for using a shared collateral UTxO, and returns a witness (signature) for that transaction. One key, one collateral UTxO per network, shared across many users so they don't have to set up collateral in their own wallet.

The whole product is one main endpoint plus operational extras:

```
POST /<environment>/collateral/   body: { "tx": "<hex cbor>" }   -> { "witness": "<hex cbor>" }
GET  /healthz                                                          -> { "status": "ok", "version": "..." }
GET  /livez                                                            -> { "status": "ok", "version": "..." }
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
    - [serializers.py](collateral_provider/api/serializers.py) — validates the JSON request shape
    - [validators/](collateral_provider/api/validators/) — module-level functions (no classes); cbor / environment / transaction
    - [signature.py](collateral_provider/api/signature.py) — Ed25519 via PyNaCl, exact-byte tx hashing, witness CBOR, stat-identity-aware key cache
    - [script_integrity.py](collateral_provider/api/script_integrity.py) — verifies body field 11 against exact redeemer/datum bytes and current language views
    - [simulate.py](collateral_provider/api/simulate.py) — queries protocol parameters and calls Koios/Ogmios `evaluateTransaction`; URL per env from `settings.ENVIRONMENTS[<env>]['KOIOS_URL']`
    - [services/collateral.py](collateral_provider/api/services/collateral.py) — `issue_witness`, the validation pipeline below
    - [middleware.py](collateral_provider/api/middleware.py) — `RequestIDMiddleware`, `RequestIDLogFilter`, `RequestBodyLimitMiddleware`, `MetricsMiddleware`
    - [health.py](collateral_provider/api/health.py) — `readiness_problems()` behind `/healthz`: signing identity plus a throttle-cache round trip
    - [known_hosts.py](collateral_provider/api/known_hosts.py) — registry schema validation for `known.hosts.json`
    - [data_files.py](collateral_provider/api/data_files.py) — `MtimeReloadingJson`, the stat-identity hot reloader
    - [negotiation.py](collateral_provider/api/negotiation.py) — pins responses to JSON regardless of `Accept`
    - [metrics.py](collateral_provider/api/metrics.py) — Prometheus counters/histograms (per-process; see gotchas)
    - [log_format.py](collateral_provider/api/log_format.py) — `build_logging_config`, text or JSON lines
    - [tx_fields.py](collateral_provider/api/tx_fields.py) — Cardano body-field index constants and `SET_TAG = 258`
    - [ban_list.py](collateral_provider/api/ban_list.py) — banned addresses + IPs
    - [util.py](collateral_provider/api/util.py) — `raise_validation_error` and `normalize_error_response` (DRF exception handler)
    - [key/](collateral_provider/api/key/) — dev `payment.skey` / `payment.vkey`. Production overrides via `SKEY_PATH` / `VKEY_PATH` env vars.
    - [templates/api/landing.html](collateral_provider/api/templates/api/landing.html) — landing page template
    - [tests/](collateral_provider/api/tests/) — Django tests; fixtures in `test_data.py` / `test_big_data.py`
  - [collateral_provider/sample.env](collateral_provider/sample.env) — copy to `.env` and fill in
- [known.hosts.json](known.hosts.json) — validated public registry keyed by 28-byte collateral PKH; each 32-byte public key must derive its PKH and each network maps to an HTTPS `/<network>/collateral/` URL plus canonical UTxO reference
- [scripts/](scripts/) — helper scripts (curl + python clients, locust stress test)
- [Dockerfile](Dockerfile) / [docker-entrypoint.sh](docker-entrypoint.sh) — what actually ships: the image App Platform builds, and the entrypoint that materializes signing keys from `SKEY_CONTENTS` / `VKEY_CONTENTS`
- [.do/app.yaml](.do/app.yaml) — App Platform bootstrap template (NOT the live spec; see Deployment below)
- [deploy/](deploy/) — self-hosting only: systemd unit, nginx template, sudoers, SSH forced command
- [.github/workflows/ci.yml](.github/workflows/ci.yml) — CI: ruff, tests, coverage, OpenAPI validate, pip-audit
- [pyproject.toml](pyproject.toml) — ruff and coverage config
- [requirements.in](requirements.in) / [requirements-dev.in](requirements-dev.in) — direct deps; `*.txt` files are pip-compile lockfiles
- [SECURITY.md](SECURITY.md) — vuln reporting policy and operator hardening checklist

## Request flow (the part Claude needs to know cold)

`POST /<env>/collateral/` → `RequestBodyLimitMiddleware` (411 without `Content-Length`,
413 over the cap) → [ProvideCollateralView.post](collateral_provider/api/views.py), which
rejects an unknown `environment` before anything else → serializer shape check →
[services.collateral.issue_witness](collateral_provider/api/services/collateral.py) runs these
free functions in cheap-to-expensive order; the first failure raises and short-circuits the rest:

1. `validators.environment.check_ip_address` — reject banned IPs
2. `validators.environment.check_environment` — env must be one of `settings.ENVIRONMENTS`
   (defence in depth; the view already rejected unknown envs, so this never fires over HTTP)
3. `validators.cbor.check_cbor_hex` — hex-decodable, ≤ 16 KiB
4. `validators.cbor.check_tx_body` — top-level CBOR is `[body, witnesses, valid_bool, aux]`; `valid_bool` must be True
5. `validators.cbor.check_inputs` — collateral UTxO must NOT be in inputs (would spend it)
6. `validators.cbor.check_outputs` — every output address must not be in `banned_addresses`
7. `validators.cbor.check_collateral` — `body[13]` MUST contain exactly the configured collateral UTxO
8. `validators.cbor.check_collateral_return` — if `body[16]` exists it must pay our own payment key hash
9. `validators.cbor.check_signers` — our PKH MUST be in `body[14]` (required signers)
10. `validators.transaction.check_valid_tx` — require redeemers, fetch current
   protocol cost models, verify body field 11 commits to the exact submitted
   redeemer/datum bytes, require a correlated non-empty phase-2 result for the
   exact same pointers, and require committed execution units at least as large
   as every evaluated budget

Only after all of that does [signature.witness_tx_cbor](collateral_provider/api/signature.py) compute Blake2b-256 over the exact encoded body-byte slice from the submitted transaction and produce the witness. It does not decode and re-serialize the body, because changing otherwise equivalent CBOR encoding choices would change the transaction ID.

Validation errors propagate as `ValidationError`; `views.py` calls `is_valid(raise_exception=True)` so they flow through `util.normalize_error_response` (registered as `REST_FRAMEWORK['EXCEPTION_HANDLER']`) and emerge as `{"detail": "<message>"}`. Every 4xx/5xx from the wallet-facing collateral endpoint uses that shape — `{"tx_body": [...]}` should never appear there.

Upstream evaluation or protocol-parameter failures from `simulate.py` are
caught in `validators.transaction.check_valid_tx` and re-raised as
`UpstreamServiceUnavailable` (status 503). Don't let them become a 400 — that
misleads the user about whether their tx is bad.

## Cardano CBOR conventions used here

The provider witness signs only the body bytes. The outer `is_valid` flag and
witness set are mutable without changing the transaction ID. The ledger checks
that the flag agrees with phase-2 execution **in both directions** — claiming
invalid when the scripts pass raises `ValidationTagMismatch PassedUnexpectedly`
and claiming valid when they fail raises `FailedUnexpectedly`; both are phase-1
predicate failures, so the transaction is rejected rather than included. The
local `is_valid=true` check is therefore UX and defence in depth, not the
control protecting the collateral. Do not describe it as cryptographically
binding.

Collateral is consumed only when a transaction is included with
`is_valid=false` and `evalPlutusScripts` genuinely fails. Every other failure
mode — stale script-data hash, swapped scripts, a spent input or reference
input, an expired validity interval, a native-script failure, a time-translation
error — is phase 1, meaning rejection with the collateral untouched. Phase-2
evaluation is a pure function of the script, its arguments, the committed
execution units, the cost models, the transaction context, and the major
protocol version; the first five are pinned by the signature or by field 11,
and the sixth is not pinned by anything. That is why SECURITY.md requires
rotating the collateral UTxO before every hard fork.

A dedicated key controlling only the advertised UTxO remains a mandatory
operator invariant: the witness authorizes the whole body, and fields 4, 5, 9,
19 and 20 are never inspected.

Transaction body field indices (Conway era) referenced by the validators:

| idx | meaning              | read by                          |
|-----|----------------------|----------------------------------|
| 0   | inputs (set)         | `validators.cbor.check_inputs`   |
| 1   | outputs (list)       | `validators.cbor.check_outputs`  |
| 11  | script data hash     | `script_integrity`               |
| 13  | collateral inputs    | `validators.cbor.check_collateral` |
| 14  | required signers     | `validators.cbor.check_signers`  |
| 16  | collateral return    | `validators.cbor.check_collateral_return` |

That is the complete set. Every other body field — notably 4 (certificates),
5 (withdrawals), 9 (mint), 18 (reference inputs), 19/20 (voting and proposal
procedures) — is signed and **not** inspected. That is why the dedicated-key
invariant below is mandatory rather than advisory.

Set-typed fields accept both Conway encodings. `set<a0> = #6.258([* a0]) /
[* a0]`, and cbor2 yields a `set` of tuples for the tagged form but a `list`
of lists for the untagged one, so `validators.cbor._set_items` normalizes the
container *and* its entries. Never gate on `isinstance(x, set)` alone — that
rejects a legal encoding and breaks builders that omit tag 258.

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

`.env` is optional; settings also read process environment variables. Required
identity/network values still fail loudly when absent.

## Operational extras

- **Request correlation:** every request gets a 12-char hex `X-Request-ID` (or echoes a safe client-supplied ID of up to 64 ASCII letters, digits, `.`, `_`, `:`, and `-`). Unsafe values are replaced. The ID is set on a `contextvars.ContextVar` by [middleware.RequestIDMiddleware](collateral_provider/api/middleware.py) and pulled onto every log record by `RequestIDLogFilter`. Log lines emitted outside any request show `[-]` in the request_id slot.
- **Health checks:** `GET /livez` is pure process liveness. `GET /healthz` is signing readiness and cryptographically revalidates the current skey/vkey/PKH, catching broken hot rotations. Neither calls Koios or inherits throttling. `known.hosts.json` is presentation data, not a signing dependency.
- **Throttling:** `ProvideCollateralThrottle` extends `AnonRateThrottle` and reads `settings.COLLATERAL_THROTTLE_RATE` (default `300/min`). The cache backend is file-based (`django.core.cache.backends.filebased.FileBasedCache`) so multi-worker gunicorn shares the count. `OPTIONS` raises `MAX_ENTRIES` to 20000 — Django's default of 300 would delete a random third of the throttle counters on every write once that many client IPs were seen. The key is one source IP, so a proxying integrator spends the whole budget from one address.
- **Error shape:** every error body is `{"detail": <string>}`. The flattening lives in `api.util.normalize_error_response`, wired via `REST_FRAMEWORK['EXCEPTION_HANDLER']`. A view returning `Response(serializer.errors, ...)` directly would bypass it — use `is_valid(raise_exception=True)`.

## Gotchas / non-obvious things

- **DB is `:memory:`.** [settings.py](collateral_provider/collateral_provider/settings.py) hardcodes sqlite in-memory. There are no migrations or models in this app — Django's ORM is effectively unused. If you ever see a stray `db.sqlite3` it's from `manage.py` commands defaulting to file-based; it's gitignored.
- **No native CSRF/auth.** It's an open POST API. Throttling is the only abuse control: `ProvideCollateralThrottle` (default `300/min` per IP, env-overridable via `COLLATERAL_THROTTLE_RATE`). `CORS_ALLOW_ALL_ORIGINS = True` means any web page can make its visitors call the endpoint, so the throttle is per-visitor-IP in that case, not per-origin.
- **Koios/Ogmios is the only upstream.** [simulate.py](collateral_provider/api/simulate.py) reads the URL from `settings.ENVIRONMENTS[<env>]['KOIOS_URL']` (defaults to `https://{preprod|api}.koios.rest/api/v1/ogmios`, overridable per network). Evaluation uses a `(5s, 5s)` connect/read timeout; protocol parameters use `(3s, 5s)` and a five-minute cache. Transport, size, JSON-RPC, and schema failures become a 503 — distinct from a correlated transaction-invalid verdict, which becomes 400. The evaluator remains a funds-at-risk trust dependency; mainnet deployments should self-host or independently trust it.
- **Additional UTxOs are unsupported.** The serializer accepts an omitted or
  empty compatibility field but rejects every non-empty `additional_utxos`.
  Never forward caller-supplied UTxOs to Ogmios: an unseen parent reference
  does not authenticate its future output. Safe support requires full parent
  CBOR verification or an authoritative mempool.
- **Signing is PyNaCl Ed25519, not cardano-cli.** Keys in `api/key/payment.{skey,vkey}` are Cardano CLI JSON (`{"cborHex": "..."}`); `get_key_from_file` strips the first 4 hex chars and caches by path plus `(mtime_ns, size, inode)`. Equal- or older-mtime atomic replacements therefore reload. Startup and `/healthz` verify the skey, vkey, and PKH are one identity; witness creation derives its public key from the exact skey snapshot and rechecks the configured PKH so split-file rotation cannot emit a mismatched witness.
- **Startup validation:** [api/apps.py](collateral_provider/api/apps.py) `ApiConfig.ready()` validates the keys at process start (skipped for `collectstatic` / `makemigrations` / `test`). A misconfigured deploy fails in the logs rather than 500ing on the first POST.
- **Tx hashing preserves wire bytes.** [signature.tx_id](collateral_provider/api/signature.py) hashes the exact body-byte slice from the submitted transaction. Never re-serialize first: valid CBOR encoding choices affect the transaction ID.
- **HTTPS is the proxy's job.** No `SECURE_SSL_REDIRECT` / `SECURE_HSTS_SECONDS` settings — production is expected behind a TLS-terminating proxy that handles HSTS and HTTP→HTTPS redirects. We set `SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')` so `request.is_secure()` works behind the proxy.
- **`banned_addresses` matches on raw output bytes hex** (full address bytes), not bech32. When adding a ban, hex-encode the binary address.
- **Logging writes to `LOG_FILE`** (default `./debug.log`) with rotation (1 MiB × 3). `LOG_TO_CONSOLE=True` switches exclusively to stderr for systemd/journald or containers; it does not instantiate the file handler. All app and Django loggers use the selected destination without propagation duplicates. Every line includes the request ID. Application request records omit raw client IPs; success records also omit the transaction hash, avoiding an operator-side link between network identity and on-chain activity. Outside requests the ID is `-`.
- **Operator JSON files reload by stat identity.** `bans.json` and `known.hosts.json` cache `(mtime_ns, size, inode)`, not an increasing mtime, so atomic replacements reload even when timestamps are preserved or older. Invalid updates retain the last valid document. The known-hosts validator checks PKH/public-key derivation, network names, UTxO references, and HTTPS endpoint paths before publishing a reload.
- **Custom DRF exception handler** [util.normalize_error_response](collateral_provider/api/util.py) flattens DRF's `{field: [messages]}` to `{"detail": "..."}`. For `non_field_errors` and our own validators the message passes through unchanged; for a field-keyed error it folds the field name in (`"tx: ..."`), with special-cased wording for DRF's required/null/blank defaults. Returning `Response(serializer.errors, ...)` from a view bypasses it — use `is_valid(raise_exception=True)` so the handler kicks in. Paths outside DRF have their own handlers: `handler404` (JSON 404 for API callers, redirect for browsers), `handler500`, and `handler400` for `DisallowedHost` — all three emit the same envelope.
- **/healthz is unthrottled** by `@throttle_classes([])`. New endpoints inherit no global throttle (we deliberately removed `DEFAULT_THROTTLE_CLASSES`), so they must opt in with `throttle_classes` — easier to forget than to mis-set.

## Deployment (verify before trusting this section)

**`main` is the deployed branch. Merging a PR to `main` ships to production
immediately.** DigitalOcean App Platform builds the repo `Dockerfile` and
auto-deploys on every push (`deploy_on_push: true`). There is no promotion
step and no manual approval gate.

DigitalOcean builds from GitHub independently of GitHub Actions, so **CI does
not gate a deploy** — a red `main` still ships. Branch protection on `main` is
what makes CI meaningful; the workflow run itself does not block anything.

Blast radius is bounded: App Platform keeps the current deployment serving
until the new one passes its `/healthz` check, so a container that fails to
boot leaves production up rather than taking it down.

The `production` branch and everything under `deploy/` —
`collateral-provider-deploy`, the systemd unit, the nginx template, the
sudoers rule — plus `.github/workflows/deploy-production.yml` and
`docs/UBUNTU_DEPLOY.md` describe a **single-host self-hosting path that this
provider does not use**. They are maintained for operators who want to run
their own instance. Do not treat them as this deployment.

`.do/app.yaml` in this repo is a bootstrap template with placeholder secrets,
**not** a mirror of the live app, and applying it over a running app destroys
the real secrets. Read the live spec instead — `doctl apps spec get <app-id>`,
or the DO console under App → Settings → App Spec. This file claiming
otherwise is what previously sent a full round of work at infrastructure that
did not exist, so check the live spec before doing any deployment work.

## Style this repo prefers

- Validators are module-level functions (no classes); raise `serializers.ValidationError` via `util.raise_validation_error` so the message logs at WARNING and surfaces to the client. Use ERROR only for things that should page on-call.
- Title Case error strings ("Tx Is Too Large") — PR #7 standardized this.
- One Django app (`api`). Resist adding more.
- One wallet-facing collateral error shape: `{"detail": "<message>"}` on every 4xx/5xx from `/<env>/collateral/`. Auxiliary endpoints may use endpoint-specific formats.
- `%`-style log args (`logger.info("foo %s", x)`) so the formatting cost is paid only when the level is actually emitted.
