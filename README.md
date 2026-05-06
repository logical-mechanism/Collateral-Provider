# Altruistic Collateral Provider API

A small Django + DRF service that signs Cardano transactions using a shared
collateral UTxO. Users build their smart-contract transaction including this
provider's collateral UTxO and PKH, POST the CBOR to `/collateral`, and get
back a vkey witness they attach to the witness set before submitting on chain.

The whole product is one endpoint:

```
POST /<environment>/collateral/   { "tx_body": "<hex cbor>" }   →   { "witness": "<hex cbor>" }
```

Validation pipeline (cheap to expensive — first failure short-circuits the rest):

1. Banned IP / unknown environment
2. CBOR decodes; tx ≤ 16 KiB
3. Top-level shape is `[body, witnesses, is_valid, aux]` with `is_valid == true`
4. Inputs do **not** include the collateral UTxO (would consume it)
5. No output addresses are on the manual ban list
6. Collateral UTxO **is** in `body[13]` (collateral inputs)
7. Provider PKH **is** in `body[14]` (required signers)
8. Koios `evaluateTransaction` accepts the tx (HTTP, with timeout + 503 on upstream failure)

If all eight pass, the body is canonicalized (set fields sorted and re-tagged
258), Blake2b-256 hashed, signed Ed25519 with the on-disk skey via PyNaCl, and
the witness CBOR `[0, [pubkey, signature]]` is returned hex-encoded.

No full node, no Cardano CLI, no Blockfrost API key. Validation is delegated
to a public Koios endpoint per environment.

### Why use it

Providing collateral from your own wallet is a privacy and key-management
concern. This service lets many users share a single collateral UTxO without
each running their own. New users can transact before ever having to set one
up themselves.

### Example use

```bash
curl -X POST https://www.giveme.my/preprod/collateral/ \
     -H 'Content-Type: application/json' \
     -d '{ "tx_body": "84a900d901028182582000...f5f6" }'
```

Replace `preprod` with whichever network the host you're calling supports.
For client-side examples in Python and Bash, see [`scripts/`](scripts/).

### API documentation

When the server is running, interactive OpenAPI docs are available at:

- `/api/docs/` — Swagger UI
- `/api/redoc/` — ReDoc
- `/api/schema/` — raw OpenAPI 3 schema

## Setup

```bash
python3 -m venv venv
source venv/bin/activate

# Service only:
pip install -r requirements.txt

# Service + tests + linter + stress tooling:
pip install -r requirements-dev.txt

cp collateral_provider/sample.env collateral_provider/.env
# fill in PKH, the network TXIDs, ALLOWED_HOSTS, etc.
```

Direct dependencies live in `requirements.in` and `requirements-dev.in`. The
`*.txt` files are lockfiles regenerated with `pip-compile`:

```bash
pip-compile --upgrade --strip-extras requirements.in
pip-compile --upgrade --strip-extras requirements-dev.in
```

The signing keys are read once at process start and validated via
`api.apps.ApiConfig.ready` — a misconfigured deploy fails fast in the logs
instead of returning 500s on the first request.

## Testing

```bash
cd collateral_provider
python3 manage.py test          # ~70 tests, runs in <50ms, no network
python3 -m coverage run --rcfile=../pyproject.toml manage.py test
python3 -m coverage report
```

## Linting

```bash
ruff check collateral_provider/
ruff check --fix collateral_provider/
```

## Running the server

```bash
cd collateral_provider
python3 manage.py runserver                 # dev
gunicorn collateral_provider.wsgi:application  # prod (behind a TLS proxy)
```

In production this expects to sit behind a TLS-terminating reverse proxy
(nginx, Caddy, etc.). Django trusts `X-Forwarded-Proto` from the proxy via
`SECURE_PROXY_SSL_HEADER`. The proxy is also responsible for HSTS and any
HTTP→HTTPS redirects.
