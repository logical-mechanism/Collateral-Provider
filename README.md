# Altruistic Collateral Provider API

A small Django + DRF service that signs Cardano transactions using a shared
collateral UTxO. Users build their smart-contract transaction including this
provider's collateral UTxO and PKH, POST the CBOR to `/collateral`, and get
back a vkey witness they attach to the witness set before submitting on chain.

The whole product is one endpoint:

```
POST /<environment>/collateral/   { "tx": "<hex cbor>" }   →   { "witness": "<hex cbor>" }
```

Validation pipeline (cheap to expensive — first failure short-circuits the rest):

1. Banned IP / unknown environment
2. CBOR decodes; tx ≤ 16 KiB
3. Top-level shape is `[body, witnesses, is_valid, aux]` with `is_valid == true`
4. Inputs do **not** include the collateral UTxO (would consume it)
5. No output addresses are on the manual ban list
6. `body[13]` contains exactly one collateral input: the configured UTxO
7. Provider PKH **is** in `body[14]` (required signers)
8. Body field 11 commits to the submitted redeemers/datums under the current
   protocol cost models
9. Koios/Ogmios returns a non-empty phase-2 result for exactly those redeemer
   pointers, and every execution budget committed in the witness set is at
   least the evaluated requirement

If all nine pass, the exact body-byte slice from the submitted transaction is
Blake2b-256 hashed, signed Ed25519 with the on-disk skey via PyNaCl, and the
witness CBOR `[0, [pubkey, signature]]` is returned hex-encoded.

No Cardano CLI or Blockfrost API key is required. By default the two upstream
queries (current protocol parameters and phase-2 evaluation) use a public Koios
endpoint per environment. That evaluator is a funds-at-risk trust dependency:
JSON-RPC correlation, response bounds, and local script-data/budget checks
protect against mixups and malformed replies, but a malicious evaluator can
still lie about script execution. Mainnet operators should point
`*_KOIOS_URL` at infrastructure they operate or independently trust.

### Collateral safety boundary

The returned vkey witness signs the transaction body. Cardano's outer
`is_valid` flag and witness set are not part of that hash; the ledger requires
the flag to agree with phase-2 execution. A phase-1 failure (expired validity
interval, missing input or signature, unbalanced value, and similar failures)
rejects the transaction without consuming collateral. Collateral is collected
only for a phase-2-invalid transaction submitted with `is_valid=false`.

To keep wallet integration straightforward, this API does not require CIP-40
`collateral_return` or `total_collateral` fields. Builders may and are
encouraged to use them to bound the provider's loss on the invalid branch,
provided the collateral return goes only to an address controlled by the
provider key. The provider requires an actual non-empty Plutus evaluation
before signing.

Non-empty `additional_utxos` is intentionally unsupported and cannot be
enabled by configuration. A reference to an unsubmitted parent transaction
does not prove what output that parent will create, while modern Ogmios
versions may prefer caller-supplied values over resolved ledger values. Safe
future-output support would require the complete parent transaction CBOR (and
verification that its body hashes to the reference) or an authoritative
mempool source. Until then, omitted or empty compatibility input is accepted
but never forwarded.

Operators must use a dedicated payment key that controls only the advertised
collateral UTxO. A body signature authorizes every use of that key hash in the
body, not merely the field labeled "collateral"; never reuse it for ordinary
wallet funds, stake credentials, native-script policies, or governance keys.

### Why use it

Providing collateral from your own wallet is a privacy and key-management
concern. This service lets many users share a single collateral UTxO without
each running their own. New users can transact before ever having to set one
up themselves.

### Example use

```bash
curl -X POST https://www.giveme.my/preprod/collateral/ \
     -H 'Content-Type: application/json' \
     -d '{ "tx": "84a900d901028182582000...f5f6" }'
```

Replace `preprod` with whichever network the host you're calling supports.
For client-side examples in Python and Bash, see [`scripts/`](scripts/).
Full-node and desktop-wallet implementers should use the
[`wallet integration contract`](docs/WALLET_INTEGRATION.md), including its
body-byte preservation and local witness-verification requirements.

### Other endpoints

- `GET /livez` — process liveness probe. Returns 200 whenever Django can serve requests.
- `GET /healthz` — signing-readiness probe. Cryptographically rechecks the
  current signing key, verification key, and PKH; returns 503 with a public-safe
  `problems` list on failure. It never calls Koios and is not rate-limited.
- `GET /known_hosts/` — full known-providers registry as JSON.
- `GET /` — public landing page (PKH, configured networks, doc links).

Every response carries an `X-Request-ID` header (mint a 12-character ID per
request, or echo a safe client-supplied ID of up to 64 ASCII characters).
Accepted client characters are letters, digits, `.`, `_`, `:`, and `-`;
unsafe or overlong values are replaced rather than reflected into logs or
headers. The ID is stamped on every log line emitted during the request, so
a user reporting a bad response can give you a single value to grep for.
Application request logs intentionally omit raw client IPs. Success records
retain the request ID plus network and duration but omit transaction hashes,
avoiding a durable link between network identities and on-chain activity.

### API documentation

When the server is running, interactive OpenAPI docs are available at:

- `/api/docs/` — Swagger UI
- `/api/redoc/` — ReDoc
- `/api/schema/` — raw OpenAPI 3 schema

### Error responses

Every error from the wallet-facing collateral endpoint uses a single shape:

```json
{ "detail": "<human-readable message>" }
```

That includes validation failures (400), method-not-allowed (405), request body
too large (413), unsupported media type (415), throttling (429), and
upstream/local signing unavailability (503). Field names from internal
serializers are not leaked. Auxiliary HTML and observability endpoints have
their own response formats.

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

The signing identity is validated via `api.apps.ApiConfig.ready`: the signing
key must derive the configured verification key, which must derive the
configured PKH. Collateral TXIDs and indices are validated too.

## Testing

```bash
./test.sh                        # everything
./test.sh api.tests.test_views   # single module
./test.sh -v 2                   # verbose
```

Or directly:

```bash
cd collateral_provider
python3 manage.py test
python3 -m coverage run --rcfile=../pyproject.toml manage.py test
python3 -m coverage report
```

## Linting

```bash
./lint.sh         # check
./lint.sh --fix   # auto-fix what's safe
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
HTTP→HTTPS redirects. Configure `TRUSTED_PROXY_IPS` with only the proxies
that can directly forward traffic to gunicorn. The service validates
`X-Forwarded-For` and walks it from right to left across those trusted hops,
so a caller-prefixed leftmost value cannot override the proxy-appended client
address. The proxy should still replace or correctly append the header and
prevent direct public access to gunicorn.

## Configuration

Every operational knob is overridable via `.env`. See
[`collateral_provider/sample.env`](collateral_provider/sample.env) for the
full list. The most useful overrides:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SKEY_PATH` / `VKEY_PATH` | `api/key/payment.{skey,vkey}` | Move signing keys outside the checkout in production. |
| `COLLATERAL_THROTTLE_RATE` | `60/min` | Per-IP rate limit for `/<env>/collateral/`. |
| `KOIOS_MAX_IN_FLIGHT` | `4` | Per-process outbound Koios admission budget; excess requests fail fast with 503. |
| `PREPROD_KOIOS_URL` / `MAINNET_KOIOS_URL` | Koios public hosting | Point evaluation at self-hosted Koios or alternate networks. |
| `LOG_LEVEL` / `LOG_FILE` | `DEBUG`, `./debug.log` | Log severity / rotated-file path when file logging is selected. |
| `LOG_TO_CONSOLE` | `False` | Send all app and Django logs to stderr instead of opening `LOG_FILE`; use for systemd/journald or containers. |
| `CACHE_DIR` | `./.cache` | File-based cache directory used by the throttle. |

## Reporting security issues

See [SECURITY.md](SECURITY.md). Short version: email
support@logicalmechanism.io rather than opening a public issue.
