# CLAUDE.md

Notes for Claude Code working in this repo. Keep this terse and current — update when something here drifts from reality.

## What this is

A Django + DRF service that takes a Cardano transaction CBOR from a user, validates it satisfies the rules for using a shared collateral UTxO, and returns a witness (signature) for that transaction. One key, one collateral UTxO per network, shared across many users so they don't have to set up collateral in their own wallet.

The whole product is essentially one endpoint:

```
POST /<environment>/collateral/   body: { "tx_body": "<hex cbor>" }   -> { "witness": "<hex cbor>" }
```

## Repo layout

- [collateral_provider/](collateral_provider/) — Django project root (`manage.py` lives here)
  - [collateral_provider/collateral_provider/](collateral_provider/collateral_provider/) — Django settings/urls/wsgi
  - [collateral_provider/api/](collateral_provider/api/) — the only app; all the real logic
    - [views.py](collateral_provider/api/views.py) — `ProvideCollateralView` (the endpoint), landing page, `known_hosts` view
    - [serializers.py](collateral_provider/api/serializers.py) — orchestrates validation, calls validators in order
    - [validators/](collateral_provider/api/validators/) — `EnvironmentValidator`, `CborValidator`, `TransactionValidator`
    - [signature.py](collateral_provider/api/signature.py) — Ed25519 signing via PyNaCl, tx hashing, witness CBOR construction
    - [simulate.py](collateral_provider/api/simulate.py) — calls Koios Ogmios `evaluateTransaction` to confirm the tx is executable
    - [ban_list.py](collateral_provider/api/ban_list.py) — banned addresses + IPs
    - [middleware.py](collateral_provider/api/middleware.py) — host header guard
    - [util.py](collateral_provider/api/util.py) — `log_and_raise_error`
    - [key/](collateral_provider/api/key/) — `payment.skey` / `payment.vkey` (gitignored in practice; do not commit real keys)
    - [tests/](collateral_provider/api/tests/) — Django tests; fixtures in `test_data.py` / `test_big_data.py`
  - [collateral_provider/sample.env](collateral_provider/sample.env) — copy to `.env` and fill in
- [known.hosts.json](known.hosts.json) — public registry of known providers, keyed by collateral PKH; surfaced on the landing page
- [scripts/](scripts/) — helper scripts (curl + python clients, locust stress test)
- [guides/](guides/) — server setup notes
- [requirements.txt](requirements.txt) — Python deps

## Request flow (the part Claude needs to know cold)

`POST /<env>/collateral/` → [ProvideCollateralView.post](collateral_provider/api/views.py) →
[ProvideCollateralSerializer.validate_tx_body](collateral_provider/api/serializers.py) runs in this order:

1. `EnvironmentValidator.check_ip_address` — reject banned IPs
2. `EnvironmentValidator.check_environment` — env must be one of `settings.ENVIRONMENTS`
3. `CborValidator.check_cbor_hex` — hex-decodable, ≤ 16 KiB
4. `CborValidator.check_tx_body` — top-level CBOR is `[body, witnesses, valid_bool, aux]`; `valid_bool` must be True
5. `CborValidator.check_inputs` — collateral UTxO must NOT be in inputs (would spend it)
6. `CborValidator.check_outputs` — every output address must not be in `banned_addresses`
7. `CborValidator.check_collateral` — collateral UTxO MUST be in `body[13]` (collateral inputs)
8. `CborValidator.check_signers` — our PKH MUST be in `body[14]` (required signers)
9. `TransactionValidator.check_valid_tx` — Koios `evaluateTransaction`; if no `result` key, reject

Only after all of that does [signature.witness_tx_cbor](collateral_provider/api/signature.py) compute the body hash (Blake2b-256, with `OrderedSet` reordering for inputs/certs/collateral/required-signers/reference-inputs/proposal-procedures) and produce the witness.

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

## Gotchas / non-obvious things

- **DB is `:memory:`.** [settings.py](collateral_provider/collateral_provider/settings.py) hardcodes sqlite in-memory. There are no migrations or models in this app — Django's ORM is effectively unused. If you ever see a stray `db.sqlite3` it's from `manage.py` commands defaulting to file-based; it's gitignored.
- **No native CSRF/auth.** It's an open POST API. Throttling is the only abuse control: `ProvideCollateralThrottle` at 60/min per IP (anon).
- **External dependency on Koios.** [simulate.py](collateral_provider/api/simulate.py) hits `https://{api|preprod|preview}.koios.rest/api/v1/ogmios`. If Koios is down, every request 400s with "Transaction Fails Validation". No timeout is set on the request — worth flagging if you touch this file.
- **Signing is PyNaCl Ed25519, not cardano-cli.** The repo recently dropped its `cardano-cli` dependency. Keys in `api/key/payment.{skey,vkey}` are Cardano CLI JSON (`{"cborHex": "..."}`); `get_key_from_file` strips the first 4 hex chars (CBOR tag) before signing.
- **Tx-hash construction is hand-rolled.** [signature.tx_id](collateral_provider/api/signature.py) re-canonicalizes specific set-typed fields with `pycardano.OrderedSet` before hashing. If a new Conway-era set field is added to the body, it'll need to be reordered here too or the hash will be wrong.
- **`ENVIRONMENT=production` doesn't actually enforce HTTPS.** [settings.py](collateral_provider/collateral_provider/settings.py) sets `SECURE_SSL_REDIRECT = False` and `SECURE_HSTS_SECONDS = 0` even in the production branch. The reverse proxy is expected to handle TLS.
- **`banned_addresses` matches on raw output bytes hex** (full address bytes), not bech32. When adding a ban, hex-encode the binary address.
- **Logging writes to `collateral_provider/debug.log`** with rotation (1 MB × 3). Gitignored. Don't tail it as a sign of liveness — DRF throttling cache is the source of truth on rate limits.

## Branch state

`production` is the deployed branch and may lag `main`. Don't assume they match. The remote `main` is the integration branch — PR there.

## Style this repo prefers

- Validators are tiny classes with a logger; raise `serializers.ValidationError` via `log_and_raise_error` so the message logs once and surfaces to the client identically. Keep error strings in Title Case ("Tx Is Too Large") — there's a whole PR (#7) standardizing that.
- One Django app (`api`). Resist adding more.
- Keep response shape stable: `{ "witness": "..." }` on 200, `{ "<field>": ["msg"] }` (DRF default) or `{ "error": "..." }` on 4xx.
