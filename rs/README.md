# Collateral Provider — Rust API

A Rust port of the Django/DRF collateral provider. Same wire contract, same
validation pipeline, same error strings — one static binary instead of
gunicorn plus a Python runtime.

```sh
cd rs
cargo build --release
cp sample.env .env      # then fill in PKH, key paths, txids
./target/release/collateral-provider
```

That is the whole deployment story: no WSGI server, no worker/thread tuning,
no static-file collection, no file-based cache directory.

## Scope

This binary is **the API only**. The HTML landing page and the Swagger/ReDoc
UIs stay in the Django service, which remains the frontend. Both
implementations read the same environment variables and the same
`known.hosts.json`, so they can run side by side against one configuration.

```
POST /<environment>/collateral/   { "tx": "<hex cbor>" }  ->  { "witness": "<hex cbor>" }
GET  /healthz                                             ->  { "status": "ok", "version": "..." }
GET  /livez                                               ->  { "status": "ok", "version": "..." }
GET  /known_hosts/                                        ->  registry JSON
GET  /metrics                                             ->  Prometheus text (off by default)
GET  /api/schema                                          ->  OpenAPI JSON
```

Every other path answers `{"detail": "Not Found"}` with a 404. The Django
service redirects browsers to its landing page; an API-only binary has nothing
to redirect to, and redirecting would make a mistyped collateral URL look like
a success to any client that follows redirects by default.

## Layout

Module names mirror `collateral_provider/api/` so the two implementations can
be diffed against each other.

| Rust | Python | What it does |
|---|---|---|
| [src/cbor.rs](src/cbor.rs) | *(cbor2)* | Hand-rolled CBOR with byte-span tracking |
| [src/signature.rs](src/signature.rs) | `signature.py` | Ed25519, exact-byte tx hashing, witness CBOR |
| [src/script_integrity.rs](src/script_integrity.rs) | `script_integrity.py` | Body field 11 vs submitted redeemers/datums |
| [src/simulate.rs](src/simulate.rs) | `simulate.py` | Koios/Ogmios protocol params + `evaluateTransaction` |
| [src/validators/](src/validators/) | `validators/` | The structural and semantic checks |
| [src/services/collateral.rs](src/services/collateral.rs) | `services/collateral.py` | The pipeline orchestrator |
| [src/routes.rs](src/routes.rs) | `views.py` + `urls.py` | HTTP surface, request shape, error envelope |
| [src/middleware/](src/middleware/) | `middleware.py` | Request id, body limit, metrics, allowed hosts |
| [src/data_files.rs](src/data_files.rs) | `data_files.py` | Stat-identity hot reload for operator JSON |
| [src/throttle.rs](src/throttle.rs) | DRF `AnonRateThrottle` | Per-IP sliding window |

## Why the CBOR codec is hand-rolled

Two things in this service are byte-exact, and no general-purpose CBOR crate
gives them to you reliably:

1. **Transaction hashing.** `signature::tx_id` hashes the body's exact wire
   byte slice. Re-serializing a decoded body changes the transaction id
   whenever the client's encoding choices — definite vs indefinite lengths,
   integer widths, map-key order, set-tag presence — differ from ours.
2. **Script-data-hash verification.** Body field 11 commits to the *original
   bytes* of the witness-set redeemers and datums. The ledger memoizes those
   bytes deliberately; re-encoding is not equivalent.

Hand-rolling also buys exact control over the semantics the Python service
inherits from `cbor2`: tag-258 sets in both Conway encodings, last-wins
duplicate map keys, and bignum handling. And it allows a nesting depth cap —
`cbor2` raises `RecursionError` on pathological input, whereas an unbounded
recursive Rust decoder would abort the process on stack overflow.

### How it is tested

`cargo test` runs **435 tests**, no network, no Python. The ones that matter
most for the codec:

- **[tests/differential.rs](tests/differential.rs) and
  [tests/cbor_chain_corpus.rs](tests/cbor_chain_corpus.rs)** — 162 real
  transactions harvested from Koios (mainnet + preprod, epochs 194–644, Byron
  through Conway), selected to maximise structural diversity. Each carries the
  hash *the chain itself assigned*, so `blake2b256(body span) == tx_hash` is an
  oracle the implementation cannot argue with. Coverage assertions fail if a
  future corpus refresh loses tag-258 sets, Babbage map outputs, Conway
  redeemer maps, or bignum quantities.
- **[tests/script_data_live.rs](tests/script_data_live.rs)** — 12 mainnet
  transactions paired with the cost models of their own epoch, so the
  language-view encoder (PlutusV1 double-bagging, indefinite parameter list,
  shortlex key ordering) is pinned to something the live network accepted.
  Includes a negative control: perturbing one cost parameter must break
  verification.
- **[tests/cbor_rfc8949.rs](tests/cbor_rfc8949.rs)** — the RFC 8949 Appendix A
  vector table plus the well-formedness negatives.
- **[tests/cbor_differential_fuzz.rs](tests/cbor_differential_fuzz.rs)** —
  frozen divergences found by running ~267,000 inputs through both this
  decoder and `cbor2` (see [scripts/](scripts/)). Every difference is
  classified `benign`, `rust-stricter`, or `rust-bug`; there are no open
  `rust-bug` entries.
- **[tests/cbor_robustness.rs](tests/cbor_robustness.rs)** — truncation,
  bit-flip, insertion and deletion sweeps over real transactions; allocation
  bombs (a byte string declaring 2^64−1 bytes must error in microseconds, not
  allocate); depth bombs; 16 KiB of container heads.

[tests/live_upstream.rs](tests/live_upstream.rs) checks Ogmios wire
compatibility against the public endpoints. It is skipped unless
`COLLATERAL_LIVE_UPSTREAM=1`, and prints why when skipped, so a green log never
implies it ran.

## Deliberate differences from the Python service

These are choices, not gaps. Everything else — the pipeline order, the
validation rules, the `{"detail": "..."}` envelope, the Title Case error
strings, the DRF wording for request-shape errors — is reproduced exactly.

| Area | Python | Rust | Why |
|---|---|---|---|
| Throttle storage | File-based Django cache | In-process sliding window | Only needed because gunicorn runs several worker processes that must share a counter. One process does not. Removes the cache directory as a failure mode, and with it the `/healthz` cache probe. |
| `KOIOS_MAX_IN_FLIGHT` | Per worker process | Whole process | One process replaces gunicorn's two. **Double it** to match an existing deployment's total budget. |
| `DJANGO_SECRET_KEY` | Required | Accepted, ignored | No sessions, CSRF, or signed cookies — nothing for it to key. Kept accepted so one env file drives either implementation. |
| Default key/data paths | Relative to Django's `BASE_DIR` | Relative to the working directory | A binary has no `BASE_DIR`. See [sample.env](sample.env). |
| `BIND_ADDRESS` | gunicorn `--bind` | Env var | No external process supervisor to carry it. |
| Landing page, `/api/docs`, `/api/redoc` | Served | Not served | Frontend stays in Django. `/api/schema` is served as a static document. |
| Nesting depth | `cbor2` fails around 500 | Hard cap at 256 | Rust would abort on stack overflow rather than raise. The deepest real transaction observed is 23. |
| Stray `0xff`, `f8 00`–`f8 1f` | `cbor2` accepts | Rejected | RFC 8949 says ill-formed. Diverges in the rejecting direction. |

## Operations

`/healthz` revalidates the signing identity cryptographically on every probe,
so a broken hot key rotation is caught immediately. `/livez` is pure process
liveness. Neither is throttled and neither calls an upstream.

SIGINT and SIGTERM drain in-flight signing requests before exit.

Logs go to stderr with `LOG_TO_CONSOLE=True` (recommended under systemd or a
container) or to a 1 MiB × 3 rotated `LOG_FILE`. `LOG_FORMAT=json` emits one
object per line with `level`, `time`, `logger`, `module`, `message` and
`request_id` — the same shape the Python service emits.

Success lines deliberately omit both the client IP and the transaction hash:
recording them together would create a durable link between a network identity
and on-chain activity. The request id still correlates a success with any
errors or timings from the same request.

See [../SECURITY.md](../SECURITY.md) for the operator hardening checklist. It
applies unchanged — in particular, the signing key must control *only* the
advertised collateral UTxO, and the collateral UTxO must be rotated before
every hard fork.

## Container

```sh
docker build -t collateral-provider-rs rs/
```

Multi-stage, non-root, dependency-layer cached. Signing keys are not baked in;
the entrypoint materializes `SKEY_CONTENTS` / `VKEY_CONTENTS` under `/run/keys`
for platforms that offer neither secret files nor volumes, exactly as the
Python image does.
