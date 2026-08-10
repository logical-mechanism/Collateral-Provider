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
duplicate map keys, and bignum handling. And it allows a lower nesting depth
cap — `cbor2` 5.9.0 stops at 400 containers, whereas an unbounded recursive
Rust decoder would abort the process on stack overflow well before that.

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

### Running it for real

`cargo test` never touches the network. Two suites go further and are off
unless you opt in:

```sh
./scripts/e2e.sh                                    # the whole cycle
COLLATERAL_LIVE_UPSTREAM=1 cargo test --test live_upstream -- --nocapture
```

[scripts/e2e.sh](scripts/e2e.sh) starts a local instance, builds a transaction
that genuinely earns a witness, runs [tests/live_service.rs](tests/live_service.rs)
against it, and stops. That test drives the assembled binary over real HTTP —
middleware ordering, request-shape wording, the error envelope — and finishes
by checking that the returned witness verifies as Ed25519 over
`blake2b256(exact submitted body bytes)` and that the signing key's hash is
the one published at `/known_hosts/`. Reaching a 200 at all means the service
fetched live protocol parameters, verified the script-data binding, and ran
live phase-2 evaluation.

The instance is configured by [scripts/run-local.sh](scripts/run-local.sh) to
sponsor a real, unspent preprod collateral UTxO while signing with this repo's
development key. Nothing is submitted and no funds move: field 13 only *names*
that UTxO, and the transaction's input belongs to someone else. Run
`./scripts/run-local.sh` on its own to keep an instance up and poke at it by
hand.

The transaction builder is `../scripts/py/dummy_collateral_tx.py`. That is the
only Python in this path and it is a test tool, not a runtime dependency —
`cargo test` never needs it and neither does the binary. Without it `e2e.sh`
runs everything except the final witness check and says so.

[tests/live_upstream.rs](tests/live_upstream.rs) separately checks Ogmios wire
compatibility against the public endpoints and reports whether the frozen cost
models have drifted from the network's current ones.

A caveat on both: skipped tests still report `ok`, because libtest has no
third outcome, and the reason only surfaces under `--nocapture`. A green line
from either suite proves nothing unless you saw the output — which is why
`e2e.sh` always passes `--nocapture`.

## Deliberate differences from the Python service

These are choices, not gaps. The pipeline order, the validation rules, the
`{"detail": "..."}` envelope, the Title Case error strings and the DRF wording
for request-shape errors are reproduced exactly; everything that is *not* is
listed here.

| Area | Python | Rust | Why |
|---|---|---|---|
| Throttle storage | File-based Django cache | In-process sliding window | Only needed because gunicorn runs several worker processes that must share a counter. One process does not. Removes the cache directory as a failure mode, and with it the `/healthz` cache probe. |
| `KOIOS_MAX_IN_FLIGHT` | Per worker process | Whole process | One process replaces gunicorn's two. **Double it** to match an existing deployment's total budget. |
| `DJANGO_SECRET_KEY` | Required | Accepted, ignored | No sessions, CSRF, or signed cookies — nothing for it to key. Kept accepted so one env file drives either implementation. |
| Default key/data paths | Relative to Django's `BASE_DIR` | Relative to the working directory | A binary has no `BASE_DIR`. Under systemd the working directory is `/`, so name `BANS_PATH` and `KNOWN_HOSTS_PATH` explicitly — an absent ban list is a supported configuration that logs nothing per request, and the bans would simply never take effect. The shipped unit sets both; see [sample.env](sample.env). |
| `BIND_ADDRESS` | gunicorn `--bind` | Env var | No external process supervisor to carry it. |
| Landing page, `/api/docs`, `/api/redoc` | Served | Not served | Frontend stays in Django. `/api/schema` is served as a static document. |
| Nesting depth | `cbor2` 5.9.0 caps at 400 containers | Hard cap at 256 | Rust would abort on stack overflow rather than raise. Depths 257–400 are accepted there and refused here; the deepest real transaction observed is 23. |
| Stray `0xff`, `f8 00`–`f8 1f` | `cbor2` accepts | Rejected | RFC 8949 says ill-formed. Diverges in the rejecting direction. |
| Semantic CBOR tags | `cbor2` runs a per-tag decoder and 400s a bad payload anywhere in the body | Only bignum tags 2/3 are interpreted | A bogus tag parked in a body field no validator reads (2–9, 15, 17–21) is a 400 from Django and is accepted here. It cannot earn a witness Django would refuse: the ledger's decoder rejects the same body in phase 1, and stripping the field would change the signed bytes. |
| Set de-duplication | Python `set`, so `0 == False == 0.0` collapse | Structural equality, so they stay distinct | Diverges in the rejecting direction, on input the ledger's decoder refuses anyway. |
| Duplicate keys in the Conway redeemer map | `dict` collapses them last-wins before validation | Every entry is shape-checked | Diverges in the rejecting direction. |
| Tag-258 set iteration order | Python `set` order, so a mixed-validity set is `PYTHONHASHSEED`-dependent | Wire order | The Python verdict is not reproducible between worker processes; this one is. |
| `HEAD` on the read-only endpoints | 405 (DRF's `api_view` does not derive it) | 200, derived from the `GET` handler | Correct HTTP, and a health probe using `HEAD` should not be told the method is unsupported. |
| `/metrics` and `/known_hosts/` rejection bodies | Empty `text/html` | `{"detail": ...}` JSON | Auxiliary endpoints may use endpoint-specific formats; a JSON body is friendlier and the wallet-facing envelope is unaffected. |
| Malformed-JSON detail text | CPython `json` wording, with a character offset | `serde_json` wording | Both are `JSON parse error - <decoder message>`; the decoder is not the same one. |
| Percent-encoded paths | Decoded before routing | Matched raw | `/pre%70rod/collateral/` is served by Django and 404s here. |
| Malformed `Content-Length` | `{"detail": "Invalid Content-Length"}` | hyper rejects the header while parsing the request, so a bare 400 with no body and no `X-Request-ID` | Not answerable above hyper. The equivalent check in `middleware/body_limit.rs` stays for any transport that does not pre-validate the header. |
| `known.hosts.json` in the container image | Copied in (`COPY . /app/`) | Not copied | The Docker build context is `rs/`, and the registry lives at the repo root. A container serves `{}` unless `KNOWN_HOSTS_PATH` points at a mounted file — the service logs which at startup. |

Config parsing also differs in small ways that only surface with unusual values:
comma-separated lists are whitespace-trimmed here and not by django-environ;
`METRICS_ALLOW_IPS` is compared as parsed addresses rather than raw strings;
`LOG_LEVEL` accepts lowercase and a few names `dictConfig` rejects; and startup
key-validation failures log at ERROR rather than CRITICAL.

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

## Self-hosting with systemd

[deploy/collateral-provider-rs.service](deploy/collateral-provider-rs.service)
is the whole thing. Compared with the Python unit in `../deploy/` there is no
virtualenv, no gunicorn worker/thread tuning, and no writable cache directory
to provision — the throttle window lives in process memory.

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin collateral-provider
sudo install -m 0755 target/release/collateral-provider /usr/local/bin/
sudo install -d -m 0750 -o root -g collateral-provider /etc/collateral-provider
sudo install -m 0640 -o root -g collateral-provider \
    sample.env /etc/collateral-provider/environment   # then edit it
sudo install -m 0644 deploy/collateral-provider-rs.service \
    /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now collateral-provider-rs
```

Put the signing keys somewhere the unit can read and the world cannot —
`/etc/collateral-provider/keys/` owned `root:collateral-provider`, mode `0640`,
with `SKEY_PATH` / `VKEY_PATH` pointing at them. The unit runs with
`ProtectSystem=strict` and no write access anywhere, so a key path inside a
writable directory is a smell, not a convenience.

**TLS is still the proxy's job.** The service binds loopback and speaks plain
HTTP; nginx or Caddy in front terminates TLS, sets HSTS, and redirects
HTTP→HTTPS. Set `TRUSTED_PROXY_IPS` to that proxy's address or the throttle
and ban list will key on the proxy instead of the caller. The nginx template
in `../deploy/` works unchanged apart from the upstream port — but drop its
static-file location blocks, since this binary serves no static assets.

Check it came up with `systemctl status collateral-provider-rs` and
`curl -s localhost:8000/healthz`, which revalidates the signing identity
cryptographically rather than just reporting that the process is alive.

## Container

```sh
docker build -t collateral-provider-rs rs/
```

Multi-stage, non-root, dependency-layer cached. Signing keys are not baked in;
the entrypoint materializes `SKEY_CONTENTS` / `VKEY_CONTENTS` under `/run/keys`
for platforms that offer neither secret files nor volumes, exactly as the
Python image does.
