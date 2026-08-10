# Rust port verification

Differential review of `rs/` against the Django reference, starting at `5432972`.
Method: 12 parallel module-pair reviews, each finding adversarially refuted by an
independent verifier, then re-validated against the tree after the code-review
fixes landed. 89 claims → 13 refuted → 76 confirmed → 3 already fixed by
`5432972` → 73 remaining: 1 medium, 67 low, 5 cosmetic.

**Status: the medium and the material low findings are fixed** (see *What was
fixed* below). What remains is listed under *Accepted divergences*, and the
durable subset is now in [README.md](README.md)'s deliberate-differences table
rather than only here.

Every DRF wording change was taken from Django itself rather than from the
source: the exact bodies, `Allow` headers and security headers were captured by
driving `django.test.Client` against the real view stack, then asserted against
the running Rust binary over HTTP.

## Verdict

**The port is correct where correctness matters.** Every divergence found is in
the HTTP envelope, config parsing, or logging — not in the code that decides
whether a witness is issued or what bytes get signed.

Independently verified (not by trusting the Rust test suite):

- All 162 corpus transactions: `blake2b256(body span) == chain-assigned tx hash`,
  recomputed with Python + `cbor2`. The Rust-recorded `body_span` agrees with
  `cbor2`'s on all 162.
- Corpus coverage: mainnet + preprod, epochs 194–644, body fields 0–18, both
  redeemer encodings (47 Alonzo lists, 13 Conway maps), 44 Babbage map outputs,
  38 tag-258 sets. Conway governance fields 19/20 are absent, but no validator
  reads them.
- Pipeline order in `services/collateral.rs:43-59` matches
  `services/collateral.py:60-72` step for step.
- Live Ogmios: cost models parse from real Koios for both networks
  (332/332/350 params for V1/V2/V3), frozen models still current.
- 445 Rust tests and 282 Django tests pass; `clippy -D warnings` and `fmt` clean;
  `#![forbid(unsafe_code)]`; 3 panic sites in 6,059 non-test lines, all
  compile-time-constant regexes.

No Python drift: zero commits touched `collateral_provider/` since `rs/` landed.

### What `5432972` fixed

The hex-decoder unification is complete on every caller-supplied path —
`validators/cbor.rs:56`, `validators/transaction.rs:94`,
`script_integrity.rs:156`, `signature.rs:248` all use `cbor::decode_hex`.

## What was fixed in response to this review

- **X-Forwarded-For** now joins every header line, closing the identity-spoofing
  vector described in §1. Key material also moved to `cbor::decode_hex`, so that
  decoder really is the only hex path.
- **DRF parity on the wallet-facing endpoint**: 405 quotes the verb and sends
  `Allow: POST, OPTIONS`; 415 names the refused media type; `null` bodies answer
  `No data provided`; empty bodies answer `Missing required field: 'tx'`;
  `application/*`, `*/*` and a missing `Content-Type` parse as JSON;
  `OPTIONS` on the collateral path returns DRF's metadata document.
- **A bare `OPTIONS` is routed instead of being short-circuited**, so a mistyped
  path answers 404 rather than an empty 200. Genuine preflights still get the
  full CORS response, now including `Access-Control-Max-Age`.
- **Django's security headers** (`nosniff`, `DENY`, `same-origin` ×2) are sent on
  every response; they were absent entirely.
- **A wrong method on the collateral path now spends throttle budget**, matching
  DRF's `initial()`.
- **Logging**: `data_files`, `simulate`, `metrics` and `cbor` records now carry
  `logger: "api"` like the Python service, so a `logger=api` query no longer
  drops the lines explaining a rejected registry reload. The witness line emits
  `env` and `duration_ms` as indexable JSON fields.
- **Startup names the known-hosts registry** it loaded and how many hosts, or
  warns that `/known_hosts/` will serve an empty object.
- **Doc corrections**: `cbor2`'s real limit is 400 containers with a
  `CBORDecodeError` (verified against 5.9.0, not ~500 with a `RecursionError`);
  the "same rejection, different message" claim for uninspected body fields; the
  `MAX_ENTRIES` comment; the Prometheus content-type comment.

Verified live against a running instance, and `scripts/e2e.sh` still earns and
verifies a real preprod witness.

---

## 1. Medium — X-Forwarded-For is read from only the first header line — FIXED

`routes.rs:320-323` → `net.rs:42-65`

`HeaderMap::get("x-forwarded-for")` returns the **first** header line only.
gunicorn joins duplicate headers with a comma
(`gunicorn/http/wsgi.py:141`), so Django's `_client_ip` walks the whole chain
right-to-left and lands on the address the trusted proxy actually appended.
Rust drops every line after the first, so only the caller-supplied prefix is
walked and **the caller's own rightmost value wins**.

That identity is the sole input to the throttle key, `check_ip_address` ban
matching, and the `/metrics` allowlist.

Reproduced live (`TRUSTED_PROXY_IPS=127.0.0.1`, `METRICS_ALLOW_IPS=9.9.9.9`):

```
-H 'X-Forwarded-For: 9.9.9.9,1.2.3.4'                  -> 403   (correct)
-H 'X-Forwarded-For: 9.9.9.9' -H 'X-Forwarded-For: 1.2.3.4' -> 200   (spoofed)
```

Identical bytes on the wire; opposite answers. Django answers 403 to both.

Only exploitable behind a proxy that appends XFF as a **new header line** rather
than merging — nginx's `$proxy_add_x_forwarded_for` merges, so many deployments
are unaffected. That is why it was medium, not high.

**Fixed** by `forwarded_chain`, which joins every `x-forwarded-for` line with a
comma before parsing, exactly as WSGI does. A line that is not readable as text
becomes a hop that cannot parse rather than vanishing, so `net::client_ip` still
fails closed at the right position in the chain. Both spellings now answer 403.

---

## 2. DRF wording and HTTP-surface parity — mostly FIXED

The README claimed error strings are "reproduced exactly". These were the
exceptions. None affected whether a transaction is signed.

| # | Issue | Status |
|---|---|---|
| 2.1 | 405 body was `{"detail":"Method Not Allowed"}` with `Allow: POST` | **fixed** — DRF's quoted verb, `Allow: POST, OPTIONS` |
| 2.2 | 415 dropped the offending media type | **fixed** — names it, as DRF does |
| 2.3 | Body `null` → `"This field may not be null."` | **fixed** — `"No data provided"` |
| 2.4 | Empty body → a parse error; no `Content-Type` → 415 | **fixed** — both now `"Missing required field: 'tx'"` |
| 2.6 | `CorsLayer` answered **every** `OPTIONS` with an empty 200 | **fixed** — only genuine preflights short-circuit; bare `OPTIONS` routes normally and the collateral path returns DRF metadata |
| 2.8 | Wildcard `Content-Type` was 415'd | **fixed** — `application/*`, `*/*` and absent all parse as JSON |
| 2.11 | No security headers at all | **fixed** — all four Django sends |
| 2.12 | Preflight had no `Access-Control-Max-Age` | **fixed** — matches Django's header set exactly |
| 2.13 | Prometheus content-type comment was wrong | **fixed** — comment now states the real reason for the pin |
| 2.14 | A wrong method never spent throttle budget | **fixed** — the collateral path routes `any` and throttles first |
| 2.17 | Request-shape errors log at WARNING; Python logs nothing | **kept** — a rejected request is worth a line; noted here for alert tuning |

Still open, all deliberate (see [README.md](README.md)):

| # | Issue | Location |
|---|---|---|
| 2.5 | JSON parse-error text differs after the shared prefix (serde_json vs CPython, no character offset) — not reproducible without reimplementing CPython's decoder | `routes.rs` |
| 2.7 | `HEAD` on the read-only endpoints → 200 here, 405 in Django. Kept: correct HTTP, and a `HEAD` health probe should not be told the method is unsupported | `routes.rs` |
| 2.9 | `/metrics` and `/known_hosts/` rejection bodies are JSON here, empty `text/html` in Django. Kept: auxiliary endpoints may use endpoint-specific formats | `routes.rs` |
| 2.10 | Malformed or oversized `Content-Length` is rejected by hyper at the parse layer → bare 400, no envelope, no `X-Request-ID`; the 413 branch for an absurd length is unreachable | `middleware/body_limit.rs` |
| 2.15 | Percent-encoded paths are matched raw: `/pre%70rod/collateral/` is served by Django and 404s here | `middleware/mod.rs` |
| 2.16 | Host-rejected requests on the collateral path are counted by Django and not here (`host::middleware` sits outside `metrics_middleware`) | `routes.rs` |

---

## 3. CBOR semantics vs `cbor2` (low)

None of these can produce a witness for a transaction Django would refuse to
sign, and the ledger's own decoder rejects the pathological inputs in phase 1.

**Rust more permissive than `cbor2`:**

- **3.1** `apply_tag` (`cbor.rs:778`) interprets only bignum tags 2/3; every other
  tag stays `Value::Tag`. `cbor2` runs per-tag semantic decoders while decoding,
  so a bogus payload under tag 0/1/4/5/30/37/258 anywhere in the body raises
  `CBORDecodeValueError` → Django 400 `"Invalid CBOR Data In Tx"`. Rust accepts
  it, passes all nine structural checks (no validator reads fields 2–9, 15,
  17–21) and burns an Ogmios round trip before failing. Confirmed with a probe
  crate on a real corpus transaction with its aux-data slot replaced by `c401`.

  **Behaviour kept; both doc residues fixed.** The `cbor.rs` module doc no
  longer claims "same rejection, different message" for uninspected fields, and
  the README's deliberate-differences table now lists it.

**Rust more strict — these reject transactions Django accepts:**

- **3.2** Set de-duplication uses structural `Hash`/`Eq`, so `Int(0)`,
  `Bool(false)` and `Float(0.0)` are three entries; Python's real `set`
  collapses them (`0 == False == 0.0`). `body[13] = 258([[txid,0],[txid,false]])`
  → Django accepts, Rust 400s `"Exactly One Collateral Input Is Required"`.
  (`validators/cbor.rs:41`)
- **3.3** `map_get` returns `None` whenever any key aliases the requested
  integer — including when the aliasing float key is the only entry — so
  float-keyed Babbage outputs and collateral returns that Django reads are
  400'd. (`cbor.rs:280`)
- **3.4** In the Conway redeemer **map** encoding, Rust shape-checks every
  duplicate entry while Python's dict collapses duplicates last-wins first, so a
  malformed shadowed entry 400s in Rust and is signed by Django.
  (`validators/transaction.rs:121-136,155-161`)

**Rust better than Django — worth keeping, worth knowing:**

- **3.5** `cbor2` raises plain `TypeError`/`ValueError` (not `CBORDecodeError`)
  for tags 35, 4 and 5, and `validators/cbor.py:85` catches only
  `CBORDecodeError` — so **Django answers 500 with a traceback** where Rust
  returns an ordinary 400. This is a Python-side bug the port does not have.
- **3.6** `_set_items` guards only `TypeError`, so `cbor2`'s C `CBORTag`
  re-entrancy `RuntimeError` escapes as a Django 500 where Rust returns 400.
- **3.7** tag-258 decodes to a Python `set`, so `_set_items` iteration order is
  `PYTHONHASHSEED`-dependent and **Django's verdict on a mixed-validity set
  varies between worker processes**. Rust is deterministic on wire order. The
  two cannot agree in both directions here; Rust's behaviour is the better one.

3.2 and 3.4 are now listed in the README as deliberate: both diverge in the
*rejecting* direction, on input the ledger's own decoder refuses anyway.

**Doc — fixed.** Three places said `cbor2` "fails around 500" / raises
`RecursionError`. Measured against 5.9.0: it caps at 400 containers and raises
`CBORDecodeError`, so depths 257–400 are accepted there and refused here.
(`cbor.rs:57`)

---

## 4. Config and environment parity (low)

| # | Issue | Location |
|---|---|---|
| 4.1 | **FIXED** — key material now uses `cbor::decode_hex`, so a `cborHex` carrying ASCII whitespace boots here exactly as it does in Django | `signature.rs` |
| 4.2 | `parse_list` trims each comma entry; django-environ only drops zero-length ones, so `A, B` gives Rust a usable second entry and Python a dead whitespace-prefixed one — affects `ALLOWED_HOSTS`, `TRUSTED_PROXY_IPS`, `METRICS_ALLOW_IPS` | `config.rs:339` |
| 4.3 | `bool_or` accepts `t` as true and hard-errors on anything unknown; django-environ maps `t`→false, `2`/`-1`→true, unknown→false silently | `config.rs:322-337` |
| 4.4 | `METRICS_ALLOW_IPS` compared as normalized `IpAddr` in Rust, raw strings in Python — `0:0:0:0:0:0:0:1` or `' 10.0.0.5'` authorizes a scraper Django 403s | `config.rs:358-372` |
| 4.5 | `TRUSTED_PROXY_IPS` entries with surrounding whitespace are honoured in Rust and dropped in Python, changing which address the throttle keys on | `net.rs:73` |
| 4.6 | `LOG_LEVEL` laxer: lowercase and `TRACE`/`NOTSET`/`FATAL` boot in Rust and fail `dictConfig` in Django; `CRITICAL` maps onto ERROR so Rust still emits every ERROR line Django silences | `logging.rs:99-110` |
| 4.7 | Startup key-validation failures log at ERROR in Rust, CRITICAL in Django — no structured line from either binary ever has level CRITICAL | `config.rs:257,267`, `main.rs:38,48,55` |
| 4.8 | The runtime stage copies only the binary and entrypoint, so a stock container publishes an empty registry. **Not silent any more**: startup now logs the registry it loaded, or warns that `/known_hosts/` will serve `{}`. Copying the file would mean moving the Docker build context from `rs/` to the repo root, which the README now documents instead | `Dockerfile` + `config.rs` |
| 4.9 | **FIXED** — the `DEFAULT_MAX_ENTRIES` comment no longer claims to mirror the Python cache's 2000, and says why an in-process map can afford more | `throttle.rs` |
| 4.10 | *(cosmetic)* `*_TXIDX=-1` boots Django in development and aborts the Rust binary before logging is installed | `config.rs:117` |

---

## 5. Operator data files (low)

- **5.1** `bans.json` with an IPv4-mapped IPv6 entry (`::ffff:10.0.0.1`) is
  enforced whole by Rust but makes Django discard the entire document — same
  file, different bans in force. (`ban_list.rs:97`)
- **5.2** known_hosts URL with `..` segments: the WHATWG parser normalizes them,
  so Rust accepts what Django rejects (and Django drops the whole registry).
  (`known_hosts.rs:186`)
- **5.3** `https://@provider.example/preprod/collateral` — empty userinfo is
  credentials to Python (whole registry rejected), absent to Rust.
  (`known_hosts.rs:171`)
- **5.4** A host whose last label is all-numeric but not valid IPv4
  (`https://1.2.3.4.5/...`) fails `Url::parse`, so **Rust rejects the whole
  registry and serves `{}` on first boot** while Django publishes it.
  (`known_hosts.rs:158`)
- **5.5** *(cosmetic)* `utxo.idx` above `u64::MAX` validates in Django and makes
  Rust reject the whole registry. (`known_hosts.rs:124`)

---

## 6. Logging and observability (low)

- **6.1 FIXED** — the witness line now emits `env` and `duration_ms` as tracing
  fields, which the JSON formatter promotes to top-level keys, while keeping
  them in the message for text mode.
- **6.2** Text-mode timestamps are host-local in Django and always UTC in Rust —
  lines from the two services for the same instant are hours apart. Kept: UTC is
  the right default for a service log. (`logging.rs`)
- **6.3 FIXED** — `data_files`, `simulate`, `metrics` and `cbor` records now
  carry `logger: "api"`, matching `logging.getLogger("api")` on the Python side,
  so a `logger=api` query no longer drops the lines explaining why a ban list or
  registry did not take effect.
- **6.4** The two upstream timeout WARNING lines omit the error detail Django
  logs, losing the connect-vs-read distinction and the endpoint.
  (`simulate.rs:230,381`)
- **6.5** A mid-body upstream stall is labelled `outcome="timeout"` by Rust and
  `outcome="request_error"` by Django — same fault, different Prometheus label.
  (`simulate.rs:577`)

---

## Accepted divergences

What is left after the fixes, and why each is a choice rather than a gap:

- **Rejecting-direction CBOR strictness** (§3.2–3.4) — the only cases where this
  service refuses a transaction Django would sign. Every one needs CBOR the
  ledger's own decoder rejects in phase 1, so it is wire-contract parity, not
  fund safety. Now listed in the README.
- **Permissive semantic tags** (§3.1) — a bogus tag in a body field no validator
  reads. Cannot earn a witness Django would refuse, for the same reason.
- **Django-side bugs not ported** (§3.5–3.7) — `cbor2` raising uncaught
  `TypeError`/`ValueError` for tags 35/4/5 makes Django answer 500; tag-258 sets
  make its verdict `PYTHONHASHSEED`-dependent. Worth fixing in Python rather
  than reproducing here.
- **`HEAD`, auxiliary rejection bodies, JSON parse-error text, percent-encoded
  paths, UTC timestamps, config coercion** — all documented in the README's
  deliberate-differences table.
- **Operator data files** (§5) — divergent validation for pathological registry
  and ban-list entries. Low value to chase; the repo's own `known.hosts.json`
  passes both.

Nothing here blocks shipping the binary as an API-compatible alternative. The
XFF fix is the one that mattered, and it has landed.

## Reproducing this

```sh
cd rs && cargo test          # 463 tests, no network
./scripts/e2e.sh             # real preprod witness, end to end
COLLATERAL_LIVE_UPSTREAM=1 cargo test --test live_upstream -- --nocapture
```

The Django wording used above was captured by driving `django.test.Client`
against the real view stack, not read off the source.
