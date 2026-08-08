# Wallet integration contract

This document is for wallet and transaction-builder implementers integrating a
collateral provider directly. The provider never submits the transaction and
never receives wallet keys. It returns one vkey witness for the exact
transaction body supplied by the caller.

## Discover a provider

`GET /known_hosts/` returns the public provider registry keyed by payment key
hash (PKH). Each network entry contains the provider URL and collateral UTxO.
Cache this registry only briefly and let users override or disable providers;
wallets should not make one public host a permanent availability dependency.

The published shape is:

```json
{
  "<56 lowercase hex PKH>": {
    "public_key": "<64 lowercase hex Ed25519 public key>",
    "<network>": {
      "utxo": {"id": "<64 lowercase hex transaction id>", "idx": 0},
      "url": "https://provider.example/<network>/collateral/"
    }
  }
}
```

The service validates every registry reload as one document: the public key
must derive the PKH via Blake2b-224, indices must be non-negative integers,
and endpoint paths must match their network key. Wallets should still perform
the same PKH/public-key check locally rather than trusting discovery data.

For `https://www.giveme.my`, the signing endpoint is:

```text
POST https://www.giveme.my/<network>/collateral/
Content-Type: application/json

{"tx":"<full transaction CBOR as lowercase or uppercase hex>"}
```

The trailing slash is optional. The transaction is the complete four-element
Cardano envelope—not merely its body:

```text
[transaction_body, witness_set, is_valid, auxiliary_data]
```

## Build the transaction

Before requesting the provider witness:

1. Put exactly the advertised provider UTxO in body field 13 (collateral
   inputs). Do not place it among regular inputs.
2. Put the provider PKH in body field 14 (required signers).
3. Set the outer phase-2 validity flag to `true` for evaluation.
4. Include at least one Plutus redeemer. This endpoint is not a general-purpose
   signing oracle for transactions without phase-2 scripts.
5. Finalize the redeemer data, datum witnesses, and non-zero execution units,
   then compute body field 11 (the script-data hash) from those exact bytes and
   the active protocol cost models. The common builder phase that uses a dummy
   hash and zero budgets for initial `evaluateTransaction` estimation is not a
   signable transaction.
6. Complete the body before calling the provider. Any body change afterward
   changes the transaction ID and invalidates the returned signature.

CIP-40 `collateral_return` and `total_collateral` remain optional. Using them is
recommended because they bound the provider's loss if the transaction is
legitimately included on its phase-2-invalid branch. Return collateral only to
an address controlled by the provider key.

## Chained transactions

The provider accepts only ledger-resolved inputs. A non-empty
`additional_utxos` field returns 400 and is never forwarded to Ogmios; an empty
list is tolerated only for client compatibility.

This is a security boundary, not a capability toggle. A future transaction ID
commits to its parent body, but a bare caller-supplied UTxO object does not prove
that it matches the output encoded by that body. The caller could evaluate
against one value/datum/script and later submit a parent that creates another.
Safe chained-transaction support would need the complete parent transaction
CBOR with output derivation and transaction-ID verification, or an authoritative
mempool source. Wallets should wait until the parent is ledger-resolvable before
requesting this provider's witness.

## Consume the response

A successful response is:

```json
{"witness":"<CBOR hex>"}
```

Decoded, the value has this shape:

```text
[0, [provider_public_key_bytes, ed25519_signature_bytes]]
```

Verify the signature locally before merging it:

1. Extract the exact encoded byte range of `transaction_body` from the original
   transaction.
2. Compute `blake2b-256(body_bytes)`.
3. Verify the 64-byte Ed25519 signature with the returned 32-byte public key.
4. Verify `blake2b-224(public_key)` equals the selected provider PKH.
5. Add `[public_key, signature]` to witness-set key 0 without modifying the
   transaction body bytes.

Do not decode and casually re-serialize the body while adding the witness.
Definite versus indefinite lengths, integer widths, map ordering, and set tags
can produce a different body encoding and therefore a different transaction
ID even when decoded values look equivalent. Use a Cardano transaction library
that preserves or canonically rebuilds the same body, or splice only the outer
witness-set element.

The wallet adds its own witnesses normally and submits the completed
transaction through its node.

## Errors and retries

Every error response is `{"detail":"..."}`.

- `400`: the request or transaction violates the provider contract. Do not
  retry the same bytes unchanged.
- `413`: the JSON body exceeds the provider's configured byte limit. Do not
  retry the same payload unchanged.
- `415`: send JSON with `Content-Type: application/json`.
- `429`: wait and retry with backoff.
- `503`: protocol-parameter lookup, phase-2 evaluation, local upstream
  capacity, or the signing identity is temporarily unavailable. Retry with
  jitter or select another provider.

Every response includes `X-Request-ID`. Supply a safe ID of up to 64 letters,
digits, `.`, `_`, `:`, or `-` if end-to-end correlation is useful. Application
request logs omit raw client IPs; successful records also omit transaction
hashes.

## Release verification

When `cardano-cli` is installed, the repository test suite independently
compares the provider's body-byte transaction ID with the official CLI. Wallet
integrators should likewise keep golden vectors produced by an implementation
different from the one used in their transaction builder.
