#!/usr/bin/env python3
"""Build a throwaway transaction that earns a real collateral witness.

Why this exists: the endpoint only signs a transaction whose Plutus scripts
actually evaluate against real ledger state, so you cannot test it with an
invented transaction. ``additional_utxos`` used to let a caller fabricate that
state; it is rejected now, because the caller choosing the facts is exactly
what lets a crafted transaction burn the collateral (see SECURITY.md).

You do not need it. The transaction built here is never submitted, so its
inputs do not have to belong to you — any real unspent UTxO on the network
works. The script therefore:

1. reads the provider's PKH and collateral UTxO from ``/known_hosts/``
2. finds a real unspent key-address UTxO on the network via Koios REST
3. mints one token under an always-true PlutusV3 policy, which supplies the
   redeemer the pipeline requires and gives the evaluator something to run
4. commits body field 11 to those exact redeemer bytes and the network's
   current cost models
5. POSTs it and prints the witness

Nothing is signed by the input's owner and nothing is submitted, so no funds
move. The only on-chain object referenced verbatim is the provider's
collateral UTxO, which is named in field 13 and never spent.

    python3 scripts/py/dummy_collateral_tx.py --network preprod
    python3 scripts/py/dummy_collateral_tx.py --network mainnet --dry-run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import cbor2
import requests

# Reuse the service's own language-view encoder so the script data hash we
# build here is derived by exactly the code that will verify it.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "collateral_provider"))
from api.script_integrity import encode_language_views

# (program 1.1.0 (lam _ (con unit ()))) — the smallest PlutusV3 script that
# always succeeds. V3 applies the script to one argument (the script context)
# and treats any non-error result as success.
#
# What goes on chain is the flat program wrapped in one CBOR byte string; the
# evaluator does decodeBytes-then-unflat, so handing it the bare flat bytes
# fails to deserialise. This is the usual Plutus "double encoding": the
# ``.plutus`` envelope cborHex is 46450101002499, one wrap further out again.
ALWAYS_TRUE_V3_FLAT = bytes.fromhex("0101002499")
ALWAYS_TRUE_V3 = cbor2.dumps(ALWAYS_TRUE_V3_FLAT)  # 450101002499
PLUTUS_V3_LANGUAGE = 2

NETWORKS = {
    "preprod": {
        "koios": "https://preprod.koios.rest/api/v1/",
        "ogmios": "https://preprod.koios.rest/api/v1/ogmios",
        "address_prefixes": ("addr_test1q", "addr_test1v"),
    },
    "mainnet": {
        "koios": "https://api.koios.rest/api/v1/",
        "ogmios": "https://api.koios.rest/api/v1/ogmios",
        "address_prefixes": ("addr1q", "addr1v"),
    },
}

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# Body / witness-set field indices used below.
INPUTS, OUTPUTS, FEE, MINT = 0, 1, 2, 9
SCRIPT_DATA_HASH, COLLATERAL_INPUTS, REQUIRED_SIGNERS = 11, 13, 14
REDEEMERS, PLUTUS_V3_SCRIPTS = 5, 7
SET_TAG = 258

# Comfortably above what an always-true script costs, so the evaluated budget
# can never exceed what the body commits to.
EX_UNITS = [2_000_000, 700_000_000]
FEE_LOVELACE = 300_000
ASSET_NAME = b"CollateralTest"


def bech32_decode_to_bytes(address: str) -> bytes:
    """Return the raw binary address behind a bech32 string."""
    separator = address.rfind("1")
    data = address[separator + 1 :]
    try:
        values = [BECH32_CHARSET.index(char) for char in data]
    except ValueError as exc:
        raise SystemExit(f"address is not bech32: {address}") from exc
    values = values[:-6]  # drop the checksum

    accumulator = bits = 0
    out = bytearray()
    for value in values:
        accumulator = (accumulator << 5) | value
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((accumulator >> bits) & 0xFF)
    return bytes(out)


def fetch_registry(base_url: str, network: str) -> tuple[str, str, int]:
    """Read the provider's PKH and collateral UTxO from its own registry."""
    registry = requests.get(f"{base_url}/known_hosts/", timeout=20).json()
    for pkh, entry in registry.items():
        if network in entry:
            utxo = entry[network]["utxo"]
            return pkh, utxo["id"], utxo["idx"]
    raise SystemExit(f"{base_url} publishes no {network} collateral UTxO")


def find_live_utxo(config: dict) -> tuple[str, int, bytes, int]:
    """Locate any real unspent UTxO sitting at a key-hash address.

    Ownership is irrelevant — the transaction is never submitted. The only
    requirement is that the evaluator can resolve the input, which means it
    has to genuinely exist on chain.
    """
    koios = config["koios"]
    blocks = requests.get(koios + "blocks", params={"limit": "60"}, timeout=25).json()
    hashes = [block["hash"] for block in blocks if block.get("tx_count", 0) > 0][:15]
    if not hashes:
        raise SystemExit("no recent blocks carried transactions")

    txs = requests.post(koios + "block_txs", json={"_block_hashes": hashes}, timeout=30).json()
    refs = [f'{tx["tx_hash"]}#0' for tx in txs][:40]
    utxos = requests.post(
        koios + "utxo_info", json={"_utxo_refs": refs, "_extended": False}, timeout=30
    ).json()

    for utxo in utxos:
        if utxo.get("is_spent"):
            continue
        if not utxo["address"].startswith(config["address_prefixes"]):
            continue  # a script address would need its script supplied too
        return (
            utxo["tx_hash"],
            utxo["tx_index"],
            bech32_decode_to_bytes(utxo["address"]),
            int(utxo["value"]),
        )
    raise SystemExit("found no unspent key-address UTxO in recent blocks")


def fetch_v3_cost_model(ogmios_url: str) -> list[int]:
    payload = {
        "jsonrpc": "2.0",
        "id": "cost-models",
        "method": "queryLedgerState/protocolParameters",
    }
    response = requests.post(ogmios_url, json=payload, timeout=20).json()
    models = response["result"]["plutusCostModels"]
    if "plutus:v3" not in models:
        raise SystemExit("network exposes no plutus:v3 cost model")
    return models["plutus:v3"]


def build_transaction(
    pkh: str,
    collateral_txid: str,
    collateral_idx: int,
    input_txid: str,
    input_idx: int,
    input_address: bytes,
    input_value: int,
    v3_cost_model: list[int],
) -> str:
    policy_id = hashlib.blake2b(b"\x03" + ALWAYS_TRUE_V3, digest_size=28).digest()
    mint = {policy_id: {ASSET_NAME: 1}}

    # Build the witness set by hand. The script data hash commits to the exact
    # bytes of witness field 5, so the bytes we hash must be byte-identical to
    # the bytes we ship — not a re-encoding of an equal value.
    redeemers_raw = cbor2.dumps({(1, 0): [cbor2.CBORTag(121, []), EX_UNITS]})
    witness_set = (
        b"\xa2"
        + b"\x05"
        + redeemers_raw
        + b"\x07"
        + cbor2.dumps([ALWAYS_TRUE_V3])
    )

    # No datums, so the datum slice is empty and only the V3 language view
    # participates. The service tries every cost-model subset, so committing
    # to just this one is enough for it to find a match.
    language_views = encode_language_views({PLUTUS_V3_LANGUAGE: v3_cost_model})
    script_data_hash = hashlib.blake2b(
        redeemers_raw + b"" + language_views, digest_size=32
    ).digest()

    body = {
        INPUTS: cbor2.CBORTag(SET_TAG, [[bytes.fromhex(input_txid), input_idx]]),
        OUTPUTS: [[input_address, [max(input_value - FEE_LOVELACE, 1_000_000), mint]]],
        FEE: FEE_LOVELACE,
        MINT: mint,
        SCRIPT_DATA_HASH: script_data_hash,
        COLLATERAL_INPUTS: cbor2.CBORTag(
            SET_TAG, [[bytes.fromhex(collateral_txid), collateral_idx]]
        ),
        REQUIRED_SIGNERS: cbor2.CBORTag(SET_TAG, [bytes.fromhex(pkh)]),
    }

    # Field 16 (collateral return) is deliberately omitted: when it is absent
    # the whole collateral UTxO is the implied return, and the service only
    # constrains the field when a builder sets it.
    transaction = b"\x84" + cbor2.dumps(body) + witness_set + b"\xf5" + b"\xf6"
    return transaction.hex()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", choices=sorted(NETWORKS), default="preprod")
    parser.add_argument("--url", default="https://www.giveme.my")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the transaction CBOR without calling the endpoint",
    )
    args = parser.parse_args()
    config = NETWORKS[args.network]
    base_url = args.url.rstrip("/")

    pkh, collateral_txid, collateral_idx = fetch_registry(base_url, args.network)
    input_txid, input_idx, input_address, input_value = find_live_utxo(config)
    v3_cost_model = fetch_v3_cost_model(config["ogmios"])

    tx_hex = build_transaction(
        pkh,
        collateral_txid,
        collateral_idx,
        input_txid,
        input_idx,
        input_address,
        input_value,
        v3_cost_model,
    )

    print(f"network     : {args.network}")
    print(f"provider pkh: {pkh}")
    print(f"collateral  : {collateral_txid}#{collateral_idx}")
    print(f"live input  : {input_txid}#{input_idx} ({input_value} lovelace, not ours)")
    print(f"tx bytes    : {len(tx_hex) // 2}")
    print(f"tx cbor     : {tx_hex}")

    if args.dry_run:
        return 0

    response = requests.post(
        f"{base_url}/{args.network}/collateral/",
        json={"tx": tx_hex},
        timeout=30,
    )
    print(f"\nHTTP {response.status_code}")
    try:
        print(json.dumps(response.json(), indent=2))
    except ValueError:
        print(response.text[:2000])
    return 0 if response.status_code == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
