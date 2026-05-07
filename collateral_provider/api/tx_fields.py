"""Cardano Conway-era transaction layout constants.

A Cardano transaction is encoded as a 4-element CBOR list:

    [ body_map, witness_set, is_valid_bool, auxiliary_data_or_nil ]

The body itself is a CBOR map with integer keys. The set-typed fields
(inputs, collateral inputs, required signers, ...) are wrapped in CBOR
tag 258. Only the field constants the validators actually inspect live
here — the signing path doesn't need them because we hash the body's
raw byte slice directly rather than walking the parsed structure.
"""

# Top-level transaction tuple positions
TX_BODY = 0
TX_IS_VALID = 2

# Body map keys
INPUTS = 0
OUTPUTS = 1
COLLATERAL_INPUTS = 13
REQUIRED_SIGNERS = 14

# CBOR tag used to mark canonicalized sets in the Cardano body
SET_TAG = 258
