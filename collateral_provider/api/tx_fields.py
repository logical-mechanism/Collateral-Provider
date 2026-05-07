"""Cardano Conway-era transaction layout constants.

A Cardano transaction is encoded as a 4-element CBOR list:

    [ body_map, witness_set, is_valid_bool, auxiliary_data_or_nil ]

The body itself is a CBOR map with integer keys. The set-typed fields
(inputs, certificates, collateral inputs, required signers, reference
inputs, proposal procedures) are wrapped in CBOR tag 258.
"""

# Top-level transaction tuple positions
TX_BODY = 0
TX_IS_VALID = 2

# Body map keys
INPUTS = 0
OUTPUTS = 1
CERTIFICATES = 4
COLLATERAL_INPUTS = 13
REQUIRED_SIGNERS = 14
REFERENCE_INPUTS = 18
PROPOSAL_PROCEDURES = 20

# CBOR tag used to mark canonicalized sets in the Cardano body
SET_TAG = 258
