//! Cardano Conway-era transaction layout constants.
//!
//! A Cardano transaction is encoded as a 4-element CBOR list:
//!
//! ```text
//! [ body_map, witness_set, is_valid_bool, auxiliary_data_or_nil ]
//! ```
//!
//! The body itself is a CBOR map with integer keys. The set-typed fields
//! (inputs, collateral inputs, required signers, ...) may be wrapped in CBOR
//! tag 258. Only the field constants the validators actually inspect live
//! here — the signing path doesn't need them because we hash the body's raw
//! byte slice directly rather than walking the parsed structure.

// Top-level transaction tuple positions
pub const TX_BODY: usize = 0;
pub const TX_WITNESS_SET: usize = 1;
pub const TX_IS_VALID: usize = 2;
pub const TX_AUXILIARY_DATA: usize = 3;

// Body map keys
pub const INPUTS: i128 = 0;
pub const OUTPUTS: i128 = 1;
pub const SCRIPT_DATA_HASH: i128 = 11;
pub const COLLATERAL_INPUTS: i128 = 13;
pub const REQUIRED_SIGNERS: i128 = 14;
pub const COLLATERAL_RETURN: i128 = 16;

// Witness-set map keys
pub const WITNESS_DATUMS: i128 = 4;
pub const WITNESS_REDEEMERS: i128 = 5;

/// CBOR tag used to mark canonicalized sets in the Cardano body.
pub const SET_TAG: u64 = 258;
