//! Print the payment key hash for a Cardano CLI verification-key file.
//!
//! The PKH is Blake2b-224 of the raw 32-byte public key, and `PKH` is a
//! required setting — so every operator needs this value at least once, and
//! getting it wrong produces a service that starts and then rejects all
//! traffic. Shipping it as an example keeps the local-run scripts free of a
//! Python dependency.
//!
//! ```sh
//! cargo run --quiet --example derive_pkh -- path/to/payment.vkey
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use collateral_provider::signature::{blake2b, KeyCache};

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: derive_pkh <path/to/payment.vkey>");
        return ExitCode::FAILURE;
    };

    // Reuse the service's own loader so this agrees with what the running
    // service will read, including the CBOR byte-string head it strips.
    let cache = KeyCache::new();
    let key_hex = match cache.get_key_from_file(&PathBuf::from(&path)) {
        Ok(key) => key,
        Err(err) => {
            eprintln!("cannot read {path}: {err}");
            return ExitCode::FAILURE;
        }
    };

    let key = match hex::decode(&key_hex) {
        Ok(key) => key,
        Err(err) => {
            eprintln!("{path} does not contain hexadecimal key material: {err}");
            return ExitCode::FAILURE;
        }
    };
    if key.len() != 32 {
        eprintln!("{path} holds {} bytes, expected 32", key.len());
        return ExitCode::FAILURE;
    }

    println!("{}", hex::encode(blake2b(&key, 28)));
    ExitCode::SUCCESS
}
