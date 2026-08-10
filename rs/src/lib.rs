//! Cardano collateral provider — Rust port of the Django/DRF service.
//!
//! The service takes a Cardano transaction CBOR from a caller, validates that
//! it satisfies the rules for using a shared collateral UTxO, and returns a
//! vkey witness (signature) for it. One key, one collateral UTxO per network,
//! shared across many users so they don't have to set up collateral in their
//! own wallet.
//!
//! Module layout mirrors `collateral_provider/api/` in the Python service so
//! the two implementations can be diffed against each other.

#![forbid(unsafe_code)]

pub mod ban_list;
pub mod cbor;
pub mod cli;
pub mod config;
pub mod data_files;
pub mod error;
pub mod health;
pub mod known_hosts;
pub mod logging;
pub mod metrics;
pub mod middleware;
pub mod net;
pub mod routes;
pub mod script_integrity;
pub mod services;
pub mod signature;
pub mod simulate;
pub mod state;
pub mod throttle;
pub mod tx_fields;
pub mod validators;

/// The service version `/healthz` and `/livez` report.
///
/// Read from `Cargo.toml` rather than written out again, so this crate has one
/// place to bump. It must stay in step with `api.__version__` on the Python
/// side — the two implementations serve the same contract and a client reading
/// `/healthz` should not be able to tell them apart.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
