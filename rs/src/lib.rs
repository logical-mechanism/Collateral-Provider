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

/// Single source of truth for the service version, mirroring
/// `api.__version__`. `/healthz` and `/livez` report it.
pub const VERSION: &str = "1.3.0";
