//! Validators are free functions (no traits, no structs) that return
//! `ApiResult<()>`. Each raises a 400 with a Title Case message on the first
//! failure and short-circuits the pipeline.

pub mod cbor;
pub mod environment;
pub mod transaction;
