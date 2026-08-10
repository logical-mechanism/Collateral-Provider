pub mod body_limit;
pub mod host;
pub mod metrics;
pub mod request_id;

use regex::Regex;
use std::sync::OnceLock;

/// The only path we care to measure or body-limit:
/// `^/(?P<env>[^/]+)/collateral/?$`.
pub fn collateral_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^/(?P<env>[^/]+)/collateral/?$").expect("valid regex"))
}
