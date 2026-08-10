use crate::ban_list::BanList;
use crate::error::{ApiError, ApiResult};

/// Reject banned client IPs.
///
/// The exact value is already available transiently for the lookup and
/// throttle. Do not persist it through the shared validation logger.
pub fn check_ip_address(ip_address: Option<&str>, bans: &BanList) -> ApiResult<()> {
    // An absent address can never be on the list: every entry is validated to
    // be a canonical address string, so Python's `None in [...]` is always
    // false too.
    match ip_address {
        Some(ip) if bans.is_banned_ip(ip) => Err(ApiError::validation("Client IP Is Banned")),
        _ => Ok(()),
    }
}

/// The environment must be one of the configured networks.
///
/// Defence in depth; the route handler already rejects unknown environments,
/// so this never fires over HTTP.
pub fn check_environment(environment: &str, networks: &[String]) -> ApiResult<()> {
    if networks.iter().any(|network| network == environment) {
        return Ok(());
    }
    Err(ApiError::validation(format!(
        "Invalid Environment: {environment}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ban list backed by a temp file holding exactly these entries.
    fn bans_with(ips: &[&str]) -> (tempfile::TempDir, BanList) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("bans.json");
        let document = serde_json::json!({ "addresses": [], "ips": ips });
        std::fs::write(&path, document.to_string()).expect("write bans");
        (dir, BanList::new(path))
    }

    /// No file at all — the loader must fall back to an empty document.
    fn empty_bans() -> (tempfile::TempDir, BanList) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("absent.json");
        (dir, BanList::new(path))
    }

    fn networks() -> Vec<String> {
        vec!["preprod".to_string(), "mainnet".to_string()]
    }

    #[test]
    fn banned_ip_is_rejected_without_echoing_the_address() {
        let (_dir, bans) = bans_with(&["127.0.0.1"]);
        let err = check_ip_address(Some("127.0.0.1"), &bans).expect_err("banned");
        assert_eq!(err.detail(), "Client IP Is Banned");
        // The message must not leak the client address into the shared log.
        assert!(!err.detail().contains("127.0.0.1"));
    }

    #[test]
    fn unlisted_ip_is_allowed() {
        let (_dir, bans) = bans_with(&["127.0.0.1"]);
        assert!(check_ip_address(Some("192.168.1.1"), &bans).is_ok());
    }

    #[test]
    fn missing_ip_is_allowed() {
        let (_dir, bans) = bans_with(&["127.0.0.1"]);
        assert!(check_ip_address(None, &bans).is_ok());
    }

    #[test]
    fn an_empty_ban_list_bans_nothing() {
        let (_dir, bans) = empty_bans();
        assert!(check_ip_address(Some("127.0.0.1"), &bans).is_ok());
    }

    #[test]
    fn unknown_environment_is_named_in_the_message() {
        let err = check_environment("invalid_env", &networks()).expect_err("unknown env");
        assert_eq!(err.detail(), "Invalid Environment: invalid_env");
    }

    #[test]
    fn configured_environment_passes() {
        assert!(check_environment("mainnet", &networks()).is_ok());
        assert!(check_environment("preprod", &networks()).is_ok());
    }

    #[test]
    fn environment_match_is_exact_and_case_sensitive() {
        for candidate in ["", "Mainnet", "main", "mainnet ", "preprod\n"] {
            let err = check_environment(candidate, &networks()).expect_err(candidate);
            assert_eq!(err.detail(), format!("Invalid Environment: {candidate}"));
        }
    }

    #[test]
    fn no_configured_networks_rejects_everything() {
        let err = check_environment("mainnet", &[]).expect_err("nothing configured");
        assert_eq!(err.detail(), "Invalid Environment: mainnet");
    }
}
