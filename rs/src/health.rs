//! Local liveness/readiness checks with no external network dependency.

use std::path::Path;

use crate::config::Config;
use crate::signature::KeyCache;
use crate::throttle::Throttle;

/// Return public-safe labels for conditions that prevent signing.
///
/// This deliberately does not call Koios: tying load-balancer readiness to a
/// transient public upstream outage would recycle healthy workers precisely
/// when retaining capacity matters most. Upstream health belongs in metrics
/// and diagnostics.
///
/// The signing identity is checked cryptographically on each probe so a
/// broken hot key rotation is detected immediately, and the throttle state is
/// exercised because a collateral request cannot be served without it.
pub fn readiness_problems(config: &Config, keys: &KeyCache, throttle: &Throttle) -> Vec<String> {
    // At most one problem is reported: the first failure already makes the
    // process unready, and the later checks would only restate it.
    for (label, path) in [
        ("skey", config.skey_path.as_path()),
        ("vkey", config.vkey_path.as_path()),
    ] {
        if !path.exists() {
            tracing::warn!(target: "api", "readiness: {} missing at {}", label, path.display());
            return vec![format!("{label} missing")];
        }
        if !is_readable(path) {
            tracing::warn!(target: "api", "readiness: {} unreadable at {}", label, path.display());
            return vec![format!("{label} unreadable")];
        }
    }

    if let Err(err) = keys.validate_key_material(&config.skey_path, &config.vkey_path, &config.pkh)
    {
        tracing::warn!(target: "api", "readiness: invalid signing identity: {}", err);
        return vec!["signing identity invalid".to_string()];
    }

    // The Python probe round-trips the file-based throttle cache because a
    // collateral POST cannot be served without it. The in-memory equivalent
    // is that the shared state is still reachable.
    if !throttle.healthy() {
        tracing::warn!(target: "api", "readiness: throttle state unusable");
        return vec!["throttle cache unwritable".to_string()];
    }

    Vec::new()
}

/// `os.access(path, os.R_OK)`, done by actually opening the file — the only
/// portable answer that cannot disagree with what the signer will experience.
fn is_readable(path: &Path) -> bool {
    std::fs::File::open(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    const PKH: &str = "6af53ff4f054348ad825c692dd9db8f1760a8e0eacf9af9f99306513";

    fn config_with_keys(skey: &Path, vkey: &Path) -> Config {
        let env: HashMap<&str, String> = [
            ("PKH", PKH.to_string()),
            ("ENVIRONMENT", "development".to_string()),
            ("SKEY_PATH", skey.display().to_string()),
            ("VKEY_PATH", vkey.display().to_string()),
            ("PREPROD_NETWORK", "--testnet-magic 1".to_string()),
            ("PREPROD_TXID", "a1".repeat(32)),
            ("PREPROD_TXIDX", "0".to_string()),
            ("MAINNET_NETWORK", "--mainnet".to_string()),
            ("MAINNET_TXID", "b2".repeat(32)),
            ("MAINNET_TXIDX", "1".to_string()),
        ]
        .into_iter()
        .collect();
        Config::from_lookup(&|key| env.get(key).cloned()).expect("config builds")
    }

    fn throttle() -> Throttle {
        Throttle::new(
            "300/min".parse().expect("valid rate"),
            crate::throttle::DEFAULT_MAX_ENTRIES,
        )
    }

    fn key_file(dir: &Path, name: &str, value: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("{{\"cborHex\":\"5820{value}\"}}")).expect("writes key");
        path
    }

    #[test]
    fn a_missing_key_is_named_before_anything_is_parsed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let skey = dir.path().join("payment.skey");
        let vkey = key_file(dir.path(), "payment.vkey", &"00".repeat(32));
        let config = config_with_keys(&skey, &vkey);
        assert_eq!(
            readiness_problems(&config, &KeyCache::new(), &throttle()),
            vec!["skey missing".to_string()]
        );
    }

    #[test]
    fn the_skey_is_checked_before_the_vkey() {
        let dir = tempfile::tempdir().expect("tempdir");
        let skey = dir.path().join("payment.skey");
        let vkey = dir.path().join("payment.vkey");
        let config = config_with_keys(&skey, &vkey);
        // Both are missing; only the first is reported.
        let problems = readiness_problems(&config, &KeyCache::new(), &throttle());
        assert_eq!(problems, vec!["skey missing".to_string()]);
    }

    #[test]
    fn a_present_but_missing_vkey_is_named_second() {
        let dir = tempfile::tempdir().expect("tempdir");
        let skey = key_file(dir.path(), "payment.skey", &"00".repeat(32));
        let vkey = dir.path().join("payment.vkey");
        let config = config_with_keys(&skey, &vkey);
        assert_eq!(
            readiness_problems(&config, &KeyCache::new(), &throttle()),
            vec!["vkey missing".to_string()]
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_key_is_distinguished_from_a_missing_one() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let skey = key_file(dir.path(), "payment.skey", &"00".repeat(32));
        let vkey = key_file(dir.path(), "payment.vkey", &"00".repeat(32));
        std::fs::set_permissions(&skey, std::fs::Permissions::from_mode(0o000))
            .expect("chmod succeeds");
        if std::fs::File::open(&skey).is_ok() {
            // Running as root, where mode 000 is not a barrier.
            return;
        }
        let config = config_with_keys(&skey, &vkey);
        assert_eq!(
            readiness_problems(&config, &KeyCache::new(), &throttle()),
            vec!["skey unreadable".to_string()]
        );
    }
}
