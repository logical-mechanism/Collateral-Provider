//! Shared application state, cloned cheaply into every request handler.

use std::sync::Arc;

use crate::ban_list::BanList;
use crate::config::Config;
use crate::known_hosts::KnownHosts;
use crate::metrics::Metrics;
use crate::signature::KeyCache;
use crate::simulate::Upstream;
use crate::throttle::{Throttle, DEFAULT_MAX_ENTRIES};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub keys: Arc<KeyCache>,
    pub bans: Arc<BanList>,
    pub known_hosts: Arc<KnownHosts>,
    pub throttle: Arc<Throttle>,
    pub upstream: Arc<Upstream>,
    pub metrics: Arc<Metrics>,
}

impl AppState {
    /// Build everything the service needs from a validated configuration.
    pub fn new(config: Config) -> Result<Self, String> {
        // A private registry per state, so two instances in one test process
        // cannot collide on an already-registered metric name.
        let metrics = Arc::new(
            Metrics::new().map_err(|err| format!("cannot build the metrics registry: {err}"))?,
        );
        // The upstream shares the metrics handle rather than owning a second
        // registry: Koios counters have to land in the same exposition the
        // /metrics endpoint renders.
        let upstream = Arc::new(
            Upstream::new(config.koios_max_in_flight, Arc::clone(&metrics))
                .map_err(|err| format!("cannot build the upstream HTTP client: {err}"))?,
        );

        Ok(AppState {
            keys: Arc::new(KeyCache::new()),
            bans: Arc::new(BanList::new(config.bans_path.clone())),
            known_hosts: Arc::new(KnownHosts::new(config.known_hosts_path.clone())),
            throttle: Arc::new(Throttle::new(config.throttle_rate, DEFAULT_MAX_ENTRIES)),
            upstream,
            metrics,
            config: Arc::new(config),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    pub(crate) fn test_config() -> Config {
        let env: HashMap<&str, String> = [
            (
                "PKH",
                "6af53ff4f054348ad825c692dd9db8f1760a8e0eacf9af9f99306513".to_string(),
            ),
            ("ENVIRONMENT", "development".to_string()),
            ("PREPROD_NETWORK", "--testnet-magic 1".to_string()),
            ("PREPROD_TXID", "a1".repeat(32)),
            ("PREPROD_TXIDX", "0".to_string()),
            ("MAINNET_NETWORK", "--mainnet".to_string()),
            ("MAINNET_TXID", "b2".repeat(32)),
            ("MAINNET_TXIDX", "1".to_string()),
        ]
        .into_iter()
        .collect();
        Config::from_lookup(&|key| env.get(key).cloned()).expect("test config builds")
    }

    #[test]
    fn new_builds_every_component_from_the_config() {
        let mut config = test_config();
        config.bans_path = PathBuf::from("/nonexistent/bans.json");
        config.known_hosts_path = PathBuf::from("/nonexistent/known.hosts.json");
        let state = AppState::new(config).expect("state builds");

        // Missing operator files fall back to their defaults rather than
        // failing construction — the service still signs without them.
        assert!(!state.bans.is_banned_ip("127.0.0.1"));
        assert!(state.known_hosts.get().is_object());
        assert!(state.throttle.healthy());
        assert_eq!(state.config.throttle_rate.num_requests, 300);
        // The registry is live: an observation shows up in the exposition.
        state
            .metrics
            .http_requests_total
            .with_label_values(&["preprod", "200"])
            .inc();
        assert!(state
            .metrics
            .gather()
            .contains("collateral_http_requests_total"));
    }

    #[test]
    fn state_clones_share_one_throttle() {
        let state = AppState::new(test_config()).expect("state builds");
        let clone = state.clone();
        assert!(Arc::ptr_eq(&state.throttle, &clone.throttle));
        assert!(Arc::ptr_eq(&state.keys, &clone.keys));
        assert!(Arc::ptr_eq(&state.metrics, &clone.metrics));
    }
}
