//! Count and time requests to `/<env>/collateral/`.
//!
//! Deliberately scoped: no label per URL path or per IP (cardinality +
//! privacy). Route values are attacker-controlled, so only configured
//! environments are labeled and every invalid value is coalesced into the
//! single bounded series `unknown`.

use std::time::Instant;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

use crate::config::Config;
use crate::middleware::collateral_path_re;
use crate::state::AppState;

/// The one bounded series every unconfigured route value collapses into.
const UNKNOWN: &str = "unknown";

pub async fn middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(environment) = environment_label(request.uri().path(), &state.config) else {
        return next.run(request).await;
    };

    let started = Instant::now();
    let response = next.run(request).await;
    let status = response.status();

    // `get_metric_with_label_values` over `with_label_values`: a label-arity
    // mistake must not turn every request into a 500.
    if let Ok(histogram) = state
        .metrics
        .http_request_duration_seconds
        .get_metric_with_label_values(&[environment.as_str()])
    {
        histogram.observe(started.elapsed().as_secs_f64());
    }
    if let Ok(counter) = state
        .metrics
        .http_requests_total
        .get_metric_with_label_values(&[environment.as_str(), status.as_str()])
    {
        counter.inc();
    }
    response
}

/// The `environment` label for a path, or `None` when the path is not the
/// collateral endpoint and should not be measured at all.
pub(crate) fn environment_label(path: &str, config: &Config) -> Option<String> {
    let captures = collateral_path_re().captures(path)?;
    let requested = captures.name("env").map_or("", |value| value.as_str());
    Some(if config.environment(requested).is_some() {
        requested.to_string()
    } else {
        UNKNOWN.to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config() -> Config {
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
        Config::from_lookup(&|key| env.get(key).cloned()).expect("config builds")
    }

    #[test]
    fn configured_networks_keep_their_own_label() {
        let config = config();
        assert_eq!(
            environment_label("/preprod/collateral/", &config).as_deref(),
            Some("preprod")
        );
        assert_eq!(
            environment_label("/mainnet/collateral", &config).as_deref(),
            Some("mainnet")
        );
    }

    #[test]
    fn attacker_controlled_route_values_collapse_into_one_series() {
        let config = config();
        for path in [
            "/preview/collateral/",
            "/../collateral/",
            "/%20/collateral/",
            "/PREPROD/collateral/",
        ] {
            assert_eq!(
                environment_label(path, &config).as_deref(),
                Some(UNKNOWN),
                "{path}"
            );
        }
    }

    #[test]
    fn other_paths_are_not_measured() {
        let config = config();
        for path in ["/", "/healthz", "/known_hosts/", "/preprod/collateral/x"] {
            assert_eq!(environment_label(path, &config), None, "{path}");
        }
    }
}
