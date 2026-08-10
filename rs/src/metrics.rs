//! Prometheus metrics for the collateral provider.
//!
//! Deliberately kept aggregated and low-cardinality. We don't label by IP,
//! PKH, tx_id, or user-agent — those would either grow unbounded or amount to
//! per-user tracking, both out of scope for this service.
//!
//! Labels we *do* use:
//! - `environment` — a configured network, or the single bounded value
//!   `unknown` for invalid route values.
//! - `status` — HTTP response status code as an integer string.
//! - `outcome` — coarse Koios call result enum.

use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder};

/// Coarse Koios call outcomes, mirroring `api/metrics.py`'s tuple of the same
/// name. It is the vocabulary of the `outcome` label, not a pre-registration:
/// like the Python client, a series appears only once its outcome first
/// occurs, so a dashboard must treat an absent series as zero. Kept as a
/// constant so the two implementations can be diffed and so the test suite can
/// assert every outcome is a usable label.
pub const KOIOS_OUTCOMES: &[&str] = &[
    "success",
    "tx_invalid",
    "timeout",
    "request_error",
    "http_error",
    "invalid_json",
    "malformed",
    "capacity",
    "protocol_params_success",
    "protocol_params_timeout",
    "protocol_params_request_error",
    "protocol_params_http_error",
    "protocol_params_invalid_json",
    "protocol_params_malformed",
];

/// Buckets for the HTTP handler. Local-only rejections land in the first
/// bucket; anything past a couple of seconds is an upstream stall.
const HTTP_DURATION_BUCKETS: &[f64] = &[0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

/// Koios calls never start below the network round trip, so the sub-25ms
/// buckets the HTTP histogram needs would only ever be empty here.
const KOIOS_DURATION_BUCKETS: &[f64] = &[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

pub struct Metrics {
    pub registry: Registry,
    pub http_requests_total: IntCounterVec,
    pub http_request_duration_seconds: HistogramVec,
    pub koios_requests_total: IntCounterVec,
    pub koios_request_duration_seconds: HistogramVec,
}

impl Metrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        // A private registry rather than the process-global default: tests
        // build independent instances, and two of them in one process must
        // not collide on an already-registered metric name.
        let registry = Registry::new();

        let http_requests_total = IntCounterVec::new(
            Opts::new(
                "collateral_http_requests_total",
                "HTTP requests handled by the collateral endpoint, labeled by environment and status code.",
            ),
            &["environment", "status"],
        )?;
        let http_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "collateral_http_request_duration_seconds",
                "Wall-clock time spent serving requests to the collateral endpoint.",
            )
            .buckets(HTTP_DURATION_BUCKETS.to_vec()),
            &["environment"],
        )?;
        let koios_requests_total = IntCounterVec::new(
            Opts::new(
                "collateral_koios_requests_total",
                "Koios evaluation and protocol-parameter calls, labeled by environment and outcome.",
            ),
            &["environment", "outcome"],
        )?;
        let koios_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "collateral_koios_request_duration_seconds",
                "Wall-clock time spent on Koios evaluation and protocol-parameter calls.",
            )
            .buckets(KOIOS_DURATION_BUCKETS.to_vec()),
            &["environment"],
        )?;

        registry.register(Box::new(http_requests_total.clone()))?;
        registry.register(Box::new(http_request_duration_seconds.clone()))?;
        registry.register(Box::new(koios_requests_total.clone()))?;
        registry.register(Box::new(koios_request_duration_seconds.clone()))?;

        Ok(Self {
            registry,
            http_requests_total,
            http_request_duration_seconds,
            koios_requests_total,
            koios_request_duration_seconds,
        })
    }

    /// Render the Prometheus text exposition format.
    pub fn gather(&self) -> String {
        let families = self.registry.gather();
        match TextEncoder::new().encode_to_string(&families) {
            Ok(text) => text,
            Err(error) => {
                // Scraping is best-effort telemetry; an encoder failure must
                // not take down the endpoint that reports it.
                tracing::error!("Failed to encode Prometheus metrics: {}", error);
                String::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_private_so_instances_are_independent() {
        // Registering the same names twice would fail against a shared
        // registry; two instances must be constructible in one process.
        let first = Metrics::new().expect("metrics");
        let second = Metrics::new().expect("metrics");

        first
            .http_requests_total
            .with_label_values(&["preprod", "200"])
            .inc();

        assert!(first.gather().contains("collateral_http_requests_total"));
        assert!(!second
            .gather()
            .contains("collateral_http_requests_total{environment=\"preprod\""));
    }

    #[test]
    fn metric_names_and_help_match_the_python_module() {
        let metrics = Metrics::new().expect("metrics");
        metrics
            .http_requests_total
            .with_label_values(&["preprod", "200"])
            .inc();
        metrics
            .http_request_duration_seconds
            .with_label_values(&["preprod"])
            .observe(0.01);
        metrics
            .koios_requests_total
            .with_label_values(&["preprod", "success"])
            .inc();
        metrics
            .koios_request_duration_seconds
            .with_label_values(&["preprod"])
            .observe(0.01);

        let text = metrics.gather();
        for expected in [
            "# HELP collateral_http_requests_total HTTP requests handled by the collateral endpoint, labeled by environment and status code.",
            "# HELP collateral_http_request_duration_seconds Wall-clock time spent serving requests to the collateral endpoint.",
            "# HELP collateral_koios_requests_total Koios evaluation and protocol-parameter calls, labeled by environment and outcome.",
            "# HELP collateral_koios_request_duration_seconds Wall-clock time spent on Koios evaluation and protocol-parameter calls.",
            "collateral_http_requests_total{environment=\"preprod\",status=\"200\"} 1",
            "collateral_koios_requests_total{environment=\"preprod\",outcome=\"success\"} 1",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
    }

    #[test]
    fn histogram_buckets_match_the_python_module() {
        let metrics = Metrics::new().expect("metrics");
        metrics
            .http_request_duration_seconds
            .with_label_values(&["preprod"])
            .observe(100.0);
        metrics
            .koios_request_duration_seconds
            .with_label_values(&["preprod"])
            .observe(100.0);
        let text = metrics.gather();

        for bound in HTTP_DURATION_BUCKETS {
            assert!(
                text.contains(&format!(
                    "collateral_http_request_duration_seconds_bucket{{environment=\"preprod\",le=\"{bound}\"}}"
                )),
                "missing http bucket {bound}"
            );
        }
        // 0.025 belongs to the HTTP histogram only.
        assert!(!text.contains(
            "collateral_koios_request_duration_seconds_bucket{environment=\"preprod\",le=\"0.025\"}"
        ));
        for bound in KOIOS_DURATION_BUCKETS {
            assert!(
                text.contains(&format!(
                    "collateral_koios_request_duration_seconds_bucket{{environment=\"preprod\",le=\"{bound}\"}}"
                )),
                "missing koios bucket {bound}"
            );
        }
    }

    #[test]
    fn every_koios_outcome_is_a_usable_label() {
        let metrics = Metrics::new().expect("metrics");
        for outcome in KOIOS_OUTCOMES {
            metrics
                .koios_requests_total
                .with_label_values(&["preprod", outcome])
                .inc();
        }
        let text = metrics.gather();
        for outcome in KOIOS_OUTCOMES {
            assert!(
                text.contains(&format!(
                    "collateral_koios_requests_total{{environment=\"preprod\",outcome=\"{outcome}\"}} 1"
                )),
                "missing outcome {outcome}"
            );
        }
    }
}
