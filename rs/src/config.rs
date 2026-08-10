//! Configuration read from the process environment, with an optional `.env`
//! file for local development.
//!
//! Port of `collateral_provider/settings.py`. Required identity/network values
//! fail loudly when absent — a misconfigured deploy must refuse to start
//! rather than 500 on the first POST.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use ipnet::IpNet;

use crate::throttle::ThrottleRate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} env var is required")]
    Missing(String),
    #[error("{0}")]
    Invalid(String),
}

/// Per-network configuration.
///
/// `koios_url` is the JSON-RPC Ogmios endpoint used for protocol-parameter
/// lookup and `evaluateTransaction`. Defaults match Koios's public hosting
/// for preprod/mainnet; override for a self-hosted evaluator.
#[derive(Debug, Clone)]
pub struct EnvironmentConfig {
    /// Free-form operator label, mirroring `NETWORK` in the Python settings
    /// (e.g. `--testnet-magic 1`). Not used for validation.
    pub network: String,
    /// Canonical lowercase hex transaction id of the collateral UTxO.
    pub txid: String,
    pub txidx: u64,
    pub koios_url: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Canonical lowercase hex of the 28-byte payment key hash.
    pub pkh: String,
    pub skey_path: PathBuf,
    pub vkey_path: PathBuf,
    /// `"development"` or anything else (treated as production).
    pub environment: String,
    /// Networks this instance serves, keyed by URL path segment.
    pub environments: BTreeMap<String, EnvironmentConfig>,
    /// Host header allowlist. Empty means "allow any", which is only reachable
    /// in development mode.
    pub allowed_hosts: Vec<String>,
    pub throttle_rate: ThrottleRate,
    pub koios_max_in_flight: usize,
    pub trusted_proxy_ips: Vec<IpNet>,
    pub bans_path: PathBuf,
    pub known_hosts_path: PathBuf,
    pub metrics_enabled: bool,
    pub metrics_allow_ips: Vec<IpAddr>,
    /// On-chain max transaction size in bytes (Conway: 16 KiB).
    pub max_tx_size: usize,
    /// Pre-parser HTTP body cap: `max_tx_size * 2 + 4 KiB`.
    pub max_body_size: usize,
    pub log_level: String,
    pub log_file: PathBuf,
    pub log_format: LogFormat,
    pub log_to_console: bool,
    pub bind_address: SocketAddr,
}

/// Reads one variable. Indirected so tests can supply a fixed environment
/// instead of mutating the process-wide one, which no test can do safely
/// while other tests run in parallel.
pub type Lookup<'a> = &'a dyn Fn(&str) -> Option<String>;

impl Config {
    /// Read and validate the whole configuration from the environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        // Container platforms inject variables directly and have no .env file;
        // that is fine, and `dotenvy` does not override anything already set.
        let _ = dotenvy::dotenv();
        Self::from_lookup(&|key| std::env::var(key).ok())
    }

    /// Build a configuration from an arbitrary variable source.
    pub fn from_lookup(get: Lookup<'_>) -> Result<Self, ConfigError> {
        let pkh = canonical_hex(&required(get, "PKH")?, "PKH", Some(28))?;
        let skey_path = path_or(get, "SKEY_PATH", "./keys/payment.skey");
        let vkey_path = path_or(get, "VKEY_PATH", "./keys/payment.vkey");
        let environment = required(get, "ENVIRONMENT")?;

        let mut environments = BTreeMap::new();
        for (name, prefix, koios_default) in [
            (
                "preprod",
                "PREPROD",
                "https://preprod.koios.rest/api/v1/ogmios",
            ),
            ("mainnet", "MAINNET", "https://api.koios.rest/api/v1/ogmios"),
        ] {
            let txid_var = format!("{prefix}_TXID");
            environments.insert(
                name.to_string(),
                EnvironmentConfig {
                    network: required(get, &format!("{prefix}_NETWORK"))?,
                    // Canonicalized for the same reason as PKH: check_collateral
                    // compares this against lowercase hex from the wire. Length
                    // is not enforced here so a local dev setup can leave a
                    // network blank; validate_startup enforces it everywhere else.
                    txid: canonical_hex(&required(get, &txid_var)?, &txid_var, None)?,
                    txidx: required_u64(get, &format!("{prefix}_TXIDX"))?,
                    koios_url: string_or(get, &format!("{prefix}_KOIOS_URL"), koios_default),
                },
            );
        }

        let allowed_hosts = if environment == "development" {
            vec!["127.0.0.1".to_string(), "localhost".to_string()]
        } else {
            let hosts = parse_list(&required(get, "ALLOWED_HOSTS")?);
            if hosts.is_empty() {
                return Err(ConfigError::Invalid(
                    "ALLOWED_HOSTS env var is empty in non-development mode — every \
                     request would be rejected. Refusing to start."
                        .to_string(),
                ));
            }
            hosts
        };

        let throttle_rate: ThrottleRate = string_or(get, "COLLATERAL_THROTTLE_RATE", "300/min")
            .parse()
            .map_err(|err| ConfigError::Invalid(format!("COLLATERAL_THROTTLE_RATE {err}")))?;

        let koios_max_in_flight = usize::try_from(u64_or(get, "KOIOS_MAX_IN_FLIGHT", 4)?)
            .map_err(|_| ConfigError::Invalid("KOIOS_MAX_IN_FLIGHT is too large".to_string()))?;
        if koios_max_in_flight == 0 {
            return Err(ConfigError::Invalid(
                "KOIOS_MAX_IN_FLIGHT must be at least 1".to_string(),
            ));
        }

        let trusted_proxy_ips =
            crate::net::parse_networks(&list_or(get, "TRUSTED_PROXY_IPS", &["127.0.0.1", "::1"]));

        let metrics_allow_ips =
            parse_allow_ips(&list_or(get, "METRICS_ALLOW_IPS", &["127.0.0.1", "::1"]));

        let max_tx_size = usize::try_from(u64_or(get, "MAX_TX_SIZE", 16 * 1024)?)
            .map_err(|_| ConfigError::Invalid("MAX_TX_SIZE is too large".to_string()))?;
        // Body = hex tx (2x binary) + 4 KiB for field names, JSON quoting, slack.
        let max_body_size = max_tx_size
            .checked_mul(2)
            .and_then(|doubled| doubled.checked_add(4 * 1024))
            .ok_or_else(|| ConfigError::Invalid("MAX_TX_SIZE is too large".to_string()))?;

        let log_format_raw = string_or(get, "LOG_FORMAT", "text");
        let log_format = match log_format_raw.as_str() {
            "text" => LogFormat::Text,
            "json" => LogFormat::Json,
            other => {
                return Err(ConfigError::Invalid(format!(
                    "LOG_FORMAT must be 'text' or 'json', got {other:?}"
                )))
            }
        };

        let bind_address_raw = string_or(get, "BIND_ADDRESS", "0.0.0.0:8080");
        let bind_address = bind_address_raw.trim().parse::<SocketAddr>().map_err(|_| {
            ConfigError::Invalid(format!(
                "BIND_ADDRESS must be <host>:<port>, got {bind_address_raw:?}"
            ))
        })?;

        Ok(Config {
            pkh,
            skey_path,
            vkey_path,
            environment,
            environments,
            allowed_hosts,
            throttle_rate,
            koios_max_in_flight,
            trusted_proxy_ips,
            bans_path: path_or(get, "BANS_PATH", "./bans.json"),
            known_hosts_path: path_or(get, "KNOWN_HOSTS_PATH", "./known.hosts.json"),
            metrics_enabled: bool_or(get, "METRICS_ENABLED", false)?,
            metrics_allow_ips,
            max_tx_size,
            max_body_size,
            log_level: string_or(get, "LOG_LEVEL", "DEBUG"),
            log_file: path_or(get, "LOG_FILE", "./debug.log"),
            log_format,
            log_to_console: bool_or(get, "LOG_TO_CONSOLE", false)?,
            bind_address,
        })
    }

    /// Look up a network by its URL path segment.
    pub fn environment(&self, name: &str) -> Option<&EnvironmentConfig> {
        self.environments.get(name)
    }

    /// The configured network names, for `check_environment`.
    pub fn networks(&self) -> Vec<String> {
        self.environments.keys().cloned().collect()
    }

    pub fn is_development(&self) -> bool {
        self.environment == "development"
    }
}

/// Normalize an operator-supplied hex value, or refuse to start.
///
/// Startup validation and `/healthz` both parse these as bytes, which
/// tolerates uppercase; every request-time comparison is an exact lowercase
/// string match instead. An uppercase or space-padded value would otherwise
/// produce a service that reports itself healthy and then rejects 100% of
/// traffic with a message blaming the caller. Canonicalizing once, here,
/// keeps both paths agreeing.
pub fn canonical_hex(
    value: &str,
    name: &str,
    expected_bytes: Option<usize>,
) -> Result<String, ConfigError> {
    let text: String = value
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    let raw = hex::decode(&text)
        .map_err(|_| ConfigError::Invalid(format!("{name} must be hexadecimal, got {value:?}")))?;
    if let Some(expected) = expected_bytes {
        if raw.len() != expected {
            return Err(ConfigError::Invalid(format!(
                "{name} must be exactly {expected} bytes ({} hex characters)",
                expected * 2
            )));
        }
    }
    Ok(text)
}

/// Startup checks that `apps.ApiConfig.ready()` performs: the signing
/// identity must be internally consistent, and outside development every
/// configured network must carry a usable 32-byte collateral reference.
pub fn validate_startup(config: &Config, keys: &crate::signature::KeyCache) -> Result<(), String> {
    for path in [&config.skey_path, &config.vkey_path] {
        if !path.exists() {
            tracing::error!(target: "api", "Signing key missing: {}", path.display());
            return Err(format!(
                "Required signing key not found at {}",
                path.display()
            ));
        }
    }

    if let Err(err) = keys.validate_key_material(&config.skey_path, &config.vkey_path, &config.pkh)
    {
        tracing::error!(target: "api", "Signing identity is invalid: {}", err);
        return Err("Signing key, verification key, and PKH do not match".to_string());
    }

    check_collateral_references(config)
}

/// Local operators commonly configure preprod first and leave mainnet blank
/// while developing. Production advertises both routes, so every configured
/// network must be usable there.
fn check_collateral_references(config: &Config) -> Result<(), String> {
    if config.is_development() {
        return Ok(());
    }
    for (name, environment) in &config.environments {
        let usable = hex::decode(&environment.txid)
            .map(|txid| txid.len() == 32)
            .unwrap_or(false);
        if !usable {
            return Err(format!("Invalid collateral configuration for {name}"));
        }
    }
    Ok(())
}

fn required(get: Lookup<'_>, key: &str) -> Result<String, ConfigError> {
    get(key).ok_or_else(|| ConfigError::Missing(key.to_string()))
}

fn string_or(get: Lookup<'_>, key: &str, default: &str) -> String {
    get(key).unwrap_or_else(|| default.to_string())
}

fn path_or(get: Lookup<'_>, key: &str, default: &str) -> PathBuf {
    PathBuf::from(string_or(get, key, default))
}

fn required_u64(get: Lookup<'_>, key: &str) -> Result<u64, ConfigError> {
    let raw = required(get, key)?;
    parse_u64(key, &raw)
}

fn u64_or(get: Lookup<'_>, key: &str, default: u64) -> Result<u64, ConfigError> {
    match get(key) {
        Some(raw) => parse_u64(key, &raw),
        None => Ok(default),
    }
}

fn parse_u64(key: &str, raw: &str) -> Result<u64, ConfigError> {
    raw.trim().parse::<u64>().map_err(|_| {
        ConfigError::Invalid(format!("{key} must be a non-negative integer, got {raw:?}"))
    })
}

/// django-environ's boolean vocabulary. Anything outside it is a hard error
/// rather than a silent `false`: an operator who wrote `METRICS_ENABLED=enable`
/// deserves a startup failure, not a service that quietly 404s /metrics.
fn bool_or(get: Lookup<'_>, key: &str, default: bool) -> Result<bool, ConfigError> {
    let Some(raw) = get(key) else {
        return Ok(default);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "t" | "on" | "ok" | "y" | "yes" | "1" => Ok(true),
        "false" | "f" | "off" | "n" | "no" | "0" => Ok(false),
        _ => Err(ConfigError::Invalid(format!(
            "{key} must be a boolean (true/false), got {raw:?}"
        ))),
    }
}

/// Comma-separated, whitespace-trimmed, empty entries dropped.
fn parse_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

fn list_or(get: Lookup<'_>, key: &str, default: &[&str]) -> Vec<String> {
    match get(key) {
        Some(raw) => parse_list(&raw),
        None => default.iter().map(|entry| (*entry).to_string()).collect(),
    }
}

/// Parse `METRICS_ALLOW_IPS` into addresses so the comparison is against
/// normalized forms on both sides — a scraper listed as `0:0:0:0:0:0:0:1`
/// must match a peer reported as `::1`. A bad entry is dropped (which denies,
/// the safe direction) rather than failing the whole deploy over metrics.
fn parse_allow_ips(entries: &[String]) -> Vec<IpAddr> {
    let mut allowed = Vec::with_capacity(entries.len());
    for entry in entries {
        match crate::net::parse_ip(entry) {
            Some(ip) => allowed.push(ip),
            None => tracing::warn!(
                target: "api",
                "Ignoring invalid METRICS_ALLOW_IPS entry: {:?}",
                entry
            ),
        }
    }
    allowed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Duration;

    const PKH: &str = "6af53ff4f054348ad825c692dd9db8f1760a8e0eacf9af9f99306513";

    fn base_env() -> HashMap<String, String> {
        [
            ("PKH", PKH.to_string()),
            ("ENVIRONMENT", "development".to_string()),
            ("PREPROD_NETWORK", "--testnet-magic 1".to_string()),
            ("PREPROD_TXID", "a1".repeat(32)),
            ("PREPROD_TXIDX", "0".to_string()),
            ("MAINNET_NETWORK", "--mainnet".to_string()),
            ("MAINNET_TXID", "b2".repeat(32)),
            ("MAINNET_TXIDX", "1".to_string()),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect()
    }

    /// Build with `overrides` applied; a `None` value removes the variable.
    fn build(overrides: &[(&str, Option<&str>)]) -> Result<Config, ConfigError> {
        let mut env = base_env();
        for (key, value) in overrides {
            match value {
                Some(value) => {
                    env.insert((*key).to_string(), (*value).to_string());
                }
                None => {
                    env.remove(*key);
                }
            }
        }
        Config::from_lookup(&|key| env.get(key).cloned())
    }

    fn set(overrides: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let owned: Vec<(&str, Option<&str>)> =
            overrides.iter().map(|(k, v)| (*k, Some(*v))).collect();
        build(&owned)
    }

    fn built(overrides: &[(&str, &str)]) -> Config {
        set(overrides).expect("config builds")
    }

    fn message(err: ConfigError) -> String {
        err.to_string()
    }

    #[test]
    fn defaults_match_the_python_settings() {
        let config = built(&[]);
        assert_eq!(config.pkh, PKH);
        assert_eq!(config.skey_path, PathBuf::from("./keys/payment.skey"));
        assert_eq!(config.vkey_path, PathBuf::from("./keys/payment.vkey"));
        assert_eq!(config.bans_path, PathBuf::from("./bans.json"));
        assert_eq!(config.known_hosts_path, PathBuf::from("./known.hosts.json"));
        assert_eq!(config.throttle_rate.num_requests, 300);
        assert_eq!(config.throttle_rate.period, Duration::from_secs(60));
        assert_eq!(config.koios_max_in_flight, 4);
        assert!(!config.metrics_enabled);
        assert_eq!(config.max_tx_size, 16384);
        assert_eq!(config.max_body_size, 16384 * 2 + 4096);
        assert_eq!(config.log_level, "DEBUG");
        assert_eq!(config.log_file, PathBuf::from("./debug.log"));
        assert_eq!(config.log_format, LogFormat::Text);
        assert!(!config.log_to_console);
        assert_eq!(config.bind_address.to_string(), "0.0.0.0:8080");
        assert_eq!(
            config.trusted_proxy_ips,
            crate::net::parse_networks(&["127.0.0.1".to_string(), "::1".to_string()])
        );
        assert_eq!(
            config.metrics_allow_ips,
            vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "::1".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn networks_carry_their_defaults() {
        let config = built(&[]);
        assert_eq!(config.networks(), vec!["mainnet", "preprod"]);
        let preprod = config.environment("preprod").expect("preprod configured");
        assert_eq!(preprod.network, "--testnet-magic 1");
        assert_eq!(preprod.txid, "a1".repeat(32));
        assert_eq!(preprod.txidx, 0);
        assert_eq!(
            preprod.koios_url,
            "https://preprod.koios.rest/api/v1/ogmios"
        );
        let mainnet = config.environment("mainnet").expect("mainnet configured");
        assert_eq!(mainnet.txidx, 1);
        assert_eq!(mainnet.koios_url, "https://api.koios.rest/api/v1/ogmios");
        assert!(config.environment("preview").is_none());
    }

    #[test]
    fn koios_urls_are_overridable() {
        let config = built(&[("PREPROD_KOIOS_URL", "http://127.0.0.1:1337")]);
        assert_eq!(
            config.environment("preprod").unwrap().koios_url,
            "http://127.0.0.1:1337"
        );
    }

    #[test]
    fn identity_and_network_values_are_required() {
        for key in [
            "PKH",
            "ENVIRONMENT",
            "PREPROD_NETWORK",
            "PREPROD_TXID",
            "PREPROD_TXIDX",
            "MAINNET_NETWORK",
            "MAINNET_TXID",
            "MAINNET_TXIDX",
        ] {
            let err = build(&[(key, None)]).expect_err("missing value must refuse to start");
            assert_eq!(message(err), format!("{key} env var is required"), "{key}");
        }
    }

    #[test]
    fn pkh_is_canonicalized_and_length_checked() {
        let config = built(&[("PKH", &format!(" {} ", PKH.to_uppercase()))]);
        assert_eq!(config.pkh, PKH);

        let err = message(set(&[("PKH", "zz")]).expect_err("non-hex PKH"));
        assert!(err.starts_with("PKH must be hexadecimal"), "{err}");

        let err = message(set(&[("PKH", "abcd")]).expect_err("short PKH"));
        assert_eq!(err, "PKH must be exactly 28 bytes (56 hex characters)");
    }

    #[test]
    fn txid_is_canonicalized_but_length_is_deferred_to_startup() {
        // A dev box may leave a network blank; validate_startup is what
        // enforces 32 bytes, and only outside development.
        let config = built(&[("PREPROD_TXID", ""), ("MAINNET_TXID", &"A1".repeat(32))]);
        assert_eq!(config.environment("preprod").unwrap().txid, "");
        assert_eq!(config.environment("mainnet").unwrap().txid, "a1".repeat(32));
    }

    #[test]
    fn development_gets_localhost_allowed_hosts() {
        let config = built(&[]);
        assert!(config.is_development());
        assert_eq!(config.allowed_hosts, vec!["127.0.0.1", "localhost"]);
    }

    #[test]
    fn production_requires_a_non_empty_allowed_hosts() {
        let err = build(&[("ENVIRONMENT", Some("production")), ("ALLOWED_HOSTS", None)])
            .expect_err("missing ALLOWED_HOSTS");
        assert_eq!(message(err), "ALLOWED_HOSTS env var is required");

        let err = message(
            set(&[("ENVIRONMENT", "production"), ("ALLOWED_HOSTS", " , ")])
                .expect_err("empty ALLOWED_HOSTS"),
        );
        assert!(err.starts_with("ALLOWED_HOSTS env var is empty"), "{err}");

        let config = built(&[
            ("ENVIRONMENT", "production"),
            ("ALLOWED_HOSTS", " a.example.com , b.example.com ,"),
        ]);
        assert!(!config.is_development());
        assert_eq!(config.allowed_hosts, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn throttle_rate_is_parsed_and_validated() {
        let config = built(&[("COLLATERAL_THROTTLE_RATE", "10/s")]);
        assert_eq!(config.throttle_rate.num_requests, 10);
        assert_eq!(config.throttle_rate.period, Duration::from_secs(1));

        let err =
            message(set(&[("COLLATERAL_THROTTLE_RATE", "lots")]).expect_err("unparseable rate"));
        assert!(err.starts_with("COLLATERAL_THROTTLE_RATE"), "{err}");
    }

    #[test]
    fn koios_in_flight_floor_is_enforced() {
        assert_eq!(
            built(&[("KOIOS_MAX_IN_FLIGHT", "9")]).koios_max_in_flight,
            9
        );
        let err = message(set(&[("KOIOS_MAX_IN_FLIGHT", "0")]).expect_err("zero budget"));
        assert_eq!(err, "KOIOS_MAX_IN_FLIGHT must be at least 1");
        assert!(set(&[("KOIOS_MAX_IN_FLIGHT", "-1")]).is_err());
    }

    #[test]
    fn max_body_size_is_derived_from_max_tx_size() {
        let config = built(&[("MAX_TX_SIZE", "1000")]);
        assert_eq!(config.max_tx_size, 1000);
        assert_eq!(config.max_body_size, 1000 * 2 + 4096);
    }

    #[test]
    fn log_format_accepts_only_text_or_json() {
        assert_eq!(built(&[("LOG_FORMAT", "json")]).log_format, LogFormat::Json);
        let err = message(set(&[("LOG_FORMAT", "logfmt")]).expect_err("bad format"));
        assert_eq!(err, "LOG_FORMAT must be 'text' or 'json', got \"logfmt\"");
    }

    #[test]
    fn booleans_use_the_django_environ_vocabulary() {
        for value in ["true", "True", "on", "yes", "y", "1", "t", "ok"] {
            assert!(
                built(&[("METRICS_ENABLED", value)]).metrics_enabled,
                "{value}"
            );
        }
        for value in ["false", "FALSE", "off", "no", "n", "0", "f"] {
            assert!(
                !built(&[("METRICS_ENABLED", value)]).metrics_enabled,
                "{value}"
            );
        }
        assert!(set(&[("METRICS_ENABLED", "enable")]).is_err());
    }

    #[test]
    fn list_entries_are_trimmed_and_empties_dropped() {
        let config = built(&[("TRUSTED_PROXY_IPS", " 10.0.0.0/8 , , ::1 ")]);
        assert_eq!(config.trusted_proxy_ips.len(), 2);

        // An empty value disables XFF trust entirely, as in Python.
        assert!(built(&[("TRUSTED_PROXY_IPS", "")])
            .trusted_proxy_ips
            .is_empty());
    }

    #[test]
    fn metrics_allow_ips_are_normalized_and_bad_entries_denied() {
        let config = built(&[("METRICS_ALLOW_IPS", "0:0:0:0:0:0:0:1, nope, 10.0.0.5")]);
        assert_eq!(
            config.metrics_allow_ips,
            vec![
                "::1".parse::<IpAddr>().unwrap(),
                "10.0.0.5".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn bind_address_must_be_host_port() {
        assert_eq!(
            built(&[("BIND_ADDRESS", "127.0.0.1:9000")])
                .bind_address
                .to_string(),
            "127.0.0.1:9000"
        );
        assert!(set(&[("BIND_ADDRESS", "8080")]).is_err());
    }

    #[test]
    fn canonical_hex_strips_whitespace_and_lowercases() {
        assert_eq!(
            canonical_hex(" DE AD\tbe\nef ", "X", None).unwrap(),
            "deadbeef"
        );
        assert!(canonical_hex("abc", "X", None).is_err(), "odd length");
        assert!(canonical_hex("de ad", "X", Some(2)).is_ok());
        assert!(canonical_hex("dead", "X", Some(3)).is_err());
        assert_eq!(canonical_hex("", "X", None).unwrap(), "");
    }

    #[test]
    fn collateral_references_are_only_enforced_outside_development() {
        // Development tolerates a blank network so a local operator can set
        // preprod up first.
        let dev = built(&[("PREPROD_TXID", "")]);
        assert!(check_collateral_references(&dev).is_ok());

        let production = built(&[
            ("ENVIRONMENT", "production"),
            ("ALLOWED_HOSTS", "example.com"),
        ]);
        assert!(check_collateral_references(&production).is_ok());

        let broken = built(&[
            ("ENVIRONMENT", "production"),
            ("ALLOWED_HOSTS", "example.com"),
            ("PREPROD_TXID", "a1a1"),
        ]);
        assert_eq!(
            check_collateral_references(&broken),
            Err("Invalid collateral configuration for preprod".to_string())
        );
    }
}
