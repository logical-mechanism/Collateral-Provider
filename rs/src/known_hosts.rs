//! Validation for the public collateral-provider registry.
//!
//! The registry is consumed directly by wallets and the landing page, so a
//! partially valid document is not useful. Hot reload keeps serving the last
//! entirely valid document when an operator update fails validation.

use std::path::PathBuf;
use std::sync::Arc;

use blake2::digest::consts::U28;
use blake2::{Blake2b, Digest};
use serde_json::Value;
use url::Url;

use crate::data_files::ReloadingJson;

type Blake2b224 = Blake2b<U28>;

pub struct KnownHosts {
    inner: ReloadingJson,
}

impl KnownHosts {
    pub fn new(path: PathBuf) -> Self {
        Self {
            inner: ReloadingJson::new(
                path,
                Value::Object(serde_json::Map::new()),
                Some(Box::new(validate_known_hosts_registry)),
            ),
        }
    }

    /// The last fully validated registry, or `{}` if the file has never
    /// existed, so consumers don't have to handle a second shape.
    pub fn get(&self) -> Arc<serde_json::Value> {
        self.inner.get()
    }
}

/// Return `Err` unless `value` matches the registry contract:
///
/// - top level is an object keyed by 56-lowercase-hex provider PKH
/// - each provider carries a 64-lowercase-hex `public_key` whose
///   Blake2b-224 digest equals its PKH key
/// - every other member is a network name matching `[a-z][a-z0-9_-]{0,31}`
///   mapping to exactly `{"utxo": {"id", "idx"}, "url"}`
/// - `utxo.id` is 64 lowercase hex, `utxo.idx` a non-negative integer
/// - `url` is an absolute HTTPS URL with no credentials, query, or fragment,
///   whose path is `/<network>/collateral` with an optional trailing slash
pub fn validate_known_hosts_registry(value: &serde_json::Value) -> Result<(), String> {
    let registry = value
        .as_object()
        .ok_or_else(|| "registry must be an object keyed by provider PKH".to_string())?;

    for (pkh, provider) in registry {
        if !is_lower_hex(pkh, 56) {
            return Err(
                "provider PKH keys must be 56 lowercase hexadecimal characters".to_string(),
            );
        }
        let location = format!("provider {pkh}");
        let provider = provider
            .as_object()
            .ok_or_else(|| format!("{location} must be an object"))?;

        let public_key = provider
            .get("public_key")
            .and_then(Value::as_str)
            .filter(|key| is_lower_hex(key, 64))
            .ok_or_else(|| {
                format!("{location}.public_key must be 64 lowercase hexadecimal characters")
            })?;
        // The key set has been range-checked as hex above, so decoding cannot
        // fail; the digest is what actually binds the advertised key to its
        // registry slot.
        let raw = hex::decode(public_key).map_err(|_| {
            format!("{location}.public_key must be 64 lowercase hexadecimal characters")
        })?;
        if hex::encode(Blake2b224::digest(&raw)) != *pkh {
            return Err(format!("{location}.public_key does not derive its PKH"));
        }

        let networks: Vec<(&String, &Value)> = provider
            .iter()
            .filter(|(name, _)| name.as_str() != "public_key")
            .collect();
        if networks.is_empty() {
            return Err(format!("{location} must advertise at least one network"));
        }

        for (network, config) in networks {
            let network_location = format!("{location}.{network}");
            if !is_network_name(network) {
                return Err(format!("{location} contains an invalid network name"));
            }
            let config = config
                .as_object()
                .filter(|config| {
                    config.len() == 2 && config.contains_key("utxo") && config.contains_key("url")
                })
                .ok_or_else(|| {
                    format!("{network_location} must contain exactly 'utxo' and 'url'")
                })?;

            let utxo = config
                .get("utxo")
                .and_then(Value::as_object)
                .filter(|utxo| {
                    utxo.len() == 2 && utxo.contains_key("id") && utxo.contains_key("idx")
                })
                .ok_or_else(|| {
                    format!("{network_location}.utxo must contain exactly 'id' and 'idx'")
                })?;

            let txid = utxo.get("id").unwrap_or(&Value::Null);
            if !txid.as_str().is_some_and(|txid| is_lower_hex(txid, 64)) {
                return Err(format!(
                    "{network_location}.utxo.id must be 64 lowercase hexadecimal characters"
                ));
            }
            // `as_u64` rejects booleans and floats, matching Python's
            // `isinstance(int) and not isinstance(bool)` and its `>= 0`.
            if utxo.get("idx").is_none_or(|idx| idx.as_u64().is_none()) {
                return Err(format!(
                    "{network_location}.utxo.idx must be a non-negative integer"
                ));
            }

            validate_endpoint_url(
                config.get("url").unwrap_or(&Value::Null),
                network,
                &network_location,
            )?;
        }
    }

    Ok(())
}

fn validate_endpoint_url(url: &Value, network: &str, location: &str) -> Result<(), String> {
    let raw = url
        .as_str()
        .filter(|raw| !raw.is_empty())
        .ok_or_else(|| format!("{location}.url must be a non-empty string"))?;

    // Check the raw string before parsing: the URL parser normalizes away
    // exactly the characters an operator would be smuggling through.
    if raw.chars().any(|c| (c as u32) < 0x21 || (c as u32) > 0x7e) {
        return Err(format!(
            "{location}.url must contain only visible ASCII characters"
        ));
    }
    if raw.contains('\\') {
        return Err(format!("{location}.url may not contain backslashes"));
    }

    let parsed = match Url::parse(raw) {
        Ok(parsed) => parsed,
        // A scheme-less URL is "not absolute" rather than "malformed", which
        // is how Python's urlsplit classifies it.
        Err(url::ParseError::RelativeUrlWithoutBase) => {
            return Err(format!("{location}.url must be an absolute HTTPS URL"))
        }
        Err(_) => return Err(format!("{location}.url is malformed")),
    };

    if parsed.scheme() != "https" || parsed.host_str().is_none_or(str::is_empty) {
        return Err(format!("{location}.url must be an absolute HTTPS URL"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!("{location}.url may not contain credentials"));
    }
    // Python tests truthiness, so a bare "?" or "#" is not a query/fragment.
    if parsed.query().is_some_and(|query| !query.is_empty())
        || parsed
            .fragment()
            .is_some_and(|fragment| !fragment.is_empty())
    {
        return Err(format!(
            "{location}.url may not contain a query or fragment"
        ));
    }

    let expected_path = format!("/{network}/collateral");
    if parsed.path().trim_end_matches('/') != expected_path {
        return Err(format!(
            "{location}.url path must be {expected_path}/ (trailing slash optional)"
        ));
    }

    Ok(())
}

/// Python's `[0-9a-f]{len}` fullmatch.
fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Python's `[a-z][a-z0-9_-]{0,31}` fullmatch.
fn is_network_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    match bytes.split_first() {
        Some((first, rest)) if first.is_ascii_lowercase() && rest.len() <= 31 => {
            rest.iter().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const PUBLIC_KEY: &str = "754c1db51aaee2e939b05b529ff5e210d8469afebcd2e487dae6f125fd500356";
    const PKH: &str = "1108b97f2e199d58a0c0697d25412d0fb14d354dcd39654b9eb0dec8";

    fn registry() -> Value {
        json!({
            PKH: {
                "public_key": PUBLIC_KEY,
                "preprod": {
                    "utxo": {"id": "ab".repeat(32), "idx": 0},
                    "url": "https://provider.example/preprod/collateral/",
                },
            },
        })
    }

    fn with_url(url: &str) -> Value {
        let mut value = registry();
        value[PKH]["preprod"]["url"] = json!(url);
        value
    }

    fn err(value: &Value) -> String {
        validate_known_hosts_registry(value).expect_err("expected rejection")
    }

    #[test]
    fn accepts_registry_contract() {
        assert_eq!(validate_known_hosts_registry(&registry()), Ok(()));
        assert_eq!(validate_known_hosts_registry(&json!({})), Ok(()));
    }

    #[test]
    fn accepts_the_checked_in_registry() {
        let shipped: Value =
            serde_json::from_str(include_str!("../../known.hosts.json")).expect("parse registry");
        assert_eq!(validate_known_hosts_registry(&shipped), Ok(()));
    }

    #[test]
    fn rejects_non_object_document() {
        assert_eq!(
            err(&json!(["not", "a", "registry"])),
            "registry must be an object keyed by provider PKH"
        );
    }

    #[test]
    fn rejects_bad_pkh_key() {
        let mut value = serde_json::Map::new();
        value.insert("not-a-pkh".to_string(), registry()[PKH].clone());
        assert_eq!(
            err(&Value::Object(value)),
            "provider PKH keys must be 56 lowercase hexadecimal characters"
        );
    }

    #[test]
    fn rejects_bad_public_key() {
        let mut missing = registry();
        missing[PKH]
            .as_object_mut()
            .expect("object")
            .remove("public_key");
        assert_eq!(
            err(&missing),
            format!("provider {PKH}.public_key must be 64 lowercase hexadecimal characters")
        );

        let mut mismatched = registry();
        mismatched[PKH]["public_key"] = json!("00".repeat(32));
        assert_eq!(
            err(&mismatched),
            format!("provider {PKH}.public_key does not derive its PKH")
        );
    }

    #[test]
    fn rejects_provider_without_networks() {
        let value = json!({PKH: {"public_key": PUBLIC_KEY}});
        assert_eq!(
            err(&value),
            format!("provider {PKH} must advertise at least one network")
        );
    }

    #[test]
    fn rejects_invalid_network_name_and_shape() {
        let mut named = json!({PKH: {"public_key": PUBLIC_KEY, "Preprod": {}}});
        assert_eq!(
            err(&named),
            format!("provider {PKH} contains an invalid network name")
        );

        named = registry();
        named[PKH]["preprod"]["enabled"] = json!(true);
        assert_eq!(
            err(&named),
            format!("provider {PKH}.preprod must contain exactly 'utxo' and 'url'")
        );
    }

    #[test]
    fn rejects_invalid_utxo() {
        let mut short_txid = registry();
        short_txid[PKH]["preprod"]["utxo"]["id"] = json!("ab");
        assert_eq!(
            err(&short_txid),
            format!("provider {PKH}.preprod.utxo.id must be 64 lowercase hexadecimal characters")
        );

        let expected = format!("provider {PKH}.preprod.utxo.idx must be a non-negative integer");
        // A CBOR/JSON boolean is never an integer, matching Python.
        let mut boolean = registry();
        boolean[PKH]["preprod"]["utxo"]["idx"] = json!(true);
        assert_eq!(err(&boolean), expected);

        let mut negative = registry();
        negative[PKH]["preprod"]["utxo"]["idx"] = json!(-1);
        assert_eq!(err(&negative), expected);

        let mut float = registry();
        float[PKH]["preprod"]["utxo"]["idx"] = json!(1.5);
        assert_eq!(err(&float), expected);

        let mut extra = registry();
        extra[PKH]["preprod"]["utxo"]["extra"] = json!(1);
        assert_eq!(
            err(&extra),
            format!("provider {PKH}.preprod.utxo must contain exactly 'id' and 'idx'")
        );
    }

    #[test]
    fn rejects_bad_urls() {
        let location = format!("provider {PKH}.preprod");
        let cases = [
            (
                json!(""),
                format!("{location}.url must be a non-empty string"),
            ),
            (
                json!("https://provider.example/preprod/collateral/ "),
                format!("{location}.url must contain only visible ASCII characters"),
            ),
            (
                json!("https://provider.example\\preprod/collateral"),
                format!("{location}.url may not contain backslashes"),
            ),
            (
                json!("http://provider.example/preprod/collateral/"),
                format!("{location}.url must be an absolute HTTPS URL"),
            ),
            (
                json!("/preprod/collateral"),
                format!("{location}.url must be an absolute HTTPS URL"),
            ),
            (
                json!("https://user:pass@provider.example/preprod/collateral/"),
                format!("{location}.url may not contain credentials"),
            ),
            (
                json!("https://provider.example/preprod/collateral/?x=1"),
                format!("{location}.url may not contain a query or fragment"),
            ),
            (
                json!("https://provider.example/preprod/collateral/#frag"),
                format!("{location}.url may not contain a query or fragment"),
            ),
            (
                json!("https://provider.example/mainnet/collateral/"),
                format!(
                    "{location}.url path must be /preprod/collateral/ (trailing slash optional)"
                ),
            ),
            (
                json!("https://provider.example:notaport/preprod/collateral/"),
                format!("{location}.url is malformed"),
            ),
            (
                json!(42),
                format!("{location}.url must be a non-empty string"),
            ),
        ];
        for (url, expected) in cases {
            let mut value = registry();
            value[PKH]["preprod"]["url"] = url.clone();
            assert_eq!(err(&value), expected, "url {url}");
        }
    }

    #[test]
    fn accepts_url_without_trailing_slash() {
        assert_eq!(
            validate_known_hosts_registry(&with_url("https://provider.example/preprod/collateral")),
            Ok(())
        );
    }

    #[test]
    fn loader_serves_empty_object_when_file_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hosts = KnownHosts::new(dir.path().join("known.hosts.json"));
        assert_eq!(*hosts.get(), json!({}));
    }

    #[test]
    fn loader_keeps_last_good_registry_on_invalid_update() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known.hosts.json");
        std::fs::write(&path, serde_json::to_vec(&registry()).expect("encode")).expect("write");

        let hosts = KnownHosts::new(path.clone());
        assert_eq!(*hosts.get(), registry());

        let later = std::fs::metadata(&path)
            .expect("stat")
            .modified()
            .expect("mtime")
            + std::time::Duration::from_secs(1);
        let insecure = with_url("http://provider.example/preprod/collateral/");
        std::fs::write(&path, serde_json::to_vec(&insecure).expect("encode")).expect("write");
        let file = std::fs::File::options()
            .write(true)
            .open(&path)
            .expect("open");
        file.set_times(std::fs::FileTimes::new().set_modified(later))
            .expect("set_times");

        assert_eq!(*hosts.get(), registry());
    }
}
