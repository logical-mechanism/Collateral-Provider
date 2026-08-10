//! Ban lists. Edit `BANS_PATH` (default `./bans.json`) and the change is
//! picked up on the next request — no redeploy needed.
//!
//! The file's shape:
//!
//! ```json
//! {
//!   "addresses": ["<hex output address>"],
//!   "ips":       ["<v4 or v6 string>"]
//! }
//! ```
//!
//! Address strings are the **raw output address bytes** in lowercase hex
//! (matching what `check_outputs` compares against), not bech32.

use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use serde_json::Value;

use crate::data_files::ReloadingJson;

pub struct BanList {
    inner: ReloadingJson,
}

impl BanList {
    pub fn new(path: PathBuf) -> Self {
        Self {
            inner: ReloadingJson::new(
                path,
                serde_json::json!({"addresses": [], "ips": []}),
                Some(Box::new(validate_bans)),
            ),
        }
    }

    /// `hex_address` is lowercase hex of the raw output address bytes.
    pub fn is_banned_address(&self, hex_address: &str) -> bool {
        self.contains("addresses", hex_address)
    }

    pub fn is_banned_ip(&self, ip: &str) -> bool {
        self.contains("ips", ip)
    }

    fn contains(&self, field: &str, needle: &str) -> bool {
        self.inner
            .get()
            .get(field)
            .and_then(Value::as_array)
            .is_some_and(|entries| entries.iter().any(|entry| entry.as_str() == Some(needle)))
    }
}

/// Accept only the exact shapes the hot path expects.
///
/// Keeping the last good document on a bad operator update is safer than
/// either failing every signing request or silently replacing the active bans
/// with an empty default.
pub fn validate_bans(value: &serde_json::Value) -> Result<(), String> {
    let document = value
        .as_object()
        .ok_or_else(|| "bans document must be an object".to_string())?;

    let addresses = document.get("addresses").and_then(Value::as_array);
    let ips = document.get("ips").and_then(Value::as_array);
    let (addresses, ips) = match (addresses, ips) {
        (Some(addresses), Some(ips)) => (addresses, ips),
        _ => return Err("bans document must contain 'addresses' and 'ips' lists".to_string()),
    };

    for address in addresses {
        if !address.as_str().is_some_and(is_lower_hex_bytes) {
            return Err(format!(
                "banned address must be lowercase hex output bytes: {}",
                py_repr(address)
            ));
        }
    }

    for address in ips {
        // A scope id is a local artefact that can never match a remote peer.
        let text = match address.as_str() {
            Some(text) if !text.contains('%') => text,
            _ => {
                return Err(format!(
                    "banned IP must be an unscoped address string: {}",
                    py_repr(address)
                ))
            }
        };
        // Python raises the "not in canonical form" ValueError inside the same
        // try that catches ValueError, so both a malformed address and a
        // non-canonical one surface as "banned IP is invalid". Reproduced.
        let canonical = IpAddr::from_str(text).is_ok_and(|parsed| parsed.to_string() == text);
        if !canonical {
            return Err(format!("banned IP is invalid: {}", py_repr(address)));
        }
    }

    Ok(())
}

/// Whole lowercase-hex bytes: Python's `(?:[0-9a-f]{2})+` fullmatch.
fn is_lower_hex_bytes(value: &str) -> bool {
    !value.is_empty()
        && value.len() % 2 == 0
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The rejection message is logged verbatim, and the Python original
/// interpolates `{value!r}`. Render the same way so operator logs match.
fn py_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => py_repr_str(text),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(py_repr).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(entries) => format!(
            "{{{}}}",
            entries
                .iter()
                .map(|(key, entry)| format!("{}: {}", py_repr_str(key), py_repr(entry)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn py_repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn err(value: serde_json::Value) -> String {
        validate_bans(&value).expect_err("expected rejection")
    }

    #[test]
    fn accepts_the_shipped_example_document() {
        let example = json!({
            "_comment": "operator notes are ignored",
            "addresses": ["70".to_string() + &"ab".repeat(28)],
            "ips": ["10.0.0.42", "2001:db8::1", "::1"],
        });
        assert_eq!(validate_bans(&example), Ok(()));
        assert_eq!(validate_bans(&json!({"addresses": [], "ips": []})), Ok(()));
    }

    #[test]
    fn rejects_non_object_document() {
        assert_eq!(
            err(json!(["wrong", "shape"])),
            "bans document must be an object"
        );
        assert_eq!(err(json!(null)), "bans document must be an object");
    }

    #[test]
    fn rejects_missing_or_non_list_fields() {
        let expected = "bans document must contain 'addresses' and 'ips' lists";
        assert_eq!(err(json!({"ips": []})), expected);
        assert_eq!(err(json!({"addresses": []})), expected);
        assert_eq!(err(json!({"addresses": {}, "ips": []})), expected);
        assert_eq!(err(json!({"addresses": [], "ips": "10.0.0.1"})), expected);
    }

    #[test]
    fn rejects_addresses_that_are_not_whole_lowercase_hex_bytes() {
        assert_eq!(
            err(json!({"addresses": ["AB"], "ips": []})),
            "banned address must be lowercase hex output bytes: 'AB'"
        );
        assert_eq!(
            err(json!({"addresses": ["abc"], "ips": []})),
            "banned address must be lowercase hex output bytes: 'abc'"
        );
        assert_eq!(
            err(json!({"addresses": [""], "ips": []})),
            "banned address must be lowercase hex output bytes: ''"
        );
        assert_eq!(
            err(json!({"addresses": [1], "ips": []})),
            "banned address must be lowercase hex output bytes: 1"
        );
        assert_eq!(
            err(json!({"addresses": [null], "ips": []})),
            "banned address must be lowercase hex output bytes: None"
        );
        assert_eq!(
            err(json!({"addresses": ["zz"], "ips": []})),
            "banned address must be lowercase hex output bytes: 'zz'"
        );
    }

    #[test]
    fn rejects_scoped_and_non_string_ips() {
        assert_eq!(
            err(json!({"addresses": [], "ips": ["fe80::1%eth0"]})),
            "banned IP must be an unscoped address string: 'fe80::1%eth0'"
        );
        assert_eq!(
            err(json!({"addresses": [], "ips": [true]})),
            "banned IP must be an unscoped address string: True"
        );
    }

    #[test]
    fn rejects_malformed_and_non_canonical_ips() {
        // Both paths surface the same message; see the note in validate_bans.
        assert_eq!(
            err(json!({"addresses": [], "ips": ["not-an-ip"]})),
            "banned IP is invalid: 'not-an-ip'"
        );
        assert_eq!(
            err(json!({"addresses": [], "ips": ["::01"]})),
            "banned IP is invalid: '::01'"
        );
        assert_eq!(
            err(json!({"addresses": [], "ips": ["127.000.000.1"]})),
            "banned IP is invalid: '127.000.000.1'"
        );
        assert_eq!(
            err(json!({"addresses": [], "ips": ["2001:DB8::1"]})),
            "banned IP is invalid: '2001:DB8::1'"
        );
    }

    #[test]
    fn membership_reads_the_file_and_survives_a_bad_update() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bans.json");
        let banned = "70".to_string() + &"ab".repeat(28);
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({"addresses": [banned], "ips": ["10.0.0.42"]}))
                .expect("encode"),
        )
        .expect("write");

        let bans = BanList::new(path.clone());
        assert!(bans.is_banned_ip("10.0.0.42"));
        assert!(!bans.is_banned_ip("10.0.0.99"));
        assert!(bans.is_banned_address(&("70".to_string() + &"ab".repeat(28))));
        assert!(!bans.is_banned_address(&"cd".repeat(29)));

        // An invalid operator update keeps the last good document live.
        let later = std::fs::metadata(&path)
            .expect("stat")
            .modified()
            .expect("mtime")
            + std::time::Duration::from_secs(1);
        std::fs::write(&path, br#"["wrong", "top-level", "shape"]"#).expect("write");
        let file = std::fs::File::options()
            .write(true)
            .open(&path)
            .expect("open");
        file.set_times(std::fs::FileTimes::new().set_modified(later))
            .expect("set_times");
        assert!(bans.is_banned_ip("10.0.0.42"));
    }

    #[test]
    fn missing_file_means_no_bans() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bans = BanList::new(dir.path().join("absent.json"));
        assert!(!bans.is_banned_ip("10.0.0.42"));
        assert!(!bans.is_banned_address(&"ab".repeat(29)));
    }

    #[test]
    fn py_repr_matches_python_quoting() {
        assert_eq!(py_repr(&json!("it's")), "\"it's\"");
        assert_eq!(py_repr(&json!("a\nb")), "'a\\nb'");
        assert_eq!(py_repr(&json!(["a"])), "['a']");
        assert_eq!(py_repr(&json!({"k": "v"})), "{'k': 'v'}");
    }
}
