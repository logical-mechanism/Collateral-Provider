//! Line-oriented CBOR decode probe, driven by `scripts/cbor_differential.py`.
//!
//! Reads one hex-encoded input per line on stdin and writes exactly one result
//! line per input on stdout, in a canonical rendering the Python driver
//! reproduces from `cbor2`'s decode of the same bytes:
//!
//! ```text
//! E:<variant>                     decode error
//! V:<consumed>:<canonical value>  decode success
//! ```
//!
//! Canonical value grammar (the Python side emits the same strings):
//!
//! ```text
//! int      i<decimal>
//! bigint   I<+|-><uppercase hex magnitude, no leading zeros>
//! bytes    b<lowercase hex>
//! text     t<lowercase hex of the UTF-8 bytes>
//! array    [v1,v2,...]
//! map      {k1:v1,k2:v2,...}
//! tag      T<n>(<value>)
//! atoms    f / t / n / u   (false / true / null / undefined)
//! simple   s<n>
//! float    F<16 hex chars of the f64 bit pattern>
//! ```
//!
//! Two deliberate quirks, both documented in `scripts/README.md`:
//!
//! * Maps are rendered with Python's duplicate-key collapse applied — first
//!   occurrence keeps its position, the last value wins — because `cbor2`
//!   builds a `dict` and cannot report wire order or duplicates. Wire-order
//!   fidelity is covered by non-differential tests instead.
//! * `true` and the empty text string both render as `t`, an ambiguity
//!   inherited from the agreed grammar. `tests/cbor_differential_fuzz.rs`
//!   pins those two cases directly so the blind spot cannot hide a bug.
//!
//! Run: `cargo run --release --example cbor_probe < inputs.txt > results.txt`

use std::fmt::Write as _;
use std::io::{self, BufRead, BufWriter, Write as _};

use collateral_provider::cbor::{decode_one, CborError, Value};

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = BufWriter::with_capacity(1 << 20, stdout.lock());

    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let hex = line.trim();
        if hex.is_empty() {
            writer.write_all(b"E:EmptyLine\n")?;
            continue;
        }
        match unhex(hex) {
            None => writer.write_all(b"E:BadHex\n")?,
            Some(bytes) => {
                let rendered = match decode_one(&bytes) {
                    Ok((value, consumed)) => {
                        let mut out = String::with_capacity(64);
                        let _ = write!(out, "V:{consumed}:");
                        render(&value, &mut out);
                        out
                    }
                    Err(error) => render_error(&error),
                };
                writer.write_all(rendered.as_bytes())?;
                writer.write_all(b"\n")?;
            }
        }
    }
    writer.flush()
}

fn unhex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

fn render_error(error: &CborError) -> String {
    match error {
        CborError::Truncated => "E:Truncated".to_owned(),
        CborError::Malformed(reason) => format!("E:Malformed({reason})"),
        CborError::InvalidUtf8 => "E:InvalidUtf8".to_owned(),
        CborError::DepthExceeded => "E:DepthExceeded".to_owned(),
        CborError::UnexpectedMajor { expected, found } => {
            format!("E:UnexpectedMajor({expected},{found})")
        }
    }
}

fn push_hex(bytes: &[u8], out: &mut String) {
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
}

/// Uppercase hex of a big-endian magnitude with leading zeros trimmed, so it
/// lines up with Python's `format(value, "X")`.
fn push_magnitude(bytes: &[u8], out: &mut String) {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02X}");
    }
    let trimmed = hex.trim_start_matches('0');
    out.push_str(if trimmed.is_empty() { "0" } else { trimmed });
}

fn render(value: &Value, out: &mut String) {
    match value {
        Value::Int(number) => {
            let _ = write!(out, "i{number}");
        }
        Value::BigInt {
            negative,
            magnitude,
        } => {
            out.push('I');
            out.push(if *negative { '-' } else { '+' });
            push_magnitude(magnitude, out);
        }
        Value::Bytes(bytes) => {
            out.push('b');
            push_hex(bytes, out);
        }
        Value::Text(text) => {
            out.push('t');
            push_hex(text.as_bytes(), out);
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                render(item, out);
            }
            out.push(']');
        }
        Value::Map(entries) => {
            // Reproduce Python's dict semantics: the first occurrence of a key
            // keeps its slot, the last occurrence supplies the value.
            let mut order: Vec<String> = Vec::with_capacity(entries.len());
            let mut values: Vec<String> = Vec::with_capacity(entries.len());
            for (key, entry_value) in entries {
                let mut key_rendered = String::new();
                render(key, &mut key_rendered);
                let mut value_rendered = String::new();
                render(entry_value, &mut value_rendered);
                match order.iter().position(|seen| *seen == key_rendered) {
                    Some(slot) => values[slot] = value_rendered,
                    None => {
                        order.push(key_rendered);
                        values.push(value_rendered);
                    }
                }
            }
            out.push('{');
            for (index, (key, entry_value)) in order.iter().zip(&values).enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(key);
                out.push(':');
                out.push_str(entry_value);
            }
            out.push('}');
        }
        Value::Tag(number, inner) => {
            let _ = write!(out, "T{number}(");
            render(inner, out);
            out.push(')');
        }
        Value::Bool(false) => out.push('f'),
        Value::Bool(true) => out.push('t'),
        Value::Null => out.push('n'),
        Value::Undefined => out.push('u'),
        Value::Simple(number) => {
            let _ = write!(out, "s{number}");
        }
        Value::Float(number) => {
            let _ = write!(out, "F{:016x}", number.to_bits());
        }
    }
}
