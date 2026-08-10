//! A small CBOR reader/writer with exact byte-span tracking.
//!
//! The service is byte-exact in two places that a general-purpose CBOR
//! library will not give us for free:
//!
//! 1. **Transaction hashing.** `signature::tx_id` must hash the body's exact
//!    byte slice as it appeared on the wire. Re-serializing a decoded body
//!    would change the transaction id whenever the client's encoding choices
//!    (definite vs indefinite lengths, integer widths, map-key order, set-tag
//!    presence) differ from ours.
//! 2. **Script-data-hash verification.** Body field 11 commits to the
//!    *original CBOR bytes* of the witness-set redeemers and datums. The
//!    ledger memoizes those bytes deliberately; re-encoding is not equivalent.
//!
//! So the decoder is a cursor: it hands back both the decoded [`Value`] and
//! the byte range it came from.
//!
//! Fidelity notes against Python's `cbor2`, which the port must match:
//! - A decoded map keeps insertion order *and* duplicates. Python builds a
//!   `dict`, so duplicate keys collapse last-wins; [`Value::map_get`]
//!   reproduces that by returning the last matching entry. Callers that must
//!   reject duplicates do so explicitly (see `script_integrity`).
//! - Bignum tags 2/3 decode to [`Value::Int`] when they fit `i128`, matching
//!   `cbor2`'s conversion to a Python `int`. Larger values become
//!   [`Value::BigInt`], which fails every `as_u64`-style check — the same
//!   outcome as Python's range checks.
//! - Unlike Python, the decoder enforces [`MAX_DEPTH`]. `cbor2` raises
//!   `RecursionError` on pathological nesting; an unbounded recursive Rust
//!   decoder would abort the process on stack overflow instead. Exceeding the
//!   limit is a decode error, which the validators surface as
//!   "Invalid CBOR Data In Tx".
//!
//! Places where this decoder is deliberately *stricter* than `cbor2`, all of
//! which turn an accepted-but-nonsensical value into a decode error:
//! - `cbor2.loads(b"\xff")` returns a break marker object; here a break with
//!   no open indefinite container is [`CborError::Malformed`].
//! - `cbor2` applies semantic decoders to tags (258 becomes a `set`, 0 a
//!   `datetime`, ...) and raises when the payload does not fit. Only the
//!   bignum tags are interpreted here; everything else stays a
//!   [`Value::Tag`] and is rejected by whichever validator inspects it. Same
//!   rejection, different message.
//! - A break in the value slot of an indefinite map is an error rather than a
//!   stored break marker.
//! - The one-byte simple-value form is rejected for arguments below 32
//!   (`f8 00`..`f8 1f`). RFC 8949 §3.3 declares those ill-formed because the
//!   values have a single-byte spelling; `cbor2` accepts them anyway. See
//!   [`decode_simple`].
//! - [`Value::map_get`] refuses to read a map that contains a non-integer key
//!   a Python `dict` would file in the requested integer's slot. See there.

use std::fmt;

/// Maximum container nesting the decoder will follow before failing.
///
/// A 16 KiB body of `9f9f9f...` is 16384 levels deep; without a cap that
/// overflows the stack. Real Cardano transactions nest single digits deep.
pub const MAX_DEPTH: usize = 256;

/// CBOR tag marking a canonicalized set in the Cardano body.
pub const SET_TAG: u64 = 258;

/// Break byte terminating an indefinite-length container.
const BREAK: u8 = 0xFF;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborError {
    /// Ran out of input mid-value.
    Truncated,
    /// A well-formedness violation (reserved additional-info, bad break, ...).
    Malformed(&'static str),
    /// Text string that is not valid UTF-8.
    InvalidUtf8,
    /// Nesting exceeded [`MAX_DEPTH`].
    DepthExceeded,
    /// Expected a specific major type and found another.
    UnexpectedMajor { expected: u8, found: u8 },
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CborError::Truncated => f.write_str("truncated CBOR"),
            CborError::Malformed(reason) => f.write_str(reason),
            CborError::InvalidUtf8 => f.write_str("error decoding unicode string"),
            CborError::DepthExceeded => f.write_str("maximum CBOR nesting depth exceeded"),
            CborError::UnexpectedMajor { expected, found } => {
                write!(f, "expected CBOR major type {expected}, got {found}")
            }
        }
    }
}

impl std::error::Error for CborError {}

/// A decoded CBOR value.
///
/// Floats are compared by bit pattern so the type can derive `Eq`; the
/// service never depends on float equality semantics.
#[derive(Debug, Clone)]
pub enum Value {
    /// Major types 0 and 1, plus bignum tags 2/3 that fit in `i128`.
    Int(i128),
    /// Bignum tags 2/3 whose magnitude exceeds `i128`.
    BigInt {
        negative: bool,
        magnitude: Vec<u8>,
    },
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Entries in wire order, duplicates preserved.
    Map(Vec<(Value, Value)>),
    Tag(u64, Box<Value>),
    Bool(bool),
    Null,
    Undefined,
    /// Simple values other than false/true/null/undefined.
    Simple(u8),
    Float(f64),
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => a == b,
            (
                Value::BigInt {
                    negative: a_neg,
                    magnitude: a_mag,
                },
                Value::BigInt {
                    negative: b_neg,
                    magnitude: b_mag,
                },
            ) => a_neg == b_neg && a_mag == b_mag,
            (Value::Bytes(a), Value::Bytes(b)) => a == b,
            (Value::Text(a), Value::Text(b)) => a == b,
            (Value::Array(a), Value::Array(b)) => a == b,
            (Value::Map(a), Value::Map(b)) => a == b,
            (Value::Tag(a_tag, a_val), Value::Tag(b_tag, b_val)) => {
                a_tag == b_tag && a_val == b_val
            }
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Null, Value::Null) => true,
            (Value::Undefined, Value::Undefined) => true,
            (Value::Simple(a), Value::Simple(b)) => a == b,
            // Bit-pattern comparison keeps `Eq` honest. NaN == NaN here, which
            // is never load-bearing: no Cardano field is a float.
            (Value::Float(a), Value::Float(b)) => a.to_bits() == b.to_bits(),
            _ => false,
        }
    }
}

impl Eq for Value {}

/// Consistent with the hand-written [`PartialEq`] above, so a [`Value`] can key
/// a `HashSet`. Two callers de-duplicate decoded values — `validators::cbor`
/// normalizing a Conway `set<T>` and `script_integrity` rejecting duplicate
/// transaction map keys — and both would otherwise be quadratic in an
/// attacker-chosen entry count.
///
/// Recursion is bounded by the decoder's `MAX_DEPTH`, so this cannot blow the
/// stack on a crafted payload.
impl std::hash::Hash for Value {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Value::Int(int) => int.hash(state),
            Value::BigInt {
                negative,
                magnitude,
            } => {
                negative.hash(state);
                magnitude.hash(state);
            }
            Value::Bytes(bytes) => bytes.hash(state),
            Value::Text(text) => text.hash(state),
            Value::Array(items) => {
                items.len().hash(state);
                for item in items {
                    item.hash(state);
                }
            }
            Value::Map(entries) => {
                entries.len().hash(state);
                for (key, entry) in entries {
                    key.hash(state);
                    entry.hash(state);
                }
            }
            Value::Tag(tag, inner) => {
                tag.hash(state);
                inner.hash(state);
            }
            Value::Bool(flag) => flag.hash(state),
            Value::Null | Value::Undefined => {}
            Value::Simple(simple) => simple.hash(state),
            // Matches the bit-pattern equality `PartialEq` uses above.
            Value::Float(float) => float.to_bits().hash(state),
        }
    }
}

impl Value {
    /// The integer value, if this is [`Value::Int`]. Booleans are never
    /// integers here, matching the Python guards that reject `bool`.
    pub fn as_int(&self) -> Option<i128> {
        match self {
            Value::Int(value) => Some(*value),
            _ => None,
        }
    }

    /// The value as a `u64`, if it is a non-negative integer in range.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Int(value) => u64::try_from(*value).ok(),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(entries) => Some(entries),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// Unwrap a tag with the given number, returning the inner value.
    pub fn as_tag(&self, tag: u64) -> Option<&Value> {
        match self {
            Value::Tag(number, inner) if *number == tag => Some(inner),
            _ => None,
        }
    }

    /// Look up an integer-keyed map entry, last-wins on duplicates.
    ///
    /// Python decodes the body into a `dict`, where a duplicate key silently
    /// overwrites the earlier one. Returning the *last* match reproduces that
    /// exactly.
    ///
    /// A Python `dict` also files keys that merely *compare* equal in the same
    /// slot — `False == 0`, `True == 1`, `1.0 == 1` — so a body carrying both
    /// `13` and `13.0` would be read as two different transactions by the two
    /// implementations. Rather than pick a winner, such a map is refused
    /// outright: the caller sees the field as absent and rejects the
    /// transaction. Valid Cardano bodies only ever use unsigned integer keys,
    /// so nothing legitimate is lost, and the ledger's own body decoder throws
    /// out a bool- or float-keyed body in phase 1 regardless.
    pub fn map_get(&self, key: i128) -> Option<&Value> {
        let entries = self.as_map()?;
        if entries
            .iter()
            .any(|(entry_key, _)| aliases_integer_key(entry_key, key))
        {
            return None;
        }
        entries
            .iter()
            .rev()
            .find(|(entry_key, _)| entry_key.as_int() == Some(key))
            .map(|(_, value)| value)
    }

    /// Whether an integer-keyed map entry exists. Mirrors `key in body`.
    pub fn map_contains(&self, key: i128) -> bool {
        self.map_get(key).is_some()
    }

    /// Index into a list-encoded (array) or map-encoded output.
    ///
    /// `utxo[0]` in Python works for both Shelley list-encoded outputs (0 is
    /// the address slot) and Babbage map-encoded outputs (0 is the address
    /// map key). This reproduces both.
    pub fn index_or_key(&self, index: i128) -> Option<&Value> {
        match self {
            // Python would treat a negative index as counting from the end;
            // no caller does that, so it is simply absent here.
            Value::Array(items) => items.get(usize::try_from(index).ok()?),
            Value::Map(_) => self.map_get(index),
            _ => None,
        }
    }
}

/// The argument carried by a CBOR head byte.
#[derive(Debug, Clone, Copy)]
enum Head {
    /// A definite argument: length, integer value, tag number, or float bits.
    Arg(u64),
    /// Additional info 31 — an indefinite-length container, or a break.
    Indefinite,
}

/// A position-tracking CBOR reader.
pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Decoder { data, pos: 0 }
    }

    /// Byte offset of the next unread byte.
    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos.min(self.data.len())..]
    }

    pub fn is_at_end(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Decode exactly one value, advancing the cursor past it.
    pub fn decode_value(&mut self) -> Result<Value, CborError> {
        self.decode_at(0)
    }

    /// Decode one value and also return the exact bytes it occupied.
    pub fn decode_value_raw(&mut self) -> Result<(Value, &'a [u8]), CborError> {
        let data = self.data;
        let start = self.pos;
        let value = self.decode_at(0)?;
        Ok((value, &data[start..self.pos]))
    }

    /// Skip exactly one value without materializing it.
    pub fn skip_value(&mut self) -> Result<&'a [u8], CborError> {
        let data = self.data;
        let start = self.pos;
        self.skip_at(0)?;
        Ok(&data[start..self.pos])
    }

    /// Read an array (major 4) or map (major 5) header and return its length,
    /// or `None` for the indefinite-length form. The cursor is left at the
    /// first item either way.
    pub fn container_header(&mut self, expected_major: u8) -> Result<Option<u64>, CborError> {
        // Read before checking the major type, so an empty buffer reports
        // truncation rather than a type mismatch (as the Python cursor does).
        let initial = self.read_byte()?;
        let major = initial >> 5;
        if major != expected_major {
            return Err(CborError::UnexpectedMajor {
                expected: expected_major,
                found: major,
            });
        }
        let info = initial & 0x1F;
        match info {
            0..=23 => Ok(Some(u64::from(info))),
            24 => Ok(Some(self.read_uint(1)?)),
            25 => Ok(Some(self.read_uint(2)?)),
            26 => Ok(Some(self.read_uint(4)?)),
            27 => Ok(Some(self.read_uint(8)?)),
            31 => Ok(None),
            _ => Err(CborError::Malformed("invalid CBOR container length")),
        }
    }

    /// Advance past any CBOR array header, definite or indefinite, without
    /// reading its items. Used by `signature::tx_id` to reach the body.
    pub fn skip_array_header(&mut self) -> Result<(), CborError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        if major != 4 {
            return Err(CborError::UnexpectedMajor {
                expected: 4,
                found: major,
            });
        }
        let info = initial & 0x1F;
        // Both the short form and 0x9f leave the cursor on the first item.
        if info < 24 || info == 31 {
            return Ok(());
        }
        let extra = match info {
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(CborError::Malformed("reserved CBOR array header info")),
        };
        self.read_slice(extra)?;
        Ok(())
    }

    pub fn at_break(&self) -> bool {
        self.data.get(self.pos) == Some(&BREAK)
    }

    pub fn consume_break(&mut self) -> Result<(), CborError> {
        if !self.at_break() {
            return Err(CborError::Malformed("missing CBOR break"));
        }
        self.pos += 1;
        Ok(())
    }

    // --- internals ---------------------------------------------------------

    fn read_byte(&mut self) -> Result<u8, CborError> {
        let byte = *self.data.get(self.pos).ok_or(CborError::Truncated)?;
        self.pos += 1;
        Ok(byte)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], CborError> {
        let data = self.data;
        let end = self.pos.checked_add(len).ok_or(CborError::Truncated)?;
        let slice = data.get(self.pos..end).ok_or(CborError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn read_uint(&mut self, len: usize) -> Result<u64, CborError> {
        let mut value = 0u64;
        for byte in self.read_slice(len)? {
            value = (value << 8) | u64::from(*byte);
        }
        Ok(value)
    }

    /// Read one head byte plus its argument, returning `(major, info, head)`.
    ///
    /// The raw `info` comes back too because major 7 needs the head *width*
    /// to tell a half float from a single or double.
    fn read_head(&mut self) -> Result<(u8, u8, Head), CborError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let info = initial & 0x1F;
        let head = match info {
            0..=23 => Head::Arg(u64::from(info)),
            24 => Head::Arg(self.read_uint(1)?),
            25 => Head::Arg(self.read_uint(2)?),
            26 => Head::Arg(self.read_uint(4)?),
            27 => Head::Arg(self.read_uint(8)?),
            31 => Head::Indefinite,
            _ => return Err(CborError::Malformed("reserved CBOR additional information")),
        };
        Ok((major, info, head))
    }

    /// A definite-length payload of `len` bytes, bounds-checked in `u64` so a
    /// 2^64-sized head cannot wrap on a 32-bit target.
    fn read_payload(&mut self, len: u64) -> Result<&'a [u8], CborError> {
        let len = usize::try_from(len).map_err(|_| CborError::Truncated)?;
        self.read_slice(len)
    }

    /// Walk the chunks of an indefinite-length string, handing each validated
    /// chunk to `on_chunk`.
    ///
    /// Every chunk must be a definite-length string of the same major type;
    /// text chunks are individually UTF-8 validated, which is what `cbor2`
    /// does when it decodes and joins them.
    ///
    /// Decoding and skipping share this walk so the two cannot drift on
    /// acceptance — skipping must reject exactly what decoding rejects.
    fn walk_string_chunks(
        &mut self,
        major: u8,
        mut on_chunk: impl FnMut(&'a [u8]),
    ) -> Result<(), CborError> {
        loop {
            if self.at_break() {
                self.pos += 1;
                return Ok(());
            }
            let (chunk_major, _, head) = self.read_head()?;
            if chunk_major != major {
                return Err(CborError::Malformed(
                    "invalid chunk in indefinite-length string",
                ));
            }
            let Head::Arg(len) = head else {
                return Err(CborError::Malformed(
                    "nested indefinite-length string chunk",
                ));
            };
            let chunk = self.read_payload(len)?;
            if major == 3 && std::str::from_utf8(chunk).is_err() {
                return Err(CborError::InvalidUtf8);
            }
            on_chunk(chunk);
        }
    }

    /// Concatenate the chunks of an indefinite-length string.
    fn read_string_chunks(&mut self, major: u8) -> Result<Vec<u8>, CborError> {
        let mut out = Vec::new();
        self.walk_string_chunks(major, |chunk| out.extend_from_slice(chunk))?;
        Ok(out)
    }

    /// Advance past an indefinite-length string without building it.
    fn skip_string_chunks(&mut self, major: u8) -> Result<(), CborError> {
        self.walk_string_chunks(major, |_| {})
    }

    fn depth_guard(depth: usize) -> Result<(), CborError> {
        if depth > MAX_DEPTH {
            // Worth a log line: legitimate Cardano transactions nest single
            // digits deep, so this only fires on a crafted payload.
            tracing::warn!(max_depth = MAX_DEPTH, "CBOR nesting depth exceeded");
            return Err(CborError::DepthExceeded);
        }
        Ok(())
    }

    fn decode_at(&mut self, depth: usize) -> Result<Value, CborError> {
        Self::depth_guard(depth)?;
        let (major, info, head) = self.read_head()?;
        match (major, head) {
            (0, Head::Arg(arg)) => Ok(Value::Int(i128::from(arg))),
            (1, Head::Arg(arg)) => Ok(Value::Int(-1 - i128::from(arg))),
            (2, Head::Arg(len)) => Ok(Value::Bytes(self.read_payload(len)?.to_vec())),
            (2, Head::Indefinite) => Ok(Value::Bytes(self.read_string_chunks(2)?)),
            (3, Head::Arg(len)) => {
                let raw = self.read_payload(len)?;
                let text = std::str::from_utf8(raw).map_err(|_| CborError::InvalidUtf8)?;
                Ok(Value::Text(text.to_owned()))
            }
            (3, Head::Indefinite) => {
                let raw = self.read_string_chunks(3)?;
                // Each chunk was validated; concatenating valid UTF-8 is valid.
                String::from_utf8(raw)
                    .map(Value::Text)
                    .map_err(|_| CborError::InvalidUtf8)
            }
            (4, Head::Arg(len)) => {
                // Never pre-allocate from the head: a 2^64 length would OOM
                // long before the input runs out.
                let mut items = Vec::new();
                for _ in 0..len {
                    items.push(self.decode_at(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            (4, Head::Indefinite) => {
                let mut items = Vec::new();
                while !self.at_break() {
                    items.push(self.decode_at(depth + 1)?);
                }
                self.pos += 1;
                Ok(Value::Array(items))
            }
            (5, Head::Arg(len)) => {
                let mut entries = Vec::new();
                for _ in 0..len {
                    let key = self.decode_at(depth + 1)?;
                    let value = self.decode_at(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            (5, Head::Indefinite) => {
                let mut entries = Vec::new();
                while !self.at_break() {
                    let key = self.decode_at(depth + 1)?;
                    // A break here lands in the value slot and errors out;
                    // cbor2 would store its break marker as the value.
                    let value = self.decode_at(depth + 1)?;
                    entries.push((key, value));
                }
                self.pos += 1;
                Ok(Value::Map(entries))
            }
            (6, Head::Arg(tag)) => {
                let inner = self.decode_at(depth + 1)?;
                apply_tag(tag, inner)
            }
            (7, Head::Arg(arg)) => decode_simple(info, arg),
            (7, Head::Indefinite) => Err(CborError::Malformed("unexpected CBOR break")),
            // Majors 0, 1 and 6 have no indefinite form.
            (_, Head::Indefinite) => Err(CborError::Malformed(
                "indefinite length is not valid for this CBOR major type",
            )),
            _ => Err(CborError::Malformed("invalid CBOR major type")),
        }
    }

    /// Traverse one value without building it, returning the major type of the
    /// value that was skipped.
    ///
    /// Acceptance *and the error reported* must match [`Decoder::decode_at`]
    /// exactly — `tx_id` slices the body span with this while Python slices it
    /// with a full `cbor2` decode, so anything one rejects the other must
    /// reject too, and the message a caller logs must not depend on which
    /// traversal happened to run.
    ///
    /// The returned major is what makes that possible for the bignum tags:
    /// [`apply_tag`] rejects a tag 2/3 payload that is not a byte string
    /// *after* decoding it, so this reports the payload's own error first and
    /// only then checks the payload's type.
    fn skip_at(&mut self, depth: usize) -> Result<u8, CborError> {
        Self::depth_guard(depth)?;
        let (major, info, head) = self.read_head()?;
        match (major, head) {
            (0 | 1, Head::Arg(_)) => Ok(major),
            (2, Head::Arg(len)) => {
                self.read_payload(len)?;
                Ok(major)
            }
            (3, Head::Arg(len)) => {
                let raw = self.read_payload(len)?;
                std::str::from_utf8(raw).map_err(|_| CborError::InvalidUtf8)?;
                Ok(major)
            }
            (2, Head::Indefinite) => self.skip_string_chunks(2).map(|()| major),
            (3, Head::Indefinite) => self.skip_string_chunks(3).map(|()| major),
            (4, Head::Arg(len)) => {
                for _ in 0..len {
                    self.skip_at(depth + 1)?;
                }
                Ok(major)
            }
            (4, Head::Indefinite) => {
                while !self.at_break() {
                    self.skip_at(depth + 1)?;
                }
                self.pos += 1;
                Ok(major)
            }
            (5, Head::Arg(len)) => {
                for _ in 0..len {
                    self.skip_at(depth + 1)?;
                    self.skip_at(depth + 1)?;
                }
                Ok(major)
            }
            (5, Head::Indefinite) => {
                while !self.at_break() {
                    self.skip_at(depth + 1)?;
                    self.skip_at(depth + 1)?;
                }
                self.pos += 1;
                Ok(major)
            }
            (6, Head::Arg(tag)) => {
                let payload_major = self.skip_at(depth + 1)?;
                // Mirrors `apply_tag`: only a byte string is a bignum payload.
                if (tag == 2 || tag == 3) && payload_major != 2 {
                    return Err(CborError::Malformed("invalid bignum value"));
                }
                Ok(major)
            }
            (7, Head::Arg(arg)) => decode_simple(info, arg).map(|_| major),
            (7, Head::Indefinite) => Err(CborError::Malformed("unexpected CBOR break")),
            (_, Head::Indefinite) => Err(CborError::Malformed(
                "indefinite length is not valid for this CBOR major type",
            )),
            _ => Err(CborError::Malformed("invalid CBOR major type")),
        }
    }
}

/// Major 7: simple values and floats, dispatched on the head width.
fn decode_simple(info: u8, arg: u64) -> Result<Value, CborError> {
    match info {
        20 => Ok(Value::Bool(false)),
        21 => Ok(Value::Bool(true)),
        22 => Ok(Value::Null),
        23 => Ok(Value::Undefined),
        0..=19 => Ok(Value::Simple(arg as u8)),
        // RFC 8949 §3.3: the one-byte form must not carry an argument below
        // 32, because those values have a single-byte spelling, and a decoder
        // has to treat `f8 00`..`f8 1f` as ill-formed. `cbor2` accepts them;
        // this rejects them. Rejecting is the fail-closed direction and costs
        // nothing — no Cardano transaction field is a major-7 simple value, so
        // the only inputs affected are hand-crafted ones.
        24 if arg >= 32 => Ok(Value::Simple(arg as u8)),
        24 => Err(CborError::Malformed("non-minimal CBOR simple value")),
        25 => Ok(Value::Float(f16_to_f64(arg as u16))),
        26 => Ok(Value::Float(f64::from(f32::from_bits(arg as u32)))),
        27 => Ok(Value::Float(f64::from_bits(arg))),
        _ => Err(CborError::Malformed("reserved CBOR simple value")),
    }
}

/// RFC 8949 appendix D half-precision conversion.
///
/// Infinities and NaNs are assembled bit for bit rather than routed through
/// `f64::NAN`, so a NaN payload survives the widening: the ten half-precision
/// significand bits move to the top of the double's 52-bit significand and the
/// quiet bit is set, which is what a hardware half-to-double conversion does
/// and what `cbor2` returns. Verified against `cbor2` for all 65 536 half
/// patterns (`half_floats_match_cbor2_bit_for_bit`).
fn f16_to_f64(bits: u16) -> f64 {
    let exponent = i32::from((bits >> 10) & 0x1F);
    let significand = u64::from(bits & 0x03FF);
    if exponent == 31 {
        let sign = u64::from(bits & 0x8000) << 48;
        let quiet = if significand == 0 { 0 } else { 1u64 << 51 };
        return f64::from_bits(sign | 0x7FF0_0000_0000_0000 | quiet | (significand << 42));
    }
    let mantissa = significand as f64;
    let magnitude = if exponent == 0 {
        mantissa * (-24f64).exp2()
    } else {
        (mantissa + 1024.0) * f64::from(exponent - 25).exp2()
    };
    if bits & 0x8000 != 0 {
        -magnitude
    } else {
        magnitude
    }
}

/// Whether a Python `dict` would file `candidate` in integer `key`'s slot even
/// though it is not a [`Value::Int`].
///
/// Only `bool` and `float` can do that: `hash(False) == hash(0)`,
/// `hash(True) == hash(1)` and `hash(1.0) == hash(1)`, and each compares equal
/// to its integer twin. Bignum keys are already normalized to [`Value::Int`]
/// by [`apply_tag`], so they need no special case here.
fn aliases_integer_key(candidate: &Value, key: i128) -> bool {
    match candidate {
        Value::Bool(flag) => key == i128::from(*flag),
        Value::Float(number) => {
            // Python compares int against float exactly. Range-check before
            // the cast, which saturates rather than wrapping and would
            // otherwise alias `i128::MAX` with 1e300.
            let limit = 127f64.exp2();
            number.is_finite()
                && number.fract() == 0.0
                && (-limit..limit).contains(number)
                && *number as i128 == key
        }
        _ => false,
    }
}

/// Interpret the bignum tags; every other tag is kept verbatim.
///
/// `cbor2` turns tags 2 and 3 into Python `int`s, so anything that fits
/// `i128` must land in [`Value::Int`] or integer-typed checks downstream
/// would behave differently between the two implementations.
fn apply_tag(tag: u64, inner: Value) -> Result<Value, CborError> {
    if tag != 2 && tag != 3 {
        return Ok(Value::Tag(tag, Box::new(inner)));
    }
    let Value::Bytes(magnitude) = inner else {
        return Err(CborError::Malformed("invalid bignum value"));
    };
    let leading = magnitude
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(magnitude.len());
    let stripped = &magnitude[leading..];
    if stripped.len() <= 16 {
        let mut buffer = [0u8; 16];
        buffer[16 - stripped.len()..].copy_from_slice(stripped);
        let value = u128::from_be_bytes(buffer);
        // Tag 3 is -1 - magnitude, so both tags fit exactly when the
        // magnitude is at most i128::MAX (tag 3 then reaches i128::MIN).
        if value <= i128::MAX as u128 {
            let value = value as i128;
            return Ok(Value::Int(if tag == 2 { value } else { -1 - value }));
        }
    }
    Ok(Value::BigInt {
        negative: tag == 3,
        magnitude: stripped.to_vec(),
    })
}

/// Decode a single value from the front of `data`, returning it and the
/// number of bytes consumed.
pub fn decode_one(data: &[u8]) -> Result<(Value, usize), CborError> {
    let mut decoder = Decoder::new(data);
    let value = decoder.decode_value()?;
    Ok((value, decoder.position()))
}

/// Decode exactly one value that must consume all of `data`.
pub fn decode_exact(data: &[u8]) -> Result<Value, CborError> {
    let (value, consumed) = decode_one(data)?;
    if consumed != data.len() {
        return Err(CborError::Malformed("trailing CBOR data"));
    }
    Ok(value)
}

// --- Hex ------------------------------------------------------------------

/// `bytes.fromhex` semantics: both digit cases are accepted and ASCII
/// whitespace is skipped, but only *between* complete byte pairs — Python
/// rejects `"a cab"` while accepting `"ac ab"`. Returns `None` on anything
/// `bytes.fromhex` would raise `ValueError` for.
///
/// Every hex-to-CBOR conversion in this crate goes through here rather than
/// `hex::decode`, which rejects the whitespace Python accepts. A request the
/// Django service signs must not be refused by this one over the same bytes,
/// and the only way to keep that true is to have a single decoder.
pub fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let raw = text.as_bytes();
    let mut out = Vec::with_capacity(raw.len() / 2);
    let mut index = 0;
    while index < raw.len() {
        if is_ascii_space(raw[index]) {
            index += 1;
            continue;
        }
        let high = hex_digit(raw[index])?;
        let low = raw.get(index + 1).copied().and_then(hex_digit)?;
        out.push((high << 4) | low);
        index += 2;
    }
    Some(out)
}

/// CPython's `Py_ISSPACE`, which includes the vertical tab that Rust's
/// `is_ascii_whitespace` leaves out.
fn is_ascii_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// --- Encoding -------------------------------------------------------------
//
// Only the shapes the service emits. Every encoder uses the minimal-length
// head, which is what `cbor2.dumps` produces for these types, so the language
// views and witness bytes match the Python implementation byte for byte.

/// Encode an unsigned integer (major type 0) with a minimal head.
pub fn encode_uint(value: u64) -> Vec<u8> {
    encode_head(0, value)
}

/// Encode a signed integer, choosing major type 0 or 1 with a minimal head.
/// Matches `cbor2.dumps(<int>)`.
pub fn encode_int(value: i64) -> Vec<u8> {
    if value >= 0 {
        encode_head(0, value as u64)
    } else {
        // -1 - value stays in range for i64::MIN because it is computed in
        // i128 before narrowing.
        encode_head(1, (-1 - i128::from(value)) as u64)
    }
}

/// Encode a definite-length byte string. Matches `cbor2.dumps(<bytes>)`.
pub fn encode_bytes(value: &[u8]) -> Vec<u8> {
    let mut out = encode_head(2, value.len() as u64);
    out.extend_from_slice(value);
    out
}

/// Encode a definite-length array from already-encoded items.
/// Matches `cbor2.dumps([...])` for a list of already-encoded elements.
pub fn encode_array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = encode_head(4, items.len() as u64);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// Encode a definite-length head for `major` with the given argument.
///
/// `major` must be 0..=7. The mask below keeps a release build from emitting a
/// head for a *different* major type when it is not, but that would still be a
/// caller bug, so debug builds and the test suite abort instead.
pub fn encode_head(major: u8, argument: u64) -> Vec<u8> {
    debug_assert!(major < 8, "CBOR major type out of range: {major}");
    let major = (major & 0x07) << 5;
    let mut out = Vec::with_capacity(9);
    if argument < 24 {
        out.push(major | argument as u8);
    } else if argument <= u64::from(u8::MAX) {
        out.push(major | 24);
        out.push(argument as u8);
    } else if argument <= u64::from(u16::MAX) {
        out.push(major | 25);
        out.extend_from_slice(&(argument as u16).to_be_bytes());
    } else if argument <= u64::from(u32::MAX) {
        out.push(major | 26);
        out.extend_from_slice(&(argument as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&argument.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real mainnet transaction that the chain accepted, from
    /// `api/tests/test_signature.py`. Its body occupies bytes 1..295 and the
    /// witness set 295..402 — the spans `tx_id` and `script_integrity` slice.
    const REAL_TX: &str = "84a300d9010281825820613ef2c284082d666d6a9b0b309437b10d1099eaca46134f77828294ad21347600018282581d60fdd320cd9c529f021452b5b39eb3a6d854f3d1d59c329d2ed1b803951a0be79cc9a300581d60fdd320cd9c529f021452b5b39eb3a6d854f3d1d59c329d2ed1b80395011a001822ca03d81858a38203589f589d010100332229800ab9cab9a9bae0039bae0024888966002a66008921104920616c77617973206661696c203a2f00168a4d15330044911856616c696461746f722072657475726e65642066616c73650013656400c4c11e581c21b5bcf6f42eeac1b00121579e1a490134b08510120be94b5c3a0c86004c0122582000e4d20dca46f31c227666ee477770304a4f805cb2e00a4e379d243fbbc0c9d10001021a0003bf3ba100d90102818258207668cfa9f6d2de5b4b86de0dc291f26574c93a9e57bd7e6a634fdb85fe19518458401bf79ba1e08f6e1546f58f82ab04991924acfd45323656f24a390b34d232e6319657187872e55d8751a51c31390b621a60ce868a3957050bab5325581d947f0ef5f6";

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("test vector is hex"))
            .collect()
    }

    fn decode(hex: &str) -> Result<Value, CborError> {
        decode_exact(&unhex(hex))
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // --- integers ----------------------------------------------------------

    #[test]
    fn unsigned_head_widths() {
        for (hex, expected) in [
            ("00", 0i128),
            ("17", 23),
            ("1818", 24),
            ("18ff", 255),
            ("190100", 256),
            ("19ffff", 65535),
            ("1a00010000", 65536),
            ("1affffffff", 4294967295),
            ("1b0000000100000000", 4294967296),
            ("1bffffffffffffffff", u64::MAX as i128),
        ] {
            assert_eq!(decode(hex), Ok(Value::Int(expected)), "{hex}");
        }
    }

    #[test]
    fn negative_head_widths() {
        for (hex, expected) in [
            ("20", -1i128),
            ("37", -24),
            ("3818", -25),
            ("38ff", -256),
            ("390100", -257),
            ("39ffff", -65536),
            ("3a00010000", -65537),
            ("3b7fffffffffffffff", i64::MIN as i128),
            ("3bffffffffffffffff", -(u64::MAX as i128) - 1),
        ] {
            assert_eq!(decode(hex), Ok(Value::Int(expected)), "{hex}");
        }
    }

    #[test]
    fn booleans_are_not_integers() {
        assert_eq!(decode("f5"), Ok(Value::Bool(true)));
        assert_eq!(decode("f4"), Ok(Value::Bool(false)));
        assert_eq!(Value::Bool(true).as_int(), None);
        assert_eq!(Value::Bool(true).as_u64(), None);
        assert_eq!(Value::Bool(false).as_int(), None);
    }

    #[test]
    fn as_u64_rejects_negative_and_bignum() {
        assert_eq!(Value::Int(-1).as_u64(), None);
        assert_eq!(Value::Int(7).as_u64(), Some(7));
        let big = Value::BigInt {
            negative: false,
            magnitude: vec![1; 17],
        };
        assert_eq!(big.as_u64(), None);
        assert_eq!(big.as_int(), None);
    }

    // --- bignums -----------------------------------------------------------

    #[test]
    fn bignums_that_fit_become_ints() {
        // cbor2: c249010000000000000000 -> 18446744073709551616
        assert_eq!(
            decode("c249010000000000000000"),
            Ok(Value::Int(18446744073709551616))
        );
        // cbor2: c349010000000000000000 -> -18446744073709551617
        assert_eq!(
            decode("c349010000000000000000"),
            Ok(Value::Int(-18446744073709551617))
        );
        assert_eq!(decode("c240"), Ok(Value::Int(0)));
        assert_eq!(decode("c340"), Ok(Value::Int(-1)));
        // Leading zeros do not change the value.
        assert_eq!(decode("c243000001"), Ok(Value::Int(1)));
    }

    #[test]
    fn bignum_boundaries_at_i128_limits() {
        let max = i128::MAX.to_be_bytes();
        assert_eq!(
            decode(&format!("c250{}", hex_of(&max))),
            Ok(Value::Int(i128::MAX))
        );
        // Tag 3 with magnitude i128::MAX is exactly i128::MIN.
        assert_eq!(
            decode(&format!("c350{}", hex_of(&max))),
            Ok(Value::Int(i128::MIN))
        );
        // 2^127 overflows tag 2 by one and tag 3's magnitude by one.
        let over = unhex("80000000000000000000000000000000");
        assert_eq!(
            decode(&format!("c250{}", hex_of(&over))),
            Ok(Value::BigInt {
                negative: false,
                magnitude: over.clone()
            })
        );
        assert_eq!(
            decode(&format!("c350{}", hex_of(&over))),
            Ok(Value::BigInt {
                negative: true,
                magnitude: over
            })
        );
    }

    #[test]
    fn bignum_payload_must_be_bytes() {
        assert_eq!(
            decode("c201"),
            Err(CborError::Malformed("invalid bignum value"))
        );
        assert_eq!(
            decode("c301"),
            Err(CborError::Malformed("invalid bignum value"))
        );
        // An indefinite byte string is still a byte string.
        assert_eq!(decode("c25f4101ff"), Ok(Value::Int(1)));
    }

    // --- strings -----------------------------------------------------------

    #[test]
    fn byte_and_text_strings() {
        assert_eq!(decode("40"), Ok(Value::Bytes(vec![])));
        assert_eq!(decode("43010203"), Ok(Value::Bytes(vec![1, 2, 3])));
        assert_eq!(decode("60"), Ok(Value::Text(String::new())));
        assert_eq!(decode("63616263"), Ok(Value::Text("abc".to_owned())));
    }

    #[test]
    fn indefinite_strings_concatenate_chunks() {
        assert_eq!(decode("5f41014102ff"), Ok(Value::Bytes(vec![1, 2])));
        assert_eq!(decode("5fff"), Ok(Value::Bytes(vec![])));
        // cbor2: 7f62616163626364ff -> "aabcd"
        assert_eq!(
            decode("7f62616163626364ff"),
            Ok(Value::Text("aabcd".to_owned()))
        );
    }

    #[test]
    fn indefinite_string_chunks_must_match_major_type() {
        assert_eq!(
            decode("5f0102ff"),
            Err(CborError::Malformed(
                "invalid chunk in indefinite-length string"
            ))
        );
        assert_eq!(
            decode("7f4101ff"),
            Err(CborError::Malformed(
                "invalid chunk in indefinite-length string"
            ))
        );
        assert_eq!(
            decode("5f5f4101ffff"),
            Err(CborError::Malformed(
                "nested indefinite-length string chunk"
            ))
        );
    }

    #[test]
    fn invalid_utf8_is_rejected() {
        // cbor2: 62c328 -> CBORDecodeValueError
        assert_eq!(decode("62c328"), Err(CborError::InvalidUtf8));
        // Each indefinite chunk must be valid UTF-8 on its own, so a
        // multi-byte sequence split across two chunks is rejected — cbor2
        // decodes and joins chunk by chunk and fails the same way.
        assert_eq!(decode("7f61c361a8ff"), Err(CborError::InvalidUtf8));
        assert_eq!(decode("7f62c3a8ff"), Ok(Value::Text("è".to_owned())));
        // Valid multi-byte UTF-8 still decodes.
        assert_eq!(decode("62c3a9"), Ok(Value::Text("é".to_owned())));
    }

    // --- containers --------------------------------------------------------

    #[test]
    fn arrays_and_maps_definite_and_indefinite() {
        assert_eq!(decode("80"), Ok(Value::Array(vec![])));
        assert_eq!(
            decode("83010203"),
            Ok(Value::Array(vec![
                Value::Int(1),
                Value::Int(2),
                Value::Int(3)
            ]))
        );
        assert_eq!(
            decode("9f010203ff"),
            Ok(Value::Array(vec![
                Value::Int(1),
                Value::Int(2),
                Value::Int(3)
            ]))
        );
        assert_eq!(decode("a0"), Ok(Value::Map(vec![])));
        assert_eq!(
            decode("a201020304"),
            Ok(Value::Map(vec![
                (Value::Int(1), Value::Int(2)),
                (Value::Int(3), Value::Int(4)),
            ]))
        );
        assert_eq!(
            decode("bf0102ff"),
            Ok(Value::Map(vec![(Value::Int(1), Value::Int(2))]))
        );
        // Nested indefinite inside definite.
        assert_eq!(
            decode("819f01ff"),
            Ok(Value::Array(vec![Value::Array(vec![Value::Int(1)])]))
        );
    }

    #[test]
    fn duplicate_map_keys_are_kept_but_read_last_wins() {
        // cbor2: a201020103 -> {1: 3}
        let value = decode("a201020103").expect("decodes");
        assert_eq!(value.as_map().map(<[_]>::len), Some(2));
        assert_eq!(value.map_get(1), Some(&Value::Int(3)));
        assert!(value.map_contains(1));
        assert!(!value.map_contains(2));
        assert_eq!(value.map_get(9), None);
    }

    #[test]
    fn boolean_map_keys_never_match_integers() {
        // Python would read `body[1]` out of {True: ...}; we do not.
        let value = decode("a1f501").expect("decodes");
        assert_eq!(value.map_get(1), None);
        assert!(!value.map_contains(1));
        let value = decode("a1f401").expect("decodes");
        assert_eq!(value.map_get(0), None);
    }

    /// A Python `dict` files `True`, `1` and `1.0` in one slot, so a map
    /// carrying two of them is read differently by the two implementations.
    /// `map_get` refuses to read such a map rather than pick a winner.
    #[test]
    fn map_get_refuses_a_key_a_python_dict_would_alias() {
        // {1: 2, true: 3}: Python answers 3, the old Rust code answered 2.
        let value = decode("a20102f503").expect("decodes");
        assert_eq!(value.map_get(1), None);
        assert!(!value.map_contains(1));
        // Both entries are still on the wire; only the lookup refuses.
        assert_eq!(value.as_map().map(<[_]>::len), Some(2));
        // Order does not matter.
        assert_eq!(decode("a2f5030102").expect("decodes").map_get(1), None);
        // {0: 2, 0.0: 3}, the float form of the same collision.
        let float_keyed = decode("a20002fb000000000000000003").expect("decodes");
        assert_eq!(float_keyed.map_get(0), None);
        // -0.0 hashes and compares equal to 0 in Python too.
        assert_eq!(decode("a20002f9800003").expect("decodes").map_get(0), None);
        // A non-integral float shares no slot with any integer.
        let fractional = decode("a20002fb3ff000000000000103").expect("decodes");
        assert_eq!(fractional.map_get(0), Some(&Value::Int(2)));
        // A float that collides with a *different* integer leaves this one
        // readable: only the requested key's slot matters.
        let other_slot = decode("a20002fb3ff000000000000003").expect("decodes");
        assert_eq!(other_slot.map_get(0), Some(&Value::Int(2)));
        assert_eq!(other_slot.map_get(1), None);
        // {i128::MAX: 5, 1e300: 6}. `1e300 as i128` saturates to i128::MAX, so
        // an unguarded cast would wrongly call this an alias and refuse a
        // perfectly readable key.
        let huge = decode("a2c2507fffffffffffffffffffffffffffffff05fb7e37e43c8800759c06")
            .expect("decodes");
        assert_eq!(huge.map_get(i128::MAX), Some(&Value::Int(5)));
    }

    #[test]
    fn index_or_key_covers_both_output_encodings() {
        // Shelley list-encoded output.
        let shelley = decode("8243aabbcc01").expect("decodes");
        assert_eq!(
            shelley.index_or_key(0),
            Some(&Value::Bytes(vec![0xaa, 0xbb, 0xcc]))
        );
        assert_eq!(shelley.index_or_key(2), None);
        assert_eq!(shelley.index_or_key(-1), None);
        // Babbage map-encoded output.
        let babbage = decode("a20043aabbcc0101").expect("decodes");
        assert_eq!(
            babbage.index_or_key(0),
            Some(&Value::Bytes(vec![0xaa, 0xbb, 0xcc]))
        );
        assert_eq!(babbage.index_or_key(7), None);
        assert_eq!(Value::Int(1).index_or_key(0), None);
    }

    // --- tags --------------------------------------------------------------

    #[test]
    fn tags_are_preserved() {
        assert_eq!(
            decode("d9010283010203"),
            Ok(Value::Tag(
                SET_TAG,
                Box::new(Value::Array(vec![
                    Value::Int(1),
                    Value::Int(2),
                    Value::Int(3)
                ]))
            ))
        );
        // cbor2 would raise here (a set cannot be built from an int); we defer
        // the rejection to the validator, which reports "Inputs Are Not A Set".
        assert_eq!(
            decode("d9010201"),
            Ok(Value::Tag(SET_TAG, Box::new(Value::Int(1))))
        );
        assert_eq!(
            decode("d818450102030405"),
            Ok(Value::Tag(24, Box::new(Value::Bytes(vec![1, 2, 3, 4, 5]))))
        );
        let nested = decode("d8d8d8d901").expect("nested tags decode");
        assert_eq!(
            nested.as_tag(216).and_then(|v| v.as_tag(217)),
            Some(&Value::Int(1))
        );
        assert_eq!(nested.as_tag(1), None);
    }

    #[test]
    fn tag_258_set_with_duplicates_keeps_wire_order() {
        // cbor2 collapses this to {1}; validators::cbor::set_items does the
        // de-duplication in the port, so the decoder keeps both entries.
        assert_eq!(
            decode("d90102820101"),
            Ok(Value::Tag(
                SET_TAG,
                Box::new(Value::Array(vec![Value::Int(1), Value::Int(1)]))
            ))
        );
    }

    #[test]
    fn tags_have_no_indefinite_form() {
        assert_eq!(
            decode("df01"),
            Err(CborError::Malformed(
                "indefinite length is not valid for this CBOR major type"
            ))
        );
    }

    // --- simple values and floats -----------------------------------------

    #[test]
    fn simple_values_and_floats() {
        assert_eq!(decode("f4"), Ok(Value::Bool(false)));
        assert_eq!(decode("f5"), Ok(Value::Bool(true)));
        assert_eq!(decode("f6"), Ok(Value::Null));
        assert_eq!(decode("f7"), Ok(Value::Undefined));
        assert_eq!(decode("e0"), Ok(Value::Simple(0)));
        assert_eq!(decode("f0"), Ok(Value::Simple(16)));
        // The one-byte form is only well-formed from 32 up (RFC 8949 §3.3).
        // cbor2 accepts `f800`; this decoder does not.
        assert_eq!(
            decode("f800"),
            Err(CborError::Malformed("non-minimal CBOR simple value"))
        );
        assert_eq!(decode("f820"), Ok(Value::Simple(32)));
        assert_eq!(decode("f8ff"), Ok(Value::Simple(255)));
        assert_eq!(decode("f93c00"), Ok(Value::Float(1.0)));
        assert_eq!(decode("f90000"), Ok(Value::Float(0.0)));
        assert_eq!(decode("f98000"), Ok(Value::Float(-0.0)));
        assert_eq!(decode("f93e00"), Ok(Value::Float(1.5)));
        assert_eq!(decode("f90001"), Ok(Value::Float(5.960464477539063e-8)));
        assert_eq!(decode("f97c00"), Ok(Value::Float(f64::INFINITY)));
        assert_eq!(decode("f9fc00"), Ok(Value::Float(f64::NEG_INFINITY)));
        assert_eq!(decode("fa47c35000"), Ok(Value::Float(100000.0)));
        assert_eq!(decode("fb3ff199999999999a"), Ok(Value::Float(1.1)));
        assert!(matches!(decode("f97e00"), Ok(Value::Float(f)) if f.is_nan()));
    }

    /// RFC 8949 §3.3 forbids the one-byte simple-value form below 32. `cbor2`
    /// accepts it; this decoder rejects it, and `skip_value` must reject it
    /// identically or the signing path and the validators would disagree about
    /// the same bytes.
    #[test]
    fn one_byte_simple_values_below_32_are_ill_formed() {
        for argument in 0u8..32 {
            let hex = format!("f8{argument:02x}");
            let data = unhex(&hex);
            assert_eq!(
                Decoder::new(&data).decode_value(),
                Err(CborError::Malformed("non-minimal CBOR simple value")),
                "{hex}: decode"
            );
            assert_eq!(
                Decoder::new(&data).skip_value(),
                Err(CborError::Malformed("non-minimal CBOR simple value")),
                "{hex}: skip"
            );
        }
        // 32 and up are the well-formed side of the boundary.
        for argument in 32u8..=u8::MAX {
            let hex = format!("f8{argument:02x}");
            assert_eq!(decode(&hex), Ok(Value::Simple(argument)), "{hex}");
        }
        // The inline spellings are untouched.
        assert_eq!(decode("e0"), Ok(Value::Simple(0)));
        assert_eq!(decode("f3"), Ok(Value::Simple(19)));
    }

    /// Half-precision NaN payloads are carried into the double instead of
    /// being flattened to `f64::NAN`. Every expectation here is what `cbor2`
    /// returns for the same bytes.
    #[test]
    fn half_float_nan_payloads_survive_the_widening() {
        for (hex, bits) in [
            // Signalling NaN, payload 1: the payload moves to the top of the
            // significand and the quiet bit is set.
            ("f97c01", 0x7ff8_0400_0000_0000u64),
            ("f9fc01", 0xfff8_0400_0000_0000),
            // Quiet NaN with no payload, the canonical one.
            ("f97e00", 0x7ff8_0000_0000_0000),
            ("f9fe00", 0xfff8_0000_0000_0000),
            // Largest payload.
            ("f97fff", 0x7fff_fc00_0000_0000),
            // Infinities keep working.
            ("f97c00", 0x7ff0_0000_0000_0000),
            ("f9fc00", 0xfff0_0000_0000_0000),
        ] {
            let Ok(Value::Float(float)) = decode(hex) else {
                panic!("{hex} did not decode to a float");
            };
            assert_eq!(float.to_bits(), bits, "{hex}");
        }
        // f32 and f64 NaN payloads were already preserved; keep them pinned.
        let Ok(Value::Float(single)) = decode("fa7fc00001") else {
            panic!("f32 NaN did not decode to a float");
        };
        assert_eq!(single.to_bits(), 0x7ff8_0000_2000_0000);
        let Ok(Value::Float(double)) = decode("fb7ff8000000000001") else {
            panic!("f64 NaN did not decode to a float");
        };
        assert_eq!(double.to_bits(), 0x7ff8_0000_0000_0001);
    }

    #[test]
    fn float_equality_is_by_bit_pattern() {
        assert_eq!(Value::Float(f64::NAN), Value::Float(f64::NAN));
        assert_ne!(Value::Float(0.0), Value::Float(-0.0));
        assert_ne!(Value::Float(1.0), Value::Int(1));
    }

    // --- well-formedness ---------------------------------------------------

    #[test]
    fn reserved_additional_info_is_rejected() {
        for hex in [
            "1c", "1d", "1e", "3c", "5c", "7c", "9c", "bc", "dc", "fc", "fd", "fe",
        ] {
            assert!(
                matches!(decode(hex), Err(CborError::Malformed(_))),
                "{hex} should be malformed, got {:?}",
                decode(hex)
            );
        }
    }

    #[test]
    fn indefinite_is_rejected_where_the_major_type_forbids_it() {
        for hex in ["1f", "3f"] {
            assert_eq!(
                decode(hex),
                Err(CborError::Malformed(
                    "indefinite length is not valid for this CBOR major type"
                )),
                "{hex}"
            );
        }
    }

    #[test]
    fn stray_break_is_rejected() {
        // cbor2 hands back a break marker object; we refuse.
        assert_eq!(
            decode("ff"),
            Err(CborError::Malformed("unexpected CBOR break"))
        );
        assert_eq!(
            decode("8201ff"),
            Err(CborError::Malformed("unexpected CBOR break"))
        );
        // Break in the value slot of an indefinite map.
        assert_eq!(
            decode("bf01ff"),
            Err(CborError::Malformed("unexpected CBOR break"))
        );
    }

    #[test]
    fn truncated_input_is_reported() {
        for hex in [
            "",
            "18",
            "19ff",
            "1a0000",
            "1b00000000000000",
            "430102",
            "830102",
            "9f0102",
            "a20102",
            "bf0102",
            "c2",
            "5f4101",
            "f8",
        ] {
            assert_eq!(decode(hex), Err(CborError::Truncated), "{hex}");
        }
    }

    #[test]
    fn oversized_length_head_is_truncation_not_allocation() {
        // 2^64-1 byte string: must fail on bounds, not try to allocate.
        assert_eq!(decode("5bffffffffffffffff"), Err(CborError::Truncated));
        assert_eq!(decode("9bffffffffffffffff00"), Err(CborError::Truncated));
    }

    #[test]
    fn trailing_data_after_a_complete_value() {
        assert_eq!(
            decode("0000"),
            Err(CborError::Malformed("trailing CBOR data"))
        );
        let (value, consumed) = decode_one(&unhex("0001")).expect("first value decodes");
        assert_eq!(value, Value::Int(0));
        assert_eq!(consumed, 1);
    }

    // --- depth -------------------------------------------------------------

    #[test]
    fn nesting_at_the_limit_is_accepted() {
        let mut bytes = vec![0x9f; MAX_DEPTH];
        bytes.push(0x01);
        bytes.extend(std::iter::repeat_n(BREAK, MAX_DEPTH));
        assert!(decode_exact(&bytes).is_ok());
    }

    #[test]
    fn nesting_past_the_limit_is_an_error_not_a_stack_overflow() {
        let mut bytes = vec![0x9f; MAX_DEPTH + 1];
        bytes.push(0x01);
        bytes.extend(std::iter::repeat_n(BREAK, MAX_DEPTH + 1));
        assert_eq!(decode_exact(&bytes), Err(CborError::DepthExceeded));

        // The shape that motivates the cap: a 16 KiB body of array headers.
        let bomb = vec![0x9f; 16 * 1024];
        assert_eq!(decode_one(&bomb), Err(CborError::DepthExceeded));
        assert_eq!(
            Decoder::new(&bomb).skip_value(),
            Err(CborError::DepthExceeded)
        );

        // Tag chains recurse too, so they must be counted.
        let tags = vec![0xc6; 16 * 1024];
        assert_eq!(decode_one(&tags), Err(CborError::DepthExceeded));
        assert_eq!(
            Decoder::new(&tags).skip_value(),
            Err(CborError::DepthExceeded)
        );
    }

    // --- byte spans --------------------------------------------------------

    #[test]
    fn decode_value_raw_returns_the_exact_subslice() {
        let data = unhex("83010203");
        let mut decoder = Decoder::new(&data);
        decoder.container_header(4).expect("array header");
        for expected in ["01", "02", "03"] {
            let (_, raw) = decoder.decode_value_raw().expect("item decodes");
            assert_eq!(hex_of(raw), expected);
        }
        assert!(decoder.is_at_end());
    }

    #[test]
    fn raw_spans_survive_indefinite_and_nested_values() {
        // A witness-set-shaped map: {5: <indefinite redeemers>, 4: <datums>}
        let redeemers = "9f9f0000d87980820a14ffff";
        let datums = "81d8799f01ff";
        let data = unhex(&format!("a205{redeemers}04{datums}"));
        let mut decoder = Decoder::new(&data);
        assert_eq!(decoder.container_header(5), Ok(Some(2)));

        assert_eq!(decoder.decode_value(), Ok(Value::Int(5)));
        let (_, raw) = decoder.decode_value_raw().expect("redeemers decode");
        assert_eq!(hex_of(raw), redeemers);

        assert_eq!(decoder.decode_value(), Ok(Value::Int(4)));
        let (_, raw) = decoder.decode_value_raw().expect("datums decode");
        assert_eq!(hex_of(raw), datums);
        assert!(decoder.is_at_end());
    }

    #[test]
    fn skip_value_returns_the_same_span_as_decode() {
        for hex in [
            "00",
            "1bffffffffffffffff",
            "43010203",
            "5f41014102ff",
            "63616263",
            "7f62616163626364ff",
            "83010203",
            "9f01ff",
            "a201020304",
            "bf0102ff",
            "d9010283010203",
            "c249010000000000000000",
            "f93c00",
            "fb3ff199999999999a",
            REAL_TX,
        ] {
            let data = unhex(hex);
            let mut skipper = Decoder::new(&data);
            let skipped = skipper.skip_value().expect("skip succeeds");
            let mut reader = Decoder::new(&data);
            let (_, raw) = reader.decode_value_raw().expect("decode succeeds");
            assert_eq!(skipped, raw, "{hex}");
            assert_eq!(skipper.position(), reader.position(), "{hex}");
        }
    }

    #[test]
    fn skip_and_decode_agree_on_rejection() {
        for hex in [
            "",
            "ff",
            "1c",
            "fc",
            "df01",
            "62c328",
            "7f4101ff",
            "c201",
            "8201ff",
            "5bffffffffffffffff",
            "9f0102",
            "5f0102ff",
            // Bignum tags whose payload is missing or ill-formed. `skip_at`
            // used to short-circuit on a peeked major type and answer
            // "invalid bignum value" where `decode_at` reported the payload's
            // real problem; it now walks the payload the same way.
            "c2",
            "c3",
            "d802",
            "c218",
            "c21c",
            "c21f",
            "c2ff",
            "c2618b",
        ] {
            let data = unhex(hex);
            let skipped = Decoder::new(&data).skip_value();
            let decoded = Decoder::new(&data).decode_value();
            assert_eq!(skipped.is_err(), decoded.is_err(), "{hex}");
            if let (Err(skip_err), Err(decode_err)) = (skipped, decoded) {
                assert_eq!(skip_err, decode_err, "{hex}");
            }
        }
    }

    // --- header helpers ----------------------------------------------------

    #[test]
    fn container_header_reports_definite_and_indefinite_lengths() {
        let data = unhex("83010203");
        assert_eq!(Decoder::new(&data).container_header(4), Ok(Some(3)));
        let data = unhex("9f01ff");
        let mut decoder = Decoder::new(&data);
        assert_eq!(decoder.container_header(4), Ok(None));
        // The cursor is left on the first item either way.
        assert_eq!(decoder.position(), 1);
        assert_eq!(decoder.decode_value(), Ok(Value::Int(1)));
        assert!(decoder.at_break());
        assert_eq!(decoder.consume_break(), Ok(()));
        assert!(decoder.is_at_end());

        for (hex, expected) in [("9818", 24u64), ("990100", 256), ("9a00010000", 65536)] {
            let data = unhex(hex);
            assert_eq!(Decoder::new(&data).container_header(4), Ok(Some(expected)));
        }
    }

    #[test]
    fn container_header_rejects_the_wrong_major_type() {
        let data = unhex("a10102");
        assert_eq!(
            Decoder::new(&data).container_header(4),
            Err(CborError::UnexpectedMajor {
                expected: 4,
                found: 5
            })
        );
        // Truncation is reported before any type mismatch.
        assert_eq!(
            Decoder::new(&[]).container_header(4),
            Err(CborError::Truncated)
        );
        let data = unhex("9c");
        assert_eq!(
            Decoder::new(&data).container_header(4),
            Err(CborError::Malformed("invalid CBOR container length"))
        );
        let data = unhex("98");
        assert_eq!(
            Decoder::new(&data).container_header(4),
            Err(CborError::Truncated)
        );
    }

    #[test]
    fn consume_break_requires_a_break() {
        let data = unhex("01");
        let mut decoder = Decoder::new(&data);
        assert!(!decoder.at_break());
        assert_eq!(
            decoder.consume_break(),
            Err(CborError::Malformed("missing CBOR break"))
        );
        assert!(!Decoder::new(&[]).at_break());
    }

    #[test]
    fn skip_array_header_accepts_every_array_encoding() {
        for (hex, expected_pos) in [
            ("84", 1usize),
            ("9f", 1),
            ("9818", 2),
            ("990100", 3),
            ("9a00010000", 5),
            ("9b0000000000000001", 9),
        ] {
            let data = unhex(hex);
            let mut decoder = Decoder::new(&data);
            assert_eq!(decoder.skip_array_header(), Ok(()), "{hex}");
            assert_eq!(decoder.position(), expected_pos, "{hex}");
        }
    }

    #[test]
    fn skip_array_header_rejects_non_arrays_and_reserved_info() {
        let data = unhex("a0");
        assert_eq!(
            Decoder::new(&data).skip_array_header(),
            Err(CborError::UnexpectedMajor {
                expected: 4,
                found: 5
            })
        );
        let data = unhex("9c");
        assert_eq!(
            Decoder::new(&data).skip_array_header(),
            Err(CborError::Malformed("reserved CBOR array header info"))
        );
        assert_eq!(
            Decoder::new(&[]).skip_array_header(),
            Err(CborError::Truncated)
        );
        // A truncated multi-byte header is truncation, not silent success.
        let data = unhex("9a0001");
        assert_eq!(
            Decoder::new(&data).skip_array_header(),
            Err(CborError::Truncated)
        );
    }

    // --- the real transaction ---------------------------------------------

    #[test]
    fn real_transaction_body_span_matches_the_python_cursor() {
        let data = unhex(REAL_TX);
        assert_eq!(data.len(), 404);
        let mut decoder = Decoder::new(&data);
        decoder.skip_array_header().expect("outer array header");
        assert_eq!(decoder.position(), 1);
        let body = decoder.skip_value().expect("body skips");
        // Offsets taken from cbor2 in the Python service: body is data[1..295].
        assert_eq!(decoder.position(), 295);
        assert_eq!(body, &data[1..295]);
        let witness = decoder.skip_value().expect("witness set skips");
        assert_eq!(witness, &data[295..402]);
        assert_eq!(decoder.decode_value(), Ok(Value::Bool(true)));
        assert_eq!(decoder.decode_value(), Ok(Value::Null));
        assert!(decoder.is_at_end());
    }

    #[test]
    fn real_transaction_decodes_to_the_expected_shape() {
        let data = unhex(REAL_TX);
        let tx = decode_exact(&data).expect("real tx decodes");
        let items = tx.as_array().expect("tx is a list");
        assert_eq!(items.len(), 4);
        let body = &items[0];
        // Inputs are tag 258 wrapping a one-element array of [txid, index].
        let inputs = body.map_get(0).expect("inputs present");
        let entries = inputs
            .as_tag(SET_TAG)
            .and_then(Value::as_array)
            .expect("tagged set of inputs");
        assert_eq!(entries.len(), 1);
        let utxo = entries[0].as_array().expect("utxo is a pair");
        assert_eq!(utxo[0].as_bytes().map(<[u8]>::len), Some(32));
        assert_eq!(utxo[1].as_int(), Some(0));
        // Outputs carry both a Shelley list output and a Babbage map output.
        let outputs = body.map_get(1).and_then(Value::as_array).expect("outputs");
        assert_eq!(outputs.len(), 2);
        assert!(matches!(outputs[0], Value::Array(_)));
        assert!(matches!(outputs[1], Value::Map(_)));
        for output in outputs {
            assert!(output.index_or_key(0).and_then(Value::as_bytes).is_some());
        }
        assert_eq!(items[2], Value::Bool(true));
        assert_eq!(items[3], Value::Null);
    }

    // --- encoding ----------------------------------------------------------

    #[test]
    fn encode_uint_matches_cbor2() {
        for (value, expected) in [
            (0u64, "00"),
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65535, "19ffff"),
            (65536, "1a00010000"),
            (4294967295, "1affffffff"),
            (4294967296, "1b0000000100000000"),
        ] {
            assert_eq!(hex_of(&encode_uint(value)), expected, "{value}");
        }
    }

    #[test]
    fn encode_int_matches_cbor2() {
        for (value, expected) in [
            (0i64, "00"),
            (23, "17"),
            (24, "1818"),
            (-1, "20"),
            (-24, "37"),
            (-25, "3818"),
            (-256, "38ff"),
            (-257, "390100"),
            (-65536, "39ffff"),
            (-65537, "3a00010000"),
            (i64::MIN, "3b7fffffffffffffff"),
            (i64::MAX, "1b7fffffffffffffff"),
        ] {
            assert_eq!(hex_of(&encode_int(value)), expected, "{value}");
        }
    }

    #[test]
    fn encode_bytes_and_arrays_match_cbor2() {
        assert_eq!(hex_of(&encode_bytes(&[])), "40");
        assert_eq!(hex_of(&encode_bytes(&[1, 2, 3])), "43010203");
        assert_eq!(hex_of(&encode_bytes(&[0u8; 24])[..2]), "5818");
        assert_eq!(hex_of(&encode_bytes(&[0u8; 256])[..3]), "590100");
        assert_eq!(hex_of(&encode_array(&[])), "80");
        // cbor2.dumps([0, [b"\xaa", b"\xbb"]])
        let nested = encode_array(&[encode_bytes(&[0xaa]), encode_bytes(&[0xbb])]);
        assert_eq!(
            hex_of(&encode_array(&[encode_uint(0), nested])),
            "82008241aa41bb"
        );
        let twenty_four: Vec<Vec<u8>> = (0..24).map(|_| encode_uint(1)).collect();
        assert_eq!(hex_of(&encode_array(&twenty_four)[..2]), "9818");
    }

    #[test]
    fn encoders_reproduce_the_witness_from_the_python_suite() {
        // api/tests/test_signature.py::test_create_proper_witness
        let public_key = unhex("fa2025e788fae01ce10deffff386f992f62a311758819e4e3792887396c171ba");
        let signature = unhex(
            "f79613a21b87e80f8fff4fa6e878c58186381ba10c46f7b4569a9183ef9fd077ad844f88ddbbe9285faa9febbf3eacbb41338b9889ff82b6252139279fb53c07",
        );
        let witness = encode_array(&[
            encode_uint(0),
            encode_array(&[encode_bytes(&public_key), encode_bytes(&signature)]),
        ]);
        assert_eq!(
            hex_of(&witness),
            "8200825820fa2025e788fae01ce10deffff386f992f62a311758819e4e3792887396c171ba5840f79613a21b87e80f8fff4fa6e878c58186381ba10c46f7b4569a9183ef9fd077ad844f88ddbbe9285faa9febbf3eacbb41338b9889ff82b6252139279fb53c07"
        );
    }

    #[test]
    fn encode_head_covers_every_width_and_major() {
        assert_eq!(hex_of(&encode_head(2, 0)), "40");
        assert_eq!(hex_of(&encode_head(4, 23)), "97");
        assert_eq!(hex_of(&encode_head(5, 24)), "b818");
        assert_eq!(hex_of(&encode_head(6, 258)), "d90102");
        assert_eq!(hex_of(&encode_head(1, u64::MAX)), "3bffffffffffffffff");
        assert_eq!(hex_of(&encode_head(7, 0)), "e0");
    }

    /// A major type above 7 is a caller bug. The release build masks it, which
    /// would silently emit a head for a different major type, so debug builds
    /// (and therefore every test and CI run) abort instead.
    #[test]
    #[should_panic(expected = "CBOR major type out of range")]
    #[cfg(debug_assertions)]
    fn encode_head_rejects_an_out_of_range_major() {
        encode_head(8, 0);
    }

    #[test]
    fn encoded_values_round_trip_through_the_decoder() {
        for value in [
            0i64,
            1,
            23,
            24,
            255,
            256,
            65536,
            -1,
            -24,
            -25,
            i64::MIN,
            i64::MAX,
        ] {
            let encoded = encode_int(value);
            assert_eq!(decode_exact(&encoded), Ok(Value::Int(i128::from(value))));
        }
        let payload = vec![0x5au8; 300];
        assert_eq!(
            decode_exact(&encode_bytes(&payload)),
            Ok(Value::Bytes(payload))
        );
        let array = encode_array(&[encode_uint(1), encode_bytes(&[2]), encode_array(&[])]);
        assert_eq!(
            decode_exact(&array),
            Ok(Value::Array(vec![
                Value::Int(1),
                Value::Bytes(vec![2]),
                Value::Array(vec![])
            ]))
        );
    }
}
