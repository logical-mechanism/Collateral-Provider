//! RFC 8949 conformance vectors for `collateral_provider::cbor`.
//!
//! Three suites, all table-driven off [`vectors()`] so a failure names the
//! vector that produced it:
//!
//! 1. **Appendix A** ("Examples of Encoded CBOR Data Items") — the full table,
//!    plus every head width for majors 0 and 1, the three float widths
//!    including the infinities/NaN/-0.0, the indefinite forms, the tags the
//!    task calls out, and the simple values.
//! 2. **Well-formedness negatives** — RFC 8949 §5.3.1 and Appendix F: reserved
//!    additional info, additional info 31 where the major type forbids it,
//!    misplaced breaks, bad indefinite-string chunks, every truncation of a
//!    multi-byte head, and invalid UTF-8.
//! 3. **Span exactness** — for every accepted vector, `decode_value_raw`
//!    returns precisely the input bytes and `skip_value` consumes precisely as
//!    many bytes as `decode_value`. That property is what makes
//!    `signature::tx_id` and `script_integrity` byte-exact; an off-by-one here
//!    is a witness for the wrong transaction hash.
//!
//! Every expected value is frozen as a literal. Nothing here reads the
//! network, the filesystem, or Python. Where the crate deliberately diverges
//! from `cbor2` (the behavioural reference) or from RFC 8949 (the
//! well-formedness reference), the vector carries a comment naming the
//! divergence — those are asserted as the crate *actually* behaves, so this
//! file stays green and the divergences are documented rather than hidden.

use collateral_provider::cbor::{
    decode_exact, decode_one, encode_array, encode_bytes, encode_head, encode_int, encode_uint,
    CborError, Decoder, Value,
};

// --- table types ------------------------------------------------------------

#[derive(Debug)]
enum Expect {
    /// Decodes to exactly this value.
    Val(Value),
    /// Decodes to a float that is NaN (bit pattern checked separately, see
    /// `nan_encodings_all_produce_a_quiet_nan`).
    Nan,
    /// Rejected with exactly this error.
    Err(CborError),
}

struct Case {
    name: String,
    hex: String,
    expect: Expect,
}

fn ok(name: &str, hex: &str, value: Value) -> Case {
    Case {
        name: name.to_owned(),
        hex: hex.to_owned(),
        expect: Expect::Val(value),
    }
}

fn nan(name: &str, hex: &str) -> Case {
    Case {
        name: name.to_owned(),
        hex: hex.to_owned(),
        expect: Expect::Nan,
    }
}

fn bad(name: &str, hex: &str, err: CborError) -> Case {
    Case {
        name: name.to_owned(),
        hex: hex.to_owned(),
        expect: Expect::Err(err),
    }
}

// --- value constructors -----------------------------------------------------

fn i(value: i128) -> Value {
    Value::Int(value)
}
fn b(bytes: &[u8]) -> Value {
    Value::Bytes(bytes.to_vec())
}
fn t(text: &str) -> Value {
    Value::Text(text.to_owned())
}
fn arr(items: Vec<Value>) -> Value {
    Value::Array(items)
}
fn map(entries: Vec<(Value, Value)>) -> Value {
    Value::Map(entries)
}
fn tag(number: u64, inner: Value) -> Value {
    Value::Tag(number, Box::new(inner))
}
fn f(value: f64) -> Value {
    Value::Float(value)
}
/// Integers 1..=n as an array, for the 25-element Appendix A vectors.
fn ints_to(n: i128) -> Value {
    arr((1..=n).map(i).collect())
}

// --- error constructors -----------------------------------------------------

fn reserved_info() -> CborError {
    CborError::Malformed("reserved CBOR additional information")
}
fn no_indefinite() -> CborError {
    CborError::Malformed("indefinite length is not valid for this CBOR major type")
}
fn stray_break() -> CborError {
    CborError::Malformed("unexpected CBOR break")
}
fn bad_chunk() -> CborError {
    CborError::Malformed("invalid chunk in indefinite-length string")
}
fn nested_chunk() -> CborError {
    CborError::Malformed("nested indefinite-length string chunk")
}

// --- hex helpers ------------------------------------------------------------

fn unhex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd-length hex vector: {hex}");
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("vector is hex"))
        .collect()
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// --- the table --------------------------------------------------------------

fn vectors() -> Vec<Case> {
    let mut cases = vec![
        // ── RFC 8949 Appendix A: unsigned integers (major 0) ─────────────
        ok("appx-a/0", "00", i(0)),
        ok("appx-a/1", "01", i(1)),
        ok("appx-a/10", "0a", i(10)),
        ok("appx-a/23", "17", i(23)),
        ok("appx-a/24", "1818", i(24)),
        ok("appx-a/25", "1819", i(25)),
        ok("appx-a/100", "1864", i(100)),
        ok("appx-a/1000", "1903e8", i(1000)),
        ok("appx-a/1000000", "1a000f4240", i(1_000_000)),
        ok(
            "appx-a/1000000000000",
            "1b000000e8d4a51000",
            i(1_000_000_000_000),
        ),
        ok(
            "appx-a/18446744073709551615",
            "1bffffffffffffffff",
            i(18_446_744_073_709_551_615),
        ),
        // Tags 2/3 are the one semantic decode the crate shares with cbor2:
        // both produce a plain integer, so downstream integer checks agree.
        ok(
            "appx-a/18446744073709551616",
            "c249010000000000000000",
            i(18_446_744_073_709_551_616),
        ),
        // ── Appendix A: negative integers (major 1) ──────────────────────
        ok(
            "appx-a/-18446744073709551616",
            "3bffffffffffffffff",
            i(-18_446_744_073_709_551_616),
        ),
        ok(
            "appx-a/-18446744073709551617",
            "c349010000000000000000",
            i(-18_446_744_073_709_551_617),
        ),
        ok("appx-a/-1", "20", i(-1)),
        ok("appx-a/-10", "29", i(-10)),
        ok("appx-a/-100", "3863", i(-100)),
        ok("appx-a/-1000", "3903e7", i(-1000)),
        // ── Every head width, both integer majors ────────────────────────
        // 0..23 inline (spot-checked above); 24/25/26/27 at each boundary.
        ok("head/uint-inline-min", "00", i(0)),
        ok("head/uint-inline-max", "17", i(23)),
        ok("head/uint-1byte-min", "1818", i(24)),
        ok("head/uint-1byte-max", "18ff", i(255)),
        ok("head/uint-2byte-min", "190100", i(256)),
        ok("head/uint-2byte-max", "19ffff", i(65535)),
        ok("head/uint-4byte-min", "1a00010000", i(65536)),
        ok("head/uint-4byte-max", "1affffffff", i(4_294_967_295)),
        ok(
            "head/uint-8byte-min",
            "1b0000000100000000",
            i(4_294_967_296),
        ),
        ok(
            "head/uint-8byte-max",
            "1bffffffffffffffff",
            i(18_446_744_073_709_551_615),
        ),
        ok("head/nint-inline-min", "20", i(-1)),
        ok("head/nint-inline-max", "37", i(-24)),
        ok("head/nint-1byte-min", "3818", i(-25)),
        ok("head/nint-1byte-max", "38ff", i(-256)),
        ok("head/nint-2byte-min", "390100", i(-257)),
        ok("head/nint-2byte-max", "39ffff", i(-65536)),
        ok("head/nint-4byte-min", "3a00010000", i(-65537)),
        ok("head/nint-4byte-max", "3affffffff", i(-4_294_967_296)),
        ok(
            "head/nint-8byte-min",
            "3b0000000100000000",
            i(-4_294_967_297),
        ),
        ok(
            "head/nint-8byte-max",
            "3bffffffffffffffff",
            i(-18_446_744_073_709_551_616),
        ),
        // Non-minimal heads are well-formed (just not canonical); cbor2
        // accepts them too, so a builder that pads its integers still works.
        ok("head/non-minimal-1byte", "1801", i(1)),
        ok("head/non-minimal-2byte", "190001", i(1)),
        ok("head/non-minimal-4byte", "1a00000001", i(1)),
        ok("head/non-minimal-8byte", "1b0000000000000001", i(1)),
        // ── Appendix A: floats and simple values (major 7) ───────────────
        ok("appx-a/0.0", "f90000", f(0.0)),
        // -0.0 must not compare equal to 0.0: Value compares float bits.
        ok("appx-a/-0.0", "f98000", f(-0.0)),
        ok("appx-a/1.0", "f93c00", f(1.0)),
        ok("appx-a/1.1", "fb3ff199999999999a", f(1.1)),
        ok("appx-a/1.5", "f93e00", f(1.5)),
        ok("appx-a/65504.0", "f97bff", f(65504.0)),
        ok("appx-a/100000.0", "fa47c35000", f(100_000.0)),
        ok(
            "appx-a/3.4028234663852886e+38",
            "fa7f7fffff",
            f(3.402_823_466_385_288_6e38),
        ),
        ok("appx-a/1.0e+300", "fb7e37e43c8800759c", f(1.0e300)),
        // Half-precision subnormal: mantissa 1 * 2^-24.
        ok(
            "appx-a/5.960464477539063e-8",
            "f90001",
            f(5.960_464_477_539_063e-8),
        ),
        ok("appx-a/0.00006103515625", "f90400", f(0.000_061_035_156_25)),
        ok("appx-a/-4.0", "f9c400", f(-4.0)),
        ok("appx-a/-4.1", "fbc010666666666666", f(-4.1)),
        ok("appx-a/Infinity-half", "f97c00", f(f64::INFINITY)),
        nan("appx-a/NaN-half", "f97e00"),
        ok("appx-a/-Infinity-half", "f9fc00", f(f64::NEG_INFINITY)),
        ok("appx-a/Infinity-single", "fa7f800000", f(f64::INFINITY)),
        nan("appx-a/NaN-single", "fa7fc00000"),
        ok(
            "appx-a/-Infinity-single",
            "faff800000",
            f(f64::NEG_INFINITY),
        ),
        ok(
            "appx-a/Infinity-double",
            "fb7ff0000000000000",
            f(f64::INFINITY),
        ),
        nan("appx-a/NaN-double", "fb7ff8000000000000"),
        ok(
            "appx-a/-Infinity-double",
            "fbfff0000000000000",
            f(f64::NEG_INFINITY),
        ),
        ok("appx-a/false", "f4", Value::Bool(false)),
        ok("appx-a/true", "f5", Value::Bool(true)),
        ok("appx-a/null", "f6", Value::Null),
        ok("appx-a/undefined", "f7", Value::Undefined),
        ok("appx-a/simple(16)", "f0", Value::Simple(16)),
        ok("appx-a/simple(255)", "f8ff", Value::Simple(255)),
        // Remaining inline simple values, including the ones adjacent to the
        // false/true/null/undefined block.
        ok("simple/0-inline", "e0", Value::Simple(0)),
        ok("simple/19-inline", "f3", Value::Simple(19)),
        ok("simple/32-one-byte", "f820", Value::Simple(32)),
        ok("simple/100-one-byte", "f864", Value::Simple(100)),
        // RFC 8949 §3.3: a simple value below 32 encoded in the one-byte form
        // is *not* well-formed, because those values have a single-byte
        // spelling. The crate rejects them. DIVERGENCE (cbor2): Python accepts
        // them as CBORSimpleValue(24) — this is the rejecting side of the
        // difference, so the crate refuses transactions Python would sign,
        // never the reverse. See `one_byte_simple_values_below_32_are_ill_formed`.
        bad(
            "ill-formed/simple(0)-one-byte",
            "f800",
            CborError::Malformed("non-minimal CBOR simple value"),
        ),
        bad(
            "ill-formed/simple(24)-one-byte",
            "f818",
            CborError::Malformed("non-minimal CBOR simple value"),
        ),
        bad(
            "ill-formed/simple(31)-one-byte",
            "f81f",
            CborError::Malformed("non-minimal CBOR simple value"),
        ),
        // ── Appendix A: tags ─────────────────────────────────────────────
        // DIVERGENCE (cbor2): tag 0 becomes a datetime in Python; the crate
        // keeps the raw tag. Harmless — no Cardano body field is a datetime,
        // and every validator that meets an unexpected Tag rejects it.
        ok(
            "appx-a/0(\"2013-03-21T20:04:00Z\")",
            "c074323031332d30332d32315432303a30343a30305a",
            tag(0, t("2013-03-21T20:04:00Z")),
        ),
        // DIVERGENCE (cbor2): tag 1 becomes a datetime in Python.
        ok(
            "appx-a/1(1363896240)",
            "c11a514b67b0",
            tag(1, i(1_363_896_240)),
        ),
        ok(
            "appx-a/1(1363896240.5)",
            "c1fb41d452d9ec200000",
            tag(1, f(1_363_896_240.5)),
        ),
        ok(
            "appx-a/23(h'01020304')",
            "d74401020304",
            tag(23, b(&[1, 2, 3, 4])),
        ),
        ok(
            "appx-a/24(h'6449455446')",
            "d818456449455446",
            tag(24, b(b"dIETF")),
        ),
        ok(
            "appx-a/32(\"http://www.example.com\")",
            "d82076687474703a2f2f7777772e6578616d706c652e636f6d",
            tag(32, t("http://www.example.com")),
        ),
        // DIVERGENCE (cbor2): tag 55799 (self-describe) is unwrapped by Python
        // — `cbor2.loads("d9d9f7f5")` is `True`, not a tag. The crate keeps
        // Tag(55799, ...). A self-describe-prefixed *transaction* is therefore
        // rejected by the Rust service (major 6 where an array is expected)
        // and would be unwrapped by Python. Stricter, so no signing risk, but
        // it is a genuine acceptance difference.
        ok(
            "divergence/55799(true)",
            "d9d9f7f5",
            tag(55799, Value::Bool(true)),
        ),
        ok(
            "divergence/55799(text)",
            "d9d9f764f0908591",
            tag(55799, t("\u{10151}")),
        ),
        // DIVERGENCE (cbor2): tag 30 becomes a Fraction in Python.
        ok(
            "divergence/30([1,3])",
            "d81e820103",
            tag(30, arr(vec![i(1), i(3)])),
        ),
        // DIVERGENCE (cbor2): tag 4 becomes a Decimal in Python.
        ok(
            "divergence/4([-2,27315])",
            "c48221196ab3",
            tag(4, arr(vec![i(-2), i(27315)])),
        ),
        // DIVERGENCE (cbor2): tag 258 becomes a Python set; the crate keeps
        // wire order and duplicates and lets validators::cbor normalise it.
        // This one is load-bearing for Cardano — see `_set_items`.
        ok(
            "divergence/258([1,2,3])",
            "d9010283010203",
            tag(258, arr(vec![i(1), i(2), i(3)])),
        ),
        // Bignum edge cases that stay integers.
        ok("tag/2(h'')", "c240", i(0)),
        ok("tag/3(h'')", "c340", i(-1)),
        // ── Appendix A: byte and text strings ────────────────────────────
        ok("appx-a/h''", "40", b(&[])),
        ok("appx-a/h'01020304'", "4401020304", b(&[1, 2, 3, 4])),
        ok("appx-a/\"\"", "60", t("")),
        ok("appx-a/\"a\"", "6161", t("a")),
        ok("appx-a/\"IETF\"", "6449455446", t("IETF")),
        ok("appx-a/\"\\\"\\\\\"", "62225c", t("\"\\")),
        ok("appx-a/\"\\u00fc\"", "62c3bc", t("\u{fc}")),
        ok("appx-a/\"\\u6c34\"", "63e6b0b4", t("\u{6c34}")),
        // Surrogate pair in the diagnostic notation; a single U+10151 on the
        // wire, encoded as four UTF-8 bytes.
        ok("appx-a/\"\\ud800\\udd51\"", "64f0908591", t("\u{10151}")),
        // ── Appendix A: arrays and maps ──────────────────────────────────
        ok("appx-a/[]", "80", arr(vec![])),
        ok("appx-a/[1,2,3]", "83010203", arr(vec![i(1), i(2), i(3)])),
        ok(
            "appx-a/[1,[2,3],[4,5]]",
            "8301820203820405",
            arr(vec![i(1), arr(vec![i(2), i(3)]), arr(vec![i(4), i(5)])]),
        ),
        ok(
            "appx-a/[1..25]",
            "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
            ints_to(25),
        ),
        ok("appx-a/{}", "a0", map(vec![])),
        ok(
            "appx-a/{1:2,3:4}",
            "a201020304",
            map(vec![(i(1), i(2)), (i(3), i(4))]),
        ),
        ok(
            "appx-a/{\"a\":1,\"b\":[2,3]}",
            "a26161016162820203",
            map(vec![(t("a"), i(1)), (t("b"), arr(vec![i(2), i(3)]))]),
        ),
        ok(
            "appx-a/[\"a\",{\"b\":\"c\"}]",
            "826161a161626163",
            arr(vec![t("a"), map(vec![(t("b"), t("c"))])]),
        ),
        ok(
            "appx-a/{\"a\":\"A\",..,\"e\":\"E\"}",
            "a56161614161626142616361436164614461656145",
            map(vec![
                (t("a"), t("A")),
                (t("b"), t("B")),
                (t("c"), t("C")),
                (t("d"), t("D")),
                (t("e"), t("E")),
            ]),
        ),
        // ── Appendix A: indefinite-length forms ──────────────────────────
        ok(
            "appx-a/(_ h'0102', h'030405')",
            "5f42010243030405ff",
            b(&[1, 2, 3, 4, 5]),
        ),
        ok(
            "appx-a/(_ \"strea\", \"ming\")",
            "7f657374726561646d696e67ff",
            t("streaming"),
        ),
        ok("appx-a/[_ ]", "9fff", arr(vec![])),
        ok(
            "appx-a/[_ 1,[2,3],[_ 4,5]]",
            "9f018202039f0405ffff",
            arr(vec![i(1), arr(vec![i(2), i(3)]), arr(vec![i(4), i(5)])]),
        ),
        ok(
            "appx-a/[_ 1,[2,3],[4,5]]",
            "9f01820203820405ff",
            arr(vec![i(1), arr(vec![i(2), i(3)]), arr(vec![i(4), i(5)])]),
        ),
        ok(
            "appx-a/[1,[2,3],[_ 4,5]]",
            "83018202039f0405ff",
            arr(vec![i(1), arr(vec![i(2), i(3)]), arr(vec![i(4), i(5)])]),
        ),
        ok(
            "appx-a/[1,[_ 2,3],[4,5]]",
            "83019f0203ff820405",
            arr(vec![i(1), arr(vec![i(2), i(3)]), arr(vec![i(4), i(5)])]),
        ),
        ok(
            "appx-a/[_ 1..25]",
            "9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff",
            ints_to(25),
        ),
        ok(
            "appx-a/{_ \"a\":1,\"b\":[_ 2,3]}",
            "bf61610161629f0203ffff",
            map(vec![(t("a"), i(1)), (t("b"), arr(vec![i(2), i(3)]))]),
        ),
        ok(
            "appx-a/[\"a\",{_ \"b\":\"c\"}]",
            "826161bf61626163ff",
            arr(vec![t("a"), map(vec![(t("b"), t("c"))])]),
        ),
        ok(
            "appx-a/{_ \"Fun\":true,\"Amt\":-2}",
            "bf6346756ef563416d7421ff",
            map(vec![(t("Fun"), Value::Bool(true)), (t("Amt"), i(-2))]),
        ),
        // Empty and degenerate indefinite containers.
        ok("indef/empty-bytes", "5fff", b(&[])),
        ok("indef/empty-text", "7fff", t("")),
        ok("indef/empty-map", "bfff", map(vec![])),
        ok("indef/single-chunk-bytes", "5f4101ff", b(&[1])),
        // Nested indefinite *containers* are fine (only nested indefinite
        // *strings* are ill-formed).
        ok(
            "indef/nested-arrays",
            "9f9f9fffffff",
            arr(vec![arr(vec![arr(vec![])])]),
        ),
        ok(
            "indef/map-in-array",
            "9fbf00a0ffff",
            arr(vec![map(vec![(i(0), map(vec![]))])]),
        ),
        // A Conway redeemer map: array keys are legal and load-bearing.
        ok(
            "cardano/redeemer-map-array-keys",
            "a18200008201820102",
            map(vec![(
                arr(vec![i(0), i(0)]),
                arr(vec![i(1), arr(vec![i(1), i(2)])]),
            )]),
        ),
        // ── §5.3.1 / Appendix F: additional info 31 where it is forbidden ─
        bad("illformed/indefinite-uint", "1f", no_indefinite()),
        bad("illformed/indefinite-nint", "3f", no_indefinite()),
        bad("illformed/indefinite-tag", "df", no_indefinite()),
        // Trailing data proves the head itself was rejected, not truncation.
        bad(
            "illformed/indefinite-uint-with-payload",
            "1f00",
            no_indefinite(),
        ),
        bad(
            "illformed/indefinite-nint-with-payload",
            "3f00",
            no_indefinite(),
        ),
        bad(
            "illformed/indefinite-tag-with-payload",
            "df00",
            no_indefinite(),
        ),
        // ── Appendix F: misplaced break bytes ────────────────────────────
        // DIVERGENCE (cbor2): Python returns a break_marker object for a bare
        // break, and even stores one *inside* a definite array ("81ff" decodes
        // to [break_marker]). The crate rejects all of these. Stricter, so a
        // transaction Python would accept is rejected here — a false negative,
        // never a bad signature.
        bad("illformed/bare-break", "ff", stray_break()),
        bad("illformed/break-in-definite-array", "81ff", stray_break()),
        bad("illformed/break-after-item", "8201ff", stray_break()),
        bad("illformed/break-as-definite-map-key", "a1ff", stray_break()),
        bad(
            "illformed/break-as-definite-map-value",
            "a100ff",
            stray_break(),
        ),
        // Odd number of items in an indefinite map: the break lands in the
        // value slot.
        bad(
            "illformed/break-as-indefinite-map-value",
            "bf00ff",
            stray_break(),
        ),
        bad(
            "illformed/break-as-indefinite-map-value-3",
            "bf000000ff",
            stray_break(),
        ),
        bad("illformed/break-as-tag-content", "c6ff", stray_break()),
        bad(
            "illformed/break-as-nested-array-item",
            "9f81ffff",
            stray_break(),
        ),
        // ── Appendix F: bad indefinite-string chunks ─────────────────────
        bad("illformed/bytes-chunk-uint", "5f00ff", bad_chunk()),
        bad("illformed/bytes-chunk-nint", "5f21ff", bad_chunk()),
        bad("illformed/bytes-chunk-text", "5f6100ff", bad_chunk()),
        bad("illformed/bytes-chunk-array", "5f80ff", bad_chunk()),
        bad("illformed/bytes-chunk-map", "5fa0ff", bad_chunk()),
        bad("illformed/bytes-chunk-tag", "5fc000ff", bad_chunk()),
        bad("illformed/bytes-chunk-simple", "5fe0ff", bad_chunk()),
        bad("illformed/text-chunk-bytes", "7f4101ff", bad_chunk()),
        bad("illformed/text-chunk-uint", "7f00ff", bad_chunk()),
        // A good chunk followed by a bad one still fails.
        bad(
            "illformed/bytes-chunk-good-then-bad",
            "5f410100ff",
            bad_chunk(),
        ),
        bad(
            "illformed/nested-indefinite-bytes",
            "5f5f4100ffff",
            nested_chunk(),
        ),
        bad(
            "illformed/nested-indefinite-text",
            "7f7f6100ffff",
            nested_chunk(),
        ),
        // ── Invalid UTF-8 in text strings ────────────────────────────────
        bad("utf8/truncated-sequence", "62c328", CborError::InvalidUtf8),
        // Lone surrogate U+D800 encoded as UTF-8 (CESU-8 style).
        bad("utf8/lone-surrogate", "63eda080", CborError::InvalidUtf8),
        // Overlong encoding of U+0000.
        bad("utf8/overlong-nul", "62c080", CborError::InvalidUtf8),
        bad("utf8/overlong-slash", "62c0af", CborError::InvalidUtf8),
        // 0xfe / 0xff never appear in UTF-8.
        bad("utf8/invalid-byte", "61fe", CborError::InvalidUtf8),
        // Bad UTF-8 inside an indefinite-length text chunk.
        bad(
            "utf8/indefinite-chunk",
            "7f62c328ff",
            CborError::InvalidUtf8,
        ),
        bad(
            "utf8/indefinite-lone-surrogate",
            "7f63eda080ff",
            CborError::InvalidUtf8,
        ),
        // A multi-byte code point split across two chunks: each chunk is
        // validated on its own, exactly as cbor2 does when it joins them.
        bad(
            "utf8/split-across-chunks",
            "7f61c361a8ff",
            CborError::InvalidUtf8,
        ),
        ok("utf8/whole-in-one-chunk", "7f62c3a8ff", t("\u{e8}")),
        // ── Oversized length heads: bounds check, never an allocation ────
        bad(
            "oversize/bytes-2^64-1",
            "5bffffffffffffffff",
            CborError::Truncated,
        ),
        bad(
            "oversize/text-2^64-1",
            "7bffffffffffffffff",
            CborError::Truncated,
        ),
        bad(
            "oversize/array-2^64-1",
            "9bffffffffffffffff00",
            CborError::Truncated,
        ),
        bad(
            "oversize/map-2^64-1",
            "bbffffffffffffffff00",
            CborError::Truncated,
        ),
        bad("oversize/bytes-4GiB", "5affffffff", CborError::Truncated),
        // ── Trailing data ────────────────────────────────────────────────
        bad(
            "trailing/two-values",
            "0000",
            CborError::Malformed("trailing CBOR data"),
        ),
        bad(
            "trailing/after-array",
            "8001",
            CborError::Malformed("trailing CBOR data"),
        ),
        // ── Bignum payload type ──────────────────────────────────────────
        bad(
            "bignum/tag2-non-bytes",
            "c201",
            CborError::Malformed("invalid bignum value"),
        ),
        bad(
            "bignum/tag3-non-bytes",
            "c301",
            CborError::Malformed("invalid bignum value"),
        ),
        // Reserved info inside a tag payload propagates out.
        bad("illformed/reserved-inside-tag", "c482281d", reserved_info()),
    ];

    // ── Reserved additional info 28/29/30, every major type ──────────────
    // RFC 8949 §3: these are reserved for future additions and are not
    // well-formed today. cbor2 rejects all 24 too.
    for major in 0u8..=7 {
        for info in 28u8..=30 {
            let byte = (major << 5) | info;
            cases.push(bad(
                &format!("reserved/major{major}-info{info}"),
                &format!("{byte:02x}"),
                reserved_info(),
            ));
            // With a following byte, so the failure cannot be truncation.
            let byte_hex = format!("{byte:02x}");
            cases.push(bad(
                &format!("reserved/major{major}-info{info}-with-payload"),
                &format!("{byte_hex}00"),
                reserved_info(),
            ));
        }
    }

    // ── Every truncation of a multi-byte head, every major type ──────────
    // For info 24/25/26/27 the head carries 1/2/4/8 argument bytes; emit the
    // bare head and every strictly-partial argument.
    for major in 0u8..=7 {
        for (info, width) in [(24u8, 1usize), (25, 2), (26, 4), (27, 8)] {
            let head = (major << 5) | info;
            for present in 0..width {
                let hex = format!("{head:02x}{}", "00".repeat(present));
                cases.push(bad(
                    &format!("truncated/major{major}-info{info}-{present}of{width}"),
                    &hex,
                    CborError::Truncated,
                ));
            }
        }
    }

    // ── Truncated payloads and containers ────────────────────────────────
    for (name, hex) in [
        ("truncated/empty-input", ""),
        ("truncated/bytes-missing-payload", "41"),
        ("truncated/bytes-short-payload", "430102"),
        ("truncated/text-missing-payload", "6261"),
        ("truncated/definite-array-missing-item", "81"),
        ("truncated/definite-array-short", "830102"),
        ("truncated/definite-map-missing-key", "a1"),
        ("truncated/definite-map-missing-value", "a100"),
        ("truncated/definite-map-short", "a20102"),
        ("truncated/indefinite-array-no-break", "9f0102"),
        ("truncated/indefinite-map-no-break", "bf0102"),
        ("truncated/indefinite-bytes-no-break", "5f4101"),
        ("truncated/indefinite-text-no-break", "7f6161"),
        ("truncated/indefinite-array-empty-no-break", "9f"),
        ("truncated/indefinite-bytes-empty-no-break", "5f"),
        ("truncated/tag-missing-content", "c0"),
        ("truncated/tag24-missing-content", "d818"),
        ("truncated/nested-array", "8181"),
        ("truncated/half-float", "f900"),
        ("truncated/single-float", "fa0000"),
        ("truncated/double-float", "fb00"),
        ("truncated/simple-one-byte", "f8"),
    ] {
        cases.push(bad(name, hex, CborError::Truncated));
    }

    cases
}

// --- suite 1 + 2: the driver ------------------------------------------------

#[test]
fn rfc8949_vectors_decode_as_expected() {
    let cases = vectors();
    // Guard against the table silently shrinking: 154 hand-written vectors
    // plus 48 reserved-additional-info, 120 truncated-head, and 22
    // truncated-payload cases generated below.
    assert_eq!(cases.len(), 362, "the vector table changed size");

    let mut failures = Vec::new();
    for case in &cases {
        let data = unhex(&case.hex);
        let got = decode_exact(&data);
        let complaint = match (&case.expect, &got) {
            (Expect::Val(want), Ok(actual)) if actual == want => None,
            (Expect::Val(want), _) => Some(format!("expected {want:?}, got {got:?}")),
            (Expect::Nan, Ok(Value::Float(value))) if value.is_nan() => None,
            (Expect::Nan, _) => Some(format!("expected a NaN float, got {got:?}")),
            (Expect::Err(want), Err(actual)) if actual == want => None,
            (Expect::Err(want), _) => Some(format!("expected Err({want:?}), got {got:?}")),
        };
        if let Some(complaint) = complaint {
            failures.push(format!("  {} [{}]: {}", case.name, case.hex, complaint));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} RFC 8949 vectors failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

/// Every NaN encoding decodes to a quiet NaN, and the payload bits survive the
/// widening from half and single precision. The expectations are what `cbor2`
/// returns for the same bytes; a NaN payload is never load-bearing on the
/// signing path (no Cardano field is a float) but silently rewriting one is a
/// fidelity bug, and it was one until this suite pinned it.
#[test]
fn nan_encodings_are_quiet_and_keep_their_payload() {
    for (hex, bits) in [
        // Canonical quiet NaN in each width.
        ("f97e00", 0x7ff8_0000_0000_0000u64),
        ("fa7fc00000", 0x7ff8_0000_0000_0000),
        ("fb7ff8000000000000", 0x7ff8_0000_0000_0000),
        // Payload-carrying NaNs. The half-precision significand lands in the
        // top of the double's, and the quiet bit is set.
        ("f97c01", 0x7ff8_0400_0000_0000),
        ("f9fc01", 0xfff8_0400_0000_0000),
        ("fa7fc00001", 0x7ff8_0000_2000_0000),
        ("fb7ff8000000000001", 0x7ff8_0000_0000_0001),
    ] {
        let value = decode_exact(&unhex(hex)).expect("NaN vector decodes");
        let Value::Float(float) = value else {
            panic!("{hex} did not decode to a float: {value:?}");
        };
        assert!(float.is_nan(), "{hex} is not NaN");
        // Bit 51 is the quiet bit: a decoded NaN is never signalling.
        assert_ne!(float.to_bits() & (1 << 51), 0, "{hex} is a signalling NaN");
        assert_eq!(float.to_bits(), bits, "{hex} payload changed");
    }
}

/// All 65 536 half-precision patterns against `cbor2`, compressed to one
/// constant.
///
/// The digest is FNV-1a over the little-endian `f64` bit pattern of every
/// half float in order, produced by the reference implementation:
///
/// ```text
/// h = 0xcbf29ce484222325
/// for bits in range(65536):
///     for byte in struct.pack('<d', cbor2.loads(b'\xf9' + struct.pack('>H', bits))):
///         h = ((h ^ byte) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
/// ```
///
/// Hashing bit patterns rather than values is the point: it catches a lost
/// sign on `-0.0` and a rewritten NaN payload, neither of which `==` can see.
/// Before the payload fix this digest was different — 2 046 of the patterns
/// disagreed with Python.
#[test]
fn every_half_float_pattern_matches_cbor2() {
    const CBOR2_DIGEST: u64 = 0x8487_69a3_ea63_c745;

    let mut digest = 0xcbf2_9ce4_8422_2325u64;
    let mut nans = 0usize;
    let mut infinities = 0usize;
    for bits in 0u32..=0xFFFF {
        let hex = format!("f9{bits:04x}");
        let Ok(Value::Float(float)) = decode_exact(&unhex(&hex)) else {
            panic!("{hex} did not decode to a float");
        };
        for byte in float.to_bits().to_le_bytes() {
            digest = (digest ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
        }

        // Structural expectations that do not depend on the digest.
        let negative = bits & 0x8000 != 0;
        let exponent = (bits >> 10) & 0x1F;
        let significand = bits & 0x03FF;
        if exponent == 31 && significand == 0 {
            infinities += 1;
            assert!(float.is_infinite(), "{hex}");
        } else if exponent == 31 {
            nans += 1;
            assert!(float.is_nan(), "{hex}");
            // Bit 51, the quiet bit: a decoded NaN is never signalling.
            assert_ne!(float.to_bits() & (1 << 51), 0, "{hex} is signalling");
        } else {
            assert!(float.is_finite(), "{hex}");
        }
        // The sign bit survives every branch, including -0.0 and NaN.
        assert_eq!(
            float.to_bits() >> 63 == 1,
            negative,
            "{hex} lost its sign bit"
        );
    }
    assert_eq!(nans, 2046, "half NaN patterns");
    assert_eq!(infinities, 2, "half infinity patterns");
    assert_eq!(
        digest, CBOR2_DIGEST,
        "half-float decoding no longer matches cbor2 bit for bit",
    );
}

/// Signed zero must survive decoding distinctly — the `Value` comparison is by
/// bit pattern, so a lost sign would be invisible to `==` on `f64`.
#[test]
fn negative_zero_is_distinct_from_positive_zero() {
    let positive = decode_exact(&unhex("f90000")).expect("0.0 decodes");
    let negative = decode_exact(&unhex("f98000")).expect("-0.0 decodes");
    assert_ne!(positive, negative);
    assert_eq!(negative, Value::Float(-0.0));
    let Value::Float(float) = negative else {
        panic!("not a float")
    };
    assert_eq!(float.to_bits(), (-0.0f64).to_bits());
}

/// RFC 8949 §3.3 declares `f8 00`..`f8 1f` ill-formed: those simple values
/// have a one-byte spelling, so the two-byte form must be rejected. cbor2
/// accepts them, which makes this a deliberate divergence — in the safe
/// direction. The crate refuses a transaction the Python service would sign;
/// it never signs one Python would refuse, and no Cardano transaction field is
/// a major-7 simple value, so nothing legitimate is affected.
#[test]
fn one_byte_simple_below_32_is_rejected_per_rfc() {
    for value in 0u8..32 {
        let hex = format!("f8{value:02x}");
        let data = unhex(&hex);
        assert_eq!(
            decode_exact(&data),
            Err(CborError::Malformed("non-minimal CBOR simple value")),
            "{hex}: ill-formed per RFC 8949 §3.3"
        );
        // Acceptance parity between the traversals is the property that keeps
        // `tx_id` (which skips) aligned with the validators (which decode).
        assert_eq!(
            Decoder::new(&data).skip_value(),
            Err(CborError::Malformed("non-minimal CBOR simple value")),
            "{hex}: skip"
        );
    }
    // The well-formed side of the boundary, for contrast.
    assert_eq!(decode_exact(&unhex("f820")), Ok(Value::Simple(32)));
    assert_eq!(decode_exact(&unhex("f8ff")), Ok(Value::Simple(255)));
    // The inline spellings of the same values stay valid.
    assert_eq!(decode_exact(&unhex("e0")), Ok(Value::Simple(0)));
    assert_eq!(decode_exact(&unhex("f3")), Ok(Value::Simple(19)));
}

/// Both `f8` forms and the inline form of the four named simple values must
/// keep their distinct decoded types: `f4/f5/f6/f7` are Bool/Null/Undefined,
/// never `Simple`.
#[test]
fn named_simple_values_are_not_generic_simples() {
    assert_eq!(decode_exact(&unhex("f4")), Ok(Value::Bool(false)));
    assert_eq!(decode_exact(&unhex("f5")), Ok(Value::Bool(true)));
    assert_eq!(decode_exact(&unhex("f6")), Ok(Value::Null));
    assert_eq!(decode_exact(&unhex("f7")), Ok(Value::Undefined));
    // The one-byte spellings of 20..23 are ill-formed per RFC 8949 §3.3 and
    // are rejected outright — in particular `f8 15` is not an alternative
    // encoding of `true`, so a validator matching on `Value::Bool` cannot be
    // fed one. (cbor2 decodes them to CBORSimpleValue, which is also not a
    // bool; both implementations refuse to read them as `true`.)
    for hex in ["f814", "f815", "f816", "f817"] {
        assert_eq!(
            decode_exact(&unhex(hex)),
            Err(CborError::Malformed("non-minimal CBOR simple value")),
            "{hex}"
        );
    }
}

// --- suite 3: spans ---------------------------------------------------------

/// Every accepted vector must report a span equal to the whole input, and
/// `skip_value` must consume exactly what `decode_value` consumed. This is the
/// property `signature::tx_id` depends on: it locates the body by *skipping*
/// and then hashes the skipped span.
#[test]
fn accepted_vectors_have_exact_spans() {
    let mut failures = Vec::new();
    let mut checked = 0usize;

    for case in vectors() {
        if matches!(case.expect, Expect::Err(_)) {
            continue;
        }
        checked += 1;
        let data = unhex(&case.hex);

        // decode_value_raw hands back precisely the input bytes.
        let mut reader = Decoder::new(&data);
        let (_, raw) = match reader.decode_value_raw() {
            Ok(pair) => pair,
            Err(err) => {
                failures.push(format!(
                    "  {} [{}]: decode failed: {err:?}",
                    case.name, case.hex
                ));
                continue;
            }
        };
        if raw != data.as_slice() {
            failures.push(format!(
                "  {} [{}]: raw span {} != input",
                case.name,
                case.hex,
                hex_of(raw)
            ));
        }
        if reader.position() != data.len() {
            failures.push(format!(
                "  {} [{}]: decode left cursor at {} of {}",
                case.name,
                case.hex,
                reader.position(),
                data.len()
            ));
        }

        // skip_value consumes exactly the same bytes.
        let mut skipper = Decoder::new(&data);
        match skipper.skip_value() {
            Ok(skipped) => {
                if skipped != raw {
                    failures.push(format!(
                        "  {} [{}]: skip span {} != decode span {}",
                        case.name,
                        case.hex,
                        hex_of(skipped),
                        hex_of(raw)
                    ));
                }
                if skipper.position() != reader.position() {
                    failures.push(format!(
                        "  {} [{}]: skip cursor {} != decode cursor {}",
                        case.name,
                        case.hex,
                        skipper.position(),
                        reader.position()
                    ));
                }
            }
            Err(err) => failures.push(format!(
                "  {} [{}]: decode accepted but skip rejected: {err:?}",
                case.name, case.hex
            )),
        }

        // decode_one reports the same consumed length.
        match decode_one(&data) {
            Ok((_, consumed)) => {
                if consumed != data.len() {
                    failures.push(format!(
                        "  {} [{}]: decode_one consumed {} of {}",
                        case.name,
                        case.hex,
                        consumed,
                        data.len()
                    ));
                }
            }
            Err(err) => failures.push(format!(
                "  {} [{}]: decode_one failed: {err:?}",
                case.name, case.hex
            )),
        }
    }

    assert!(
        checked >= 100,
        "only {checked} accepted vectors were spanned"
    );
    assert!(
        failures.is_empty(),
        "{} span mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The same span check with the vector embedded mid-stream, which is how the
/// real code meets it: the body is the second byte onward of a transaction and
/// the witness set follows it immediately. A span that is right only at offset
/// zero would pass the test above and still corrupt a transaction hash.
#[test]
fn accepted_vectors_have_exact_spans_when_embedded() {
    let mut failures = Vec::new();

    for case in vectors() {
        if matches!(case.expect, Expect::Err(_)) {
            continue;
        }
        let inner = unhex(&case.hex);
        // [ <vector>, 1 ] — the sentinel proves the cursor stopped in the
        // right place rather than running to the end of the buffer.
        let mut framed = vec![0x82];
        framed.extend_from_slice(&inner);
        framed.push(0x01);

        let mut decoder = Decoder::new(&framed);
        assert_eq!(
            decoder.container_header(4),
            Ok(Some(2)),
            "{}: frame header",
            case.name
        );
        match decoder.decode_value_raw() {
            Ok((_, raw)) => {
                if raw != inner.as_slice() {
                    failures.push(format!(
                        "  {} [{}]: embedded span {} != vector",
                        case.name,
                        case.hex,
                        hex_of(raw)
                    ));
                    continue;
                }
            }
            Err(err) => {
                failures.push(format!(
                    "  {} [{}]: embedded decode failed: {err:?}",
                    case.name, case.hex
                ));
                continue;
            }
        }
        if decoder.decode_value() != Ok(Value::Int(1)) {
            failures.push(format!(
                "  {} [{}]: sentinel after the vector was not read back",
                case.name, case.hex
            ));
            continue;
        }
        if !decoder.is_at_end() {
            failures.push(format!(
                "  {} [{}]: {} bytes left after the frame",
                case.name,
                case.hex,
                framed.len() - decoder.position()
            ));
        }

        // skip_value must land on the same sentinel.
        let mut skipper = Decoder::new(&framed);
        skipper.container_header(4).expect("frame header");
        match skipper.skip_value() {
            Ok(skipped) if skipped == inner.as_slice() => {}
            other => failures.push(format!(
                "  {} [{}]: embedded skip mismatch: {other:?}",
                case.name, case.hex
            )),
        }
    }

    assert!(
        failures.is_empty(),
        "{} embedded span mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Rejected vectors must be rejected by `skip_value` too, with the same error.
/// Acceptance parity between the two traversals is what keeps `tx_id` (which
/// skips) from disagreeing with the validators (which decode); error parity is
/// what keeps the message a caller sees from depending on which traversal ran.
#[test]
fn skip_and_decode_agree_on_rejection() {
    let mut variant_mismatches = Vec::new();
    let mut acceptance_mismatches = Vec::new();

    for case in vectors() {
        if !matches!(case.expect, Expect::Err(_)) {
            continue;
        }
        let data = unhex(&case.hex);
        // decode_exact's trailing-data check is not part of skip_value, so
        // compare the single-value paths directly.
        let decoded = Decoder::new(&data).decode_value();
        let skipped = Decoder::new(&data).skip_value();

        match (decoded, skipped) {
            (Err(decode_err), Err(skip_err)) => {
                if decode_err != skip_err {
                    variant_mismatches.push(format!(
                        "  {} [{}]: decode {decode_err:?} vs skip {skip_err:?}",
                        case.name, case.hex
                    ));
                }
            }
            (Ok(_), Ok(_)) => {
                // Trailing-data cases: both accept the leading value.
                assert!(
                    case.name.starts_with("trailing/"),
                    "{} [{}] was expected to be rejected but both paths accepted it",
                    case.name,
                    case.hex
                );
            }
            (decoded, skipped) => acceptance_mismatches.push(format!(
                "  {} [{}]: decode {decoded:?} vs skip {skipped:?}",
                case.name, case.hex
            )),
        }
    }

    assert!(
        acceptance_mismatches.is_empty(),
        "skip and decode disagree on ACCEPTANCE (this is the dangerous kind):\n{}",
        acceptance_mismatches.join("\n")
    );

    assert!(
        variant_mismatches.is_empty(),
        "skip and decode report different error variants:\n{}",
        variant_mismatches.join("\n")
    );
}

/// The inputs that used to make `skip_value` and `decode_value` report
/// *different* errors: `skip_at` peeked the bignum payload's major type and
/// answered "invalid bignum value" before the payload's own problem could
/// surface. It now walks the payload and checks its type afterwards, exactly
/// as `apply_tag` does, so both traversals report the same error.
#[test]
fn bignum_payload_errors_are_the_same_from_skip_and_decode() {
    for (hex, expected) in [
        // Bare tag head, no payload at all.
        ("c2", CborError::Truncated),
        ("c3", CborError::Truncated),
        // Non-minimal spelling of tag 2 reaches the same branch.
        ("d802", CborError::Truncated),
        // Payload head is a truncated integer.
        ("c218", CborError::Truncated),
        // Payload head uses reserved additional info.
        (
            "c21c",
            CborError::Malformed("reserved CBOR additional information"),
        ),
        // Payload head is an indefinite integer, which no major type allows.
        (
            "c21f",
            CborError::Malformed("indefinite length is not valid for this CBOR major type"),
        ),
        // Payload head is a stray break.
        ("c2ff", CborError::Malformed("unexpected CBOR break")),
        // Payload is a text string that is not UTF-8.
        ("c2618b", CborError::InvalidUtf8),
        // Payload is a nested container that runs out mid-way.
        ("c282", CborError::Truncated),
    ] {
        let data = unhex(hex);
        assert_eq!(
            Decoder::new(&data).decode_value(),
            Err(expected.clone()),
            "{hex}: decode"
        );
        assert_eq!(
            Decoder::new(&data).skip_value(),
            Err(expected),
            "{hex}: skip must report the payload's own error, not the bignum check"
        );
    }

    // Where the payload decodes cleanly but is the wrong type, both agree.
    for hex in ["c201", "c301", "c280", "c2f5"] {
        let data = unhex(hex);
        assert_eq!(
            Decoder::new(&data).decode_value(),
            Err(CborError::Malformed("invalid bignum value")),
            "{hex}: decode"
        );
        assert_eq!(
            Decoder::new(&data).skip_value(),
            Err(CborError::Malformed("invalid bignum value")),
            "{hex}: skip"
        );
    }
}

/// How `skip_value` compared to `decode_value` on one input.
///
/// There is no longer an exempted class: the two traversals must agree on
/// acceptance, on the span, and on the exact error. The bignum short-circuit
/// that used to live here is fixed, and
/// `bignum_payload_errors_are_the_same_from_skip_and_decode` pins the inputs
/// it used to affect.
#[derive(PartialEq, Eq)]
enum Verdict {
    /// Same acceptance, same bytes consumed, same error.
    Agree,
    /// Anything else: a real disagreement.
    Disagree(String),
}

/// Compare the two traversals over one input. Shared by both sweeps.
fn compare_skip_and_decode(data: &[u8]) -> Verdict {
    let mut reader = Decoder::new(data);
    let decoded = reader.decode_value_raw().map(|(_, raw)| raw.len());
    let mut skipper = Decoder::new(data);
    let skipped = skipper.skip_value().map(<[u8]>::len);

    match (decoded, skipped) {
        (Ok(decode_len), Ok(skip_len)) => {
            if decode_len == skip_len && reader.position() == skipper.position() {
                Verdict::Agree
            } else {
                Verdict::Disagree(format!(
                    "{}: decode consumed {decode_len}, skip consumed {skip_len}",
                    hex_of(data)
                ))
            }
        }
        (Err(decode_err), Err(skip_err)) => {
            if decode_err == skip_err {
                Verdict::Agree
            } else {
                Verdict::Disagree(format!(
                    "{}: decode {decode_err:?} vs skip {skip_err:?}",
                    hex_of(data)
                ))
            }
        }
        (decoded, skipped) => Verdict::Disagree(format!(
            "{}: ACCEPTANCE MISMATCH decode {decoded:?} vs skip {skipped:?}",
            hex_of(data)
        )),
    }
}

/// Exhaustive proof over every 1- and 2-byte input (65 792 of them) that
/// `skip_value` and `decode_value` agree on acceptance, on the number of bytes
/// consumed, and on the error when they reject. Short inputs are where head
/// handling lives, so this is a complete check of the head decoder rather than
/// a sample. Runs in a few milliseconds.
///
/// Acceptance parity is the property that matters: `signature::tx_id` locates
/// the body by *skipping* while the validators *decode* it, so an input that
/// one accepts and the other rejects would mean the two views of the same
/// transaction disagree.
#[test]
fn exhaustive_short_inputs_agree_between_skip_and_decode() {
    let mut inputs: Vec<Vec<u8>> = (0..=u8::MAX).map(|byte| vec![byte]).collect();
    for first in 0..=u8::MAX {
        for second in 0..=u8::MAX {
            inputs.push(vec![first, second]);
        }
    }
    assert_eq!(inputs.len(), 256 + 65536);

    let mut disagreements = Vec::new();
    for data in &inputs {
        match compare_skip_and_decode(data) {
            Verdict::Agree => {}
            Verdict::Disagree(detail) => disagreements.push(format!("  {detail}")),
        }
    }

    // Zero exemptions. This was 442 before the bignum short-circuit was fixed.
    assert!(
        disagreements.is_empty(),
        "{} of {} short inputs disagree:\n{}",
        disagreements.len(),
        inputs.len(),
        disagreements
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The same sweep over all 16 777 216 three-byte inputs — every possible CBOR
/// head plus two payload bytes, which reaches every branch of both traversals
/// including the tag, chunk, and container paths. About 2.5 s in debug, so it
/// runs by default rather than behind `--ignored`; it is the strongest
/// acceptance-parity evidence in the file.
#[test]
fn exhaustive_three_byte_inputs_agree_between_skip_and_decode() {
    let mut disagreements = Vec::new();
    for value in 0u32..0x0100_0000 {
        let data = [(value >> 16) as u8, (value >> 8) as u8, value as u8];
        match compare_skip_and_decode(&data) {
            Verdict::Agree => {}
            Verdict::Disagree(detail) => {
                if disagreements.len() < 20 {
                    disagreements.push(format!("  {detail}"));
                }
            }
        }
    }
    // Zero exemptions. This was 110 456 before the bignum short-circuit fix.
    assert!(
        disagreements.is_empty(),
        "three-byte inputs disagree:\n{}",
        disagreements.join("\n")
    );
}

// --- encoders ---------------------------------------------------------------

/// For the Appendix A entries whose shape the crate can encode — unsigned
/// integers, signed integers, byte strings, definite arrays, and raw heads —
/// the encoders must reproduce the vector's exact bytes. The crate has no
/// encoder for text, maps, tags, floats, simple values, or indefinite forms;
/// those are skipped rather than faked.
#[test]
fn crate_encoders_reproduce_round_trippable_vectors() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        // major 0
        ("00", encode_uint(0)),
        ("01", encode_uint(1)),
        ("0a", encode_uint(10)),
        ("17", encode_uint(23)),
        ("1818", encode_uint(24)),
        ("1819", encode_uint(25)),
        ("1864", encode_uint(100)),
        ("1903e8", encode_uint(1000)),
        ("1a000f4240", encode_uint(1_000_000)),
        ("1b000000e8d4a51000", encode_uint(1_000_000_000_000)),
        ("1bffffffffffffffff", encode_uint(u64::MAX)),
        // major 0 via encode_int
        ("00", encode_int(0)),
        ("17", encode_int(23)),
        ("1818", encode_int(24)),
        ("18ff", encode_int(255)),
        ("190100", encode_int(256)),
        ("19ffff", encode_int(65535)),
        ("1a00010000", encode_int(65536)),
        ("1affffffff", encode_int(4_294_967_295)),
        ("1b0000000100000000", encode_int(4_294_967_296)),
        ("1b7fffffffffffffff", encode_int(i64::MAX)),
        // major 1
        ("20", encode_int(-1)),
        ("29", encode_int(-10)),
        ("37", encode_int(-24)),
        ("3818", encode_int(-25)),
        ("3863", encode_int(-100)),
        ("38ff", encode_int(-256)),
        ("390100", encode_int(-257)),
        ("3903e7", encode_int(-1000)),
        ("39ffff", encode_int(-65536)),
        ("3a00010000", encode_int(-65537)),
        ("3affffffff", encode_int(-4_294_967_296)),
        ("3b0000000100000000", encode_int(-4_294_967_297)),
        ("3b7fffffffffffffff", encode_int(i64::MIN)),
        // -18446744073709551616 exceeds i64; the head encoder still reaches it.
        ("3bffffffffffffffff", encode_head(1, u64::MAX)),
        // major 2
        ("40", encode_bytes(&[])),
        ("4401020304", encode_bytes(&[1, 2, 3, 4])),
        // major 3 head + literal payload (no text encoder in the crate)
        ("6449455446", {
            let mut out = encode_head(3, 4);
            out.extend_from_slice(b"IETF");
            out
        }),
        ("60", encode_head(3, 0)),
        // major 4
        ("80", encode_array(&[])),
        (
            "83010203",
            encode_array(&[encode_uint(1), encode_uint(2), encode_uint(3)]),
        ),
        (
            "8301820203820405",
            encode_array(&[
                encode_uint(1),
                encode_array(&[encode_uint(2), encode_uint(3)]),
                encode_array(&[encode_uint(4), encode_uint(5)]),
            ]),
        ),
        (
            "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
            encode_array(&(1..=25u64).map(encode_uint).collect::<Vec<_>>()),
        ),
        // major 5 head + already-encoded entries
        ("a0", encode_head(5, 0)),
        ("a201020304", {
            let mut out = encode_head(5, 2);
            for value in [1u64, 2, 3, 4] {
                out.extend_from_slice(&encode_uint(value));
            }
            out
        }),
        // major 6 heads (the crate never encodes tag content itself)
        ("d90102", encode_head(6, 258)),
        ("c2", encode_head(6, 2)),
        ("d818", encode_head(6, 24)),
        ("d82076", {
            let mut out = encode_head(6, 32);
            out.extend_from_slice(&encode_head(3, 22));
            out
        }),
        // head-width boundaries for a container major
        ("97", encode_head(4, 23)),
        ("9818", encode_head(4, 24)),
        ("990100", encode_head(4, 256)),
        ("9a00010000", encode_head(4, 65536)),
        ("9b0000000100000000", encode_head(4, 4_294_967_296)),
    ];

    let mut failures = Vec::new();
    for (expected, produced) in &cases {
        let actual = hex_of(produced);
        if &actual != expected {
            failures.push(format!("  expected {expected}, produced {actual}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} encoder mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );

    // Everything the encoders produce must survive a decode round trip.
    for (expected, produced) in &cases {
        let decoded_from_vector = decode_one(&unhex(expected));
        let decoded_from_encoder = decode_one(produced);
        assert_eq!(
            decoded_from_vector.is_ok(),
            decoded_from_encoder.is_ok(),
            "{expected}: vector and encoder output disagree on decodability"
        );
    }
}

/// The encoders always choose the minimal head, matching `cbor2.dumps`. A
/// wider-than-necessary head would still decode, so only a byte comparison
/// catches it.
#[test]
fn encoders_choose_minimal_heads_at_every_boundary() {
    for (argument, expected_len) in [
        (0u64, 1usize),
        (23, 1),
        (24, 2),
        (255, 2),
        (256, 3),
        (65535, 3),
        (65536, 5),
        (4_294_967_295, 5),
        (4_294_967_296, 9),
        (u64::MAX, 9),
    ] {
        for major in 0u8..=7 {
            let head = encode_head(major, argument);
            assert_eq!(
                head.len(),
                expected_len,
                "major {major} argument {argument} head {}",
                hex_of(&head)
            );
            assert_eq!(head[0] >> 5, major, "major bits for {argument}");
        }
        assert_eq!(encode_uint(argument).len(), expected_len);
    }
    // A byte string's head follows the same widths, with the payload after it.
    for (len, expected_head) in [(0usize, "40"), (23, "57"), (24, "5818"), (256, "590100")] {
        let encoded = encode_bytes(&vec![0u8; len]);
        assert_eq!(
            hex_of(&encoded[..expected_head.len() / 2]),
            expected_head,
            "byte string of {len}"
        );
        assert_eq!(encoded.len(), expected_head.len() / 2 + len);
    }
}
