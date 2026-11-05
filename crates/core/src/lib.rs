mod emit;
mod hmac;
pub(crate) mod parse;

use std::cmp::Ordering;
use std::fmt;

use sha2::{Digest, Sha256};

pub use hmac::{
    audit_mac_input_ascii, audit_signing_key, controlled_signing_key, resign_audit_receipt,
    resign_audit_receipt_bytes, sign_controlled_integrity, verify_audit_receipt,
    verify_audit_receipt_bytes, verify_controlled_integrity, verify_controlled_integrity_bytes,
    SignerError, SigningKey, AUDIT_RECEIPT_V2_VERSION, AUDIT_RECEIPT_VERSION,
    CONTROLLED_INTEGRITY_VERSION,
};

#[cfg(test)]
mod reference;

/// Maximum nested containers. The outermost container counts.
pub const MAX_DEPTH: usize = 128;

/// Name reserved for a parsed receipt. No constructor in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    _private: (),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NotUtf8,
    InvalidJson,
    TooDeep,
    Cycle,
    TypeError,
}

impl Error {
    /// Stable code copied onto host exceptions.
    pub fn code(self) -> &'static str {
        match self {
            Error::NotUtf8 => "not_utf8",
            Error::InvalidJson => "invalid_json",
            Error::TooDeep => "too_deep",
            Error::Cycle => "cycle",
            Error::TypeError => "type_error",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for Error {}

/// UTF-16 code units. Unpaired surrogates are valid data. This is not a Rust str.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wtf16 {
    units: Vec<u16>,
}

impl Wtf16 {
    pub fn from_units(units: Vec<u16>) -> Self {
        Self { units }
    }

    /// Encode each Unicode scalar. A Rust str has no unpaired surrogate.
    #[allow(clippy::should_implement_trait)] // Infallible. `FromStr` returns `Result`.
    pub fn from_str(text: &str) -> Self {
        Self {
            units: text.encode_utf16().collect(),
        }
    }

    pub fn units(&self) -> &[u16] {
        &self.units
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Finite(f64);

impl Finite {
    fn try_new(value: f64) -> Option<Self> {
        if !value.is_finite() {
            return None;
        }
        Some(Self(if value == 0.0 { 0.0 } else { value }))
    }

    fn get(self) -> f64 {
        self.0
    }
}

/// Owned JSON tree. Variants are private. A cycle cannot be represented.
#[derive(Clone, Debug, PartialEq)]
pub struct Json {
    node: Node,
}

#[derive(Clone, Debug, PartialEq)]
enum Node {
    Null,
    Bool(bool),
    Number(Finite),
    String(Wtf16),
    Array(Vec<Json>),
    Object(Vec<(Wtf16, Json)>),
}

impl Json {
    pub fn null() -> Self {
        Self { node: Node::Null }
    }

    pub fn bool(value: bool) -> Self {
        Self {
            node: Node::Bool(value),
        }
    }

    /// Non-finite input is `type_error`. `-0` is stored as `+0`.
    pub fn number(value: f64) -> Result<Self, Error> {
        Finite::try_new(value)
            .map(|finite| Self {
                node: Node::Number(finite),
            })
            .ok_or(Error::TypeError)
    }

    pub fn string(units: Wtf16) -> Self {
        Self {
            node: Node::String(units),
        }
    }

    pub fn array(items: Vec<Json>) -> Self {
        Self {
            node: Node::Array(items),
        }
    }

    /// Duplicate code-unit keys are `invalid_json`. Entries are stored in canonical key order.
    pub fn object(mut entries: Vec<(Wtf16, Json)>) -> Result<Self, Error> {
        entries.sort_by(|left, right| cmp_key(&left.0, &right.0));
        if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(Error::InvalidJson);
        }
        debug_assert!(entries
            .windows(2)
            .all(|pair| cmp_key(&pair[0].0, &pair[1].0).is_lt()));
        Ok(Self {
            node: Node::Object(entries),
        })
    }

    pub(crate) fn as_object(&self) -> Option<&[(Wtf16, Json)]> {
        match &self.node {
            Node::Object(entries) => Some(entries),
            _ => None,
        }
    }

    pub(crate) fn as_string(&self) -> Option<&Wtf16> {
        match &self.node {
            Node::String(text) => Some(text),
            _ => None,
        }
    }

    pub(crate) fn is_object(&self) -> bool {
        matches!(self.node, Node::Object(_))
    }
}

/// `depth` counts the container being entered. `128` succeeds and `129` is `too_deep`.
/// Scalars do not call this.
pub fn check_depth(depth: usize) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        Err(Error::TooDeep)
    } else {
        Ok(())
    }
}

pub fn canonical_json(input: &[u8]) -> Result<Vec<u8>, Error> {
    emit::emit(&parse::parse(input)?)
}

pub fn stable_hash(input: &[u8]) -> Result<String, Error> {
    Ok(sha256_hex(&canonical_json(input)?))
}

pub fn canonical_json_value(value: &Json) -> Result<Vec<u8>, Error> {
    emit::emit(value)
}

pub fn stable_hash_value(value: &Json) -> Result<String, Error> {
    Ok(sha256_hex(&canonical_json_value(value)?))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        hex.push(char::from(HEX[usize::from(byte >> 4)]));
        hex.push(char::from(HEX[usize::from(byte & 0x0F)]));
    }
    hex
}

fn cmp_key(left: &Wtf16, right: &Wtf16) -> Ordering {
    match (array_index(left.units()), array_index(right.units())) {
        (Some(left_index), Some(right_index)) => left_index.cmp(&right_index),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => left.units().cmp(right.units()),
    }
}

fn array_index(units: &[u16]) -> Option<u32> {
    if units.is_empty() || units.len() > 10 {
        return None;
    }
    if units.len() > 1 && units[0] == u16::from(b'0') {
        return None;
    }
    let mut value = 0u64;
    for &unit in units {
        let digit = ascii_digit(unit)?;
        value = value * 10 + digit;
    }
    // The last canonical array index is 2^32 - 2. 2^32 - 1 stays an ordinary string.
    if value > u64::from(u32::MAX - 1) {
        return None;
    }
    u32::try_from(value).ok()
}

fn ascii_digit(unit: u16) -> Option<u64> {
    if (u16::from(b'0')..=u16::from(b'9')).contains(&unit) {
        Some(u64::from(unit - u16::from(b'0')))
    } else {
        None
    }
}

#[cfg(test)]
mod invariants {
    use super::{Finite, Json, Node};

    #[test]
    fn negative_zero_clears_the_sign_bit() {
        let Json {
            node: Node::Number(Finite(number)),
        } = Json::number(-0.0).unwrap()
        else {
            panic!("expected a number");
        };
        assert!(number.is_sign_positive());
    }
}
