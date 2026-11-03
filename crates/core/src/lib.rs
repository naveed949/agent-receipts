use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// Name reserved for a parsed receipt. No constructor in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    _private: (),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NotUtf8,
    InvalidJson,
}

impl Error {
    /// Stable code copied onto host exceptions.
    pub fn code(self) -> &'static str {
        match self {
            Error::NotUtf8 => "not_utf8",
            Error::InvalidJson => "invalid_json",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Error {}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor).map(StrictValue)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_i128<E: de::Error>(self, value: i128) -> Result<Value, E> {
        Number::deserialize(de::value::I128Deserializer::new(value)).map(Value::Number)
    }

    fn visit_u128<E: de::Error>(self, value: u128) -> Result<Value, E> {
        Number::deserialize(de::value::U128Deserializer::new(value)).map(Value::Number)
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| de::Error::custom("non-finite number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        Deserialize::deserialize(deserializer).map(|StrictValue(value)| value)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(StrictValue(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        while let Some((key, StrictValue(value))) = map.next_entry::<String, StrictValue>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom("duplicate key"));
            }
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

/// Provisional canonical JSON bytes. Not the receipt spec.
pub fn canonicalize_bytes(input: &[u8]) -> Result<Vec<u8>, Error> {
    let text = std::str::from_utf8(input).map_err(|_| Error::NotUtf8)?;
    let StrictValue(value) = serde_json::from_str(text).map_err(|_| Error::InvalidJson)?;
    serde_json::to_vec(&value).map_err(|_| Error::InvalidJson)
}
