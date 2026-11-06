use std::fmt;
use std::num::NonZeroUsize;

pub const DEFAULT_STREAM_CAPACITY: usize = 32;
pub const DEFAULT_MAX_LINE_LEN: usize = 1_048_576;

const DEFAULT_CAPACITY: NonZeroUsize = match NonZeroUsize::new(DEFAULT_STREAM_CAPACITY) {
    Some(value) => value,
    None => panic!("DEFAULT_STREAM_CAPACITY is zero"),
};
const DEFAULT_MAX_LINE: NonZeroUsize = match NonZeroUsize::new(DEFAULT_MAX_LINE_LEN) {
    Some(value) => value,
    None => panic!("DEFAULT_MAX_LINE_LEN is zero"),
};

const _: () = assert!(DEFAULT_STREAM_CAPACITY > 0 && DEFAULT_MAX_LINE_LEN > 0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamLimits {
    capacity: NonZeroUsize,
    max_line_len: NonZeroUsize,
}

impl StreamLimits {
    pub const fn with_capacity(mut self, capacity: usize) -> Result<Self, LimitsError> {
        match NonZeroUsize::new(capacity) {
            Some(capacity) => {
                self.capacity = capacity;
                Ok(self)
            }
            None => Err(LimitsError::ZeroCapacity),
        }
    }

    pub const fn with_max_line_len(mut self, max_line_len: usize) -> Result<Self, LimitsError> {
        match NonZeroUsize::new(max_line_len) {
            Some(max_line_len) => {
                self.max_line_len = max_line_len;
                Ok(self)
            }
            None => Err(LimitsError::ZeroMaxLineLen),
        }
    }

    pub const fn capacity(self) -> usize {
        self.capacity.get()
    }

    pub const fn max_line_len(self) -> usize {
        self.max_line_len.get()
    }

    pub const fn max_retained_line_bytes(self) -> usize {
        retained_line_bytes(self.capacity(), self.max_line_len())
    }
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_CAPACITY,
            max_line_len: DEFAULT_MAX_LINE,
        }
    }
}

const fn retained_line_bytes(capacity: usize, max_line_len: usize) -> usize {
    let slots = match capacity.checked_add(2) {
        Some(slots) => slots,
        None => panic!("retained line bytes overflowed usize"),
    };
    let lines = match slots.checked_mul(max_line_len) {
        Some(lines) => lines,
        None => panic!("retained line bytes overflowed usize"),
    };
    match lines.checked_add(READ_CHUNK) {
        Some(total) => total,
        None => panic!("retained line bytes overflowed usize"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitsError {
    ZeroCapacity,
    ZeroMaxLineLen,
}

impl fmt::Display for LimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            LimitsError::ZeroCapacity => "capacity must be greater than zero",
            LimitsError::ZeroMaxLineLen => "max_line_len must be greater than zero",
        })
    }
}

impl std::error::Error for LimitsError {}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditReceiptCounts {
    pub ok: u64,
    pub invalid: u64,
    pub malformed: u64,
}

impl AuditReceiptCounts {
    pub const fn lines(self) -> u128 {
        self.ok as u128 + self.invalid as u128 + self.malformed as u128
    }
}

#[cfg_attr(not(test), allow(dead_code))]
enum LineClass {
    Ok,
    Invalid,
    Malformed,
}

#[cfg_attr(not(test), allow(dead_code))]
fn classify_line(body: &[u8], key: &[u8]) -> LineClass {
    if crate::verify_audit_receipt_bytes(body, key) {
        LineClass::Ok
    } else if crate::parse::parse(body).is_ok() {
        LineClass::Invalid
    } else {
        LineClass::Malformed
    }
}

const READ_CHUNK: usize = 8192;

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::{
        classify_line, AuditReceiptCounts, LimitsError, LineClass, StreamLimits,
        DEFAULT_MAX_LINE_LEN, DEFAULT_STREAM_CAPACITY, READ_CHUNK,
    };
    use crate::{parse::parse, Json, Wtf16};

    #[test]
    fn limits_reject_zero_and_name_the_ceiling() {
        let limits = StreamLimits::default();
        assert_eq!(limits.capacity(), DEFAULT_STREAM_CAPACITY);
        assert_eq!(limits.max_line_len(), DEFAULT_MAX_LINE_LEN);
        assert_eq!(
            limits.max_retained_line_bytes(),
            (DEFAULT_STREAM_CAPACITY + 2) * DEFAULT_MAX_LINE_LEN + READ_CHUNK
        );
        assert_eq!(
            limits.with_capacity(0).unwrap_err(),
            LimitsError::ZeroCapacity
        );
        assert_eq!(
            limits.with_max_line_len(0).unwrap_err(),
            LimitsError::ZeroMaxLineLen
        );
        let tight = limits
            .with_capacity(1)
            .expect("capacity")
            .with_max_line_len(4)
            .expect("max line");
        assert_eq!(tight.capacity(), 1);
        assert_eq!(tight.max_line_len(), 4);
        assert_eq!(
            LimitsError::ZeroCapacity.to_string(),
            "capacity must be greater than zero"
        );
        assert_eq!(
            LimitsError::ZeroMaxLineLen.to_string(),
            "max_line_len must be greater than zero"
        );
        let counts = AuditReceiptCounts {
            ok: 1,
            invalid: 2,
            malformed: 3,
        };
        assert_eq!(counts.lines(), 6);
    }

    #[test]
    fn classify_line_matches_bytes_verify_on_compact_v1() {
        let (body, key) = v1_body_and_key();
        assert!(crate::verify_audit_receipt_bytes(&body, &key));
        assert!(matches!(classify_line(&body, &key), LineClass::Ok));
        let mut tampered = body.clone();
        flip_signature_hex(&mut tampered);
        assert!(!crate::verify_audit_receipt_bytes(&tampered, &key));
        assert!(parse(&tampered).is_ok());
        assert!(matches!(classify_line(&tampered, &key), LineClass::Invalid));
    }

    #[test]
    fn classify_line_marks_empty_whitespace_and_bad_json_malformed() {
        let (_body, key) = v1_body_and_key();
        let malformed: &[&[u8]] = &[
            b"",
            b" ",
            b"\t",
            b"\r",
            b" \t\r",
            b"{\"a\":1,\"a\":2}",
            b"{}{}",
            b"1 2",
            b"\xff",
        ];
        for body in malformed {
            assert!(
                matches!(classify_line(body, &key), LineClass::Malformed),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        assert!(matches!(
            classify_line(&nested_arrays(129), &key),
            LineClass::Malformed
        ));
        assert!(matches!(
            classify_line(&nested_arrays(128), &key),
            LineClass::Invalid
        ));
    }

    fn nested_arrays(depth: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(depth * 2 + 1);
        bytes.extend(std::iter::repeat(b'[').take(depth));
        bytes.push(b'0');
        bytes.extend(std::iter::repeat(b']').take(depth));
        bytes
    }

    fn vectors_root() -> &'static Json {
        static ROOT: OnceLock<Json> = OnceLock::new();
        ROOT.get_or_init(|| {
            let raw = include_bytes!("../../../vectors/reference/vectors.json");
            parse(raw).expect("vectors.json")
        })
    }

    fn v1_body_and_key() -> (Vec<u8>, Vec<u8>) {
        let root = vectors_root();
        let rows = field(root, "vectors").as_array().expect("vectors");
        for row in rows {
            if json_str(field(row, "name")) == "hmac-audit-receipt-valid" {
                let input = field(row, "input");
                let key = json_str(field(input, "signingKeyUtf8")).into_bytes();
                let body = crate::canonical_json_value(field(input, "receipt")).expect("canonical");
                return (body, key);
            }
        }
        panic!("missing hmac-audit-receipt-valid");
    }

    fn field<'a>(value: &'a Json, name: &str) -> &'a Json {
        let want = Wtf16::from_str(name);
        value
            .as_object()
            .expect("object")
            .iter()
            .find(|(key, _)| key == &want)
            .map(|(_, item)| item)
            .unwrap_or_else(|| panic!("missing {name}"))
    }

    fn json_str(value: &Json) -> String {
        String::from_utf16(value.as_string().expect("string").units()).expect("utf-16")
    }

    fn flip_signature_hex(bytes: &mut [u8]) {
        let marker = b"\"signature\":\"";
        let start = bytes
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("signature")
            + marker.len();
        bytes[start] = if bytes[start] == b'a' { b'b' } else { b'a' };
    }
}
