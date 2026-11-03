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

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Error {}

/// Provisional canonical JSON bytes. Not the receipt spec.
pub fn canonicalize_bytes(input: &[u8]) -> Result<Vec<u8>, Error> {
    let text = std::str::from_utf8(input).map_err(|_| Error::NotUtf8)?;
    let value: serde_json::Value = serde_json::from_str(text).map_err(|_| Error::InvalidJson)?;
    serde_json::to_vec(&value).map_err(|_| Error::InvalidJson)
}
