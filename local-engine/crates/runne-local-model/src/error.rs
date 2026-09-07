//! Typed manifest errors. Variants are matched by tests via their
//! `Debug`/`Display` names — keep names stable.

use std::fmt;

#[derive(Debug)]
#[non_exhaustive]
pub enum ManifestError {
    InvalidUtf8,
    /// Duplicate object key at byte offset.
    DuplicateKey(usize),
    /// Syntactically invalid JSON.
    Json(String),
    /// V1 number restriction violated (float, negative or > 2^53-1).
    Number(String),
    /// Supplied bytes are not the canonical JCS serialization.
    NonCanonical,
    /// Schema violation: unknown member, wrong type or missing field.
    Schema(String),
    /// Declared `manifestDigest` malformed or mismatched.
    Digest(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 => write!(f, "manifest is not valid UTF-8"),
            Self::DuplicateKey(off) => write!(f, "duplicate object key at byte {off}"),
            Self::Json(m) => write!(f, "invalid JSON: {m}"),
            Self::Number(m) => write!(f, "V1 number restriction: {m}"),
            Self::NonCanonical => write!(f, "input is not in canonical JCS form: NonCanonical"),
            Self::Schema(m) => write!(f, "schema violation: {m}"),
            Self::Digest(m) => write!(f, "manifest digest mismatch: {m}"),
        }
    }
}

impl std::error::Error for ManifestError {}

impl From<serde_json::Error> for ManifestError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err.to_string())
    }
}
