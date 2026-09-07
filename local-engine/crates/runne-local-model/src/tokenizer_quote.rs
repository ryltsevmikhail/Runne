//! Bounded offline tokenizer quote (REQ-PROV-125): exact, deterministic
//! token counting for REGISTERED tokenizer revisions only. Heuristic
//! estimates (`char/4` and friends) are banned — an unregistered or
//! ambiguous revision refuses instead of guessing. The worker-side
//! cross-check re-runs the same revision on load; a mismatch is a
//! typed reject.

use crate::error::ManifestError;

/// Registered tokenizer quote revisions. A manifest pins one; adding a
/// revision is a contract change (new entry + golden vectors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteRevision {
    /// Exact byte count: one token per byte. Trivially exact for
    /// qualification fixtures and the lower-bound cross-check.
    IdentityBytesV1,
    /// Exact count of Unicode scalar values (each char is at least one
    /// token under every registered vocab; used as the floor quote).
    Utf8CharsV1,
}

impl QuoteRevision {
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "identity-bytes-v1" => Self::IdentityBytesV1,
            "utf8-chars-v1" => Self::Utf8CharsV1,
            _ => return None,
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::IdentityBytesV1 => "identity-bytes-v1",
            Self::Utf8CharsV1 => "utf8-chars-v1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuoteError {
    /// Revision not registered: refuse, never estimate.
    UnknownRevision(String),
    /// Input is not valid UTF-8 for a char-based revision.
    InvalidUtf8,
}

impl std::fmt::Display for QuoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownRevision(r) => write!(f, "unknown tokenizer quote revision: {r}"),
            Self::InvalidUtf8 => write!(f, "rendered input is not valid UTF-8"),
        }
    }
}

impl std::error::Error for QuoteError {}

impl From<QuoteError> for ManifestError {
    fn from(e: QuoteError) -> Self {
        match e {
            QuoteError::UnknownRevision(r) => {
                ManifestError::Schema(format!("unknown tokenizer quote revision: {r}"))
            }
            QuoteError::InvalidUtf8 => ManifestError::InvalidUtf8,
        }
    }
}

/// Exact token quote for the rendered input under the pinned revision.
/// Deterministic: same bytes + same revision → same count.
pub fn token_quote(revision: QuoteRevision, rendered: &[u8]) -> Result<u64, QuoteError> {
    match revision {
        QuoteRevision::IdentityBytesV1 => {
            u64::try_from(rendered.len()).map_err(|_| QuoteError::InvalidUtf8)
        }
        QuoteRevision::Utf8CharsV1 => {
            let s = std::str::from_utf8(rendered).map_err(|_| QuoteError::InvalidUtf8)?;
            u64::try_from(s.chars().count()).map_err(|_| QuoteError::InvalidUtf8)
        }
    }
}

/// Parses the revision name from manifest tokenizer metadata.
pub fn revision_from_name(name: &str) -> Result<QuoteRevision, QuoteError> {
    QuoteRevision::from_name(name).ok_or_else(|| QuoteError::UnknownRevision(name.to_string()))
}
