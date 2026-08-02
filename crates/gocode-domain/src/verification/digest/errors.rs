/// Digest computation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestError {
    /// Hex string has wrong length (must be 64 chars).
    InvalidLength(usize),
    /// Hex string contains uppercase characters.
    UppercaseHex,
    /// Invalid hex characters.
    InvalidHex,
    /// Duplicate evidence ref in set.
    DuplicateEvidenceRef(crate::verification::identity::EvidenceRefID),
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(n) => write!(f, "invalid digest length: {} (expected 64)", n),
            Self::UppercaseHex => write!(f, "uppercase hex not allowed"),
            Self::InvalidHex => write!(f, "invalid hex characters"),
            Self::DuplicateEvidenceRef(id) => write!(f, "duplicate evidence ref: {}", id),
        }
    }
}

impl std::error::Error for DigestError {}
