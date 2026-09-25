use thiserror::Error;

/// Maximum normalized identifier size shared by provider adapter intake.
pub const MAX_IDENTIFIER_BYTES: usize = 128;

/// Identifier field used in a safe normalization error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierKind {
    /// Provider namespace.
    Provider,
    /// Provider model family.
    Model,
    /// Immutable model revision.
    Revision,
}

/// Bounded identifier normalization failure without the rejected value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IdentifierError {
    /// The normalized value is empty.
    #[error("{kind:?} identifier is empty")]
    Empty {
        /// Identifier field.
        kind: IdentifierKind,
    },
    /// The normalized value exceeds the shared bound.
    #[error("{kind:?} identifier exceeds {max} bytes (actual {actual})")]
    TooLong {
        /// Identifier field.
        kind: IdentifierKind,
        /// Maximum accepted bytes.
        max: usize,
        /// Rejected byte count.
        actual: usize,
    },
    /// The normalized value is not printable ASCII.
    #[error("{kind:?} identifier contains an invalid character")]
    InvalidCharacter {
        /// Identifier field.
        kind: IdentifierKind,
    },
}

/// Canonical provider/model/revision tuple used by conformance intake tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedIdentifiers {
    provider_id: String,
    model_id: String,
    revision: String,
}

impl NormalizedIdentifiers {
    /// Returns the canonical provider namespace.
    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    /// Returns the canonical model family.
    #[must_use]
    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    /// Returns the canonical immutable revision.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }
}

/// Trims ASCII-adjacent whitespace, lowercases ASCII, and validates one tuple.
///
/// # Errors
///
/// Returns [`IdentifierError`] when any field is empty, oversized, or contains
/// a non-printable/non-ASCII character.
pub fn normalize_identifier(
    provider_id: &str,
    model_id: &str,
    revision: &str,
) -> Result<NormalizedIdentifiers, IdentifierError> {
    Ok(NormalizedIdentifiers {
        provider_id: normalize_one(IdentifierKind::Provider, provider_id)?,
        model_id: normalize_one(IdentifierKind::Model, model_id)?,
        revision: normalize_one(IdentifierKind::Revision, revision)?,
    })
}

fn normalize_one(kind: IdentifierKind, raw: &str) -> Result<String, IdentifierError> {
    let value = raw.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Err(IdentifierError::Empty { kind });
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(IdentifierError::TooLong {
            kind,
            max: MAX_IDENTIFIER_BYTES,
            actual: value.len(),
        });
    }
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(IdentifierError::InvalidCharacter { kind });
    }
    Ok(value)
}
