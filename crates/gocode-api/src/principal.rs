//! API command identities and their validation.

use crate::types::ResponseSeed;

/// Maximum UTF-8 byte length of an API principal or actor identifier.
pub const MAX_API_IDENTITY_BYTES: usize = 256;

/// Bounded, non-empty principal identifier without NUL or ASCII control bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApiPrincipalId(String);

impl ApiPrincipalId {
    /// Validates and creates a principal identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, PrincipalError> {
        let value = value.into();
        validate_api_identity(&value)?;
        Ok(Self(value))
    }

    /// Returns the validated principal identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded, non-empty actor identifier without NUL or ASCII control bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApiActor(String);

impl ApiActor {
    /// Validates and creates an actor identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, PrincipalError> {
        let value = value.into();
        validate_api_identity(&value)?;
        Ok(Self(value))
    }

    /// Returns the validated actor identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable reason an API principal or actor identifier was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalError {
    /// The identifier is empty.
    Empty,
    /// The identifier exceeded its maximum UTF-8 byte length.
    TooLong {
        /// The permitted maximum byte length.
        max: usize,
        /// The actual UTF-8 byte length.
        actual: usize,
    },
    /// The identifier contains a forbidden ASCII byte.
    InvalidChar {
        /// Zero-based byte offset of the invalid byte.
        position: usize,
        /// The invalid byte.
        byte: u8,
    },
}

fn validate_api_identity(value: &str) -> Result<(), PrincipalError> {
    if value.is_empty() {
        return Err(PrincipalError::Empty);
    }
    if value.len() > MAX_API_IDENTITY_BYTES {
        return Err(PrincipalError::TooLong {
            max: MAX_API_IDENTITY_BYTES,
            actual: value.len(),
        });
    }
    if let Some((position, byte)) = value
        .bytes()
        .enumerate()
        .find(|(_, byte)| *byte == 0 || *byte < 0x20 || *byte == 0x7f)
    {
        return Err(PrincipalError::InvalidChar { position, byte });
    }
    Ok(())
}

/// Context carried by every API-level command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiCommandContext {
    /// Authenticated principal that authorized the command.
    pub principal: ApiPrincipalId,
    /// Actor that initiated the command.
    pub actor: ApiActor,
    /// Values needed to reconstruct a stable OpenCode response after recovery.
    pub response_seed: ResponseSeed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_principal_and_actor_identities() {
        assert!(ApiPrincipalId::new("user-1").is_ok());
        assert!(ApiActor::new("agent-1").is_ok());
    }

    #[test]
    fn rejects_empty_identities() {
        assert_eq!(ApiPrincipalId::new(""), Err(PrincipalError::Empty));
        assert_eq!(ApiActor::new(""), Err(PrincipalError::Empty));
    }

    #[test]
    fn rejects_control_bytes() {
        assert_eq!(
            ApiPrincipalId::new("bad\0char"),
            Err(PrincipalError::InvalidChar {
                position: 3,
                byte: 0,
            })
        );
        assert_eq!(
            ApiActor::new("bad\u{7f}char"),
            Err(PrincipalError::InvalidChar {
                position: 3,
                byte: 0x7f,
            })
        );
    }

    #[test]
    fn enforces_a_utf8_byte_bound() {
        let value = "x".repeat(MAX_API_IDENTITY_BYTES + 1);
        assert_eq!(
            ApiPrincipalId::new(value),
            Err(PrincipalError::TooLong {
                max: MAX_API_IDENTITY_BYTES,
                actual: MAX_API_IDENTITY_BYTES + 1,
            })
        );
    }
}
