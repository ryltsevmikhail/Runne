//! Native-only credential prompt boundary.

use std::fmt;

use zeroize::Zeroizing;

/// Maximum accepted credential bytes, before a native writer can receive them.
pub const MAX_CREDENTIAL_BYTES: usize = 4096;

/// Closed result of a host-native credential prompt.
pub enum SecureCredentialPromptDisposition {
    Submitted(SecureCredentialMaterial),
    Confirmed,
    Cancelled,
    TimedOut,
}

impl fmt::Debug for SecureCredentialPromptDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Submitted(_) => {
                formatter.write_str("SecureCredentialPromptDisposition::Submitted(<redacted>)")
            }
            Self::Confirmed => formatter.write_str("SecureCredentialPromptDisposition::Confirmed"),
            Self::Cancelled => formatter.write_str("SecureCredentialPromptDisposition::Cancelled"),
            Self::TimedOut => formatter.write_str("SecureCredentialPromptDisposition::TimedOut"),
        }
    }
}

/// A bounded, zeroizing credential buffer. It has no serialization representation.
pub struct SecureCredentialMaterial(CredentialPipeBytes);

impl SecureCredentialMaterial {
    /// Validates material before it enters host-owned memory.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for empty, oversized, or line-control material.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SecureCredentialPromptError> {
        Self::from_zeroizing(Zeroizing::new(bytes))
    }

    /// Validates material already held in zeroizing native storage.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for empty, oversized, or line-control material.
    pub fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Result<Self, SecureCredentialPromptError> {
        if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_BYTES {
            return Err(SecureCredentialPromptError::Rejected);
        }
        if bytes.iter().any(|byte| matches!(*byte, 0 | b'\n' | b'\r')) {
            return Err(SecureCredentialPromptError::Rejected);
        }
        Ok(Self(CredentialPipeBytes(bytes)))
    }

    /// Consumes the material only at the native writer pipe boundary.
    #[must_use]
    pub fn into_pipe_bytes(self) -> CredentialPipeBytes {
        self.0
    }
}

/// Transfer-only credential bytes. They are zeroed if the writer pipe closes.
pub struct CredentialPipeBytes(Zeroizing<Vec<u8>>);

impl CredentialPipeBytes {
    /// Moves the host-owned bytes into the authenticated sealing boundary.
    #[must_use]
    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

/// Metadata presented in a native confirmation/prompt. It contains no material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureCredentialPromptRequest {
    provider: CredentialPromptProvider,
    action: CredentialPromptAction,
    expected_revision: u64,
}

impl SecureCredentialPromptRequest {
    /// # Errors
    ///
    /// Returns a closed failure when the expected revision is zero.
    pub const fn new(
        provider: CredentialPromptProvider,
        action: CredentialPromptAction,
        expected_revision: u64,
    ) -> Result<Self, SecureCredentialPromptError> {
        if expected_revision == 0 {
            return Err(SecureCredentialPromptError::Rejected);
        }
        Ok(Self {
            provider,
            action,
            expected_revision,
        })
    }

    #[must_use]
    pub const fn provider(self) -> CredentialPromptProvider {
        self.provider
    }
    #[must_use]
    pub const fn action(self) -> CredentialPromptAction {
        self.action
    }
    #[must_use]
    pub const fn expected_revision(self) -> u64 {
        self.expected_revision
    }
}

/// Closed provider identities accepted by the secure host prompt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialPromptProvider {
    OpenAi,
    DeepSeek,
}

/// Closed native actions accepted by the secure host prompt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialPromptAction {
    Pair,
    Rotate,
    Revoke,
    MigrateLegacy,
}

impl CredentialPromptAction {
    #[must_use]
    pub const fn requires_secret(self) -> bool {
        matches!(self, Self::Pair | Self::Rotate)
    }
}

/// Deliberately non-Serde native prompt port.
pub trait SecureCredentialPromptPort {
    /// Shows a focused host-native prompt and returns a safe closed disposition.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when no secure focused native prompt is available.
    fn prompt(
        &mut self,
        request: SecureCredentialPromptRequest,
    ) -> Result<SecureCredentialPromptDisposition, SecureCredentialPromptError>;
}

/// Opaque prompt failure; native details never cross the host boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecureCredentialPromptError {
    Rejected,
    Unavailable,
}

impl fmt::Display for SecureCredentialPromptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secure credential prompt unavailable")
    }
}

impl std::error::Error for SecureCredentialPromptError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_material_rejects_empty_oversize_and_line_control() {
        for material in [
            vec![],
            vec![b'a'; MAX_CREDENTIAL_BYTES + 1],
            b"a\nb".to_vec(),
            b"a\rb".to_vec(),
            b"a\0b".to_vec(),
        ] {
            assert!(matches!(
                SecureCredentialMaterial::new(material),
                Err(SecureCredentialPromptError::Rejected)
            ));
        }
        assert!(SecureCredentialMaterial::new(b"correct horse battery staple".to_vec()).is_ok());
    }

    #[test]
    fn prompt_request_rejects_zero_revision() {
        assert_eq!(
            SecureCredentialPromptRequest::new(
                CredentialPromptProvider::OpenAi,
                CredentialPromptAction::Pair,
                0
            ),
            Err(SecureCredentialPromptError::Rejected),
        );
    }

    #[test]
    fn prompt_actions_distinguish_secret_entry_from_confirmation() {
        assert!(CredentialPromptAction::Pair.requires_secret());
        assert!(CredentialPromptAction::Rotate.requires_secret());
        assert!(!CredentialPromptAction::Revoke.requires_secret());
        assert!(!CredentialPromptAction::MigrateLegacy.requires_secret());
    }
}
