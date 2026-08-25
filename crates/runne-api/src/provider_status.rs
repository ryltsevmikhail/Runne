use serde::{Deserialize, Serialize};
use std::fmt;

const MAX_PROVIDER_STATUS_TEXT_BYTES: usize = 128;

/// Closed, metadata-only provider readiness disposition.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderReadinessStatusV1 {
    /// Credential and native provider gates are ready.
    Ready,
    /// Credential metadata is absent.
    CredentialMissing,
    /// Native credential access was denied.
    CredentialAccessDenied,
    /// Native reader/writer identity differs from the bound pair.
    CredentialIdentityMismatch,
    /// The secure-store or retained-key backend is unavailable.
    SecureStoreUnavailable,
    /// This provider is not the runtime's selected activation.
    NotSelected,
}

/// Safe provider status returned by the authenticated runtime owner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderStatusSnapshotV1 {
    provider_id: String,
    mode: String,
    profile_id: String,
    profile_digest: String,
    readiness: ProviderReadinessStatusV1,
    selected: bool,
}

/// Rejected provider status metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderStatusValidationError {
    /// A text field is empty, oversized, or contains a control character.
    InvalidText,
    /// The profile digest is not exactly lower-case SHA-256 hex.
    InvalidDigest,
    /// A selected provider cannot advertise the not-selected disposition.
    SelectedNotReady,
}

impl fmt::Display for ProviderStatusValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidText => "provider status contains invalid text",
            Self::InvalidDigest => "provider status contains invalid profile digest",
            Self::SelectedNotReady => "selected provider has not-selected readiness",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ProviderStatusValidationError {}

impl ProviderStatusSnapshotV1 {
    /// Builds and validates one metadata-only provider status.
    pub fn new(
        provider_id: impl Into<String>,
        mode: impl Into<String>,
        profile_id: impl Into<String>,
        profile_digest: [u8; 32],
        readiness: ProviderReadinessStatusV1,
        selected: bool,
    ) -> Result<Self, ProviderStatusValidationError> {
        let value = Self {
            provider_id: provider_id.into(),
            mode: mode.into(),
            profile_id: profile_id.into(),
            profile_digest: encode_digest(profile_digest),
            readiness,
            selected,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates a deserialized status before it reaches application code.
    pub fn validate(&self) -> Result<(), ProviderStatusValidationError> {
        for value in [&self.provider_id, &self.mode, &self.profile_id] {
            if value.is_empty()
                || value.len() > MAX_PROVIDER_STATUS_TEXT_BYTES
                || value.chars().any(char::is_control)
            {
                return Err(ProviderStatusValidationError::InvalidText);
            }
        }
        if self.profile_digest.len() != 64
            || self
                .profile_digest
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(ProviderStatusValidationError::InvalidDigest);
        }
        if self.selected && self.readiness == ProviderReadinessStatusV1::NotSelected {
            return Err(ProviderStatusValidationError::SelectedNotReady);
        }
        Ok(())
    }

    /// Returns the stable provider identifier.
    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    /// Returns the stable provider activation mode.
    #[must_use]
    pub fn mode(&self) -> &str {
        &self.mode
    }

    /// Returns the immutable provider profile identifier.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Returns the lower-case profile digest.
    #[must_use]
    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    /// Returns the metadata-only readiness disposition.
    #[must_use]
    pub const fn readiness(&self) -> ProviderReadinessStatusV1 {
        self.readiness
    }

    /// Returns whether this is the selected runtime activation.
    #[must_use]
    pub const fn selected(&self) -> bool {
        self.selected
    }
}

fn encode_digest(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
