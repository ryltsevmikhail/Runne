//! Runtime-owned provider credential control contracts.

use std::{future::Future, pin::Pin};

use runne_domain::id::{CommandId, IdempotencyKey};
use zeroize::{Zeroize, Zeroizing};

/// Capability required before provider credential mutation is exposed.
pub const PROVIDER_CREDENTIAL_CONTROL_CAPABILITY_V1: &str = "provider.credential-control.v1";
/// Maximum credential material accepted by the public host boundary.
pub const MAX_PROVIDER_CREDENTIAL_BYTES_V1: usize = 4_096;

/// Closed provider identities accepted by the first Desktop profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCredentialProviderV1 {
    OpenAi,
    DeepSeek,
}

impl ProviderCredentialProviderV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::DeepSeek => "deepseek",
        }
    }

    /// Parses the stable provider identifier.
    pub fn parse(value: &str) -> Result<Self, ProviderCredentialValidationError> {
        match value {
            "openai" => Ok(Self::OpenAi),
            "deepseek" => Ok(Self::DeepSeek),
            _ => Err(ProviderCredentialValidationError::UnknownProvider),
        }
    }
}

/// Safe outcome of one provider credential operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCredentialStatusV1 {
    Configured,
    Missing,
    Unsupported,
    AccessDenied,
    IdentityMismatch,
    Unavailable,
}

/// Validation failures that never contain credential material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCredentialValidationError {
    UnknownProvider,
    EmptyCredential,
    CredentialTooLarge,
    CredentialContainsForbiddenByte,
}

/// Authenticated identity and replay key for one credential mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCredentialCommandContext {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub principal: ApiPrincipalId,
    pub actor: ApiActor,
}

impl ProviderCredentialCommandContext {
    /// Builds a context from canonical public wire identities without exposing
    /// the domain crate across the desktop platform boundary.
    pub fn from_canonical_ids(
        command_id: &str,
        idempotency_key: &str,
        principal: ApiPrincipalId,
        actor: ApiActor,
    ) -> Option<Self> {
        Some(Self {
            command_id: CommandId::parse(command_id).ok()?,
            idempotency_key: IdempotencyKey::new(idempotency_key).ok()?,
            principal,
            actor,
        })
    }
}

/// Pair/replace command. Material is zeroized after the command is dropped.
pub struct ProviderCredentialPairCommand {
    provider: ProviderCredentialProviderV1,
    material: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for ProviderCredentialPairCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderCredentialPairCommand")
            .field("provider", &self.provider)
            .field("material", &"<redacted>")
            .finish()
    }
}

impl ProviderCredentialPairCommand {
    /// Validates bounded single-line material before it reaches a host.
    pub fn new(
        provider: ProviderCredentialProviderV1,
        material: Vec<u8>,
    ) -> Result<Self, ProviderCredentialValidationError> {
        if material.is_empty() {
            return Err(ProviderCredentialValidationError::EmptyCredential);
        }
        if material.len() > MAX_PROVIDER_CREDENTIAL_BYTES_V1 {
            return Err(ProviderCredentialValidationError::CredentialTooLarge);
        }
        if material
            .iter()
            .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
        {
            return Err(ProviderCredentialValidationError::CredentialContainsForbiddenByte);
        }
        Ok(Self {
            provider,
            material: Zeroizing::new(material),
        })
    }

    #[must_use]
    pub const fn provider(&self) -> ProviderCredentialProviderV1 {
        self.provider
    }

    /// Borrows material only for the duration of a host-owned operation.
    pub fn with_material<T>(&self, operation: impl FnOnce(&[u8]) -> T) -> T {
        operation(&self.material)
    }
}

impl Drop for ProviderCredentialPairCommand {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}

/// Revoke command for one provider identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderCredentialRevokeCommand {
    provider: ProviderCredentialProviderV1,
}

impl ProviderCredentialRevokeCommand {
    #[must_use]
    pub const fn new(provider: ProviderCredentialProviderV1) -> Self {
        Self { provider }
    }

    #[must_use]
    pub const fn provider(self) -> ProviderCredentialProviderV1 {
        self.provider
    }
}

/// Redacted acknowledgement returned after secure-store mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderCredentialMutationAckV1 {
    provider: ProviderCredentialProviderV1,
    status: ProviderCredentialStatusV1,
}

impl ProviderCredentialMutationAckV1 {
    #[must_use]
    pub const fn new(
        provider: ProviderCredentialProviderV1,
        status: ProviderCredentialStatusV1,
    ) -> Self {
        Self { provider, status }
    }

    #[must_use]
    pub const fn provider(self) -> ProviderCredentialProviderV1 {
        self.provider
    }

    #[must_use]
    pub const fn status(self) -> ProviderCredentialStatusV1 {
        self.status
    }
}

/// Closed host failures for provider credential control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCredentialHostError {
    InvalidRequest,
    Forbidden,
    Conflict,
    Unsupported,
    Unavailable,
    InvariantViolation,
}

/// Runtime-owned provider credential mutation boundary.
pub trait ProviderCredentialControlHostPort: Send + Sync {
    fn pair_provider_credential<'a>(
        &'a self,
        context: ProviderCredentialCommandContext,
        command: ProviderCredentialPairCommand,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<ProviderCredentialMutationAckV1, ProviderCredentialHostError>,
                > + Send
                + 'a,
        >,
    >;

    fn revoke_provider_credential<'a>(
        &'a self,
        context: ProviderCredentialCommandContext,
        command: ProviderCredentialRevokeCommand,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<ProviderCredentialMutationAckV1, ProviderCredentialHostError>,
                > + Send
                + 'a,
        >,
    >;
}

use crate::{ApiActor, ApiPrincipalId};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_command_is_bounded_and_debug_redacted() {
        let command = ProviderCredentialPairCommand::new(
            ProviderCredentialProviderV1::OpenAi,
            b"credential-never-debugged".to_vec(),
        )
        .expect("valid command");
        assert_eq!(command.provider(), ProviderCredentialProviderV1::OpenAi);
        assert!(!format!("{command:?}").contains("credential-never-debugged"));
    }

    #[test]
    fn pair_command_rejects_empty_oversized_and_multiline_material() {
        assert!(matches!(
            ProviderCredentialPairCommand::new(ProviderCredentialProviderV1::OpenAi, Vec::new()),
            Err(ProviderCredentialValidationError::EmptyCredential)
        ));
        assert!(matches!(
            ProviderCredentialPairCommand::new(
                ProviderCredentialProviderV1::OpenAi,
                vec![b'x'; MAX_PROVIDER_CREDENTIAL_BYTES_V1 + 1],
            ),
            Err(ProviderCredentialValidationError::CredentialTooLarge)
        ));
        assert!(matches!(
            ProviderCredentialPairCommand::new(
                ProviderCredentialProviderV1::OpenAi,
                b"x\ny".to_vec()
            ),
            Err(ProviderCredentialValidationError::CredentialContainsForbiddenByte)
        ));
    }

    #[test]
    fn provider_parser_is_closed() {
        assert_eq!(
            ProviderCredentialProviderV1::parse("openai"),
            Ok(ProviderCredentialProviderV1::OpenAi)
        );
        assert_eq!(
            ProviderCredentialProviderV1::parse("github"),
            Err(ProviderCredentialValidationError::UnknownProvider)
        );
    }
}
