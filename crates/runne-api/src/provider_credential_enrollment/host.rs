use core::{future::Future, pin::Pin};

use super::{
    BeginProviderCredentialEnrollment, ProviderCredentialOperationIdV2,
    ProviderCredentialOperationSnapshotV2, ProviderCredentialProviderV2,
    ProviderCredentialSafeSnapshotV2, VerifyProviderCredential,
};
use crate::ProviderCredentialCommandContext;

mod authority;

pub use authority::{
    ProviderCredentialBaseRequestAuthority, ProviderCredentialIntentConsumptionProof,
    ProviderCredentialRequestAuthorityIssuer, ProviderCredentialRequestAuthorityPair,
    ProviderCredentialRequestAuthorityVerifier,
};

/// Future returned by mutation/resume/verification host methods.
pub type ProviderCredentialHostFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<
                    ProviderCredentialOperationSnapshotV2,
                    ProviderCredentialEnrollmentHostError,
                >,
            > + Send
            + 'a,
    >,
>;

/// Future returned by the authenticated dynamic status query.
pub type ProviderCredentialStatusFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<
                    ProviderCredentialSafeSnapshotV2,
                    ProviderCredentialEnrollmentHostError,
                >,
            > + Send
            + 'a,
    >,
>;

/// Protected daemon host boundary. Wire values never carry request authority.
pub trait ProviderCredentialEnrollmentHostPort: Send + Sync {
    fn begin<'a>(
        &'a self,
        authority: ProviderCredentialBaseRequestAuthority,
        proof: ProviderCredentialIntentConsumptionProof,
        context: ProviderCredentialCommandContext,
        command: BeginProviderCredentialEnrollment,
    ) -> ProviderCredentialHostFuture<'a>;
    fn resume<'a>(
        &'a self,
        authority: ProviderCredentialBaseRequestAuthority,
        context: ProviderCredentialCommandContext,
        operation_id: ProviderCredentialOperationIdV2,
    ) -> ProviderCredentialHostFuture<'a>;
    fn status<'a>(
        &'a self,
        authority: ProviderCredentialBaseRequestAuthority,
        provider: ProviderCredentialProviderV2,
    ) -> ProviderCredentialStatusFuture<'a>;
    fn verify<'a>(
        &'a self,
        authority: ProviderCredentialBaseRequestAuthority,
        proof: ProviderCredentialIntentConsumptionProof,
        context: ProviderCredentialCommandContext,
        command: VerifyProviderCredential,
    ) -> ProviderCredentialHostFuture<'a>;
}

/// Closed, redacted failures exposed by the protected enrollment host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCredentialEnrollmentHostError {
    InvalidRequest,
    AccessDenied,
    Conflict,
    Unsupported,
    Unavailable,
    InvariantViolation,
}

impl ProviderCredentialEnrollmentHostError {
    /// Returns the stable public error code without backend details.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "provider_credential_invalid_request",
            Self::AccessDenied => "provider_credential_access_denied",
            Self::Conflict => "provider_credential_conflict",
            Self::Unsupported => "provider_credential_unsupported",
            Self::Unavailable => "provider_credential_unavailable",
            Self::InvariantViolation => "provider_credential_invariant_violation",
        }
    }
}
