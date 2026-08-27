//! Protected metadata-only provider credential enrollment contracts.

mod host;
mod types;

/// Capability admitted only for an exact qualified ProtectedBundled release tuple.
pub const PROVIDER_CREDENTIAL_ENROLLMENT_CAPABILITY_V2: &str = "provider.credential-enrollment.v2";

pub use host::{
    ProviderCredentialBaseRequestAuthority, ProviderCredentialEnrollmentHostError,
    ProviderCredentialEnrollmentHostPort, ProviderCredentialHostFuture,
    ProviderCredentialIntentConsumptionProof, ProviderCredentialRequestAuthorityIssuer,
    ProviderCredentialRequestAuthorityPair, ProviderCredentialRequestAuthorityVerifier,
    ProviderCredentialStatusFuture,
};

pub use types::{
    BeginProviderCredentialEnrollment, ProviderCredentialBeginIntentBinding,
    ProviderCredentialEnrollmentActionV2, ProviderCredentialLastDispositionV2,
    ProviderCredentialOperationHandleV2, ProviderCredentialOperationKindV2,
    ProviderCredentialOperationSnapshotV2, ProviderCredentialOperationStateV2,
    ProviderCredentialPendingOperationV2, ProviderCredentialProviderV2,
    ProviderCredentialReadinessV2, ProviderCredentialSafeSnapshotV2, ProviderCredentialStateV2,
    ProviderCredentialValidationErrorV2, ProviderCredentialVerificationKindV2,
    ProviderCredentialVerificationStateV2, ProviderCredentialVerifyIntentBinding,
    VerifyProviderCredential,
};

#[cfg(test)]
mod tests;
