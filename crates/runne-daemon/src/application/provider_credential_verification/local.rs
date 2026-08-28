use rand::{RngCore, rngs::OsRng};
use runne_api::{
    ProviderCredentialBaseRequestAuthority, ProviderCredentialCommandContext,
    ProviderCredentialEnrollmentHostError, ProviderCredentialLastDispositionV2,
    ProviderCredentialOperationSnapshotV2, ProviderCredentialOperationStateV2,
    ProviderCredentialProviderV2, ProviderCredentialVerificationKindV2, VerifyProviderCredential,
};
use runne_provider::{
    BeginCredentialVerification, CompleteCredentialVerification, CredentialBindingDigest,
    CredentialOperationId, CredentialVerificationKind, CredentialVerificationObservation,
    CredentialVerificationResult, CredentialVerifierRevision, ProviderCredentialEnrollmentStore,
    ProviderId,
};
use runne_secure_store::{ProviderCredentialVerificationReadback, SecureStoreError};

use super::super::provider_credential_enrollment::{
    ProviderCredentialAdmission, ProviderCredentialOperationHandleIssuer,
    ProviderCredentialVerificationHost,
};

/// Explicit local-only credential verifier with no materialization or transport.
pub(crate) struct LocalProviderCredentialVerification<'a, S: ?Sized, R: ?Sized> {
    admission: ProviderCredentialAdmission,
    handles: ProviderCredentialOperationHandleIssuer,
    store: &'a S,
    reader: &'a R,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protected V2 host remains unmounted until trusted writer admission is composed"
    )
)]
impl<'a, S: ?Sized, R: ?Sized> LocalProviderCredentialVerification<'a, S, R> {
    pub(crate) const fn new(
        admission: ProviderCredentialAdmission,
        handles: ProviderCredentialOperationHandleIssuer,
        store: &'a S,
        reader: &'a R,
    ) -> Self {
        Self {
            admission,
            handles,
            store,
            reader,
        }
    }
}

impl<S, R> ProviderCredentialVerificationHost for LocalProviderCredentialVerification<'_, S, R>
where
    S: ProviderCredentialEnrollmentStore + Send + Sync + ?Sized,
    R: ProviderCredentialVerificationReadback + Send + Sync + ?Sized,
{
    fn verify(
        &self,
        authority: ProviderCredentialBaseRequestAuthority,
        proof: runne_api::ProviderCredentialIntentConsumptionProof,
        context: ProviderCredentialCommandContext,
        command: VerifyProviderCredential,
    ) -> Result<ProviderCredentialOperationSnapshotV2, ProviderCredentialEnrollmentHostError> {
        self.admission
            .require_verify_command(&authority, &proof, &command, &context)?;
        if command.verification_kind() != ProviderCredentialVerificationKindV2::Local {
            return Err(ProviderCredentialEnrollmentHostError::Unsupported);
        }
        let provider = provider(command.provider())?;
        let current = self
            .store
            .current_verification_context(&provider)
            .map_err(map_store)?;
        if current.lifecycle_revision().get() != command.expected_lifecycle_revision()
            || current.release_tuple_digest().as_bytes() != *authority.release_tuple_digest()
            || proof.expires_at_high_water() <= current.observed_at_high_water()
        {
            return Err(ProviderCredentialEnrollmentHostError::Conflict);
        }
        let intent_proof = CredentialBindingDigest::from_measured(*proof.proof_digest())
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let observation_id = observation_id()?;
        let lease = self
            .store
            .begin_verification(
                BeginCredentialVerification::new(
                    observation_id,
                    None,
                    provider.clone(),
                    CredentialVerificationKind::Local,
                    current.lifecycle_revision(),
                    current.fence(),
                    current.readiness_revision(),
                    current.release_tuple_digest(),
                    intent_proof,
                    CredentialVerifierRevision::new(1)
                        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
                    current.observed_at_high_water(),
                    proof.expires_at_high_water(),
                )
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvalidRequest)?,
            )
            .map_err(map_store)?;
        let result = self.reader.verify_local(&lease).unwrap_or_else(map_reader_error);
        self.store
            .complete_verification(CompleteCredentialVerification::new(
                CredentialVerificationObservation::new(
                    lease.observation_id(),
                    result,
                    current.observed_at_high_water(),
                )
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
                current.lifecycle_revision(),
                current.fence(),
            ))
            .map_err(map_store)?;
        ProviderCredentialOperationSnapshotV2::new(
            self.handles.issue(lease.observation_id()),
            None,
            command.provider(),
            runne_api::ProviderCredentialOperationKindV2::VerifyLocal,
            ProviderCredentialOperationStateV2::Completed,
            current.lifecycle_revision().get(),
            current.readiness_revision().get(),
            false,
            disposition(result),
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
    }
}

fn provider(value: ProviderCredentialProviderV2) -> Result<ProviderId, ProviderCredentialEnrollmentHostError> {
    ProviderId::new(match value {
        ProviderCredentialProviderV2::OpenAi => "openai",
        ProviderCredentialProviderV2::DeepSeek => "deepseek",
    })
    .map_err(|_| ProviderCredentialEnrollmentHostError::InvalidRequest)
}

fn observation_id() -> Result<CredentialOperationId, ProviderCredentialEnrollmentHostError> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
    CredentialOperationId::from_bytes(bytes).map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)
}

fn map_store(error: runne_provider::CredentialLifecycleError) -> ProviderCredentialEnrollmentHostError {
    match error {
        runne_provider::CredentialLifecycleError::Conflict
        | runne_provider::CredentialLifecycleError::StaleLease => ProviderCredentialEnrollmentHostError::Conflict,
        runne_provider::CredentialLifecycleError::LifecycleClosed => ProviderCredentialEnrollmentHostError::Unsupported,
        runne_provider::CredentialLifecycleError::InvalidInput => ProviderCredentialEnrollmentHostError::InvalidRequest,
        runne_provider::CredentialLifecycleError::CorruptState => ProviderCredentialEnrollmentHostError::InvariantViolation,
        _ => ProviderCredentialEnrollmentHostError::Unavailable,
    }
}

fn map_reader_error(error: SecureStoreError) -> CredentialVerificationResult {
    match error {
        SecureStoreError::CredentialAccessDenied | SecureStoreError::CredentialIdentityMismatch
        | SecureStoreError::CredentialAclMigrationRequired => CredentialVerificationResult::AccessDenied,
        SecureStoreError::UnsupportedSecureStoreBackend => CredentialVerificationResult::Unsupported,
        SecureStoreError::ProviderCredentialNotFound => CredentialVerificationResult::Failed,
        _ => CredentialVerificationResult::Unavailable,
    }
}

const fn disposition(result: CredentialVerificationResult) -> Option<ProviderCredentialLastDispositionV2> {
    match result {
        CredentialVerificationResult::Verified => Some(ProviderCredentialLastDispositionV2::Completed),
        CredentialVerificationResult::Unsupported => Some(ProviderCredentialLastDispositionV2::Unsupported),
        CredentialVerificationResult::Unavailable => Some(ProviderCredentialLastDispositionV2::Unavailable),
        CredentialVerificationResult::AccessDenied => Some(ProviderCredentialLastDispositionV2::AccessDenied),
        CredentialVerificationResult::Conflict => Some(ProviderCredentialLastDispositionV2::Conflict),
        CredentialVerificationResult::Failed => None,
    }
}
