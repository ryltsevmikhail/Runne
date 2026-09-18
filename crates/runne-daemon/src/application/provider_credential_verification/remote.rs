use std::{sync::Arc, time::Duration};

use runne_api::{
    ProviderCredentialBaseRequestAuthority, ProviderCredentialCommandContext,
    ProviderCredentialEnrollmentHostError, ProviderCredentialLastDispositionV2,
    ProviderCredentialOperationKindV2, ProviderCredentialOperationSnapshotV2,
    ProviderCredentialOperationStateV2, ProviderCredentialProviderV2,
    ProviderCredentialVerificationKindV2, VerifyProviderCredential,
};
use runne_daemon_chat_completions_effect::{AuthorizedQuotaRefresher, QuotaRefreshTransport};
use runne_provider::{
    BeginCredentialVerification, CompleteCredentialVerification, CredentialBindingDigest,
    CredentialEnrollmentMeasurementAuthority, CredentialOperationId, CredentialVerificationKind,
    CredentialVerificationObservation, CredentialVerificationResult, CredentialVerifierRevision,
    ProviderCredentialEnrollmentStore, ProviderId,
};
use runne_provider_quota::{
    QuotaEndpointScope, QuotaEvidenceSink, QuotaRefreshStatus, QuotaRequestDescriptor,
    SubscriptionBudgetAuthority,
};
use runne_secure_store::ProviderCredentialVerificationMaterializer;
use runne_store::provider::SqliteProviderCredentialLifecycleStore;

#[path = "remote_helpers.rs"]
mod helpers;
#[cfg(test)]
#[path = "remote_tests.rs"]
mod tests;
use helpers::{descriptor, high_water_seconds, observation_id};

const REMOTE_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONCURRENT_REMOTE_VERIFICATIONS: usize = 2;

/// Production remote verifier reached only through a fresh protected native intent.
pub(crate) struct RemoteProviderCredentialVerification<T: QuotaRefreshTransport + 'static> {
    store: Arc<SqliteProviderCredentialLifecycleStore>,
    measurements: CredentialEnrollmentMeasurementAuthority,
    handles: super::super::provider_credential_enrollment::ProviderCredentialOperationHandleIssuer,
    refresher: AuthorizedQuotaRefresher<T>,
    provider: ProviderCredentialProviderV2,
    descriptor: Option<QuotaRequestDescriptor>,
    model_name: Option<String>,
    concurrency: Arc<tokio::sync::Semaphore>,
    budget: Option<Arc<dyn SubscriptionBudgetAuthority>>,
}

impl<T: QuotaRefreshTransport + 'static> RemoteProviderCredentialVerification<T> {
    /// Composes the verifier from the service's existing store/measurement pair.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        store: Arc<SqliteProviderCredentialLifecycleStore>,
        measurements: CredentialEnrollmentMeasurementAuthority,
        handles: super::super::provider_credential_enrollment::ProviderCredentialOperationHandleIssuer,
        materializer: Arc<dyn ProviderCredentialVerificationMaterializer>,
        transport: Arc<T>,
        sink: Arc<dyn QuotaEvidenceSink>,
        provider: ProviderCredentialProviderV2,
        model_name: Option<String>,
        budget: Option<Arc<dyn SubscriptionBudgetAuthority>>,
    ) -> Self {
        let descriptor = descriptor(provider);
        let model_name = match descriptor.as_ref().map(QuotaRequestDescriptor::provider) {
            Some(runne_provider_quota::QuotaProvider::MiniMax)
            | Some(runne_provider_quota::QuotaProvider::MiniMaxChina) => model_name,
            _ => None,
        };
        Self {
            store,
            measurements,
            handles,
            refresher: AuthorizedQuotaRefresher::new(materializer, transport, sink),
            provider,
            descriptor,
            model_name,
            concurrency: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_REMOTE_VERIFICATIONS,
            )),
            budget,
        }
    }

    fn refresh(
        &self,
        capability: &runne_provider::CredentialVerificationCapability,
        descriptor: &QuotaRequestDescriptor,
        observed_at: u64,
    ) -> CredentialVerificationResult {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return CredentialVerificationResult::Unavailable;
        };
        handle.block_on(async {
            let request = async {
                let _permit = self
                    .concurrency
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| QuotaRefreshStatus::TransportUnavailable)?;
                self.refresher
                    .refresh(
                        capability,
                        descriptor,
                        self.model_name.as_deref(),
                        observed_at,
                    )
                    .await
            };
            match tokio::time::timeout(REMOTE_VERIFICATION_TIMEOUT, request).await {
                Ok(Ok(snapshot)) => {
                    if let Some(budget) = self.budget.as_ref() {
                        let provider_id = match descriptor.provider() {
                            runne_provider_quota::QuotaProvider::ZaiGlobal => "zai",
                            runne_provider_quota::QuotaProvider::ZaiChina => "zai-coding-cn",
                            runne_provider_quota::QuotaProvider::QwenTokenPlanIndividual => {
                                "qwen-token-plan-individual"
                            }
                            runne_provider_quota::QuotaProvider::KimiCoding => "kimi-coding",
                            runne_provider_quota::QuotaProvider::MiniMax => "minimax",
                            runne_provider_quota::QuotaProvider::MiniMaxChina => "minimax-cn",
                        };
                        let version = capability.lease().active_credential_version().version();
                        if let Some(remaining) = snapshot
                            .windows()
                            .iter()
                            .filter_map(|window| window.remaining())
                            .min()
                        {
                            budget.refill_if_known(
                                provider_id,
                                version,
                                remaining,
                                i64::try_from(observed_at).unwrap_or(i64::MAX),
                            );
                        }
                    }
                    CredentialVerificationResult::Verified
                }
                Ok(Err(status)) => map_refresh(status),
                Err(_) => CredentialVerificationResult::Unavailable,
            }
        })
    }
}

impl<T: QuotaRefreshTransport + 'static>
    super::super::provider_credential_enrollment::ProviderCredentialVerificationHost
    for RemoteProviderCredentialVerification<T>
{
    fn verify(
        &self,
        authority: ProviderCredentialBaseRequestAuthority,
        proof: runne_api::ProviderCredentialIntentConsumptionProof,
        _context: ProviderCredentialCommandContext,
        command: VerifyProviderCredential,
    ) -> Result<ProviderCredentialOperationSnapshotV2, ProviderCredentialEnrollmentHostError> {
        if command.verification_kind() != ProviderCredentialVerificationKindV2::Remote
            || command.provider() != self.provider
        {
            return Err(ProviderCredentialEnrollmentHostError::Unsupported);
        }
        let provider = ProviderId::new(command.provider().as_str())
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvalidRequest)?;
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
        let observation_id = observation_id()?;
        let lease = self
            .store
            .begin_verification(
                BeginCredentialVerification::new(
                    observation_id,
                    None,
                    provider,
                    CredentialVerificationKind::Remote,
                    current.lifecycle_revision(),
                    current.fence(),
                    current.readiness_revision(),
                    current.release_tuple_digest(),
                    CredentialBindingDigest::from_measured(*proof.proof_digest())
                        .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?,
                    CredentialVerifierRevision::new(1)
                        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
                    current.observed_at_high_water(),
                    proof.expires_at_high_water(),
                )
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvalidRequest)?,
            )
            .map_err(map_store)?;
        let result = match self.descriptor.as_ref() {
            Some(descriptor) if descriptor.scope() == QuotaEndpointScope::ProviderApi => {
                let binding = CredentialBindingDigest::from_measured(descriptor.binding_digest(
                    lease.active_credential_version().version(),
                    self.model_name.as_deref(),
                ))
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?;
                match self
                    .measurements
                    .issue_credential_verification_capability(lease, binding)
                {
                    Ok(capability) => self.refresh(
                        &capability,
                        descriptor,
                        high_water_seconds(current.observed_at_high_water()),
                    ),
                    Err(_) => CredentialVerificationResult::AccessDenied,
                }
            }
            _ => CredentialVerificationResult::Unsupported,
        };
        self.store
            .complete_verification(CompleteCredentialVerification::new(
                CredentialVerificationObservation::new(
                    observation_id,
                    result,
                    current.observed_at_high_water(),
                )
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
                current.lifecycle_revision(),
                current.fence(),
            ))
            .map_err(map_store)?;
        ProviderCredentialOperationSnapshotV2::new(
            self.handles.issue(observation_id),
            None,
            command.provider(),
            ProviderCredentialOperationKindV2::VerifyRemote,
            ProviderCredentialOperationStateV2::Completed,
            current.lifecycle_revision().get(),
            current.readiness_revision().get(),
            false,
            disposition(result),
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
    }
}

const fn map_refresh(status: QuotaRefreshStatus) -> CredentialVerificationResult {
    match status {
        QuotaRefreshStatus::Unauthorized => CredentialVerificationResult::AccessDenied,
        QuotaRefreshStatus::UnknownSchema | QuotaRefreshStatus::ConsoleRequired => {
            CredentialVerificationResult::Unsupported
        }
        QuotaRefreshStatus::RateLimited { .. } | QuotaRefreshStatus::TransportUnavailable => {
            CredentialVerificationResult::Unavailable
        }
    }
}

fn map_store(
    error: runne_provider::CredentialLifecycleError,
) -> ProviderCredentialEnrollmentHostError {
    match error {
        runne_provider::CredentialLifecycleError::Conflict
        | runne_provider::CredentialLifecycleError::StaleLease => {
            ProviderCredentialEnrollmentHostError::Conflict
        }
        runne_provider::CredentialLifecycleError::LifecycleClosed => {
            ProviderCredentialEnrollmentHostError::Unsupported
        }
        runne_provider::CredentialLifecycleError::InvalidInput => {
            ProviderCredentialEnrollmentHostError::InvalidRequest
        }
        runne_provider::CredentialLifecycleError::CorruptState => {
            ProviderCredentialEnrollmentHostError::InvariantViolation
        }
        _ => ProviderCredentialEnrollmentHostError::Unavailable,
    }
}

const fn disposition(
    result: CredentialVerificationResult,
) -> Option<ProviderCredentialLastDispositionV2> {
    match result {
        CredentialVerificationResult::Verified => {
            Some(ProviderCredentialLastDispositionV2::Completed)
        }
        CredentialVerificationResult::Unsupported => {
            Some(ProviderCredentialLastDispositionV2::Unsupported)
        }
        CredentialVerificationResult::Unavailable => {
            Some(ProviderCredentialLastDispositionV2::Unavailable)
        }
        CredentialVerificationResult::AccessDenied => {
            Some(ProviderCredentialLastDispositionV2::AccessDenied)
        }
        CredentialVerificationResult::Conflict => {
            Some(ProviderCredentialLastDispositionV2::Conflict)
        }
        CredentialVerificationResult::Failed => None,
    }
}
