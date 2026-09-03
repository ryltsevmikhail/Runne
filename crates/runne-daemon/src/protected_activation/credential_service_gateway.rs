use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialEnrollmentStoreAuthority,
};
use runne_secure_store::{
    CredentialReadbackObservation, ExactAbsenceReadback, ExactVersionReadback,
    ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead,
    ProviderCredentialMaterial, ProviderCredentialReadback, SecureStoreError,
};

use super::credential_service_registration::CredentialServiceRuntimeSession;

mod rejoin;
mod retry;
use rejoin::{CredentialServiceRejoinCoordinator, CredentialServiceRejoinRequest};

const REJOIN_WAIT: Duration = Duration::from_secs(5);

/// Shared daemon boundary installed only by an authenticated Desktop/service
/// registration and consumed by enrollment readback and provider dispatch.
pub(crate) struct CredentialServiceRuntimeGateway {
    session: Mutex<Option<CredentialServiceRuntimeSession>>,
    authority: CredentialEnrollmentStoreAuthority,
    runtime: tokio::runtime::Handle,
    rejoin: CredentialServiceRejoinCoordinator,
}

impl CredentialServiceRuntimeGateway {
    pub(crate) const fn new(
        authority: CredentialEnrollmentStoreAuthority,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            session: Mutex::new(None),
            authority,
            runtime,
            rejoin: CredentialServiceRejoinCoordinator::new(),
        }
    }

    pub(crate) fn install(
        &self,
        session: CredentialServiceRuntimeSession,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let mut slot = self
            .session
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        if let Some(current) = slot.as_ref()
            && !session.supersedes(current)
        {
            return Err(ProviderCredentialEnrollmentHostError::Conflict);
        }
        *slot = Some(session);
        Ok(())
    }

    pub(crate) fn arm_mutation(
        &self,
        command: CredentialBrokerCommand,
    ) -> Result<
        runne_provider::CredentialWriterBrokerHandoffFrame,
        ProviderCredentialEnrollmentHostError,
    > {
        let now = now_unix_millis()?;
        let (result, missing_epoch) = self.with_session(|session| {
            session
                .ok_or(ProviderCredentialEnrollmentHostError::Unavailable)?
                .arm_mutation(
                    &self.runtime,
                    &self.authority.runtime_arm_authority(),
                    command,
                    now,
                )
        });
        if let Some(epoch) = missing_epoch {
            let _ = self.rejoin.queue(epoch);
        }
        result
    }

    fn read_metadata(
        &self,
        version: runne_provider::CredentialVersionRef,
        lifecycle: runne_provider::CredentialLifecycleRevision,
        fence: runne_provider::CredentialFence,
    ) -> Result<bool, SecureStoreError> {
        self.retry_metadata_after_rejoin(|| {
            let call_now = match now_unix_millis() {
                Ok(value) => value,
                Err(error) => return (Err(error), None),
            };
            self.with_session(|session| {
                session
                    .ok_or(ProviderCredentialEnrollmentHostError::Unavailable)?
                    .read_metadata(
                        &self.runtime,
                        &self.authority.runtime_read_authority(),
                        version.clone(),
                        lifecycle,
                        fence,
                        call_now,
                    )
            })
        })
        .map_err(map_host_error)
    }

    fn with_session<T>(
        &self,
        operation: impl FnOnce(
            Option<&mut CredentialServiceRuntimeSession>,
        ) -> Result<T, ProviderCredentialEnrollmentHostError>,
    ) -> (
        Result<T, ProviderCredentialEnrollmentHostError>,
        Option<runne_provider::CredentialServiceEpoch>,
    ) {
        let Ok(mut slot) = self.session.lock() else {
            return (
                Err(ProviderCredentialEnrollmentHostError::Unavailable),
                None,
            );
        };
        let result = operation(slot.as_mut());
        let missing = slot
            .as_mut()
            .and_then(CredentialServiceRuntimeSession::take_missing_epoch);
        (result, missing)
    }

    pub(crate) fn take_rejoin_request(
        &self,
    ) -> Result<Option<CredentialServiceRejoinRequest>, ProviderCredentialEnrollmentHostError> {
        self.rejoin.take()
    }

    pub(crate) fn complete_rejoin(
        &self,
        request: CredentialServiceRejoinRequest,
        succeeded: bool,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        self.rejoin.complete(request, succeeded)
    }

    pub(crate) fn prepare_rejoin_binding(
        &self,
        request: CredentialServiceRejoinRequest,
        owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
        expires_at_unix_millis: u64,
    ) -> Result<runne_api::CredentialServiceRejoinBinding, ProviderCredentialEnrollmentHostError>
    {
        self.session
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?
            .as_ref()
            .ok_or(ProviderCredentialEnrollmentHostError::Unavailable)?
            .prepare_rejoin_binding(request.epoch(), owned, expires_at_unix_millis)
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
    }
}

impl ProviderCredentialReadback for CredentialServiceRuntimeGateway {
    fn readback_exact_version(
        &self,
        input: ExactVersionReadback,
    ) -> Result<CredentialReadbackObservation, SecureStoreError> {
        let command = input.command();
        let present = self.read_metadata(
            input.version_ref().clone(),
            command.expected_lifecycle_revision(),
            command.expected_prior_fence(),
        )?;
        input.observe_service_presence(present)
    }

    fn readback_exact_absence(
        &self,
        input: ExactAbsenceReadback,
    ) -> Result<CredentialReadbackObservation, SecureStoreError> {
        let version = input
            .version_ref()
            .cloned()
            .ok_or(SecureStoreError::UnsupportedSecureStoreBackend)?;
        let command = input.command();
        let present = self.read_metadata(
            version,
            command.expected_lifecycle_revision(),
            command.expected_prior_fence(),
        )?;
        input.observe_service_presence(present)
    }
}

impl ProviderCredentialDispatchMaterializer for CredentialServiceRuntimeGateway {
    fn materialize_active(
        &self,
        read: ProviderCredentialDispatchRead<'_>,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        let receipt = CredentialBindingDigest::from_measured(read.effect_receipt_digest())
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        let now = now_unix_millis().map_err(map_host_error)?;
        let (result, missing_epoch) = self.with_session(|session| {
            session
                .ok_or(ProviderCredentialEnrollmentHostError::Unavailable)?
                .read_material(
                    &self.runtime,
                    &self.authority.runtime_read_authority(),
                    &self.authority.dispatch_effect_receipt_authority(),
                    read.capability().version_ref().clone(),
                    read.lifecycle(),
                    read.fence(),
                    receipt,
                    now,
                )
        });
        if let Some(epoch) = missing_epoch {
            let _ = self.rejoin.queue(epoch);
        }
        let material = result.map_err(map_host_error)?;
        let mut converted = Err(SecureStoreError::InvalidProviderCredential);
        material.consume(|bytes| {
            converted = ProviderCredentialMaterial::new(bytes.to_vec());
        });
        converted
    }
}

fn now_unix_millis() -> Result<u64, ProviderCredentialEnrollmentHostError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or(ProviderCredentialEnrollmentHostError::Unavailable)
}

const fn map_host_error(error: ProviderCredentialEnrollmentHostError) -> SecureStoreError {
    match error {
        ProviderCredentialEnrollmentHostError::Unsupported => {
            SecureStoreError::UnsupportedSecureStoreBackend
        }
        ProviderCredentialEnrollmentHostError::Unavailable => SecureStoreError::Unavailable,
        ProviderCredentialEnrollmentHostError::Conflict => {
            SecureStoreError::ProviderCredentialOperationFailed
        }
        ProviderCredentialEnrollmentHostError::InvariantViolation => {
            SecureStoreError::CorruptProviderCredential
        }
        ProviderCredentialEnrollmentHostError::InvalidRequest
        | ProviderCredentialEnrollmentHostError::AccessDenied => {
            SecureStoreError::CredentialAccessDenied
        }
    }
}
