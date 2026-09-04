use rand::{RngCore, rngs::OsRng};
use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    BindCredentialReadback, CompleteCredentialOperation, CredentialBindingDigest,
    CredentialLifecycleRevision, CredentialLifecycleSnapshot, CredentialOperationAction,
    CredentialOperationId, CredentialOperationSnapshot, CredentialReadbackDisposition,
    CredentialReadinessDisposition, CredentialReadinessObservation, CredentialReadinessRevision,
    FailCredentialOperation,
};
use runne_secure_store::SecureStoreError;
use runne_secure_store::{ExactAbsenceReadback, ExactVersionReadback, ProviderCredentialReadback};

pub(crate) trait CredentialEnrollmentReadback {
    fn observe(
        &self,
        operation: &CredentialOperationSnapshot,
        command: &runne_provider::CredentialBrokerCommand,
    ) -> Result<BindCredentialReadback, ProviderCredentialEnrollmentHostError>;

    fn observe_recovery(
        &self,
        operation: &CredentialOperationSnapshot,
        command: &runne_provider::CredentialBrokerCommand,
    ) -> Result<CredentialRecoveryReadback, ProviderCredentialEnrollmentHostError> {
        self.observe(operation, command)
            .map(CredentialRecoveryReadback::Bound)
    }
}

pub(crate) enum CredentialRecoveryReadback {
    Bound(BindCredentialReadback),
    VerifiedAbsence(FailCredentialOperation),
}

impl<R: ProviderCredentialReadback + ?Sized> CredentialEnrollmentReadback for R {
    fn observe(
        &self,
        operation: &CredentialOperationSnapshot,
        command: &runne_provider::CredentialBrokerCommand,
    ) -> Result<BindCredentialReadback, ProviderCredentialEnrollmentHostError> {
        match observe_exact(self, operation, command)? {
            CredentialRecoveryReadback::Bound(readback) => Ok(readback),
            CredentialRecoveryReadback::VerifiedAbsence(_) => {
                Err(ProviderCredentialEnrollmentHostError::InvariantViolation)
            }
        }
    }

    fn observe_recovery(
        &self,
        operation: &CredentialOperationSnapshot,
        command: &runne_provider::CredentialBrokerCommand,
    ) -> Result<CredentialRecoveryReadback, ProviderCredentialEnrollmentHostError> {
        observe_exact(self, operation, command)
    }
}

pub(super) const fn supported(action: CredentialOperationAction) -> bool {
    matches!(
        action,
        CredentialOperationAction::Pair
            | CredentialOperationAction::MigrateLegacy
            | CredentialOperationAction::Revoke
            | CredentialOperationAction::RetiredVersionCleanup
            | CredentialOperationAction::LegacySourceCleanup
    )
}

fn observe_exact<R: ProviderCredentialReadback + ?Sized>(
    reader: &R,
    operation: &CredentialOperationSnapshot,
    command: &runne_provider::CredentialBrokerCommand,
) -> Result<CredentialRecoveryReadback, ProviderCredentialEnrollmentHostError> {
    let (disposition, observation) = match operation.action() {
        CredentialOperationAction::Pair | CredentialOperationAction::MigrateLegacy => (
            CredentialReadbackDisposition::ExactVersion,
            reader
                .readback_exact_version(
                    ExactVersionReadback::new(command.clone())
                        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
                )
                .map_err(map_readback_error)?,
        ),
        CredentialOperationAction::Revoke
        | CredentialOperationAction::RetiredVersionCleanup
        | CredentialOperationAction::LegacySourceCleanup => (
            CredentialReadbackDisposition::ExactAbsence,
            reader
                .readback_exact_absence(
                    ExactAbsenceReadback::new(command.clone())
                        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
                )
                .map_err(map_readback_error)?,
        ),
        _ => return Err(ProviderCredentialEnrollmentHostError::Unsupported),
    };
    if !observation.present()
        && matches!(
            operation.action(),
            CredentialOperationAction::Pair | CredentialOperationAction::MigrateLegacy
        )
    {
        return Ok(CredentialRecoveryReadback::VerifiedAbsence(
            FailCredentialOperation::new(operation.operation_id(), observation.binding()),
        ));
    }
    if observation.present() != (disposition == CredentialReadbackDisposition::ExactVersion) {
        return Err(ProviderCredentialEnrollmentHostError::InvariantViolation);
    }
    BindCredentialReadback::new(operation.operation_id(), disposition, observation.binding())
        .map(CredentialRecoveryReadback::Bound)
        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
}

fn map_readback_error(error: SecureStoreError) -> ProviderCredentialEnrollmentHostError {
    match error {
        SecureStoreError::CredentialAccessDenied
        | SecureStoreError::CredentialIdentityMismatch
        | SecureStoreError::CredentialAclMigrationRequired => {
            ProviderCredentialEnrollmentHostError::AccessDenied
        }
        SecureStoreError::UnsupportedSecureStoreBackend => {
            ProviderCredentialEnrollmentHostError::Unsupported
        }
        SecureStoreError::CorruptProviderCredential => {
            ProviderCredentialEnrollmentHostError::InvariantViolation
        }
        SecureStoreError::ProviderCredentialOperationFailed => {
            ProviderCredentialEnrollmentHostError::Conflict
        }
        _ => ProviderCredentialEnrollmentHostError::Unavailable,
    }
}

pub(super) fn persisted(
    operation: &CredentialOperationSnapshot,
) -> Result<BindCredentialReadback, ProviderCredentialEnrollmentHostError> {
    let metadata = operation.metadata();
    let disposition = metadata
        .readback_disposition()
        .ok_or(ProviderCredentialEnrollmentHostError::InvariantViolation)?;
    let digest = metadata
        .readback_observation_digest()
        .ok_or(ProviderCredentialEnrollmentHostError::InvariantViolation)?;
    let expected = match operation.action() {
        CredentialOperationAction::Pair | CredentialOperationAction::MigrateLegacy => {
            CredentialReadbackDisposition::ExactVersion
        }
        CredentialOperationAction::Revoke
        | CredentialOperationAction::RetiredVersionCleanup
        | CredentialOperationAction::LegacySourceCleanup => {
            CredentialReadbackDisposition::ExactAbsence
        }
        _ => return Err(ProviderCredentialEnrollmentHostError::Unsupported),
    };
    if disposition != expected {
        return Err(ProviderCredentialEnrollmentHostError::InvariantViolation);
    }
    BindCredentialReadback::new(operation.operation_id(), disposition, digest)
        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
}

pub(super) fn completion(
    operation: &CredentialOperationSnapshot,
    readback: BindCredentialReadback,
    lifecycle: CredentialLifecycleSnapshot,
    now_high_water: i64,
) -> Result<CompleteCredentialOperation, ProviderCredentialEnrollmentHostError> {
    let legacy_cleanup = operation.action() == CredentialOperationAction::LegacySourceCleanup;
    let head_matches = if legacy_cleanup {
        operation.metadata().legacy_cleanup_binding().is_some()
            && lifecycle.lifecycle_revision().get() >= operation.lifecycle_revision().get()
            && lifecycle.fence().get() >= operation.fence().get()
    } else {
        lifecycle.lifecycle_revision() == operation.lifecycle_revision()
            && lifecycle.fence() == operation.fence()
    };
    if now_high_water < 0 || lifecycle.provider() != operation.provider() || !head_matches {
        return Err(ProviderCredentialEnrollmentHostError::Conflict);
    }
    let tuple = operation
        .metadata()
        .qualified_release_tuple_digest()
        .ok_or(ProviderCredentialEnrollmentHostError::InvariantViolation)?;
    if operation.action() == CredentialOperationAction::LegacySourceCleanup {
        return CompleteCredentialOperation::new(
            operation.operation_id(),
            readback,
            operation.lifecycle_revision(),
            operation.fence(),
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation);
    }
    let successor_lifecycle = next_lifecycle(operation.lifecycle_revision())?;
    let successor_readiness = next_readiness(lifecycle.readiness_revision())?;
    let (disposition, active) = match operation.action() {
        CredentialOperationAction::Pair | CredentialOperationAction::MigrateLegacy => {
            let version = operation
                .allocated_credential_version()
                .ok_or(ProviderCredentialEnrollmentHostError::InvariantViolation)?;
            (
                CredentialReadinessDisposition::Ready,
                Some(
                    CredentialBindingDigest::from_measured(*version.ref_digest())
                        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
                ),
            )
        }
        CredentialOperationAction::Revoke => (CredentialReadinessDisposition::Missing, None),
        CredentialOperationAction::RetiredVersionCleanup => match lifecycle.active_version() {
            Some(version) => (
                CredentialReadinessDisposition::Ready,
                Some(
                    CredentialBindingDigest::from_measured(*version.ref_digest())
                        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
                ),
            ),
            None => (CredentialReadinessDisposition::Missing, None),
        },
        _ => return Err(ProviderCredentialEnrollmentHostError::Unsupported),
    };
    let readiness = CredentialReadinessObservation::new(
        observation_id()?,
        Some(operation.operation_id()),
        operation.provider().clone(),
        successor_lifecycle,
        successor_readiness,
        disposition,
        active,
        tuple,
        now_high_water,
    )
    .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?;
    CompleteCredentialOperation::new(
        operation.operation_id(),
        readback,
        operation.lifecycle_revision(),
        operation.fence(),
    )
    .map(|input| input.with_readiness_observation(readiness))
    .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
}

fn next_lifecycle(
    value: CredentialLifecycleRevision,
) -> Result<CredentialLifecycleRevision, ProviderCredentialEnrollmentHostError> {
    CredentialLifecycleRevision::new(
        value
            .get()
            .checked_add(1)
            .ok_or(ProviderCredentialEnrollmentHostError::InvariantViolation)?,
    )
    .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
}

fn next_readiness(
    value: CredentialReadinessRevision,
) -> Result<CredentialReadinessRevision, ProviderCredentialEnrollmentHostError> {
    CredentialReadinessRevision::new(
        value
            .get()
            .checked_add(1)
            .ok_or(ProviderCredentialEnrollmentHostError::InvariantViolation)?,
    )
    .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
}

fn observation_id() -> Result<CredentialOperationId, ProviderCredentialEnrollmentHostError> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
    CredentialOperationId::from_bytes(bytes)
        .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)
}
