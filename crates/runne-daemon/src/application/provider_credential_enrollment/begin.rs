#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protected V2 host composes authenticated begin after Task 8 admission wiring"
    )
)]

use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialBaseRequestAuthority,
    ProviderCredentialCommandContext, ProviderCredentialEnrollmentHostError,
    ProviderCredentialIntentConsumptionProof, ProviderCredentialOperationSnapshotV2,
};
use runne_provider::{ProviderCredentialEnrollmentStore, ProviderId};

use super::{
    CredentialEnrollmentReadback, CredentialEnrollmentRecoveryGateway, ProviderCredentialAdmission,
    operation_handle::ProviderCredentialOperationHandleIssuer, operation_projection,
};

/// Authenticated, recovery-first begin projection with no writer authority.
pub(crate) struct ProviderCredentialEnrollmentBegin<'a, S: ?Sized, R: ?Sized> {
    admission: ProviderCredentialAdmission,
    handles: ProviderCredentialOperationHandleIssuer,
    store: &'a S,
    reader: &'a R,
}

impl<'a, S: ?Sized, R: ?Sized> ProviderCredentialEnrollmentBegin<'a, S, R> {
    /// Retains only the durable admission dependencies and opaque handle key.
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

impl<S, R> ProviderCredentialEnrollmentBegin<'_, S, R>
where
    S: ProviderCredentialEnrollmentStore + ?Sized,
    R: CredentialEnrollmentReadback + ?Sized,
{
    /// Begins or exactly replays metadata-only enrollment after shared recovery.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit(
        &self,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        context: &ProviderCredentialCommandContext,
        command: &BeginProviderCredentialEnrollment,
        now_high_water: i64,
    ) -> Result<ProviderCredentialOperationSnapshotV2, ProviderCredentialEnrollmentHostError> {
        self.admission
            .require_begin_command(authority, proof, command, context)?;
        CredentialEnrollmentRecoveryGateway::new(self.store, self.reader)
            .reconcile_online(now_high_water)?;
        let proof_digest =
            runne_provider::CredentialBindingDigest::from_measured(*proof.proof_digest())
                .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        if let Some(operation) = self
            .store
            .find_by_begin_proof(proof_digest)
            .map_err(map_store)?
        {
            return self.replay(authority, proof_digest, context, command, operation);
        }
        let lifecycle = self
            .store
            .begin_admission_snapshot(&provider(command.provider())?)
            .map_err(map_store)?;
        let operation = match self
            .admission
            .admit_begin(authority, proof, command, context, lifecycle, self.store)?
        {
            super::coordinator::ProviderCredentialBeginAdmission::FreshWinner(effect) => {
                effect.consume()
            }
            super::coordinator::ProviderCredentialBeginAdmission::ExactReplay(operation) => {
                operation
            }
        };
        let lifecycle = self
            .store
            .lifecycle_snapshot(operation.provider())
            .map_err(map_store)?;
        operation_projection::snapshot(
            operation,
            &self.handles,
            lifecycle.readiness_revision().get(),
        )
    }

    fn replay(
        &self,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: runne_provider::CredentialBindingDigest,
        context: &ProviderCredentialCommandContext,
        command: &BeginProviderCredentialEnrollment,
        operation: runne_provider::CredentialOperationSnapshot,
    ) -> Result<ProviderCredentialOperationSnapshotV2, ProviderCredentialEnrollmentHostError> {
        let owner = runne_provider::CredentialInstallationOwnerId::from_bytes(
            *authority.installation_identity(),
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        if operation.begin_proof_digest() != proof
            || operation.installation_owner_id() != owner
            || operation.metadata().command_id() != context.command_id
            || operation.metadata().idempotency_key() != &context.idempotency_key
            || operation.lifecycle_revision().get() != command.expected_lifecycle_revision()
            || operation.provider() != &provider(command.provider())?
            || action(command.action())? != operation.action()
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let lifecycle = self
            .store
            .lifecycle_snapshot(operation.provider())
            .map_err(map_store)?;
        operation_projection::snapshot(
            operation,
            &self.handles,
            lifecycle.readiness_revision().get(),
        )
    }
}

fn provider(
    provider: runne_api::ProviderCredentialProviderV2,
) -> Result<ProviderId, ProviderCredentialEnrollmentHostError> {
    ProviderId::new(match provider {
        runne_api::ProviderCredentialProviderV2::OpenAi => "openai",
        runne_api::ProviderCredentialProviderV2::DeepSeek => "deepseek",
    })
    .map_err(|_| ProviderCredentialEnrollmentHostError::InvalidRequest)
}

fn action(
    action: runne_api::ProviderCredentialEnrollmentActionV2,
) -> Result<runne_provider::CredentialOperationAction, ProviderCredentialEnrollmentHostError> {
    match action {
        runne_api::ProviderCredentialEnrollmentActionV2::Pair => {
            Ok(runne_provider::CredentialOperationAction::Pair)
        }
        runne_api::ProviderCredentialEnrollmentActionV2::Revoke => {
            Ok(runne_provider::CredentialOperationAction::Revoke)
        }
        runne_api::ProviderCredentialEnrollmentActionV2::MigrateLegacy => {
            Ok(runne_provider::CredentialOperationAction::MigrateLegacy)
        }
    }
}

fn map_store(
    error: runne_provider::CredentialLifecycleError,
) -> ProviderCredentialEnrollmentHostError {
    super::effect_authority::map_store(error)
}
