use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialBaseRequestAuthority,
    ProviderCredentialCommandContext, ProviderCredentialEnrollmentHostError,
    ProviderCredentialIntentConsumptionProof, ProviderCredentialOperationSnapshotV2,
};
use runne_provider::ProviderCredentialEnrollmentStore;
#[cfg(unix)]
use runne_provider::{ClosePreparedCredentialOperation, CredentialOperationState, ProviderId};

#[cfg(unix)]
use super::operation_projection;
use super::{
    CredentialEnrollmentReadback, CredentialEnrollmentRecoveryGateway, ProviderCredentialAdmission,
    broker::pending::{PendingBrokerAdmissionGate, PendingBrokerRendezvousRegistry},
    operation_handle::ProviderCredentialOperationHandleIssuer,
};

/// Authenticated, recovery-first begin projection with no writer authority.
pub(crate) struct ProviderCredentialEnrollmentBegin<'a, S: ?Sized, R: ?Sized> {
    admission: ProviderCredentialAdmission,
    #[cfg_attr(not(unix), allow(dead_code))]
    handles: ProviderCredentialOperationHandleIssuer,
    store: &'a S,
    reader: &'a R,
    #[cfg_attr(not(unix), allow(dead_code))]
    rendezvous: PendingBrokerRendezvousRegistry,
    #[cfg(test)]
    before_gate_barrier: Option<std::sync::Arc<std::sync::Barrier>>,
}

#[cfg(unix)]
struct ExactBeginReplay<'a> {
    authority: &'a ProviderCredentialBaseRequestAuthority,
    proof: &'a ProviderCredentialIntentConsumptionProof,
    context: &'a ProviderCredentialCommandContext,
    command: &'a BeginProviderCredentialEnrollment,
    operation: runne_provider::CredentialOperationSnapshot,
    now_high_water: i64,
    gate: PendingBrokerAdmissionGate<'a>,
}

impl<'a, S: ?Sized, R: ?Sized> ProviderCredentialEnrollmentBegin<'a, S, R> {
    /// Retains only the durable admission dependencies and opaque handle key.
    pub(crate) const fn new(
        admission: ProviderCredentialAdmission,
        handles: ProviderCredentialOperationHandleIssuer,
        store: &'a S,
        reader: &'a R,
        rendezvous: PendingBrokerRendezvousRegistry,
    ) -> Self {
        Self {
            admission,
            handles,
            store,
            reader,
            rendezvous,
            #[cfg(test)]
            before_gate_barrier: None,
        }
    }

    // Consumed by the unix rendezvous race scenario only.
    #[cfg(all(test, unix))]
    pub(crate) fn with_before_gate_barrier(
        mut self,
        barrier: std::sync::Arc<std::sync::Barrier>,
    ) -> Self {
        self.before_gate_barrier = Some(barrier);
        self
    }
}

impl<S, R> ProviderCredentialEnrollmentBegin<'_, S, R>
where
    S: ProviderCredentialEnrollmentStore + ?Sized,
    R: CredentialEnrollmentReadback + ?Sized,
{
    /// Begins or exactly replays metadata-only enrollment after shared recovery.
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
        #[cfg(test)]
        if let Some(barrier) = &self.before_gate_barrier {
            barrier.wait();
        }
        #[cfg(not(unix))]
        return Err(ProviderCredentialEnrollmentHostError::Unsupported);
        #[cfg(unix)]
        self.admit_with_rendezvous(authority, proof, context, command, now_high_water)
    }

    /// Unix rendezvous half of the begin flow: the reserved broker transition
    /// exists only on the unix native transport, so non-unix hosts fail with
    /// the typed unsupported refusal before reaching this method.
    #[cfg(unix)]
    #[allow(clippy::too_many_arguments)]
    fn admit_with_rendezvous(
        &self,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        context: &ProviderCredentialCommandContext,
        command: &BeginProviderCredentialEnrollment,
        now_high_water: i64,
    ) -> Result<ProviderCredentialOperationSnapshotV2, ProviderCredentialEnrollmentHostError> {
        let gate = self.rendezvous.begin_gate(now_high_water)?;
        if let Some(operation) = self
            .store
            .find_by_command(context.command_id, &context.idempotency_key)
            .map_err(map_store)?
        {
            return self.replay(ExactBeginReplay {
                authority,
                proof,
                context,
                command,
                operation,
                now_high_water,
                gate,
            });
        }
        let rendezvous = gate.preflight(authority, proof)?;
        let lifecycle = self
            .store
            .begin_admission_snapshot(&provider(command.provider())?)
            .map_err(map_store)?;
        let operation = match self
            .admission
            .admit_begin(authority, proof, command, context, lifecycle, self.store)?
        {
            super::coordinator::ProviderCredentialBeginAdmission::FreshWinner(effect) => {
                rendezvous.commit_fresh(effect)
            }
            super::coordinator::ProviderCredentialBeginAdmission::ExactReplay(operation) => {
                // A different store connection committed after the gated lookup. Its
                // operation owns no endpoint in this process, so destroy our unused
                // reservation and return only the exact durable projection.
                drop(rendezvous);
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
            &self.rendezvous,
            now_high_water,
        )
    }

    #[cfg(unix)]
    fn replay(
        &self,
        replay: ExactBeginReplay<'_>,
    ) -> Result<ProviderCredentialOperationSnapshotV2, ProviderCredentialEnrollmentHostError> {
        let ExactBeginReplay {
            authority,
            proof,
            context,
            command,
            mut operation,
            now_high_water,
            gate,
        } = replay;
        let replay_identity = (|| {
            let owner = runne_provider::CredentialInstallationOwnerId::from_bytes(
                *authority.installation_identity(),
            )
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
            let release = runne_provider::CredentialBindingDigest::from_measured(
                *authority.release_tuple_digest(),
            )
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
            Ok(operation.installation_owner_id() == owner
                && operation.metadata().command_id() == context.command_id
                && operation.metadata().idempotency_key() == &context.idempotency_key
                && operation.lifecycle_revision().get() == command.expected_lifecycle_revision()
                && operation.provider() == &provider(command.provider())?
                && action(command.action())? == operation.action()
                && operation.metadata().qualified_release_tuple_digest() == Some(release))
        })();
        match replay_identity {
            Ok(true) => {}
            Ok(false) => {
                gate.discard_unused(authority, proof)?;
                return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
            }
            Err(error) => {
                gate.discard_unused(authority, proof)?;
                return Err(error);
            }
        }
        let lost_prepared_rendezvous = operation.state() == CredentialOperationState::Prepared
            && !gate.has_process_authority(operation.operation_id())?;
        if lost_prepared_rendezvous
            && operation.action() == runne_provider::CredentialOperationAction::Revoke
        {
            gate.preflight(authority, proof)?
                .commit_recovered_revoke(&operation)?;
        } else {
            gate.discard_unused(authority, proof)?;
        }
        if lost_prepared_rendezvous
            && operation.action() != runne_provider::CredentialOperationAction::Revoke
        {
            let closure = ClosePreparedCredentialOperation::new(
                operation.operation_id(),
                CredentialOperationState::Expired,
            )
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?;
            operation = self.store.expire_before_claim(closure).map_err(map_store)?;
        }
        let lifecycle = self
            .store
            .lifecycle_snapshot(operation.provider())
            .map_err(map_store)?;
        operation_projection::snapshot(
            operation,
            &self.handles,
            lifecycle.readiness_revision().get(),
            &self.rendezvous,
            now_high_water,
        )
    }
}

#[cfg(unix)]
fn provider(
    provider: runne_api::ProviderCredentialProviderV2,
) -> Result<ProviderId, ProviderCredentialEnrollmentHostError> {
    ProviderId::new(provider.as_str())
        .map_err(|_| ProviderCredentialEnrollmentHostError::InvalidRequest)
}

#[cfg(unix)]
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

#[cfg(unix)]
fn map_store(
    error: runne_provider::CredentialLifecycleError,
) -> ProviderCredentialEnrollmentHostError {
    super::effect_authority::map_store(error)
}
