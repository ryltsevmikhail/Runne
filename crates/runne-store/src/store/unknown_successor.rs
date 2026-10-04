mod commit;
mod validate;

use super::*;
use runne_application::ports::{
    AggregateScope, CommitError, IdempotencyScope, OperationTag, UnknownSuccessorCommit,
    UnknownSuccessorCommitResult,
};
use runne_application::provider::HistoricalProviderModelResolver;
use runne_domain::id::{CommandId, EventId, IdempotencyKey, IntegrityDigest, TaskRunId};
use std::sync::Arc;

fn storage_failure(kind: StorageFailureKind) -> CommitError {
    CommitError::StorageFailure(kind)
}

impl StoreTransaction {
    pub fn unknown_successor_repository(
        &self,
        resolver: Arc<dyn HistoricalProviderModelResolver>,
    ) -> SqliteUnknownSuccessorRepository {
        SqliteUnknownSuccessorRepository {
            store: self.clone(),
            resolver,
        }
    }

    pub(crate) fn commit_unknown_successor(
        &self,
        payload: UnknownSuccessorCommit,
        resolver: &dyn HistoricalProviderModelResolver,
    ) -> Result<UnknownSuccessorCommitResult, CommitError> {
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let tx = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        commit::commit(self, tx, payload, resolver)
    }

    fn unknown_successor_is_eligible(
        &self,
        taskrun_id: TaskRunId,
        expected_version: u64,
        resolver: &dyn HistoricalProviderModelResolver,
    ) -> Result<bool, CommitError> {
        let mut connection = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let tx = connection
            .transaction()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let eligible = unknown_successor_eligibility_in_transaction(
            &tx,
            &self.runtime_authority_id,
            taskrun_id,
            expected_version,
            resolver,
        )?;
        tx.commit()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        Ok(matches!(
            eligible,
            runne_api::SuccessorEligibilityV1::Eligible
                | runne_api::SuccessorEligibilityV1::RequiresDuplicateEffectAcknowledgment
        ))
    }
}

/// Evaluates successor eligibility inside the caller's authoritative read transaction.
pub(crate) fn unknown_successor_eligibility_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    runtime_authority_id: &RuntimeAuthorityId,
    taskrun_id: TaskRunId,
    expected_version: u64,
    resolver: &dyn HistoricalProviderModelResolver,
) -> Result<runne_api::SuccessorEligibilityV1, CommitError> {
    let origin = crate::store::taskrun_submit_origin::verify_submitted_v2_origin(
        tx,
        taskrun_id,
        runtime_authority_id,
    )?;
    let Some(origin) = origin else {
        return Ok(runne_api::SuccessorEligibilityV1::NotApplicable);
    };
    if origin.input.local_command().is_some() {
        return Ok(runne_api::SuccessorEligibilityV1::NotApplicable);
    }
    let payload = UnknownSuccessorCommit {
        // These IDs are never persisted by the read-only eligibility
        // query; they only satisfy the shared validation input shape.
        command_id: CommandId::from_bytes([0xe1; 16]),
        idempotency_key: IdempotencyKey::new("effects-readiness").expect("static key"),
        idempotency_scope: IdempotencyScope {
            runtime_authority_id: runtime_authority_id.clone(),
            principal_id: origin.principal_id.clone(),
            operation: OperationTag::SupersedeUnknownTaskRun,
            aggregate_scope: AggregateScope::ExistingTaskRun { taskrun_id },
        },
        command_fingerprint: runne_application::fingerprint::CommandFingerprint::from_bytes(
            [0; 32],
        ),
        predecessor_taskrun_id: taskrun_id,
        expected_predecessor_version: expected_version,
        successor_taskrun_id: TaskRunId::from_bytes([0xe2; 16]),
        acknowledgement_digest: IntegrityDigest::from_bytes([0; 32]),
        event_ids: [
            EventId::from_bytes([0xe3; 16]),
            EventId::from_bytes([0xe4; 16]),
            EventId::from_bytes([0xe5; 16]),
            EventId::from_bytes([0xe6; 16]),
        ],
        actor: origin.actor,
    };
    Ok(if validate::validate(tx, &payload, resolver).is_ok() {
        runne_api::SuccessorEligibilityV1::RequiresDuplicateEffectAcknowledgment
    } else {
        runne_api::SuccessorEligibilityV1::Blocked
    })
}

pub struct SqliteUnknownSuccessorRepository {
    store: StoreTransaction,
    resolver: Arc<dyn HistoricalProviderModelResolver>,
}

impl runne_application::ports::UnknownSuccessorRepository for SqliteUnknownSuccessorRepository {
    fn supersede_unknown_task_run(
        &self,
        payload: UnknownSuccessorCommit,
    ) -> Result<UnknownSuccessorCommitResult, CommitError> {
        self.store
            .commit_unknown_successor(payload, self.resolver.as_ref())
    }
}

impl SqliteUnknownSuccessorRepository {
    /// Returns only whether the commit validator currently accepts the exact
    /// predecessor/version. The command transaction still repeats this proof.
    pub fn is_eligible(
        &self,
        taskrun_id: TaskRunId,
        expected_version: u64,
    ) -> Result<bool, CommitError> {
        self.store.unknown_successor_is_eligible(
            taskrun_id,
            expected_version,
            self.resolver.as_ref(),
        )
    }
}
