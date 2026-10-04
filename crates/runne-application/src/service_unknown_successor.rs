use crate::commands::SupersedeUnknownTaskRunInput;
use crate::ports::{
    AggregateScope, IdempotencyScope, UnknownSuccessorCommit, UnknownSuccessorCommitResult,
    UnknownSuccessorRepository,
};

impl<E, U, I, A> TaskRunService<E, U, I, A>
where
    I: crate::ports::IdGenerator,
{
    /// Installs the trusted repository adapter that owns exact historical
    /// route resolution and the atomic successor transaction.
    pub fn with_unknown_successor_repository(
        mut self,
        repository: std::sync::Arc<dyn UnknownSuccessorRepository>,
    ) -> Self {
        self.unknown_successor_repository = Some(repository);
        self
    }

    /// Creates an explicitly acknowledged successor for an unresolved effect.
    /// All predecessor, conversation, stop-proof, route, and idempotency checks
    /// are repeated by the single repository transaction.
    pub fn supersede_unknown_task_run(
        &self,
        context: &ApplicationCommandContext,
        input: SupersedeUnknownTaskRunInput,
    ) -> Result<UnknownSuccessorCommitResult, ApplicationError> {
        let successor_taskrun_id = self
            .pipeline
            .id_generator
            .next_taskrun_id()
            .map_err(ApplicationError::IdGenerationFailed)?;
        let event_ids = self
            .pipeline
            .id_generator
            .next_event_ids(4)
            .map_err(ApplicationError::IdGenerationFailed)?
            .try_into()
            .map_err(|_| ApplicationError::StorageFailed(crate::ports::StorageFailureKind::CorruptData))?;
        let scope = IdempotencyScope {
            runtime_authority_id: self.pipeline.runtime_authority_id.clone(),
            principal_id: context.principal_id.clone(),
            operation: OperationTag::SupersedeUnknownTaskRun,
            aggregate_scope: AggregateScope::ExistingTaskRun {
                taskrun_id: input.predecessor_taskrun_id,
            },
        };
        let fingerprint = CommandFingerprint::for_supersede_unknown_task_run(&input);
        self.unknown_successor_repository
            .as_ref()
            .ok_or(ApplicationError::StorageFailed(
                crate::ports::StorageFailureKind::PolicyDenied,
            ))?
            .supersede_unknown_task_run(UnknownSuccessorCommit {
                command_id: context.command_id,
                idempotency_key: context.idempotency_key.clone(),
                idempotency_scope: scope,
                command_fingerprint: fingerprint,
                predecessor_taskrun_id: input.predecessor_taskrun_id,
                expected_predecessor_version: input.expected_predecessor_version,
                successor_taskrun_id,
                acknowledgement_digest: input.acknowledgment.digest(),
                event_ids,
                actor: context.actor.clone(),
            })
            .map_err(ApplicationError::from)
    }
}
