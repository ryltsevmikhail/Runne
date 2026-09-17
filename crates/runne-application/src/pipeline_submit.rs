//! Client-authorized atomic TaskRun submit — pipeline stage.
//!
//! Companion module of [`crate::pipeline`]: one submit performs exactly one
//! [`UnitOfWork::commit`](crate::ports::UnitOfWork::commit) whose event batch
//! is `TaskRunCreated` followed by `TaskRunQueued`; a `create`-then-`queue`
//! sequence is forbidden by construction. Admission, attempt start, and
//! terminal completion stay runtime-owned and are never part of this command.

use runne_domain::command::SubmitTaskRun;
use runne_domain::event::{CommandContext, materialize_batch};
use runne_domain::task_run::TaskRun;

use crate::commands::CommandOutcome;
use crate::errors::ApplicationError;
use crate::fingerprint::CommandFingerprint;
use crate::pipeline::Pipeline;
use crate::ports::{
    AggregateScope, ApplicationCommandContext, CommandCommit, CommitResult, EventStore,
    IdGenerator, IdempotencyScope, OperationTag, ReceiptLookup, StorageFailureKind, UnitOfWork,
};

impl<E: EventStore, U: UnitOfWork, I: IdGenerator> Pipeline<E, U, I> {
    /// Executes one atomic submit: duplicate identities replay the stored
    /// acknowledgement, and the only successful commit appends the exact
    /// two-event `Created + Queued` batch as a single unit of work.
    pub(crate) fn execute_submit(
        &self,
        context: &ApplicationCommandContext,
        conversation_id: runne_domain::id::ConversationId,
        workspace_id: runne_domain::id::WorkspaceId,
        fingerprint: &CommandFingerprint,
    ) -> Result<CommandOutcome, ApplicationError> {
        let taskrun_id = self
            .id_generator
            .next_taskrun_id()
            .map_err(ApplicationError::IdGenerationFailed)?;

        let scope = IdempotencyScope {
            runtime_authority_id: self.runtime_authority_id.clone(),
            principal_id: context.principal_id.clone(),
            operation: OperationTag::SubmitTaskRun,
            aggregate_scope: AggregateScope::NewTaskRun {
                conversation_id,
                workspace_id,
            },
        };

        let lookup = self
            .unit_of_work
            .lookup_receipt(
                context.command_id,
                &context.idempotency_key,
                &scope,
                fingerprint,
            )
            .map_err(ApplicationError::from)?;
        if let ReceiptLookup::Duplicate { stored_result } = lookup {
            return Ok(stored_result);
        }

        let domain_ctx = CommandContext {
            command_id: context.command_id,
            idempotency_key: context.idempotency_key.clone(),
            actor: context.actor.clone(),
        };

        let drafts = TaskRun::decide_submit(SubmitTaskRun {
            taskrun_id,
            conversation_id,
            workspace_id,
        })
        .map_err(ApplicationError::Domain)?;
        debug_assert_eq!(drafts.len(), 2, "submit batch is Created + Queued");
        let event_count = drafts.len();

        let event_ids = self
            .id_generator
            .next_event_ids(event_count)
            .map_err(ApplicationError::IdGenerationFailed)?;

        let uncommitted = materialize_batch(drafts, &event_ids, None, &domain_ctx)
            .map_err(|_| ApplicationError::StorageFailed(StorageFailureKind::CorruptData))?;

        let new_version = event_count as u64;
        let outcome = CommandOutcome::TaskRunSubmitted {
            taskrun_id,
            new_version,
        };

        let commit_payload = CommandCommit {
            command_id: context.command_id,
            idempotency_key: context.idempotency_key.clone(),
            idempotency_scope: scope,
            command_fingerprint: *fingerprint,
            expected_version: 0,
            events: uncommitted,
            command_result: outcome.clone(),
        };

        match self
            .unit_of_work
            .commit(commit_payload)
            .map_err(ApplicationError::from)?
        {
            CommitResult::Committed { new_version: v } => {
                if v != new_version {
                    return Err(ApplicationError::CommitVersionMismatch {
                        computed: new_version,
                        returned: v,
                    });
                }
                Ok(outcome)
            }
            CommitResult::Duplicate { stored_result } => Ok(stored_result),
        }
    }
}
