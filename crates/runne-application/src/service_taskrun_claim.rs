use runne_domain::event::{CommandContext, materialize_batch};
use runne_domain::task_run::TaskRun;
use sha2::{Digest, Sha256};

fn claim_identity(
    context: &ApplicationCommandContext,
    input: &ClaimTaskRunInput,
    runtime_authority_id: &crate::ports::RuntimeAuthorityId,
) -> (
    crate::ports::IdempotencyScope,
    crate::fingerprint::CommandFingerprint,
) {
    let scope = crate::ports::IdempotencyScope {
        runtime_authority_id: runtime_authority_id.clone(),
        principal_id: context.principal_id.clone(),
        operation: crate::ports::OperationTag::TaskRunClaim,
        aggregate_scope: crate::ports::AggregateScope::ExistingTaskRun {
            taskrun_id: input.taskrun_id,
        },
    };
    let mut hasher = Sha256::new();
    hasher.update(b"runne-taskrun-claim-v1");
    hasher.update(input.taskrun_id.as_bytes());
    hasher.update(input.expected_version.to_be_bytes());
    hasher.update((input.node_id.0.len() as u64).to_be_bytes());
    hasher.update(input.node_id.0.as_bytes());
    hasher.update(input.node_epoch.to_be_bytes());
    hasher.update((input.capability_descriptor.len() as u64).to_be_bytes());
    hasher.update(input.capability_descriptor.as_bytes());
    hasher.update(input.lease_duration_ms.to_be_bytes());
    let fingerprint = crate::fingerprint::CommandFingerprint::from_bytes(hasher.finalize().into());
    (scope, fingerprint)
}

/// Runtime-selected target and lease intent for a queued TaskRun.
#[derive(Debug, Clone)]
pub struct ClaimTaskRunInput {
    pub taskrun_id: runne_domain::id::TaskRunId,
    pub expected_version: u64,
    pub node_id: crate::ports::ExecutionNodeId,
    pub node_epoch: u64,
    pub capability_descriptor: String,
    pub lease_duration_ms: u64,
}

/// Application-side failure. Every error is fail closed and makes no claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimTaskRunServiceError {
    EventStore(crate::ports::EventStoreError),
    Domain(runne_domain::error::DomainError),
    VersionConflict { expected: u64, actual: u64 },
    NotQueued,
    IdGeneration(crate::ports::IdGenerationError),
    InvalidStream,
    Port(crate::ports::TaskRunClaimError),
}

impl<E: EventStore, U: UnitOfWork, I: IdGenerator, A> TaskRunService<E, U, I, A> {
    /// Atomically assign one committed Queued stream to a runtime-selected node.
    /// The single store call owns assignment, fencing, lease and both events.
    pub fn claim_task_run<P: crate::ports::TaskRunClaimPort>(
        &self,
        context: &ApplicationCommandContext,
        input: ClaimTaskRunInput,
        port: &P,
    ) -> Result<crate::ports::TaskRunClaimResult, ClaimTaskRunServiceError> {
        let (scope, command_fingerprint) =
            claim_identity(context, &input, &self.pipeline.runtime_authority_id);
        let lookup = port
            .lookup_task_run_claim(crate::ports::TaskRunClaimLookup {
                command_id: context.command_id,
                idempotency_key: context.idempotency_key.clone(),
                idempotency_scope: scope.clone(),
                command_fingerprint,
            })
            .map_err(ClaimTaskRunServiceError::Port)?;
        if let crate::ports::TaskRunClaimLookupResult::Duplicate(receipt) = lookup {
            return Ok(crate::ports::TaskRunClaimResult::Duplicate(receipt));
        }
        let stream = self
            .pipeline
            .event_store
            .load_task_run(input.taskrun_id)
            .map_err(ClaimTaskRunServiceError::EventStore)?;
        if stream.events.is_empty()
            || stream.events.last().map(|e| e.sequence()) != Some(stream.current_version)
            || stream.last_event_id != stream.events.last().map(|e| *e.event_id())
        {
            return Err(ClaimTaskRunServiceError::InvalidStream);
        }
        let mut task = TaskRun::replay(&stream.events).map_err(ClaimTaskRunServiceError::Domain)?;
        if stream.current_version != input.expected_version {
            if let Some(replay) = replay_after_preflight_race(
                port,
                context,
                &scope,
                command_fingerprint,
            )? {
                return Ok(replay);
            }
            return Err(ClaimTaskRunServiceError::VersionConflict {
                expected: input.expected_version,
                actual: stream.current_version,
            });
        }
        if task.state() != TaskRunState::Queued {
            if let Some(replay) = replay_after_preflight_race(
                port,
                context,
                &scope,
                command_fingerprint,
            )? {
                return Ok(replay);
            }
            return Err(ClaimTaskRunServiceError::NotQueued);
        }
        let admitted = task
            .decide(TaskRunCommand::Admit)
            .map_err(ClaimTaskRunServiceError::Domain)?;
        if admitted.len() != 1 {
            return Err(ClaimTaskRunServiceError::InvalidStream);
        }
        task.apply_payload(admitted[0].payload())
            .map_err(ClaimTaskRunServiceError::Domain)?;
        let attempt_id = self
            .pipeline
            .id_generator
            .next_attempt_id()
            .map_err(ClaimTaskRunServiceError::IdGeneration)?;
        let started = task
            .decide(TaskRunCommand::StartAttempt { attempt_id })
            .map_err(ClaimTaskRunServiceError::Domain)?;
        if started.len() != 1 {
            return Err(ClaimTaskRunServiceError::InvalidStream);
        }
        let event_ids = self
            .pipeline
            .id_generator
            .next_event_ids(2)
            .map_err(ClaimTaskRunServiceError::IdGeneration)?;
        if event_ids.len() != 2 {
            return Err(ClaimTaskRunServiceError::InvalidStream);
        }
        let command_context = CommandContext {
            command_id: context.command_id,
            idempotency_key: context.idempotency_key.clone(),
            actor: context.actor.clone(),
        };
        let events = materialize_batch(
            vec![admitted[0].clone(), started[0].clone()],
            &event_ids,
            stream.last_event_id,
            &command_context,
        )
        .map_err(|_| ClaimTaskRunServiceError::InvalidStream)?;
        let [admitted_event, started_event]: [_; 2] = events
            .try_into()
            .map_err(|_| ClaimTaskRunServiceError::InvalidStream)?;
        port.claim_task_run(crate::ports::TaskRunClaimRequest {
            command_id: context.command_id,
            idempotency_key: context.idempotency_key.clone(),
            idempotency_scope: scope,
            command_fingerprint,
            expected_version: input.expected_version,
            taskrun_id: input.taskrun_id,
            attempt_id,
            node_id: input.node_id,
            node_epoch: input.node_epoch,
            capability_descriptor: input.capability_descriptor,
            lease_duration_ms: input.lease_duration_ms,
            admitted_event,
            started_event,
        })
        .map_err(ClaimTaskRunServiceError::Port)
    }
}

fn replay_after_preflight_race<P: crate::ports::TaskRunClaimPort>(
    port: &P,
    context: &ApplicationCommandContext,
    scope: &crate::ports::IdempotencyScope,
    fingerprint: crate::fingerprint::CommandFingerprint,
) -> Result<Option<crate::ports::TaskRunClaimResult>, ClaimTaskRunServiceError> {
    match port
        .lookup_task_run_claim(crate::ports::TaskRunClaimLookup {
            command_id: context.command_id,
            idempotency_key: context.idempotency_key.clone(),
            idempotency_scope: scope.clone(),
            command_fingerprint: fingerprint,
        })
        .map_err(ClaimTaskRunServiceError::Port)?
    {
        crate::ports::TaskRunClaimLookupResult::Miss => Ok(None),
        crate::ports::TaskRunClaimLookupResult::Duplicate(receipt) => {
            Ok(Some(crate::ports::TaskRunClaimResult::Duplicate(receipt)))
        }
    }
}
