
/// Fail-closed failures while settling a claimed attempt proven never dispatched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskRunNoEffectSettlementError {
    EventStore(crate::ports::EventStoreError),
    Domain(runne_domain::error::DomainError),
    InvalidStream,
    IdGeneration(crate::ports::IdGenerationError),
    Port(crate::ports::TaskRunNoEffectReleaseError),
}

include!("service_taskrun_release/claimed_cancellation.rs");

impl<E: EventStore, U: UnitOfWork, I: IdGenerator, A> TaskRunService<E, U, I, A> {
    /// Atomically fails an old-epoch attempt whose durable ledgers prove no dispatch.
    pub fn settle_taskrun_no_effect<P: crate::ports::TaskRunNoEffectReleasePort>(
        &self,
        context: &ApplicationCommandContext,
        candidate: crate::ports::TaskRunNoEffectCandidate,
        port: &P,
    ) -> Result<crate::ports::TaskRunNoEffectReleaseResult, TaskRunNoEffectSettlementError> {
        let identity = &candidate.identity;
        let stream = self
            .pipeline
            .event_store
            .load_task_run(identity.taskrun_id)
            .map_err(TaskRunNoEffectSettlementError::EventStore)?;
        if stream.current_version != candidate.current_version
            || stream.last_event_id != stream.events.last().map(|event| *event.event_id())
        {
            return Err(TaskRunNoEffectSettlementError::InvalidStream);
        }
        let task = TaskRun::replay(&stream.events)
            .map_err(TaskRunNoEffectSettlementError::Domain)?;
        if task.state() != TaskRunState::Running {
            return Err(TaskRunNoEffectSettlementError::InvalidStream);
        }
        let drafts = task
            .decide(TaskRunCommand::Fail {
                reason: "dispatch_not_started".into(),
            })
            .map_err(TaskRunNoEffectSettlementError::Domain)?;
        if drafts.len() != 1 {
            return Err(TaskRunNoEffectSettlementError::InvalidStream);
        }
        let event_id = self
            .pipeline
            .id_generator
            .next_event_ids(1)
            .map_err(TaskRunNoEffectSettlementError::IdGeneration)?;
        let [failure_event]: [_; 1] = event_id
            .try_into()
            .map_err(|_| TaskRunNoEffectSettlementError::InvalidStream)?;
        let events = materialize_batch(
            drafts,
            &[failure_event],
            stream.last_event_id,
            &CommandContext {
                command_id: context.command_id,
                idempotency_key: context.idempotency_key.clone(),
                actor: context.actor.clone(),
            },
        )
        .map_err(|_| TaskRunNoEffectSettlementError::InvalidStream)?;
        let [failure_event]: [_; 1] = events
            .try_into()
            .map_err(|_| TaskRunNoEffectSettlementError::InvalidStream)?;
        let fingerprint = no_effect_fingerprint(identity, candidate.current_version);
        let scope = crate::ports::IdempotencyScope {
            runtime_authority_id: self.pipeline.runtime_authority_id.clone(),
            principal_id: context.principal_id.clone(),
            operation: crate::ports::OperationTag::TaskRunNoEffectRelease,
            aggregate_scope: crate::ports::AggregateScope::ExistingTaskRun {
                taskrun_id: identity.taskrun_id,
            },
        };
        port.release_taskrun_no_effect(crate::ports::TaskRunNoEffectReleaseRequest {
            command_id: context.command_id,
            idempotency_key: context.idempotency_key.clone(),
            idempotency_scope: scope,
            command_fingerprint: fingerprint,
            expected_version: candidate.current_version,
            identity: identity.clone(),
            failure_event,
        })
        .map_err(TaskRunNoEffectSettlementError::Port)
    }
}

fn no_effect_fingerprint(
    identity: &crate::ports::TaskRunAssignmentIdentity,
    version: u64,
) -> crate::fingerprint::CommandFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(b"runne-taskrun-no-effect-settlement-v1");
    hasher.update(identity.taskrun_id.as_bytes());
    hasher.update(identity.attempt_id.as_bytes());
    hasher.update(identity.fence.0.to_be_bytes());
    hasher.update(version.to_be_bytes());
    crate::fingerprint::CommandFingerprint::from_bytes(hasher.finalize().into())
}

/// Fail-closed failures completing a never-claimed queued cancellation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompleteQueuedCancellationServiceError {
    EventStore(crate::ports::EventStoreError),
    Domain(runne_domain::error::DomainError),
    VersionConflict { expected: u64, actual: u64 },
    InvalidStream,
    IdGeneration(crate::ports::IdGenerationError),
    Port(crate::ports::CompleteQueuedCancellationError),
}

impl<E: EventStore, U: UnitOfWork, I: IdGenerator, A> TaskRunService<E, U, I, A> {
    /// Completes cancellation only when the store atomically proves the run
    /// never had a claim, dispatch intent, or provider binding.
    pub fn complete_queued_cancellation<P: crate::ports::TaskRunCancellationCompletionPort>(
        &self,
        context: &ApplicationCommandContext,
        input: crate::ports::CompleteQueuedCancellationInput,
        port: &P,
    ) -> Result<crate::ports::CompleteQueuedCancellationResult, CompleteQueuedCancellationServiceError> {
        let stream = self.pipeline.event_store.load_task_run(input.taskrun_id)
            .map_err(CompleteQueuedCancellationServiceError::EventStore)?;
        if stream.current_version != input.expected_version
            || stream.last_event_id != stream.events.last().map(|event| *event.event_id())
        {
            return Err(CompleteQueuedCancellationServiceError::VersionConflict {
                expected: input.expected_version,
                actual: stream.current_version,
            });
        }
        let task = TaskRun::replay(&stream.events)
            .map_err(CompleteQueuedCancellationServiceError::Domain)?;
        if task.state() != TaskRunState::Cancelling {
            return Err(CompleteQueuedCancellationServiceError::InvalidStream);
        }
        let drafts = task.decide(TaskRunCommand::CompleteCancellation)
            .map_err(CompleteQueuedCancellationServiceError::Domain)?;
        if drafts.len() != 1 {
            return Err(CompleteQueuedCancellationServiceError::InvalidStream);
        }
        let event_ids = self.pipeline.id_generator.next_event_ids(1)
            .map_err(CompleteQueuedCancellationServiceError::IdGeneration)?;
        let [event_id]: [_; 1] = event_ids.try_into()
            .map_err(|_| CompleteQueuedCancellationServiceError::InvalidStream)?;
        let events = materialize_batch(drafts, &[event_id], stream.last_event_id, &CommandContext {
            command_id: context.command_id,
            idempotency_key: context.idempotency_key.clone(),
            actor: context.actor.clone(),
        }).map_err(|_| CompleteQueuedCancellationServiceError::InvalidStream)?;
        let [cancellation_completed]: [_; 1] = events.try_into()
            .map_err(|_| CompleteQueuedCancellationServiceError::InvalidStream)?;
        let mut hasher = Sha256::new();
        hasher.update(b"runne-taskrun-queued-cancellation-complete-v1");
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        let command_fingerprint = crate::fingerprint::CommandFingerprint::from_bytes(hasher.finalize().into());
        let idempotency_scope = crate::ports::IdempotencyScope {
            runtime_authority_id: self.pipeline.runtime_authority_id.clone(),
            principal_id: context.principal_id.clone(),
            operation: crate::ports::OperationTag::CompleteQueuedCancellation,
            aggregate_scope: crate::ports::AggregateScope::ExistingTaskRun { taskrun_id: input.taskrun_id },
        };
        port.complete_queued_cancellation(crate::ports::CompleteQueuedCancellationRequest {
            command_id: context.command_id,
            idempotency_key: context.idempotency_key.clone(),
            idempotency_scope,
            command_fingerprint,
            expected_version: input.expected_version,
            cancellation_completed,
        }).map_err(CompleteQueuedCancellationServiceError::Port)
    }
}
