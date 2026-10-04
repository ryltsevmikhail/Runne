impl<E: EventStore, U: UnitOfWork, I: IdGenerator, A> TaskRunService<E, U, I, A> {
    /// Completes only a claimed cancellation whose store can prove it never
    /// crossed the atomic text-generation begin boundary.
    pub fn complete_claimed_taskrun_cancellation<
        P: crate::ports::TaskRunCancellationCompletionPort,
    >(
        &self,
        context: &ApplicationCommandContext,
        input: crate::ports::CompleteClaimedTaskRunCancellationInput,
        port: &P,
    ) -> Result<crate::ports::CompleteQueuedCancellationResult, CompleteQueuedCancellationServiceError>
    {
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
        let ids = self.pipeline.id_generator.next_event_ids(1)
            .map_err(CompleteQueuedCancellationServiceError::IdGeneration)?;
        let [id]: [_; 1] = ids.try_into()
            .map_err(|_| CompleteQueuedCancellationServiceError::InvalidStream)?;
        let events = materialize_batch(drafts, &[id], stream.last_event_id, &CommandContext {
            command_id: context.command_id,
            idempotency_key: context.idempotency_key.clone(),
            actor: context.actor.clone(),
        }).map_err(|_| CompleteQueuedCancellationServiceError::InvalidStream)?;
        let [cancellation_completed]: [_; 1] = events.try_into()
            .map_err(|_| CompleteQueuedCancellationServiceError::InvalidStream)?;
        let mut hasher = Sha256::new();
        hasher.update(b"runne-taskrun-claimed-cancellation-complete-v1");
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        let command_fingerprint = crate::fingerprint::CommandFingerprint::from_bytes(hasher.finalize().into());
        let idempotency_scope = crate::ports::IdempotencyScope {
            runtime_authority_id: self.pipeline.runtime_authority_id.clone(),
            principal_id: context.principal_id.clone(),
            operation: crate::ports::OperationTag::CompleteQueuedCancellation,
            aggregate_scope: crate::ports::AggregateScope::ExistingTaskRun { taskrun_id: input.taskrun_id },
        };
        port.complete_claimed_taskrun_cancellation(crate::ports::CompleteQueuedCancellationRequest {
            command_id: context.command_id,
            idempotency_key: context.idempotency_key.clone(),
            idempotency_scope,
            command_fingerprint,
            expected_version: input.expected_version,
            cancellation_completed,
        }).map_err(CompleteQueuedCancellationServiceError::Port)
    }
}
