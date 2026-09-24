use super::*;
mod transition;

impl TaskRun {
    // ── apply ────────────────────────────────────────────────────────────

    /// Apply a committed event to this aggregate, mutating state.
    pub fn apply(&mut self, event: &EventEnvelope<TaskRunEvent>) -> Result<(), DomainError> {
        // Validate aggregate ID
        let expected = AggregateId::TaskRun(self.id);
        if *event.aggregate_id() != expected {
            return Err(DomainError::AggregateIdMismatch {
                expected: expected.clone(),
                actual: event.aggregate_id().clone(),
            });
        }

        if *event.correlation_id() != expected {
            return Err(DomainError::AggregateIdMismatch {
                expected,
                actual: event.correlation_id().clone(),
            });
        }

        self.apply_payload(event.payload())
    }

    // ── replay ───────────────────────────────────────────────────────────

    /// Replay a sequence of committed events to reconstruct an aggregate.
    ///
    /// # Requirements
    /// - The event stream must not be empty.
    /// - Sequence numbers must be continuous starting from 1.
    /// - All events must share the same task run ID.
    /// - The first event must be `TaskRunCreated`.
    /// - `TaskRunCreated` must not appear more than once.
    pub fn replay(events: &[EventEnvelope<TaskRunEvent>]) -> Result<Self, DomainError> {
        if events.is_empty() {
            return Err(DomainError::MissingCreationEvent {
                aggregate_type: AggregateType::TaskRun,
            });
        }

        // Validate first event is creation
        let first = &events[0];
        if first.payload().kind() != TaskRunEventKind::TaskRunCreated {
            return Err(DomainError::MissingCreationEvent {
                aggregate_type: AggregateType::TaskRun,
            });
        }

        // Validate initial sequence
        if first.sequence() != 1 {
            return Err(DomainError::InvalidInitialSequence {
                expected: 1,
                actual: first.sequence(),
            });
        }

        // The TaskRun's aggregate and correlation IDs must both be the same
        // TaskRun variant. Derive the ID from the aggregate ID so an invalid
        // correlation cannot fabricate an aggregate identity during replay.
        let taskrun_id = match first.aggregate_id() {
            AggregateId::TaskRun(tid) => *tid,
            _ => {
                return Err(DomainError::AggregateIdMismatch {
                    expected: first.correlation_id().clone(),
                    actual: first.aggregate_id().clone(),
                });
            }
        };
        let expected = AggregateId::TaskRun(taskrun_id);
        if *first.correlation_id() != expected {
            return Err(DomainError::AggregateIdMismatch {
                expected,
                actual: first.correlation_id().clone(),
            });
        }
        let mut agg = Self {
            id: taskrun_id,
            conversation_id: None,
            workspace_id: None,
            input: None,
            state: TaskRunState::Created,
            active_attempt: None,
            attempt_history: Vec::new(),
            terminal_result: None,
            active_cycle: None,
            last_completed_cycle: None,
            pending_successor: None,
            pending_loop_wait: None,
            pending_retry: None,
            pending_loop_checkpoint: None,
            cycle_history: Vec::new(),
            recovery_generation: 0,
        };

        let mut creation_seen = false;
        for (index, event) in events.iter().enumerate() {
            let expected_seq = index as u64 + 1;
            // Sequence continuity
            if event.sequence() != expected_seq {
                return Err(DomainError::SequenceGap {
                    expected: expected_seq,
                    actual: event.sequence(),
                });
            }

            // All events must belong to the same TaskRun aggregate and
            // correlation stream. Both checks are variant-sensitive equality.
            if *event.aggregate_id() != expected {
                return Err(DomainError::AggregateIdMismatch {
                    expected: expected.clone(),
                    actual: event.aggregate_id().clone(),
                });
            }
            if *event.correlation_id() != expected {
                return Err(DomainError::AggregateIdMismatch {
                    expected: expected.clone(),
                    actual: event.correlation_id().clone(),
                });
            }

            let payload = event.payload();

            // Duplicate creation check
            if payload.kind() == TaskRunEventKind::TaskRunCreated {
                if creation_seen {
                    return Err(DomainError::DuplicateCreationEvent {
                        aggregate_type: AggregateType::TaskRun,
                        aggregate_id: event.aggregate_id().clone(),
                    });
                }
                creation_seen = true;
            }

            Self::validate_replay_batch(events, index, &agg)?;
            agg.apply_payload(payload)?;
        }

        if agg.pending_loop_checkpoint.is_some() {
            return Err(DomainError::CorruptCheckpointBatch);
        }
        Ok(agg)
    }
}
