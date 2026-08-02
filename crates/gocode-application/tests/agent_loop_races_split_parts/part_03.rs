#[test]
fn race_recovery_resume_vs_cancellation() {
    let mut stream = base_loop_stream();
    stream.push(envelope(6, TaskRunEvent::ReconciliationStarted));
    let agg = TaskRun::replay(&stream).unwrap();
    assert_eq!(agg.state(), TaskRunState::Reconciling);
    let before = agg.clone();

    let reconciliation_ref = ReconciliationResultRef {
        reconciliation_run_id: OTHER.parse().unwrap(),
        taskrun_id: TASK.parse().unwrap(),
        predecessor_attempt_id: ATTEMPT.parse().unwrap(),
        recovery_generation: 0,
        reconciled_stream_position: 5,
        status: ReconciliationStatus::Reconciled,
        unresolved_effect_count: 0,
        result_digest: digest(16),
    };

    let winner = TaskRunCommand::CommitRecoveryResume {
        new_attempt_id: ATT2.parse().unwrap(),
        context_manifest_ref: context_ref(),
        checkpoint_ref: CheckpointRef {
            checkpoint_id: OTHER.parse().unwrap(),
            event_position: 5,
            integrity_digest: digest(15),
        },
        reconciliation_ref: reconciliation_ref.clone(),
    };
    let winner_drafts = agg.decide(winner).unwrap();
    assert!(!winner_drafts.is_empty());

    let err = agg.decide(TaskRunCommand::RequestCancellation).unwrap_err();
    assert!(matches!(err, DomainError::InvalidTransition { .. }));

    let mut after_winner = agg.clone();
    for draft in &winner_drafts {
        after_winner.apply_payload(draft.payload()).unwrap();
    }
    assert_eq!(after_winner.state(), TaskRunState::Running);
    assert_eq!(after_winner.recovery_generation(), 1);
    assert_ne!(after_winner, before);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Race 6: Loop checkpoint vs terminal completion
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn race_loop_checkpoint_vs_completion() {
    let mut stream = base_loop_stream();
    stream.push(envelope(
        6,
        TaskRunEvent::ContextCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            manifest_ref: context_ref(),
        },
    ));
    let agg = TaskRun::replay(&stream).unwrap();
    assert_eq!(agg.state(), TaskRunState::Running);
    let _before = agg.clone();

    let checkpoint_id: CheckpointId = OTHER.parse().unwrap();
    let check_body = LoopCheckpointBody {
        schema_version: "1".into(),
        cycle_id: CYCLE.parse().unwrap(),
        attempt_id: ATTEMPT.parse().unwrap(),
        plan_revision_ref: None,
        context_manifest_ref: Some(context_ref()),
        step_outcome_refs: vec![],
    };

    let winner = TaskRunCommand::CommitLoopCheckpoint {
        checkpoint_id,
        event_position: 7,
        body: check_body,
        integrity_digest: digest(17),
    };
    let loser = TaskRunCommand::Complete {
        result: TerminalResult::Success,
    };

    let winner_drafts = agg.decide(winner).unwrap();
    let loser_drafts = agg.decide(loser.clone()).unwrap();
    assert_eq!(winner_drafts.len(), 3);
    assert!(!loser_drafts.is_empty());

    let mut after_winner = agg.clone();
    for draft in &winner_drafts {
        after_winner.apply_payload(draft.payload()).unwrap();
    }
    assert_eq!(after_winner.state(), TaskRunState::Running);
    assert!(after_winner.pending_loop_checkpoint().is_none());

    // Loser still valid on post-winner (state unchanged by checkpoint),
    // but pipeline catches version mismatch.
    let _ = after_winner.decide(loser).unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Cross-cutting: no partial mutations from failed loser
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn loser_never_causes_partial_mutations() {
    let mut stream = base_loop_stream();
    stream.push(envelope(
        6,
        TaskRunEvent::ContextCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            manifest_ref: context_ref(),
        },
    ));
    stream.push(envelope(
        7,
        TaskRunEvent::PlanCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            plan_revision_ref: plan_ref(vec![0]),
            input_digest: digest(9),
            output_digest: digest(10),
            expected_proposal_indexes: vec![0],
        },
    ));
    stream.push(envelope(
        8,
        TaskRunEvent::StepOutcomeRecorded {
            cycle_id: CYCLE.parse().unwrap(),
            outcome: StepOutcomeRecord {
                proposal_index: 0,
                step_id: OTHER.parse().unwrap(),
                outcome_type: StepOutcomeType::FailedBeforeCommit,
                result_ref: None,
                effect_id: None,
                evidence_digests: vec![],
            },
        },
    ));
    stream.push(envelope(
        9,
        TaskRunEvent::RetryScheduled {
            ordinal: 1,
            old_attempt_id: ATTEMPT.parse().unwrap(),
            new_attempt_id: ATT2.parse().unwrap(),
            abandoned_cycle_id: CYCLE.parse().unwrap(),
            step_outcome_ref: StepOutcomeRef {
                cycle_id: CYCLE.parse().unwrap(),
                proposal_index: 0,
                step_id: OTHER.parse().unwrap(),
                outcome_digest: digest(13),
            },
            retry_policy_digest: digest(14),
            budget_reservation_ref: budget_ref(),
            delay_ms: 25,
            due_at_unix_us: 25_100,
        },
    ));
    let agg = TaskRun::replay(&stream).unwrap();
    let before = agg.clone();

    let err = agg
        .decide(TaskRunCommand::ActivateScheduledRetryAttempt {
            retry_ordinal: 1,
            now_unix_us: 25_000,
        })
        .unwrap_err();
    assert_eq!(
        err,
        DomainError::LoopInvariantViolation {
            violation: LoopInvariantViolation::RetryNotDue,
        }
    );
    assert_eq!(agg, before);

    let err2 = before
        .decide(TaskRunCommand::ActivateScheduledRetryAttempt {
            retry_ordinal: 99,
            now_unix_us: 25_200,
        })
        .unwrap_err();
    assert!(matches!(err2, DomainError::LoopInvariantViolation { .. }));
    assert_eq!(before, agg);
}

// Service-level OCC version-conflict test

// (imports from top of file)

// Simple version-tracking store: load returns fixed events, commit checks OCC.
// After winner commits and advances version, loser's load sees updated version
// and pipeline returns VersionConflict (checked before domain decide).

#[derive(Clone)]
struct OccStore {
    events: Rc<RefCell<Vec<EventEnvelope<TaskRunEvent>>>>,
    version: Rc<Cell<u64>>,
}

impl OccStore {
    fn new(events: Vec<EventEnvelope<TaskRunEvent>>) -> Self {
        let v = events.last().map(|e| e.sequence()).unwrap_or(0);
        Self {
            events: Rc::new(RefCell::new(events)),
            version: Rc::new(Cell::new(v)),
        }
    }
}

impl EventStore for OccStore {
    fn load_task_run(&self, _: TaskRunId) -> Result<LoadedStream, EventStoreError> {
        let events = self.events.borrow().clone();
        let v = self.version.get();
        Ok(LoadedStream {
            current_version: v,
            last_event_id: events.last().map(|e| *e.event_id()),
            events,
        })
    }
}

impl UnitOfWork for OccStore {
    fn lookup_receipt(
        &self,
        _: CommandId,
        _: &IdempotencyKey,
        _: &IdempotencyScope,
        _: &CommandFingerprint,
    ) -> Result<ReceiptLookup, CommitError> {
        Ok(ReceiptLookup::Miss)
    }
    fn commit(&self, payload: CommandCommit) -> Result<CommitResult, CommitError> {
        let cur = self.version.get();
        if payload.expected_version != cur {
            return Err(CommitError::VersionConflict {
                expected: payload.expected_version,
                actual: cur,
            });
        }
        let nv = cur + payload.events.len() as u64;
        // Append committed events to keep version/event-count consistent
        let mut ev = self.events.borrow_mut();
        let mut seq = cur;
        for ue in &payload.events {
            seq += 1;
            ev.push(envelope(seq, ue.payload().clone()));
        }
        self.version.set(nv);
        Ok(CommitResult::Committed { new_version: nv })
    }
}

const GEN_ID: &str = "018f2e3a-7000-7000-8000-000000000010";
struct OI;
