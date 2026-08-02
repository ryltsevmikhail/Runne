impl IdGenerator for OI {
    fn next_taskrun_id(&self) -> Result<TaskRunId, IdGenerationError> {
        Ok(TASK.parse().unwrap())
    }
    fn next_conversation_id(&self) -> Result<gocode_domain::id::ConversationId, IdGenerationError> {
        Ok(OTHER.parse().unwrap())
    }
    fn next_attempt_id(&self) -> Result<AttemptId, IdGenerationError> {
        Ok(ATT2.parse().unwrap())
    }
    fn next_cycle_id(&self) -> Result<gocode_domain::id::CycleId, IdGenerationError> {
        Ok(OTHER.parse().unwrap())
    }
    fn next_checkpoint_id(&self) -> Result<gocode_domain::id::CheckpointId, IdGenerationError> {
        Ok(OTHER.parse().unwrap())
    }
    fn next_event_ids(
        &self,
        c: usize,
    ) -> Result<Vec<gocode_domain::id::EventId>, IdGenerationError> {
        Ok((0..c).map(|_| GEN_ID.parse().unwrap()).collect())
    }
}

struct OT;
impl TimePort for OT {
    fn now_unix_us(&self) -> Result<i64, TimeError> {
        Ok(0)
    }
}
struct OR;
impl RetrySchedulePort for OR {
    fn prepare(
        &self,
        _: TaskRunId,
        _: AttemptId,
        _: u64,
        _: &StepOutcomeRef,
        p: &IntegrityDigest,
        b: &BudgetReservationRef,
        n: i64,
    ) -> Result<PreparedRetrySchedule, RetryScheduleError> {
        Ok(PreparedRetrySchedule {
            retry_policy_digest: *p,
            budget_reservation_ref: b.clone(),
            delay_ms: 1,
            due_at_unix_us: n + 1000,
        })
    }
}
struct OW;
impl WakeEvidenceQueryPort for OW {
    fn validate_current(
        &self,
        _: &WakeEvidenceRef,
        _: TaskRunId,
        _: gocode_domain::id::CycleId,
        _: &WakeCondition,
    ) -> Result<(), WakeEvidenceError> {
        Ok(())
    }
}
struct OC;
impl ReconciliationQueryPort for OC {
    fn validate_current(
        &self,
        _: &gocode_domain::recovery::ReconciliationResultRef,
        _: TaskRunId,
        _: AttemptId,
        _: u64,
        _: u64,
    ) -> Result<(), ReconciliationError> {
        Ok(())
    }
}
struct OV;
impl VerificationQueryPort for OV {
    fn get_exact(&self, _: &PlanEvaluationRef) -> Result<PlanEvaluation, VerificationQueryError> {
        panic!("unexpected")
    }
}

fn oc_ctx(key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: TASK.parse().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId("p".into()),
        actor: Actor::new("p").unwrap(),
    }
}

/// Two concurrent CreateNextCycle commands on the same version.
/// Winner commits and advances version; loser hits VersionConflict via the pipeline.
#[test]
fn pipeline_version_conflict_two_create_next_cycle() {
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
            plan_revision_ref: plan_ref(vec![]),
            input_digest: digest(9),
            output_digest: digest(10),
            expected_proposal_indexes: vec![],
        },
    ));
    stream.push(envelope(
        8,
        TaskRunEvent::LoopCycleCompleted {
            cycle_id: CYCLE.parse().unwrap(),
            attempt_id: ATTEMPT.parse().unwrap(),
            disposition: LoopDisposition::Continue,
        },
    ));

    let tr: TaskRunId = TASK.parse().unwrap();
    let store = OccStore::new(stream);
    let svc = TaskRunService::with_agent_loop_authorities(
        store.clone(),
        store.clone(),
        OI,
        RuntimeAuthorityId("t".into()),
        AgentLoopAuthorities {
            time: OT,
            retry_schedule: OR,
            wake_evidence: OW,
            reconciliation: OC,
            verification: OV,
        },
    );

    let w = svc.create_next_cycle(
        &oc_ctx("w"),
        CreateNextCycleInput {
            taskrun_id: tr,
            expected_version: 8,
            parent_cycle_id: CYCLE.parse().unwrap(),
        },
    );
    assert!(
        matches!(w, Ok(CommandOutcome::NextCycleAllocated { .. })),
        "winner: {:?}",
        w
    );

    let l = svc.create_next_cycle(
        &oc_ctx("l"),
        CreateNextCycleInput {
            taskrun_id: tr,
            expected_version: 8,
            parent_cycle_id: CYCLE.parse().unwrap(),
        },
    );
    assert!(
        matches!(l, Err(ApplicationError::VersionConflict { .. })),
        "loser: {:?}",
        l
    );
}
