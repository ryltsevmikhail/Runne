pub(super) struct LoopPorts;
impl TimePort for LoopPorts {
    fn now_unix_us(&self) -> Result<i64, TimeError> {
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| TimeError::Unavailable)?
            .as_micros() as i64)
    }
}
impl RetrySchedulePort for LoopPorts {
    fn prepare(
        &self,
        _: runne_domain::id::TaskRunId,
        _: runne_domain::id::AttemptId,
        _: u64,
        _: &runne_domain::agent_loop::StepOutcomeRef,
        _: &IntegrityDigest,
        _: &runne_domain::reference::BudgetReservationRef,
        _: i64,
    ) -> Result<runne_application::ports::PreparedRetrySchedule, RetryScheduleError> {
        Err(RetryScheduleError::Unavailable)
    }
}
impl WakeEvidenceQueryPort for LoopPorts {
    fn validate_current(
        &self,
        _: &runne_domain::agent_loop::WakeEvidenceRef,
        _: runne_domain::id::TaskRunId,
        _: runne_domain::id::CycleId,
        _: &runne_domain::agent_loop::WakeCondition,
    ) -> Result<(), WakeEvidenceError> {
        Err(WakeEvidenceError::Unavailable)
    }
}
impl ReconciliationQueryPort for LoopPorts {
    fn validate_current(
        &self,
        _: &runne_domain::recovery::ReconciliationResultRef,
        _: runne_domain::id::TaskRunId,
        _: runne_domain::id::AttemptId,
        _: u64,
        _: u64,
    ) -> Result<(), runne_application::ports::ReconciliationError> {
        Err(ReconciliationError::Unavailable)
    }
}
impl VerificationQueryPort for LoopPorts {
    fn get_exact(
        &self,
        _: &runne_domain::verification::PlanEvaluationRef,
    ) -> Result<runne_application::ports::PlanEvaluation, VerificationQueryError> {
        Err(VerificationQueryError::Unavailable)
    }
}

pub(super) fn loop_task_runs(
    store: &StoreTransaction,
) -> TaskRunService<
    StoreTransaction,
    StoreTransaction,
    StoreTransaction,
    AgentLoopAuthorities<LoopPorts, LoopPorts, LoopPorts, LoopPorts, LoopPorts>,
> {
    loop_task_runs_for_authority(store, authority())
}

pub(super) fn loop_task_runs_for_authority(
    store: &StoreTransaction,
    runtime_authority_id: runne_application::ports::RuntimeAuthorityId,
) -> TaskRunService<
    StoreTransaction,
    StoreTransaction,
    StoreTransaction,
    AgentLoopAuthorities<LoopPorts, LoopPorts, LoopPorts, LoopPorts, LoopPorts>,
> {
    TaskRunService::with_agent_loop_authorities(
        store.clone(),
        store.clone(),
        store.clone(),
        runtime_authority_id,
        AgentLoopAuthorities {
            time: LoopPorts,
            retry_schedule: LoopPorts,
            wake_evidence: LoopPorts,
            reconciliation: LoopPorts,
            verification: LoopPorts,
        },
    )
}
