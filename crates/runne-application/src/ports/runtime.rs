// ── IdGenerator ─────────────────────────────────────────────────────────────

/// Generates unique identifiers for aggregates, events, and attempts.
pub trait IdGenerator {
    /// Generate a new unique [`TaskRunId`].
    fn next_taskrun_id(&self) -> Result<TaskRunId, IdGenerationError>;

    /// Generate a new unique [`ConversationId`].
    fn next_conversation_id(&self) -> Result<ConversationId, IdGenerationError>;

    /// Generate a new unique [`AttemptId`].
    fn next_attempt_id(&self) -> Result<AttemptId, IdGenerationError>;

    /// Generate a new unique [`MessageId`].
    fn next_message_id(&self) -> Result<MessageId, IdGenerationError> {
        Err(IdGenerationError::Unavailable)
    }

    /// Generate a new unique loop cycle ID.
    fn next_cycle_id(&self) -> Result<CycleId, IdGenerationError> {
        Err(IdGenerationError::Unavailable)
    }

    /// Generate a new unique loop checkpoint ID.
    fn next_checkpoint_id(&self) -> Result<CheckpointId, IdGenerationError> {
        Err(IdGenerationError::Unavailable)
    }

    /// Generate `count` new unique [`EventId`]s.
    fn next_event_ids(&self, count: usize) -> Result<Vec<EventId>, IdGenerationError>;
}

/// Error from [`IdGenerator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdGenerationError {
    /// The ID source has been exhausted.
    Exhausted,
    /// The ID source is temporarily unavailable.
    Unavailable,
}

// ── Clock ───────────────────────────────────────────────────────────────────

/// Provides the current wall-clock time for event timestamps.
pub trait Clock {
    /// Return the current time as a [`Timestamp`].
    fn now(&self) -> Result<Timestamp, ClockError>;
}

/// Error from [`Clock`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockError {
    /// The clock could not be read.
    Unavailable,
}

/// Provider of authoritative wall-clock microseconds for retry scheduling.
pub trait TimePort {
    fn now_unix_us(&self) -> Result<i64, TimeError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeError {
    Unavailable,
    OutOfRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRetrySchedule {
    pub retry_policy_digest: IntegrityDigest,
    pub budget_reservation_ref: BudgetReservationRef,
    pub delay_ms: u64,
    pub due_at_unix_us: i64,
}

pub trait RetrySchedulePort {
    #[allow(clippy::too_many_arguments)]
    fn prepare(
        &self,
        taskrun_id: TaskRunId,
        attempt_id: AttemptId,
        retry_ordinal: u64,
        step_outcome_ref: &StepOutcomeRef,
        requested_policy_digest: &IntegrityDigest,
        requested_budget_reservation: &BudgetReservationRef,
        now_unix_us: i64,
    ) -> Result<PreparedRetrySchedule, RetryScheduleError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryScheduleError {
    Denied,
    BudgetExhausted,
    StaleReservation,
    Unavailable,
}

pub trait WakeEvidenceQueryPort {
    fn validate_current(
        &self,
        evidence: &WakeEvidenceRef,
        taskrun_id: TaskRunId,
        cycle_id: CycleId,
        condition: &WakeCondition,
    ) -> Result<(), WakeEvidenceError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeEvidenceError {
    Missing,
    Stale,
    Forged,
    CrossCycle,
    Unavailable,
}

pub trait ReconciliationQueryPort {
    fn validate_current(
        &self,
        evidence: &ReconciliationResultRef,
        taskrun_id: TaskRunId,
        predecessor_attempt_id: AttemptId,
        expected_generation: u64,
        expected_stream_head: u64,
    ) -> Result<(), ReconciliationError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationError {
    Missing,
    Stale,
    UnresolvedEffects,
    InvalidBinding,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateEvaluationRef {
    pub gate_id: String,
    pub evidence_digest: IntegrityDigest,
    pub result_digest: IntegrityDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanEvaluation {
    pub reference: PlanEvaluationRef,
    pub gate_evaluation_refs: Vec<GateEvaluationRef>,
    pub evaluated_at_unix_us: i64,
    pub superseded_by: Option<PlanEvaluationId>,
}

pub trait VerificationQueryPort {
    fn get_exact(
        &self,
        reference: &PlanEvaluationRef,
    ) -> Result<PlanEvaluation, VerificationQueryError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationQueryError {
    Missing,
    Stale,
    InvalidBinding,
    DigestMismatch,
    Unavailable,
}
