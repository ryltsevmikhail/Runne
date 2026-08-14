#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunPromotionStateV1 {
    pub(super) lifecycle: TaskRunLifecycleV1,
    pub(super) active_attempt: Option<[u8; 16]>,
    pub(super) attempt_history: Vec<[u8; 16]>,
    pub(super) terminal_result: Option<TaskRunTerminalResultV1>,
    pub(super) active_cycle: Option<TaskRunActiveCycleV1>,
    pub(super) last_completed_cycle: Option<TaskRunCompletedCycleV1>,
    pub(super) pending_successor: Option<TaskRunSuccessorV1>,
    pub(super) pending_wait: Option<TaskRunWaitV1>,
    pub(super) pending_retry: Option<TaskRunRetryV1>,
    pub(super) pending_checkpoint: Option<TaskRunCheckpointV1>,
    pub(super) cycle_history: Vec<TaskRunCycleHistoryV1>,
    pub(super) recovery_generation: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TaskRunLifecycleV1 {
    Created,
    Queued,
    Admitted,
    Running,
    Waiting,
    Retrying,
    Checkpointing,
    Cancelling,
    Reconciling,
    Succeeded,
    Failed,
    Cancelled,
    BudgetExhausted,
    PolicyDenied,
    Unrecoverable,
}
#[derive(Clone, PartialEq, Eq)]
pub enum TaskRunTerminalResultV1 {
    Success,
    Failure { reason: String },
}
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunActiveCycleV1 {
    pub(super) cycle_id: [u8; 16],
    pub(super) attempt_id: [u8; 16],
    pub(super) sequence: u64,
    pub(super) parent_cycle_id: Option<[u8; 16]>,
    pub(super) state: TaskRunLoopStateV1,
    pub(super) context: Option<TaskRunContextRefV1>,
    pub(super) plan: Option<TaskRunPlanRefV1>,
    pub(super) expected_indexes: Vec<u32>,
    pub(super) outcomes: Vec<TaskRunOutcomeV1>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TaskRunLoopStateV1 {
    Observing,
    Proposing,
    Acting,
    Evaluating,
    Completed,
}
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunContextRefV1 {
    pub(super) manifest_id: [u8; 16],
    pub(super) taskrun_id: [u8; 16],
    pub(super) attempt_id: [u8; 16],
    pub(super) cycle_id: [u8; 16],
    pub(super) revision: u64,
    pub(super) policy_revision: String,
    pub(super) integrity_digest: [u8; 32],
}
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunPlanRefV1 {
    pub(super) plan_id: [u8; 16],
    pub(super) taskrun_id: [u8; 16],
    pub(super) cycle_id: [u8; 16],
    pub(super) revision: u64,
    pub(super) context: TaskRunContextRefV1,
    pub(super) expected_indexes: Vec<u32>,
    pub(super) proposal_batch_digest: [u8; 32],
    pub(super) policy: TaskRunResultRefV1,
    pub(super) budget: TaskRunBudgetRefV1,
    pub(super) parent: Option<TaskRunPlanParentV1>,
    pub(super) integrity_digest: [u8; 32],
}
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunPlanParentV1 {
    pub(super) plan_id: [u8; 16],
    pub(super) revision: u64,
    pub(super) integrity_digest: [u8; 32],
}
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunResultRefV1 {
    pub(super) result_id: [u8; 16],
    pub(super) media_type: String,
    pub(super) integrity_digest: [u8; 32],
}
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunBudgetRefV1 {
    pub(super) reservation_id: [u8; 16],
    pub(super) taskrun_id: [u8; 16],
    pub(super) attempt_id: [u8; 16],
    pub(super) retry_ordinal: u64,
    pub(super) reservation_digest: [u8; 32],
}
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunOutcomeV1 {
    pub(super) proposal_index: u32,
    pub(super) step_id: [u8; 16],
    pub(super) outcome: TaskRunOutcomeKindV1,
    pub(super) result: Option<TaskRunResultRefV1>,
    pub(super) effect_id: Option<[u8; 16]>,
    pub(super) evidence_digests: Vec<[u8; 32]>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TaskRunOutcomeKindV1 {
    Succeeded,
    FailedBeforeCommit,
    FailedAfterCommit,
    Uncertain,
    Cancelled,
}
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunCompletedCycleV1 {
    pub(super) cycle_id: [u8; 16],
    pub(super) attempt_id: [u8; 16],
    pub(super) sequence: u64,
    pub(super) disposition: TaskRunDispositionV1,
    pub(super) accepted_wake_evidence: Option<TaskRunWakeEvidenceV1>,
    pub(super) successor_allocated: bool,
}
#[derive(Clone, PartialEq, Eq)]
pub enum TaskRunDispositionV1 {
    Continue,
    Wait {
        reason: String,
        wake: TaskRunWakeV1,
    },
    Complete {
        evaluation: TaskRunEvaluationV1,
    },
    Fail {
        reason: String,
        unresolved_indexes: Vec<u32>,
    },
}
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunWakeV1 {
    pub(super) kind: TaskRunWakeKindV1,
    pub(super) condition_ref: String,
    pub(super) condition_digest: [u8; 32],
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TaskRunWakeKindV1 {
    ExternalInput,
    Approval,
    ChildTaskRun,
    Timer,
    Reconciliation,
}
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunWakeEvidenceV1 {
    pub(super) cycle_id: [u8; 16],
    pub(super) condition_digest: [u8; 32],
    pub(super) source: TaskRunWakeKindV1,
    pub(super) evidence_id: [u8; 16],
    pub(super) evidence_digest: [u8; 32],
    pub(super) observed_at_unix_us: i64,
    pub(super) authority_revision: String,
}
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunEvaluationV1 {
    pub(super) evaluation_id: [u8; 16],
    pub(super) taskrun_id: [u8; 16],
    pub(super) plan_id: [u8; 16],
    pub(super) plan_revision: u64,
    pub(super) evaluated_stream_head: u64,
    pub(super) result: TaskRunEvaluationResultV1,
    pub(super) gate_definitions_digest: [u8; 32],
    pub(super) evidence_set_digest: [u8; 32],
    pub(super) evaluation_digest: [u8; 32],
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TaskRunEvaluationResultV1 {
    Passed,
    Failed,
    Blocked,
    RequiresReview,
}
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunSuccessorV1 {
    pub(super) parent_cycle_id: [u8; 16],
    pub(super) successor_cycle_id: [u8; 16],
    pub(super) attempt_id: [u8; 16],
    pub(super) sequence: u64,
}
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunWaitV1 {
    pub(super) cycle_id: [u8; 16],
    pub(super) wake: TaskRunWakeV1,
}
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunRetryV1 {
    pub(super) ordinal: u64,
    pub(super) old_attempt_id: [u8; 16],
    pub(super) new_attempt_id: [u8; 16],
    pub(super) abandoned_cycle_id: [u8; 16],
    pub(super) outcome: TaskRunOutcomeRefV1,
    pub(super) due_at_unix_us: i64,
    pub(super) delay_ms: u64,
    pub(super) budget: TaskRunBudgetRefV1,
    pub(super) retry_policy_digest: [u8; 32],
}
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunOutcomeRefV1 {
    pub(super) cycle_id: [u8; 16],
    pub(super) proposal_index: u32,
    pub(super) step_id: [u8; 16],
    pub(super) outcome_digest: [u8; 32],
}
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunCheckpointV1 {
    pub(super) checkpoint_id: [u8; 16],
    pub(super) start_position: u64,
    pub(super) expected_integrity_digest: [u8; 32],
    pub(super) recorded_integrity_digest: Option<[u8; 32]>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunCycleHistoryV1 {
    pub(super) cycle_id: [u8; 16],
    pub(super) attempt_id: [u8; 16],
    pub(super) sequence: u64,
    pub(super) parent_cycle_id: Option<[u8; 16]>,
}

impl TaskRunPromotionStateV1 {
    pub const fn lifecycle(&self) -> TaskRunLifecycleV1 {
        self.lifecycle
    }
    pub fn active_attempt(&self) -> Option<[u8; 16]> {
        self.active_attempt
    }
    pub fn attempt_history(&self) -> &[[u8; 16]] {
        &self.attempt_history
    }
    pub fn terminal_result(&self) -> Option<&TaskRunTerminalResultV1> {
        self.terminal_result.as_ref()
    }
    pub fn active_cycle(&self) -> Option<&TaskRunActiveCycleV1> {
        self.active_cycle.as_ref()
    }
    pub fn last_completed_cycle(&self) -> Option<&TaskRunCompletedCycleV1> {
        self.last_completed_cycle.as_ref()
    }
    pub fn pending_successor(&self) -> Option<&TaskRunSuccessorV1> {
        self.pending_successor.as_ref()
    }
    pub fn pending_wait(&self) -> Option<&TaskRunWaitV1> {
        self.pending_wait.as_ref()
    }
    pub fn pending_retry(&self) -> Option<&TaskRunRetryV1> {
        self.pending_retry.as_ref()
    }
    pub fn pending_checkpoint(&self) -> Option<&TaskRunCheckpointV1> {
        self.pending_checkpoint.as_ref()
    }
    pub fn cycle_history(&self) -> &[TaskRunCycleHistoryV1] {
        &self.cycle_history
    }
    pub const fn recovery_generation(&self) -> u64 {
        self.recovery_generation
    }
}
impl TaskRunLifecycleV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Queued => "queued",
            Self::Admitted => "admitted",
            Self::Running => "running",
            Self::Waiting => "waiting",
            Self::Retrying => "retrying",
            Self::Checkpointing => "checkpointing",
            Self::Cancelling => "cancelling",
            Self::Reconciling => "reconciling",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::BudgetExhausted => "budget_exhausted",
            Self::PolicyDenied => "policy_denied",
            Self::Unrecoverable => "unrecoverable",
        }
    }
}
