/// Exact claim identity required for every worker lifecycle mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRunAssignmentIdentity {
    pub taskrun_id: TaskRunId,
    pub attempt_id: AttemptId,
    pub node_id: ExecutionNodeId,
    pub node_epoch: u64,
    pub fence: TaskRunFence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRunLeaseRenewal {
    pub identity: TaskRunAssignmentIdentity,
    pub renewal_id: CommandId,
    pub lease_duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRunLeaseReceipt {
    pub lease_expires_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRunDispatchIntentResult { Prepared, Duplicate }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskRunAssignmentError {
    StaleAssignment,
    LeaseExpired,
    NodeUnavailable,
    IdempotencyConflict,
    CorruptData,
    Unavailable,
}

/// Runtime-owned narrow worker lifecycle boundary. Implementations must use one
/// immediate transaction and the store's database clock for both operations.
pub trait TaskRunAssignmentPort {
    fn renew_taskrun_assignment_lease(&self, request: TaskRunLeaseRenewal) -> Result<TaskRunLeaseReceipt, TaskRunAssignmentError>;
    fn prepare_taskrun_dispatch(&self, identity: TaskRunAssignmentIdentity) -> Result<TaskRunDispatchIntentResult, TaskRunAssignmentError>;
}
