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
pub enum TaskRunDispatchIntentResult {
    Prepared,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskRunAssignmentError {
    StaleAssignment,
    LeaseExpired,
    NodeUnavailable,
    IdempotencyConflict,
    CorruptData,
    Unavailable,
}

/// Prompt data proven by the authoritative TaskRun stream and current claim.
/// This is data only; it grants no dispatch or effect authority. Consumers must
/// separately validate the live node epoch, lease and fence and prepare dispatch.
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunExecutionInputV2 {
    pub taskrun_id: TaskRunId,
    pub attempt_id: AttemptId,
    pub stream_version: u64,
    pub conversation_id: ConversationId,
    pub workspace_id: WorkspaceId,
    /// Authenticated submitter from the immutable TaskRun submission receipt.
    pub principal_id: crate::ports::PrincipalId,
    /// Domain actor recorded on the immutable submission event.
    pub submit_actor: runne_domain::event::Actor,
    /// Exact model admitted when the immutable submission was accepted.
    pub requested_model: Option<String>,
    /// Exact profile identity included in the authenticated submit stream.
    pub selected_profile: Option<runne_domain::task_run::SelectedProviderProfile>,
    pub input: runne_domain::task_run::TaskRunInput,
}

impl std::fmt::Debug for TaskRunExecutionInputV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskRunExecutionInputV2")
            .field("taskrun_id", &self.taskrun_id)
            .field("attempt_id", &self.attempt_id)
            .field("stream_version", &self.stream_version)
            .field("conversation_id", &self.conversation_id)
            .field("workspace_id", &self.workspace_id)
            .field("principal_id", &self.principal_id)
            .field("submit_actor", &self.submit_actor)
            .field("requested_model", &self.requested_model)
            .field("input", &self.input)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRunExecutionInputError {
    UnsupportedInput,
    StaleAssignment,
    StaleVersion,
    NotExecutable,
    CorruptData,
    Unavailable,
}

/// Read-only boundary for one exact, currently active TaskRun assignment.
/// A successful read does not authorize dispatch or effects.
pub trait TaskRunExecutionInputPort {
    fn read_taskrun_execution_input(
        &self,
        identity: TaskRunAssignmentIdentity,
        expected_claim_version: u64,
    ) -> Result<TaskRunExecutionInputV2, TaskRunExecutionInputError>;
}

/// Runtime-owned narrow worker lifecycle boundary. Implementations must use one
/// immediate transaction and the store's database clock for both operations.
pub trait TaskRunAssignmentPort {
    fn renew_taskrun_assignment_lease(
        &self,
        request: TaskRunLeaseRenewal,
    ) -> Result<TaskRunLeaseReceipt, TaskRunAssignmentError>;
    fn prepare_taskrun_dispatch(
        &self,
        identity: TaskRunAssignmentIdentity,
    ) -> Result<TaskRunDispatchIntentResult, TaskRunAssignmentError>;
}
