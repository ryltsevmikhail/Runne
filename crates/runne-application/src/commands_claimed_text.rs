/// Starts text generation against the exact TaskRun already claimed by a worker.
#[derive(Debug, Clone)]
pub struct BeginClaimedConversationTextInput {
    /// Conversation input, including its expected stream version.
    pub original: BeginConversationTextInput,
    /// Existing submitted TaskRun. The operation never creates another run.
    pub taskrun_id: TaskRunId,
    /// Exact attempt allocated by the TaskRun claim.
    pub attempt_id: AttemptId,
    /// Current TaskRun stream version from the claim receipt.
    pub taskrun_version: u64,
    /// Workspace recorded by both the Conversation and submitted TaskRun.
    pub workspace_id: WorkspaceId,
    /// Current node, epoch, attempt and monotonically increasing fence.
    pub assignment: crate::ports::TaskRunAssignmentIdentity,
}
