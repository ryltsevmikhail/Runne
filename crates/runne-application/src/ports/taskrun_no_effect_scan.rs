/// Exact assignment proven old-epoch, active, and never dispatched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRunNoEffectCandidate {
    pub identity: TaskRunAssignmentIdentity,
    pub current_version: u64,
}

/// Bounded old-epoch scan position and page size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRunNoEffectScanRequest {
    after: Option<TaskRunId>,
    limit: usize,
    node_id: ExecutionNodeId,
    current_epoch: u64,
}

impl TaskRunNoEffectScanRequest {
    pub fn new(
        after: Option<TaskRunId>,
        limit: usize,
        node_id: ExecutionNodeId,
        current_epoch: u64,
    ) -> Option<Self> {
        (1..=MAX_NO_EFFECT_SCAN_PAGE)
            .contains(&limit)
            .then_some(Self { after, limit, node_id, current_epoch })
    }
    pub fn after(&self) -> Option<TaskRunId> { self.after }
    pub const fn limit(&self) -> usize { self.limit }
    pub fn node_id(&self) -> &ExecutionNodeId { &self.node_id }
    pub const fn current_epoch(&self) -> u64 { self.current_epoch }
}

pub const MAX_NO_EFFECT_SCAN_PAGE: usize = 128;

/// Page of exact assignments that can be safely terminalized without replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRunNoEffectScanPage {
    pub candidates: Vec<TaskRunNoEffectCandidate>,
    pub next_cursor: Option<TaskRunId>,
    pub reached_end: bool,
}

/// Read-only bounded recovery scan; it grants no release authority by itself.
pub trait TaskRunNoEffectScanner {
    fn scan_no_effect_assignments(
        &self,
        request: TaskRunNoEffectScanRequest,
    ) -> Result<TaskRunNoEffectScanPage, EventStoreError>;
}
