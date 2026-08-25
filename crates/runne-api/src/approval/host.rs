use runne_domain::id::{CommandId, IdempotencyKey};

/// Authenticated identity for an approval decision command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalCommandContext {
    /// Unique command identity used for idempotent reconciliation.
    pub command_id: CommandId,
    /// Caller idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Authenticated principal.
    pub principal: crate::ApiPrincipalId,
    /// Runtime actor recorded in the authoritative event.
    pub actor: crate::ApiActor,
}

/// Authenticated identity for an approval query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalQueryContext {
    /// Principal whose approval scope is being queried.
    pub principal: crate::ApiPrincipalId,
}

/// Runtime-bound decision request. The action digest and policy revision are
/// repeated by the client so the runtime can reject stale or substituted UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalDecisionCommand {
    approval_id: ApprovalId,
    expected_version: u64,
    decision: ApprovalDecision,
    action_digest: [u8; 32],
    policy_revision: u64,
    renderer_generation: u64,
}

impl ApprovalDecisionCommand {
    /// Validates the decision binding before it reaches a host implementation.
    pub fn new(
        approval_id: ApprovalId,
        expected_version: u64,
        decision: ApprovalDecision,
        action_digest: [u8; 32],
        policy_revision: u64,
        renderer_generation: u64,
    ) -> Result<Self, ApprovalValidationError> {
        if expected_version == 0 {
            return Err(ApprovalValidationError::InvalidExpectedVersion);
        }
        if policy_revision == 0 {
            return Err(ApprovalValidationError::InvalidVersion);
        }
        if renderer_generation == 0 {
            return Err(ApprovalValidationError::InvalidRendererGeneration);
        }
        if action_digest == [0; 32] {
            return Err(ApprovalValidationError::MissingActionDigest);
        }
        Ok(Self {
            approval_id,
            expected_version,
            decision,
            action_digest,
            policy_revision,
            renderer_generation,
        })
    }

    /// Returns the approval identity.
    #[must_use]
    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }
    /// Returns the optimistic concurrency version.
    #[must_use]
    pub const fn expected_version(&self) -> u64 {
        self.expected_version
    }
    /// Returns the requested decision.
    #[must_use]
    pub const fn decision(&self) -> ApprovalDecision {
        self.decision
    }
    /// Returns the policy-bound digest.
    #[must_use]
    pub const fn action_digest(&self) -> &[u8; 32] {
        &self.action_digest
    }
    /// Returns the policy revision echoed by the client.
    #[must_use]
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
    /// Returns the renderer generation that created the intent.
    #[must_use]
    pub const fn renderer_generation(&self) -> u64 {
        self.renderer_generation
    }
}

/// Durable acknowledgement of an approval decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalDecisionAck {
    approval_id: ApprovalId,
    task_run_id: TaskRunId,
    new_version: u64,
    state: ApprovalState,
}

impl ApprovalDecisionAck {
    /// Creates an acknowledgement after the runtime commits the transition.
    pub fn new(
        approval_id: ApprovalId,
        task_run_id: TaskRunId,
        new_version: u64,
        state: ApprovalState,
    ) -> Result<Self, ApprovalValidationError> {
        if new_version == 0 || matches!(state, ApprovalState::Pending) {
            return Err(ApprovalValidationError::InvalidExpectedVersion);
        }
        Ok(Self {
            approval_id,
            task_run_id,
            new_version,
            state,
        })
    }

    /// Returns the approval identity.
    #[must_use]
    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }
    /// Returns the owning TaskRun identity.
    #[must_use]
    pub const fn task_run_id(&self) -> TaskRunId {
        self.task_run_id
    }
    /// Returns the committed version.
    #[must_use]
    pub const fn new_version(&self) -> u64 {
        self.new_version
    }
    /// Returns the committed state.
    #[must_use]
    pub const fn state(&self) -> ApprovalState {
        self.state
    }
}

/// Closed failures exposed by approval hosts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalHostError {
    NotFound,
    Conflict,
    Forbidden,
    Expired,
    Backpressure,
    Unavailable,
    InvariantViolation,
}

impl ApprovalHostError {
    /// Returns a stable redacted error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotFound => "approval_not_found",
            Self::Conflict => "approval_conflict",
            Self::Forbidden => "approval_forbidden",
            Self::Expired => "approval_expired",
            Self::Backpressure => "runtime_backpressure",
            Self::Unavailable => "runtime_unavailable",
            Self::InvariantViolation => "runtime_invariant_violation",
        }
    }
}

/// Runtime-owned approval query boundary.
pub trait ApprovalQueryHostPort: Send + Sync {
    /// Lists only approvals visible to the authenticated principal.
    fn list_pending_approvals(
        &self,
        context: ApprovalQueryContext,
    ) -> impl std::future::Future<Output = Result<Vec<ApprovalSummary>, ApprovalHostError>> + Send;
    /// Reads one approval after rechecking principal scope.
    fn get_approval(
        &self,
        context: ApprovalQueryContext,
        approval_id: ApprovalId,
    ) -> impl std::future::Future<Output = Result<ApprovalSummary, ApprovalHostError>> + Send;
}

/// Runtime-owned approval decision boundary.
pub trait ApprovalCommandHostPort: Send + Sync {
    /// Commits one single-use, versioned decision after runtime revalidation.
    fn decide_approval(
        &self,
        context: ApprovalCommandContext,
        command: ApprovalDecisionCommand,
    ) -> impl std::future::Future<Output = Result<ApprovalDecisionAck, ApprovalHostError>> + Send;
}
