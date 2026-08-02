/// Compact reference to a parent plan revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanParentRef {
    pub plan_id: PlanId,
    pub revision: u64,
    pub integrity_digest: IntegrityDigest,
}

/// Exact replay-safe reference to an immutable plan revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRevisionRef {
    pub plan_id: PlanId,
    pub taskrun_id: TaskRunId,
    pub cycle_id: CycleId,
    pub revision: u64,
    pub context_manifest_ref: ContextManifestRef,
    pub expected_proposal_indexes: Vec<u32>,
    pub proposal_batch_digest: IntegrityDigest,
    pub planning_policy_ref: ResultRef,
    pub planning_budget_ref: BudgetReservationRef,
    pub parent_ref: Option<PlanParentRef>,
    pub integrity_digest: IntegrityDigest,
}

// ── PlanRevision ────────────────────────────────────────────────────────

/// Immutable committed planning output for a loop cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRevision {
    pub plan_id: PlanId,
    pub cycle_id: CycleId,
    pub taskrun_id: TaskRunId,
    pub revision: u64,
    pub context_manifest_ref: ContextManifestRef,
    pub observations_ref: Vec<ObservationRef>,
    pub planning_policy_ref: PlanningPolicyRef,
    pub planning_budget_ref: PlanningBudgetRef,
    pub input_digest: IntegrityDigest,
    pub proposal_batch: ProposalBatch,
    pub output_digest: IntegrityDigest,
    pub parent_plan_ref: Option<PlanParentRef>,
    pub created_at: Timestamp,
    pub planner_revision: String,
}

// ── ObservationRef ──────────────────────────────────────────────────────

/// Reference to a loop observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationRef {
    pub observation_id: String,
    pub digest: IntegrityDigest,
}

// ── PlanningPolicyRef ───────────────────────────────────────────────────

/// Versioned planning policy reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanningPolicyRef {
    pub policy_id: String,
    pub version: String,
    pub digest: IntegrityDigest,
}

// ── PlanningBudgetRef ───────────────────────────────────────────────────

/// Budget context for planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanningBudgetRef {
    pub budget_id: String,
    pub digest: IntegrityDigest,
}

// ── ProposalBatch ───────────────────────────────────────────────────────

/// Closed set of proposals bound to exact input digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalBatch {
    pub batch_id: ProposalBatchId,
    pub input_digest: IntegrityDigest,
    pub proposals: Vec<Proposal>,
    expected_proposal_indexes: Vec<u32>,
    pub disposition: BatchDisposition,
}

impl ProposalBatch {
    pub fn new(
        batch_id: ProposalBatchId,
        input_digest: IntegrityDigest,
        mut proposals: Vec<Proposal>,
        disposition: BatchDisposition,
    ) -> Result<Self, PlanError> {
        proposals.sort_by_key(|proposal| proposal.proposal_index);
        let expected_proposal_indexes = proposals
            .iter()
            .map(|proposal| proposal.proposal_index)
            .collect::<Vec<_>>();
        if expected_proposal_indexes
            .windows(2)
            .any(|indexes| indexes[0] == indexes[1])
        {
            return Err(PlanError::DuplicateProposalIndex);
        }
        Ok(Self {
            batch_id,
            input_digest,
            proposals,
            expected_proposal_indexes,
            disposition,
        })
    }

    pub fn expected_indexes(&self) -> &[u32] {
        &self.expected_proposal_indexes
    }
}

/// Validation errors for immutable plan values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    DuplicateProposalIndex,
}

// ── ProposalBatchId ─────────────────────────────────────────────────────

/// Identifier for a proposal batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProposalBatchId(pub [u8; 16]);

// ── Proposal ────────────────────────────────────────────────────────────

/// A single proposed action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub proposal_index: u32,
    pub action_type: ProposalActionType,
    pub capability_required: Option<CapabilityAction>,
    pub budget_required: BudgetReservationRequest,
    pub tool_ref: Option<String>,
    pub delegate_objective: Option<String>,
}

// ── CapabilityAction ────────────────────────────────────────────────────

/// Capability action required for a proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityAction {
    pub action: String,
    pub resource: String,
}

// ── BudgetReservationRequest ────────────────────────────────────────────

/// Budget reservation request for a proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetReservationRequest {
    pub amount: u64,
    pub dimension: String,
}

// ── BatchDisposition ────────────────────────────────────────────────────

/// Overall disposition of a proposal batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchDisposition {
    Continue,
    Wait { reason: String },
    Complete,
    Fail { reason: String },
}
