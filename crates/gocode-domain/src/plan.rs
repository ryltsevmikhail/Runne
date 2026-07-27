//! Plan revision model — immutable planning output.
//!
//! PlanRevision binds exact cycle, context, observations, and policy
//! references into a committed planning output.

use crate::agent_loop::ProposalActionType;
use crate::context::ContextManifestRef;
use crate::id::{CycleId, IntegrityDigest, PlanId, TaskRunId};
use crate::reference::{BudgetReservationRef, ResultRef};
use crate::timestamp::Timestamp;

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

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::ContextManifestRef as ExactContextManifestRef;
    use crate::id::{AttemptId, BudgetReservationId, ContextManifestId, IntegrityDigest, ResultId};
    use crate::reference::{BudgetReservationRef, ResultRef};

    fn proposal(index: u32) -> Proposal {
        Proposal {
            proposal_index: index,
            action_type: ProposalActionType::Wait,
            capability_required: None,
            budget_required: BudgetReservationRequest {
                amount: 1,
                dimension: "provider_calls".into(),
            },
            tool_ref: None,
            delegate_objective: None,
        }
    }

    #[test]
    fn proposal_batch_canonicalizes_exact_indexes() {
        let batch = ProposalBatch::new(
            ProposalBatchId([1; 16]),
            IntegrityDigest::from_bytes([2; 32]),
            vec![proposal(2), proposal(0), proposal(1)],
            BatchDisposition::Continue,
        )
        .unwrap();

        assert_eq!(batch.expected_indexes(), &[0, 1, 2]);
    }

    #[test]
    fn plan_revision_ref_binds_exact_owner_context_and_proposals() {
        let uuid = "018f2e3a-7000-7000-8000-000000000010";
        let taskrun_id: TaskRunId = uuid.parse().unwrap();
        let attempt_id: AttemptId = uuid.parse().unwrap();
        let cycle_id: CycleId = uuid.parse().unwrap();
        let context_manifest_ref = ExactContextManifestRef {
            manifest_id: uuid.parse::<ContextManifestId>().unwrap(),
            taskrun_id,
            attempt_id,
            cycle_id,
            revision: 2,
            policy_revision: "context-v2".into(),
            integrity_digest: IntegrityDigest::from_bytes([3; 32]),
        };
        let planning_policy_ref = ResultRef::new(
            uuid.parse::<ResultId>().unwrap(),
            "application/json",
            IntegrityDigest::from_bytes([4; 32]),
        )
        .unwrap();
        let planning_budget_ref = BudgetReservationRef {
            reservation_id: uuid.parse::<BudgetReservationId>().unwrap(),
            taskrun_id,
            attempt_id,
            retry_ordinal: 0,
            reservation_digest: IntegrityDigest::from_bytes([5; 32]),
        };
        let reference = PlanRevisionRef {
            plan_id: uuid.parse().unwrap(),
            taskrun_id,
            cycle_id,
            revision: 3,
            context_manifest_ref,
            expected_proposal_indexes: vec![0, 2],
            proposal_batch_digest: IntegrityDigest::from_bytes([6; 32]),
            planning_policy_ref,
            planning_budget_ref,
            parent_ref: None,
            integrity_digest: IntegrityDigest::from_bytes([7; 32]),
        };

        assert_eq!(reference.expected_proposal_indexes, vec![0, 2]);
    }

    #[test]
    fn plan_revision_immutable_fields() {
        let plan_id: PlanId = "018f2e3a-7000-7000-8000-000000000010".parse().unwrap();
        let cycle_id: CycleId = "018f2e3a-7000-7000-8000-000000000011".parse().unwrap();
        let taskrun_id: TaskRunId = "018f2e3a-7000-7000-8000-000000000012".parse().unwrap();

        let pr = PlanRevision {
            plan_id,
            cycle_id,
            taskrun_id,
            revision: 1,
            context_manifest_ref: ContextManifestRef {
                manifest_id: "018f2e3a-7000-7000-8000-000000000013".parse().unwrap(),
                taskrun_id,
                attempt_id: "018f2e3a-7000-7000-8000-000000000014".parse().unwrap(),
                cycle_id,
                revision: 1,
                policy_revision: "v1".into(),
                integrity_digest: IntegrityDigest::from_bytes([0u8; 32]),
            },
            observations_ref: vec![],
            planning_policy_ref: PlanningPolicyRef {
                policy_id: "pol1".into(),
                version: "v1".into(),
                digest: IntegrityDigest::from_bytes([1u8; 32]),
            },
            planning_budget_ref: PlanningBudgetRef {
                budget_id: "bud1".into(),
                digest: IntegrityDigest::from_bytes([2u8; 32]),
            },
            input_digest: IntegrityDigest::from_bytes([3u8; 32]),
            proposal_batch: ProposalBatch {
                batch_id: ProposalBatchId([0u8; 16]),
                input_digest: IntegrityDigest::from_bytes([4u8; 32]),
                proposals: vec![],
                expected_proposal_indexes: vec![],
                disposition: BatchDisposition::Continue,
            },
            output_digest: IntegrityDigest::from_bytes([5u8; 32]),
            parent_plan_ref: None,
            created_at: Timestamp::from_unix_micros(1000),
            planner_revision: "planner-v1".into(),
        };

        assert_eq!(pr.revision, 1);
        assert!(pr.parent_plan_ref.is_none());
    }

    #[test]
    fn revision_increment_checked() {
        let plan_id: PlanId = "018f2e3a-7000-7000-8000-000000000010".parse().unwrap();
        let parent = PlanParentRef {
            plan_id,
            revision: 3,
            integrity_digest: IntegrityDigest::from_bytes([0u8; 32]),
        };

        let new_revision = parent.revision.checked_add(1).unwrap();
        assert_eq!(new_revision, 4);
    }
}
