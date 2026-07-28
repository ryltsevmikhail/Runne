//! Migration control-plane persistence and shadow-execution ports.

pub use super::manifests::{
    CutoverManifest, MigrationReport, RetirementManifest, RollbackManifest,
};
use gocode_domain::{
    id::{CommandId, IdempotencyKey},
    timestamp::Timestamp,
};

use super::{
    error::MigrationError,
    gates::MigrationEvidence,
    state::{MigrationPhase, MigrationPlan},
    types::{
        ArtifactDigest, MigrationCycleId, MigrationPlanId, OperatorId, RoutingGeneration,
        RoutingSnapshot, RoutingUnit, RuntimeAuthority, RuntimeBinding,
    },
};

/// Context shared by every migration control command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationCommandContext {
    /// Stable command identity.
    pub command_id: CommandId,
    /// Caller-supplied idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Authenticated operator identity.
    pub operator_id: OperatorId,
    /// Optimistic plan version expected by the caller.
    pub expected_plan_version: u64,
    /// Routing head generation expected by a routing mutation.
    pub expected_routing_generation: Option<RoutingGeneration>,
    /// Authority-supplied evaluation time for freshness-sensitive policies.
    pub evaluated_at: Timestamp,
}

/// Canonical semantic fingerprint of a migration command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MigrationCommandFingerprint([u8; 32]);

impl MigrationCommandFingerprint {
    /// Construct a fingerprint from a canonical SHA-256 result.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One immutable phase transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationTransition {
    /// Stable transition identity.
    pub transition_id: String,
    /// Owning migration plan.
    pub plan_id: MigrationPlanId,
    /// Owning migration cycle.
    pub cycle_id: MigrationCycleId,
    /// Previous phase.
    pub from: MigrationPhase,
    /// New phase.
    pub to: MigrationPhase,
    /// Plan version after the transition.
    pub plan_version: u64,
    /// Persistence-authoritative transition time.
    pub occurred_at: Timestamp,
}

/// Closed intent captured by a prepared cutover manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutoverIntent {
    /// Bounded internal canary.
    InternalCanary,
    /// Bounded cohort expansion.
    CohortExpansion,
    /// Candidate becomes the default for new work.
    DefaultNative,
    /// Authority returns through an isolated rollback cycle.
    Rollback,
}

/// Atomic audit action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationAuditAction {
    /// Stage a migration plan.
    StagePlan,
    /// Record immutable evidence.
    RecordEvidence,
    /// Advance to the next phase.
    AdvancePhase,
    /// Prepare a cutover without changing authority.
    PrepareCutover,
    /// Commit a prepared cutover.
    CommitCutover,
    /// Start an isolated rollback cycle.
    StartRollbackCycle,
    /// Begin bounded source drain.
    BeginDrain,
    /// Retire the source authority.
    RetireSource,
    /// Emergency revocation of candidate routing authority.
    EmergencyRevoke,
}

/// Audit evidence stored atomically with a control mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationAuditRecord {
    /// Canonical audit record digest.
    pub record_id: ArtifactDigest,
    /// Affected plan.
    pub plan_id: MigrationPlanId,
    /// Command that authorized the mutation.
    pub command_id: CommandId,
    /// Authenticated operator.
    pub operator_id: OperatorId,
    /// Closed control action.
    pub action: MigrationAuditAction,
    /// Persistence-authoritative record time.
    pub recorded_at: Timestamp,
}

/// Exact migration plan state reconstructed from durable artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedMigrationPlan {
    /// Current plan state.
    pub plan: MigrationPlan,
    /// Append-only phase transition history.
    pub transitions: Vec<MigrationTransition>,
    /// Append-only evidence history.
    pub evidence: Vec<MigrationEvidence>,
    /// Append-only one-way import reports.
    pub migration_reports: Vec<MigrationReport>,
    /// Append-only cutover preparation manifests.
    pub cutover_manifests: Vec<CutoverManifest>,
    /// Append-only isolated rollback-cycle manifests.
    pub rollback_manifests: Vec<RollbackManifest>,
    /// Append-only final retirement manifests.
    pub retirement_manifests: Vec<RetirementManifest>,
}

/// Closed semantic result stored in an idempotency receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationCommandOutcome {
    /// Plan state after the accepted command.
    pub plan: MigrationPlan,
    /// Routing snapshot committed by the command, if any.
    pub routing_snapshot: Option<RoutingSnapshot>,
    /// Durable transition identity.
    pub transition_id: String,
}

/// Durable receipt for one accepted migration command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReceipt {
    /// Committed command identity.
    pub command_id: CommandId,
    /// Committed idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Committed semantic fingerprint.
    pub fingerprint: MigrationCommandFingerprint,
    /// Original semantic result.
    pub stored_result: MigrationCommandOutcome,
    /// Persistence-authoritative commit time.
    pub committed_at: Timestamp,
}

/// Result of looking up a migration command receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationReceiptLookup {
    /// No receipt exists for the supplied command identity.
    Miss,
    /// The exact command was already committed.
    Duplicate {
        /// Original semantic result.
        stored_result: Box<MigrationCommandOutcome>,
    },
}

/// Typed storage-boundary failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationStoreError {
    /// Durable bytes are malformed or inconsistent.
    CorruptData,
    /// Stored schema or codec version is unsupported.
    UnsupportedSchema,
    /// Storage is temporarily unavailable.
    Unavailable,
    /// Persisted plan version differs from the expected version.
    PlanVersionConflict {
        /// Caller expectation.
        expected: u64,
        /// Durable version.
        actual: u64,
    },
    /// Persisted routing head differs from the expected generation.
    RoutingGenerationConflict {
        /// Caller expectation.
        expected: RoutingGeneration,
        /// Durable generation.
        actual: RoutingGeneration,
    },
    /// Command identity or idempotency scope conflicts with a receipt.
    IdempotencyConflict,
    /// Durable integrity or lineage verification failed.
    IntegrityViolation,
    /// A durable counter exceeded its supported range.
    ArithmeticOverflow,
    /// An aggregate is already pinned under another routing unit.
    RuntimeBindingConflict,
    /// Dispatch identity or semantic input conflicts with durable state.
    DispatchIntentConflict,
    /// Dispatch state transition is invalid or cannot be proved safe.
    InvalidDispatchTransition,
    /// Stage 7/8 transition lacks a certified durable admission authority.
    LifecycleAuthorityRequired {
        /// Requested lifecycle phase that requires certified admission authority.
        target: MigrationPhase,
    },
}

/// Closed atomic mutations understood by the control store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationMutation {
    /// Insert a new plan.
    InsertPlan(MigrationPlan),
    /// Append a phase transition.
    AppendTransition(MigrationTransition),
    /// Append immutable evidence.
    AppendEvidence(MigrationEvidence),
    /// Append an immutable one-way import report.
    AppendMigrationReport(Box<MigrationReport>),
    /// Append an immutable cutover preparation manifest.
    AppendCutoverManifest(Box<CutoverManifest>),
    /// Append an immutable rollback-cycle manifest.
    AppendRollbackManifest(Box<RollbackManifest>),
    /// Append an immutable source-retirement manifest.
    AppendRetirementManifest(Box<RetirementManifest>),
    /// Append an immutable routing snapshot.
    AppendRoutingSnapshot(RoutingSnapshot),
    /// Compare-and-swap the routing head.
    AdvanceRoutingHead {
        /// Exact routing-unit digest.
        unit_digest: ArtifactDigest,
        /// Expected current routing generation.
        expected: RoutingGeneration,
        /// Next routing generation.
        next: RoutingGeneration,
    },
    /// Persist the immutable runtime binding for a new aggregate.
    InsertRuntimeBinding(RuntimeBinding),
}

impl MigrationMutation {
    fn has_same_identity_as(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::InsertPlan(left), Self::InsertPlan(right)) => left.plan_id == right.plan_id,
            (Self::AppendTransition(left), Self::AppendTransition(right)) => {
                left.transition_id == right.transition_id
            }
            (Self::AppendEvidence(left), Self::AppendEvidence(right)) => {
                left.identity_digest() == right.identity_digest()
            }
            (Self::AppendMigrationReport(left), Self::AppendMigrationReport(right)) => {
                left.report.digest == right.report.digest
            }
            (Self::AppendCutoverManifest(left), Self::AppendCutoverManifest(right)) => {
                left.manifest_digest == right.manifest_digest
            }
            (Self::AppendRollbackManifest(left), Self::AppendRollbackManifest(right)) => {
                left.manifest.digest == right.manifest.digest
            }
            (Self::AppendRetirementManifest(left), Self::AppendRetirementManifest(right)) => {
                left.manifest.digest == right.manifest.digest
            }
            (Self::AppendRoutingSnapshot(left), Self::AppendRoutingSnapshot(right)) => {
                left.routing_generation == right.routing_generation
            }
            (
                Self::AdvanceRoutingHead {
                    unit_digest: left, ..
                },
                Self::AdvanceRoutingHead {
                    unit_digest: right, ..
                },
            ) => left == right,
            (Self::InsertRuntimeBinding(left), Self::InsertRuntimeBinding(right)) => {
                left.aggregate_id == right.aggregate_id
            }
            _ => false,
        }
    }

    fn requires_expected_routing_generation(&self) -> bool {
        match self {
            Self::AppendRoutingSnapshot(snapshot) => {
                matches!(snapshot.authority, RuntimeAuthority::Candidate(_))
            }
            Self::AdvanceRoutingHead { .. } | Self::InsertRuntimeBinding(_) => true,
            Self::InsertPlan(_)
            | Self::AppendTransition(_)
            | Self::AppendEvidence(_)
            | Self::AppendMigrationReport(_)
            | Self::AppendCutoverManifest(_)
            | Self::AppendRollbackManifest(_)
            | Self::AppendRetirementManifest(_) => false,
        }
    }
}

/// Validated atomic control-plane commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationCommit {
    context: MigrationCommandContext,
    fingerprint: MigrationCommandFingerprint,
    guard_plan_id: MigrationPlanId,
    plan: MigrationPlan,
    mutations: Vec<MigrationMutation>,
    outcome: MigrationCommandOutcome,
    audit: MigrationAuditRecord,
}

impl MigrationCommit {
    /// Validate and construct an atomic commit payload.
    pub fn new(
        context: MigrationCommandContext,
        fingerprint: MigrationCommandFingerprint,
        plan: MigrationPlan,
        mutations: Vec<MigrationMutation>,
        outcome: MigrationCommandOutcome,
        audit: Option<MigrationAuditRecord>,
    ) -> Result<Self, MigrationError> {
        let guard_plan_id = plan.plan_id.clone();
        Self::new_with_guard(
            context,
            fingerprint,
            guard_plan_id,
            plan,
            mutations,
            outcome,
            audit,
        )
    }

    /// Validate a commit whose optimistic version guard belongs to another
    /// plan, as required when an isolated rollback cycle is created from an
    /// immutable parent.
    pub fn new_with_guard(
        context: MigrationCommandContext,
        fingerprint: MigrationCommandFingerprint,
        guard_plan_id: MigrationPlanId,
        plan: MigrationPlan,
        mutations: Vec<MigrationMutation>,
        outcome: MigrationCommandOutcome,
        audit: Option<MigrationAuditRecord>,
    ) -> Result<Self, MigrationError> {
        let audit = audit.ok_or(MigrationError::AuditUnavailable)?;

        if mutations
            .iter()
            .any(MigrationMutation::requires_expected_routing_generation)
            && context.expected_routing_generation.is_none()
        {
            return Err(MigrationError::ExpectedRoutingGenerationRequired);
        }

        if audit.plan_id != plan.plan_id
            || audit.command_id != context.command_id
            || audit.operator_id != context.operator_id
        {
            return Err(MigrationError::StorageContractViolation);
        }

        for (index, mutation) in mutations.iter().enumerate() {
            if mutations[index + 1..]
                .iter()
                .any(|candidate| mutation.has_same_identity_as(candidate))
            {
                return Err(MigrationError::StorageContractViolation);
            }
        }

        Ok(Self {
            context,
            fingerprint,
            guard_plan_id,
            plan,
            mutations,
            outcome,
            audit,
        })
    }

    /// Command context used for optimistic concurrency and idempotency.
    pub fn context(&self) -> &MigrationCommandContext {
        &self.context
    }

    /// Semantic fingerprint stored with the durable receipt.
    pub fn fingerprint(&self) -> &MigrationCommandFingerprint {
        &self.fingerprint
    }

    /// Plan whose durable version must match the command expectation.
    pub fn guard_plan_id(&self) -> &MigrationPlanId {
        &self.guard_plan_id
    }

    /// Resulting plan state.
    pub fn plan(&self) -> &MigrationPlan {
        &self.plan
    }

    /// Closed mutations applied by the adapter.
    pub fn mutations(&self) -> &[MigrationMutation] {
        &self.mutations
    }

    /// Semantic outcome stored with the durable receipt.
    pub fn outcome(&self) -> &MigrationCommandOutcome {
        &self.outcome
    }

    /// Audit record committed atomically with the mutations.
    pub fn audit(&self) -> &MigrationAuditRecord {
        &self.audit
    }
}

/// Result returned after an atomic store commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationCommitResult {
    /// New durable state and receipt were committed.
    Committed {
        /// Durable receipt containing the semantic outcome.
        receipt: MigrationReceipt,
    },
    /// The exact command was committed previously.
    Duplicate {
        /// Original semantic result.
        stored_result: MigrationCommandOutcome,
    },
}

impl MigrationCommitResult {
    /// Return the semantic outcome for either a new or duplicate commit.
    pub fn outcome(&self) -> &MigrationCommandOutcome {
        match self {
            Self::Committed { receipt } => &receipt.stored_result,
            Self::Duplicate { stored_result } => stored_result,
        }
    }

    /// Return the resulting plan.
    pub fn plan(&self) -> &MigrationPlan {
        &self.outcome().plan
    }
}

/// Read and atomic-write authority for migration control state.
pub trait MigrationControlStore {
    /// Load a migration plan and its immutable histories.
    fn load_plan(
        &self,
        plan_id: &MigrationPlanId,
    ) -> Result<Option<LoadedMigrationPlan>, MigrationStoreError>;

    /// Load the current routing head for an exact routing unit.
    fn load_routing_head(
        &self,
        unit: &RoutingUnit,
    ) -> Result<Option<RoutingSnapshot>, MigrationStoreError>;

    /// Look up the receipt for an exact command and semantic fingerprint.
    fn lookup_receipt(
        &self,
        context: &MigrationCommandContext,
        fingerprint: &MigrationCommandFingerprint,
    ) -> Result<MigrationReceiptLookup, MigrationStoreError>;

    /// Atomically persist mutations, audit evidence, and the receipt.
    fn commit(&self, commit: MigrationCommit)
    -> Result<MigrationCommitResult, MigrationStoreError>;
}

/// Input accepted by the capability-free shadow executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SanitizedShadowInput {
    /// Immutable recorded fixture.
    RecordedFixture {
        /// Fixture identity.
        fixture_id: String,
        /// Digest of the pinned source result.
        source_digest: ArtifactDigest,
    },
    /// Redacted deterministic translation.
    RedactedTranslation {
        /// Baseline operation identity.
        operation_id: String,
        /// Canonical redacted input bytes.
        canonical_bytes: Vec<u8>,
    },
    /// Explicit negative-test input representing forbidden authority.
    ExternalEffect {
        /// Attempted effect identity.
        operation_id: String,
    },
}

impl SanitizedShadowInput {
    /// Construct an explicit forbidden-effect input for negative validation.
    pub fn external_effect(operation_id: impl Into<String>) -> Self {
        Self::ExternalEffect {
            operation_id: operation_id.into(),
        }
    }
}

/// Semantic relationship between source and candidate shadow results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowSemanticClass {
    /// Canonical results are byte-identical.
    Exact,
    /// Results are semantically equivalent after governed translation.
    Equivalent,
    /// Results differ semantically.
    Divergent,
}

/// Uninhabited type proving that shadow evaluation cannot acknowledge a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Never {}

/// Deterministic output of a pure shadow comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowDiffReport {
    /// Digest of the pinned source result.
    pub source_digest: ArtifactDigest,
    /// Digest of the candidate result.
    pub candidate_digest: ArtifactDigest,
    /// Semantic comparison class.
    pub semantic_class: ShadowSemanticClass,
    /// Unconstructable client acknowledgement.
    pub client_acknowledgement: Option<Never>,
}

/// Closed pure-shadow evaluation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShadowExecutionError {
    /// Input requested an external effect.
    ExternalEffectForbidden,
    /// Requested fixture is not in the immutable catalog.
    FixtureNotFound,
    /// Input is malformed or exceeds governed bounds.
    InvalidInput,
}

/// Capability-free semantic shadow boundary.
pub trait ShadowExecutionPort {
    /// Evaluate sanitized input without canonical writes or external effects.
    fn evaluate(
        &self,
        input: SanitizedShadowInput,
    ) -> Result<ShadowDiffReport, ShadowExecutionError>;
}

#[cfg(test)]
mod tests {
    use gocode_domain::{
        id::{CommandId, IdempotencyKey},
        timestamp::Timestamp,
    };

    use super::*;
    use crate::migration::{
        state::{MigrationCycleKind, MigrationPhase, MigrationPlan, MigrationPlanStatus},
        types::{
            ArtifactDigest, CohortDimension, CohortSelector, DeploymentId, FeatureProfileRef,
            FencingToken, GatePolicyRef, MigrationCycleId, MigrationPlanId, OperatorId,
            RollbackDisposition, RoutingGeneration, RoutingSnapshot, RoutingUnit, RuntimeAuthority,
            RuntimeGenerationRef,
        },
    };

    #[test]
    fn production_mutation_requires_an_expected_routing_generation() {
        let commit = MigrationCommit::new(
            test_context(None),
            test_fingerprint(),
            test_plan(),
            vec![
                MigrationMutation::AppendTransition(test_transition()),
                MigrationMutation::AppendRoutingSnapshot(candidate_snapshot()),
            ],
            test_outcome(),
            Some(test_audit_record()),
        );

        assert_eq!(
            commit,
            Err(crate::migration::error::MigrationError::ExpectedRoutingGenerationRequired)
        );
    }

    #[test]
    fn audit_record_is_required_for_every_mutation() {
        let commit = MigrationCommit::new(
            test_context(Some(RoutingGeneration::new(1).unwrap())),
            test_fingerprint(),
            test_plan(),
            vec![MigrationMutation::AppendTransition(test_transition())],
            test_outcome(),
            None,
        );

        assert_eq!(
            commit,
            Err(crate::migration::error::MigrationError::AuditUnavailable)
        );
    }

    #[test]
    fn duplicate_mutation_identity_is_rejected_before_the_adapter() {
        let transition = test_transition();
        let commit = MigrationCommit::new(
            test_context(Some(RoutingGeneration::new(1).unwrap())),
            test_fingerprint(),
            test_plan(),
            vec![
                MigrationMutation::AppendTransition(transition.clone()),
                MigrationMutation::AppendTransition(transition),
            ],
            test_outcome(),
            Some(test_audit_record()),
        );

        assert_eq!(
            commit,
            Err(crate::migration::error::MigrationError::StorageContractViolation)
        );
    }

    #[test]
    fn audit_identity_must_match_the_command_and_plan() {
        let mut audit = test_audit_record();
        audit.command_id = "018f2e3a-8d5c-7b20-8d9a-000000000002"
            .parse::<CommandId>()
            .unwrap();
        let commit = MigrationCommit::new(
            test_context(Some(RoutingGeneration::new(1).unwrap())),
            test_fingerprint(),
            test_plan(),
            vec![MigrationMutation::AppendTransition(test_transition())],
            test_outcome(),
            Some(audit),
        );

        assert_eq!(
            commit,
            Err(crate::migration::error::MigrationError::StorageContractViolation)
        );
    }

    fn test_context(
        expected_routing_generation: Option<RoutingGeneration>,
    ) -> MigrationCommandContext {
        MigrationCommandContext {
            command_id: "018f2e3a-8d5c-7b20-8d9a-000000000001"
                .parse::<CommandId>()
                .unwrap(),
            idempotency_key: IdempotencyKey::new("migration-command-1").unwrap(),
            operator_id: OperatorId::new("operator-1").unwrap(),
            expected_plan_version: 0,
            expected_routing_generation,
            evaluated_at: Timestamp::from_unix_micros(100),
        }
    }

    fn test_plan() -> MigrationPlan {
        MigrationPlan {
            plan_id: MigrationPlanId::new("plan-1").unwrap(),
            cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            cycle_kind: MigrationCycleKind::Forward,
            source: source_generation(),
            candidate: candidate_generation(),
            phase: MigrationPhase::InternalCanary,
            status: MigrationPlanStatus::Active,
            routing_unit: test_routing_unit(),
            gate_policy: GatePolicyRef::new("policy-v1").unwrap(),
            plan_version: 0,
            created_at: Timestamp::from_unix_micros(1),
        }
    }

    fn test_transition() -> MigrationTransition {
        MigrationTransition {
            transition_id: "transition-1".to_owned(),
            plan_id: MigrationPlanId::new("plan-1").unwrap(),
            cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            from: MigrationPhase::SimulatedShadow,
            to: MigrationPhase::InternalCanary,
            plan_version: 1,
            occurred_at: Timestamp::from_unix_micros(10),
        }
    }

    fn candidate_snapshot() -> RoutingSnapshot {
        RoutingSnapshot::new(
            RoutingGeneration::new(2).unwrap(),
            source_generation(),
            candidate_generation(),
            MigrationPhase::InternalCanary,
            RuntimeAuthority::Candidate(candidate_generation()),
            test_routing_unit(),
            FencingToken::new([7; 32]).unwrap(),
            RollbackDisposition::Eligible,
            Timestamp::from_unix_micros(10),
        )
        .unwrap()
    }

    fn test_audit_record() -> MigrationAuditRecord {
        MigrationAuditRecord {
            record_id: ArtifactDigest::from_bytes([9; 32]),
            plan_id: MigrationPlanId::new("plan-1").unwrap(),
            command_id: test_context(None).command_id,
            operator_id: OperatorId::new("operator-1").unwrap(),
            action: MigrationAuditAction::AdvancePhase,
            recorded_at: Timestamp::from_unix_micros(10),
        }
    }

    fn test_fingerprint() -> MigrationCommandFingerprint {
        MigrationCommandFingerprint::from_bytes([8; 32])
    }

    fn test_outcome() -> MigrationCommandOutcome {
        MigrationCommandOutcome {
            plan: test_plan(),
            routing_snapshot: Some(candidate_snapshot()),
            transition_id: "transition-1".to_owned(),
        }
    }

    fn source_generation() -> RuntimeGenerationRef {
        RuntimeGenerationRef::new("runtime-legacy").unwrap()
    }

    fn candidate_generation() -> RuntimeGenerationRef {
        RuntimeGenerationRef::new("runtime-native").unwrap()
    }

    fn test_routing_unit() -> RoutingUnit {
        RoutingUnit {
            deployment: DeploymentId::new("production").unwrap(),
            cohort: CohortSelector::new(vec![
                CohortDimension::new("client_class", "premium").unwrap(),
            ])
            .unwrap(),
            feature_profile: FeatureProfileRef::new(
                "default",
                1,
                ArtifactDigest::from_bytes([1; 32]),
            )
            .unwrap(),
            contract_digest: ArtifactDigest::from_bytes([2; 32]),
            schema_digest: ArtifactDigest::from_bytes([3; 32]),
            config_digest: ArtifactDigest::from_bytes([4; 32]),
        }
    }
}
