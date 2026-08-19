
pub use super::manifests::{
    CutoverManifest, MigrationReport, RetirementManifest, RollbackManifest,
};
use runne_domain::{
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
