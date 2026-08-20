//! Migration control-plane application service.

use sha2::{Digest, Sha256};

pub use super::ports::CutoverIntent;

use super::{
    error::MigrationError,
    gates::{
        GateApplicabilityError, GateContext, GateSetValidationError, MigrationEvidence,
        PhaseGatePolicy, ValidatedGateSet,
    },
    manifests::{
        ArtifactRef, CandidateValidationReport, CutoverManifest, CutoverManifestFields,
        DrainReportArtifact, MigrationReport, RetirementManifest, RollbackPolicy,
    },
    ports::{
        LoadedMigrationPlan, MigrationAuditAction, MigrationAuditRecord, MigrationCommandContext,
        MigrationCommandFingerprint, MigrationCommandOutcome, MigrationCommit,
        MigrationCommitResult, MigrationControlStore, MigrationMutation, MigrationReceiptLookup,
        MigrationStoreError, MigrationTransition, ShadowExecutionPort,
    },
    rollout::{CutoverPolicy, RetirementReadiness},
    state::{MigrationCycleKind, MigrationPhase, MigrationPlan, MigrationPlanStatus},
    types::{
        ArtifactDigest, CohortSelector, FencingToken, MigrationPlanId, RollbackDisposition,
        RoutingGeneration, RoutingSnapshot, RuntimeAuthority,
    },
};

const COMMAND_FINGERPRINT_PREFIX: &[u8] = b"gocode-migration-command\x01";
const AUDIT_RECORD_PREFIX: &[u8] = b"gocode-migration-audit\x01";

/// Application facade for the eight migration control primitives.
pub struct MigrationService<S, H> {
    store: S,
    _shadow: H,
}

include!("service/core.rs");
include!("service/stage.rs");
include!("service/prepare.rs");
include!("service/commit.rs");
include!("service/rollback.rs");
include!("service/duplicate.rs");
include!("service/types.rs");
include!("service/validation.rs");
include!("service/outputs.rs");
include!("service/tags.rs");
include!("service/errors.rs");
