//! Versioned canonical codecs for migration control-plane artifacts.

use core::fmt;
use std::time::Duration;

use gocode_application::migration::{
    gates::{GateEvidence, GateFailureCode, GateRevocationReason, GateStatus, MigrationEvidence},
    manifests::{
        ArtifactRef, ArtifactValidation, CutoverManifest, ImportDisposition, MigrationCounts,
        MigrationReport, MigrationReportFields, RetirementManifest, RollbackManifest,
        RollbackPolicy,
    },
    ports::{
        CutoverIntent, MigrationAuditAction, MigrationAuditRecord, MigrationCommandOutcome,
        MigrationTransition,
    },
    rollout::{CanaryPolicy, CutoverPolicy, PreDispatchFallbackPolicy, RolloutStep},
    state::{MigrationCycleKind, MigrationPhase, MigrationPlan, MigrationPlanStatus},
    types::{
        ArtifactDigest, CohortDimension, CohortSelector, DeploymentId, FeatureProfileRef,
        FencingToken, GateFamily, GateId, GatePolicyRef, MigrationCycleId, MigrationPlanId,
        MigrationValueError, RollbackDisposition, RoutingGeneration, RoutingSnapshot, RoutingUnit,
        RuntimeAuthority, RuntimeBinding, RuntimeGenerationRef,
    },
};
use gocode_domain::{
    id::{AggregateId, ConversationId, TaskRunId},
    timestamp::Timestamp,
};

const CODEC_VERSION: u8 = 1;
const CUTOVER_MANIFEST_CODEC_VERSION: u8 = 5;
const RETIREMENT_MANIFEST_CODEC_VERSION: u8 = 2;

/// Fail-closed migration codec errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationCodecError {
    /// Unsupported leading codec version.
    UnknownVersion {
        /// Version read from durable bytes.
        actual: u8,
    },
    /// Closed enum tag is unknown.
    UnknownTag {
        /// Field whose tag was invalid.
        field: &'static str,
        /// Unknown tag.
        actual: u8,
    },
    /// Durable bytes ended before the value was complete.
    Truncated,
    /// Bytes remained after one canonical value.
    TrailingBytes {
        /// Number of bytes not consumed.
        remaining: usize,
    },
    /// A length-prefixed value exceeds its bound.
    Oversized {
        /// Field whose value was oversized.
        field: &'static str,
        /// Maximum number of bytes.
        max: usize,
        /// Actual number of bytes.
        actual: usize,
    },
    /// A string is not valid UTF-8.
    InvalidUtf8 {
        /// Field containing invalid UTF-8.
        field: &'static str,
    },
    /// Decoded values violate the application value contract.
    InvalidValue {
        /// Field whose value is invalid.
        field: &'static str,
    },
}

impl fmt::Display for MigrationCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for MigrationCodecError {}

include!("migration_codec/routing_plan.rs");
include!("migration_codec/cutover.rs");
include!("migration_codec/report_manifests.rs");
include!("migration_codec/evidence_runtime.rs");
include!("migration_codec/helper_structural.rs");
include!("migration_codec/helper_tags.rs");
include!("migration_codec/decoder.rs");

#[cfg(test)]
mod tests {
    include!("migration_codec/tests_part1.rs");
    include!("migration_codec/tests_part2.rs");
}
