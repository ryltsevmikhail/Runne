//! Immutable reports and manifests used by production migration stages.

use std::collections::BTreeSet;

use gocode_domain::timestamp::Timestamp;

use super::{
    error::MigrationError,
    ports::CutoverIntent,
    rollout::CutoverPolicy,
    types::{
        ArtifactDigest, MigrationCycleId, MigrationPlanId, RoutingGeneration, RoutingUnit,
        RuntimeGenerationRef,
    },
};

const MAX_ARTIFACT_REF_BYTES: usize = 256;
const MAX_TRANSITION_ID_BYTES: usize = 128;

/// Immutable content-addressed artifact reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ArtifactRef {
    /// Bounded external reference.
    pub reference: String,
    /// Expected content digest.
    pub digest: ArtifactDigest,
}

impl ArtifactRef {
    /// Construct a non-empty, bounded, content-addressed reference.
    pub fn new(
        reference: impl Into<String>,
        digest: ArtifactDigest,
    ) -> Result<Self, MigrationError> {
        let reference = reference.into();
        validate_reference(&reference)?;
        if digest.as_bytes() == &[0; 32] {
            return Err(MigrationError::StorageContractViolation);
        }
        Ok(Self { reference, digest })
    }

    /// Verify the value contract after durable decoding.
    pub fn is_valid(&self) -> bool {
        validate_reference(&self.reference).is_ok() && self.digest.as_bytes() != &[0; 32]
    }
}

/// Closed result of an integrity or rebuild validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactValidation {
    /// Validation passed.
    Passed,
    /// Validation failed.
    Failed,
}

/// Exact import counters frozen in a migration report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationCounts {
    /// Imported records.
    pub imported: u64,
    /// Explicitly skipped records.
    pub skipped: u64,
    /// Unsupported records.
    pub unsupported: u64,
    /// Rejected records.
    pub rejected: u64,
    /// Unknown records.
    pub unknown: u64,
    /// Records whose import loses information.
    pub lossy: u64,
    /// Records with ambiguous interpretation.
    pub ambiguous: u64,
}

impl MigrationCounts {
    /// Check that the total population fits in `u64`.
    pub fn checked_total(self) -> Option<u64> {
        [self.imported, self.skipped, self.unsupported, self.rejected]
            .into_iter()
            .try_fold(0_u64, u64::checked_add)
    }

    fn requires_manual_disposition(self) -> bool {
        self.unknown != 0 || self.lossy != 0 || self.ambiguous != 0
    }
}

/// Explicit disposition for import risk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportDisposition {
    /// Import contains no unknown, lossy or ambiguous source data.
    Clean,
    /// A separately audited artifact authorizes the exact exceptional range.
    ManualAuthorized(ArtifactRef),
}

/// Construction fields for an immutable migration report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReportFields {
    pub report: ArtifactRef,
    pub plan_id: MigrationPlanId,
    pub cycle_id: MigrationCycleId,
    pub source_snapshot: ArtifactRef,
    pub source_high_water: u64,
    pub source_generation: RuntimeGenerationRef,
    pub candidate_generation: RuntimeGenerationRef,
    pub counts: MigrationCounts,
    pub schema: ArtifactRef,
    pub mapping: ArtifactRef,
    pub profile: ArtifactRef,
    pub integrity: ArtifactValidation,
    pub rebuild: ArtifactValidation,
    pub disposition: ImportDisposition,
    pub created_at: Timestamp,
}

/// Immutable one-way data/config import report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    pub report: ArtifactRef,
    pub plan_id: MigrationPlanId,
    pub cycle_id: MigrationCycleId,
    pub source_snapshot: ArtifactRef,
    pub source_high_water: u64,
    pub source_generation: RuntimeGenerationRef,
    pub candidate_generation: RuntimeGenerationRef,
    pub counts: MigrationCounts,
    pub schema: ArtifactRef,
    pub mapping: ArtifactRef,
    pub profile: ArtifactRef,
    pub integrity: ArtifactValidation,
    pub rebuild: ArtifactValidation,
    pub disposition: ImportDisposition,
    pub created_at: Timestamp,
}

impl MigrationReport {
    /// Validate and freeze one migration report.
    pub fn new(fields: MigrationReportFields) -> Result<Self, MigrationError> {
        if fields.source_generation == fields.candidate_generation
            || fields.counts.checked_total().is_none()
            || !all_artifacts_unique([
                &fields.report,
                &fields.source_snapshot,
                &fields.schema,
                &fields.mapping,
                &fields.profile,
            ])
        {
            return Err(MigrationError::StorageContractViolation);
        }
        match (
            &fields.disposition,
            fields.counts.requires_manual_disposition(),
        ) {
            (ImportDisposition::Clean, true) => {}
            (ImportDisposition::ManualAuthorized(authorization), true)
                if authorization.is_valid()
                    && all_artifacts_unique([
                        &fields.report,
                        &fields.source_snapshot,
                        &fields.schema,
                        &fields.mapping,
                        &fields.profile,
                        authorization,
                    ]) => {}
            (ImportDisposition::ManualAuthorized(_), true) => {
                return Err(MigrationError::StorageContractViolation);
            }
            (_, false) => {}
        }
        Ok(Self {
            report: fields.report,
            plan_id: fields.plan_id,
            cycle_id: fields.cycle_id,
            source_snapshot: fields.source_snapshot,
            source_high_water: fields.source_high_water,
            source_generation: fields.source_generation,
            candidate_generation: fields.candidate_generation,
            counts: fields.counts,
            schema: fields.schema,
            mapping: fields.mapping,
            profile: fields.profile,
            integrity: fields.integrity,
            rebuild: fields.rebuild,
            disposition: fields.disposition,
            created_at: fields.created_at,
        })
    }

    /// Return whether risky import classes have explicit manual authorization.
    pub fn is_cutover_eligible(&self) -> bool {
        if self.integrity != ArtifactValidation::Passed
            || self.rebuild != ArtifactValidation::Passed
        {
            return false;
        }
        !self.counts.requires_manual_disposition()
            || matches!(
                self.disposition,
                ImportDisposition::ManualAuthorized(ref authorization)
                    if authorization.is_valid()
            )
    }

    /// Verify the complete report contract after durable decoding.
    pub fn has_valid_identity(&self) -> bool {
        Self::new(MigrationReportFields {
            report: self.report.clone(),
            plan_id: self.plan_id.clone(),
            cycle_id: self.cycle_id.clone(),
            source_snapshot: self.source_snapshot.clone(),
            source_high_water: self.source_high_water,
            source_generation: self.source_generation.clone(),
            candidate_generation: self.candidate_generation.clone(),
            counts: self.counts,
            schema: self.schema.clone(),
            mapping: self.mapping.clone(),
            profile: self.profile.clone(),
            integrity: self.integrity,
            rebuild: self.rebuild,
            disposition: self.disposition.clone(),
            created_at: self.created_at,
        })
        .is_ok()
    }
}

/// Durable drain evidence referenced by a cutover manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainReportArtifact {
    pub report: ArtifactRef,
    pub complete: bool,
    pub timed_out: bool,
    pub unresolved_effects: u64,
    pub source_high_water: u64,
}

/// Durable candidate rebuild/validation evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateValidationReport {
    pub report: ArtifactRef,
    pub validation: ArtifactValidation,
}

/// Closed rollback policy frozen before a routing CAS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackPolicy {
    /// Rollback before candidate writes may reuse a verified retained source.
    BeforeCandidateWrites,
    /// Candidate writes require an exact reverse migration contract.
    ReverseMigrationRequired(ArtifactRef),
    /// Automatic rollback is unavailable.
    ManualOnly,
}

/// Complete construction fields for a cutover manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CutoverManifestFields {
    pub manifest: ArtifactRef,
    pub plan_id: MigrationPlanId,
    pub cycle_id: MigrationCycleId,
    pub intent: CutoverIntent,
    pub rollout_policy: CutoverPolicy,
    pub routing_unit: RoutingUnit,
    pub source_release: ArtifactRef,
    pub source_generation: RuntimeGenerationRef,
    pub candidate_release: ArtifactRef,
    pub candidate_generation: RuntimeGenerationRef,
    pub frozen_evidence_set: ArtifactRef,
    pub migration_report: MigrationReport,
    pub drain_report: DrainReportArtifact,
    pub candidate_validation: CandidateValidationReport,
    pub expected_routing_generation: RoutingGeneration,
    pub routing_generation_at_prepare: RoutingGeneration,
    pub rollback_policy: RollbackPolicy,
    pub retention_until: Timestamp,
    pub operator_authorization: ArtifactRef,
    pub prepared_transition_id: String,
    pub expected_plan_version: u64,
    pub prepared_plan_version: u64,
    pub prepared_at: Timestamp,
}

/// Immutable cutover authorization persisted before any routing CAS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CutoverManifest {
    pub manifest_digest: ArtifactDigest,
    pub manifest_ref: String,
    pub plan_id: MigrationPlanId,
    pub cycle_id: MigrationCycleId,
    pub intent: CutoverIntent,
    pub rollout_policy: CutoverPolicy,
    pub routing_unit: RoutingUnit,
    pub source_release: ArtifactRef,
    pub source_generation: RuntimeGenerationRef,
    pub candidate_release: ArtifactRef,
    pub candidate_generation: RuntimeGenerationRef,
    pub evidence_set_digest: ArtifactDigest,
    pub evidence_set_ref: String,
    pub import_report: ArtifactRef,
    pub drain_report: ArtifactRef,
    pub candidate_validation: ArtifactRef,
    pub source_high_water: u64,
    pub expected_routing_generation: RoutingGeneration,
    pub rollback_policy: RollbackPolicy,
    pub retention_until: Timestamp,
    pub operator_authorization: ArtifactRef,
    pub prepared_transition_id: String,
    pub expected_plan_version: u64,
    pub plan_version: u64,
    pub prepared_at: Timestamp,
}

impl CutoverManifest {
    /// Validate all evidence and freeze a complete cutover manifest.
    pub fn new(fields: CutoverManifestFields) -> Result<Self, MigrationError> {
        if !fields.migration_report.has_valid_identity() {
            return Err(MigrationError::StorageContractViolation);
        }
        if !fields.migration_report.is_cutover_eligible() {
            return Err(MigrationError::ImportAmbiguous);
        }
        if !fields.drain_report.complete {
            return Err(MigrationError::DrainIncomplete);
        }
        if fields.drain_report.timed_out {
            return Err(MigrationError::DrainTimedOut);
        }
        if fields.drain_report.unresolved_effects != 0 {
            return Err(MigrationError::UnresolvedEffect);
        }
        if fields.candidate_validation.validation != ArtifactValidation::Passed {
            return Err(MigrationError::ProductionGatesUnavailable);
        }
        if fields.intent == CutoverIntent::CohortExpansion
            && fields.rollback_policy == RollbackPolicy::ManualOnly
        {
            return Err(MigrationError::RollbackIneligible);
        }
        fields.rollout_policy.validate_manifest(
            fields.intent,
            &fields.routing_unit,
            fields.expected_routing_generation,
            fields.prepared_at,
        )?;
        let expected_prepared_version = fields
            .expected_plan_version
            .checked_add(1)
            .ok_or(MigrationError::ArithmeticOverflow)?;
        if fields.plan_id != fields.migration_report.plan_id
            || fields.cycle_id != fields.migration_report.cycle_id
            || fields.source_generation != fields.migration_report.source_generation
            || fields.candidate_generation != fields.migration_report.candidate_generation
            || fields.source_high_water() != fields.drain_report.source_high_water
            || fields.expected_routing_generation != fields.routing_generation_at_prepare
            || fields.prepared_plan_version != expected_prepared_version
            || fields.routing_unit.schema_digest != fields.migration_report.schema.digest
            || fields.routing_unit.feature_profile.profile_digest
                != fields.migration_report.profile.digest
        {
            return Err(MigrationError::StorageContractViolation);
        }
        let rollback_contract = match &fields.rollback_policy {
            RollbackPolicy::ReverseMigrationRequired(contract) => Some(contract),
            RollbackPolicy::BeforeCandidateWrites | RollbackPolicy::ManualOnly => None,
        };
        let mut artifacts = vec![
            &fields.manifest,
            &fields.source_release,
            &fields.candidate_release,
            &fields.frozen_evidence_set,
            &fields.migration_report.report,
            &fields.drain_report.report,
            &fields.candidate_validation.report,
            &fields.operator_authorization,
        ];
        if let Some(contract) = rollback_contract {
            artifacts.push(contract);
        }
        if !all_artifacts_unique(artifacts)
            || !valid_bounded(&fields.prepared_transition_id, MAX_TRANSITION_ID_BYTES)
        {
            return Err(MigrationError::StorageContractViolation);
        }

        Ok(Self {
            manifest_digest: fields.manifest.digest,
            manifest_ref: fields.manifest.reference,
            plan_id: fields.plan_id,
            cycle_id: fields.cycle_id,
            intent: fields.intent,
            rollout_policy: fields.rollout_policy,
            routing_unit: fields.routing_unit,
            source_release: fields.source_release,
            source_generation: fields.source_generation,
            candidate_release: fields.candidate_release,
            candidate_generation: fields.candidate_generation,
            evidence_set_digest: fields.frozen_evidence_set.digest,
            evidence_set_ref: fields.frozen_evidence_set.reference,
            import_report: fields.migration_report.report,
            drain_report: fields.drain_report.report,
            candidate_validation: fields.candidate_validation.report,
            source_high_water: fields.migration_report.source_high_water,
            expected_routing_generation: fields.expected_routing_generation,
            rollback_policy: fields.rollback_policy,
            retention_until: fields.retention_until,
            operator_authorization: fields.operator_authorization,
            prepared_transition_id: fields.prepared_transition_id,
            expected_plan_version: fields.expected_plan_version,
            plan_version: fields.prepared_plan_version,
            prepared_at: fields.prepared_at,
        })
    }

    /// Verify persisted identity and all immutable artifact references.
    pub fn has_valid_identity(&self) -> bool {
        let rollback_contract = match &self.rollback_policy {
            RollbackPolicy::ReverseMigrationRequired(contract) => Some(contract),
            RollbackPolicy::BeforeCandidateWrites | RollbackPolicy::ManualOnly => None,
        };
        let mut artifacts = vec![
            ArtifactRef {
                reference: self.manifest_ref.clone(),
                digest: self.manifest_digest,
            },
            self.source_release.clone(),
            self.candidate_release.clone(),
            ArtifactRef {
                reference: self.evidence_set_ref.clone(),
                digest: self.evidence_set_digest,
            },
            self.import_report.clone(),
            self.drain_report.clone(),
            self.candidate_validation.clone(),
            self.operator_authorization.clone(),
        ];
        if let Some(contract) = rollback_contract {
            artifacts.push(contract.clone());
        }
        all_artifacts_unique(artifacts.iter())
            && valid_bounded(&self.prepared_transition_id, MAX_TRANSITION_ID_BYTES)
            && self.expected_plan_version.checked_add(1) == Some(self.plan_version)
            && self.source_generation != self.candidate_generation
            && self.retention_until >= self.prepared_at
            && !(self.intent == CutoverIntent::CohortExpansion
                && self.rollback_policy == RollbackPolicy::ManualOnly)
            && self
                .rollout_policy
                .validate_manifest(
                    self.intent,
                    &self.routing_unit,
                    self.expected_routing_generation,
                    self.prepared_at,
                )
                .is_ok()
    }
}

/// Immutable rollback-cycle artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackManifest {
    pub manifest: ArtifactRef,
    pub plan_id: MigrationPlanId,
    pub cycle_id: MigrationCycleId,
    pub parent_plan_id: MigrationPlanId,
    pub routing_unit: RoutingUnit,
    pub candidate_high_water: u64,
    pub changed_state_inventory: ArtifactRef,
    pub reconciliation_report: ArtifactRef,
    pub reverse_migration_contract: Option<ArtifactRef>,
    pub expected_routing_generation: RoutingGeneration,
    pub operator_authorization: ArtifactRef,
    pub created_at: Timestamp,
}

impl RollbackManifest {
    /// Verify isolated-cycle identity and all immutable references.
    pub fn has_valid_identity(&self) -> bool {
        let mut artifacts = vec![
            &self.manifest,
            &self.changed_state_inventory,
            &self.reconciliation_report,
            &self.operator_authorization,
        ];
        if let Some(contract) = &self.reverse_migration_contract {
            artifacts.push(contract);
        }
        self.plan_id != self.parent_plan_id && all_artifacts_unique(artifacts)
    }
}

/// Immutable source-retirement artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetirementManifest {
    pub manifest: ArtifactRef,
    pub plan_id: MigrationPlanId,
    pub cycle_id: MigrationCycleId,
    pub final_drain_report: ArtifactRef,
    pub final_audit: ArtifactRef,
    pub removal_diff: ArtifactRef,
    pub retention_until: Timestamp,
    pub operator_authorization: ArtifactRef,
    pub created_at: Timestamp,
}

impl RetirementManifest {
    /// Verify final-retirement identity, retention, and artifact uniqueness.
    pub fn has_valid_identity(&self) -> bool {
        self.retention_until >= self.created_at
            && all_artifacts_unique([
                &self.manifest,
                &self.final_drain_report,
                &self.final_audit,
                &self.removal_diff,
                &self.operator_authorization,
            ])
    }
}

impl CutoverManifestFields {
    fn source_high_water(&self) -> u64 {
        self.migration_report.source_high_water
    }
}

fn validate_reference(reference: &str) -> Result<(), MigrationError> {
    if !valid_bounded(reference, MAX_ARTIFACT_REF_BYTES) {
        return Err(MigrationError::StorageContractViolation);
    }
    Ok(())
}

fn valid_bounded(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
}

fn all_artifacts_unique<'a>(artifacts: impl IntoIterator<Item = &'a ArtifactRef>) -> bool {
    let mut references = BTreeSet::new();
    artifacts
        .into_iter()
        .all(|artifact| artifact.is_valid() && references.insert(artifact.reference.as_str()))
}
