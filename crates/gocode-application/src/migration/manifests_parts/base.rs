/// New-binding policy published with a legacy deprecation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyNewBindingPolicy {
    /// No new binding may select Source authority.
    Closed,
}

/// Immutable Stage 7 descriptor and exact legacy-reference inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeprecationManifest {
    /// Content-addressed manifest identity.
    pub manifest: ArtifactRef,
    /// Owning migration plan.
    pub plan_id: MigrationPlanId,
    /// Owning migration cycle.
    pub cycle_id: MigrationCycleId,
    /// Exact affected cohort.
    pub cohort: CohortSelector,
    /// Verified replacement feature profile.
    pub replacement_profile: FeatureProfileRef,
    /// Digest of every exact identity affected by deprecation.
    pub affected_identity_digest: ArtifactDigest,
    /// Last instant in the published support window.
    pub support_until: Timestamp,
    /// Content-addressed operator migration guidance.
    pub migration_guidance: ArtifactRef,
    /// Content-addressed cohort drain report.
    pub drain_report: ArtifactRef,
    /// Complete categorized legacy-reference inventory.
    pub reference_inventory: LegacyReferenceInventory,
    /// Closed new-binding policy.
    pub new_binding_policy: LegacyNewBindingPolicy,
    /// Persistence-authoritative creation time.
    pub created_at: Timestamp,
}

impl DeprecationManifest {
    /// Validate identity, time, artifacts, inventory, and closed admission.
    pub fn has_valid_identity(&self) -> bool {
        self.support_until >= self.created_at
            && self.affected_identity_digest.as_bytes() != &[0; 32]
            && self.reference_inventory.has_valid_identity()
            && self.new_binding_policy == LegacyNewBindingPolicy::Closed
            && all_artifacts_unique([&self.manifest, &self.migration_guidance, &self.drain_report])
    }
}

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
