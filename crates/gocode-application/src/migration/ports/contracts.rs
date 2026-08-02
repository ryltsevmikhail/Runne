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
