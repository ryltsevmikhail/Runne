
use std::time::Duration;

use gocode_domain::timestamp::Timestamp;
use sha2::{Digest, Sha256};

use super::{
    error::MigrationError,
    ports::CutoverIntent,
    types::{
        ArtifactDigest, CohortSelector, FeatureProfileRef, GatePolicyRef, RoutingGeneration,
        RoutingUnit,
    },
};

/// Maximum number of concurrently admitted commands in the internal canary.
pub const MAX_CANARY_ADMISSION_LIMIT: u32 = 1_024;
/// Maximum command admission bound for one cohort rollout step.
pub const MAX_ROLLOUT_ADMISSION_LIMIT: u32 = 1_000_000;

/// Closed disposition for one legacy-reference category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyReferenceDisposition {
    /// References remain unresolved and block retirement.
    Unresolved,
    /// References were fully resolved.
    Resolved,
    /// References were moved to immutable retention authority.
    RetainedByPolicy,
}

/// Exact blocking count and identity digest for one legacy-reference category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyReferenceSet {
    /// References that still require the legacy runtime.
    pub blocking_count: u64,
    /// Canonical digest of the exact referenced identities.
    pub identity_digest: ArtifactDigest,
    /// Explicit resolution or retention disposition.
    pub disposition: LegacyReferenceDisposition,
}

impl LegacyReferenceSet {
    fn is_retirement_clear(&self) -> bool {
        self.blocking_count == 0
            && self.identity_digest.as_bytes() != &[0; 32]
            && self.disposition != LegacyReferenceDisposition::Unresolved
    }
}

/// Complete Stage 7 inventory of references that may retain legacy authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyReferenceInventory {
    /// Accepted or currently executing work.
    pub active_and_in_flight: LegacyReferenceSet,
    /// Work that still requires recovery.
    pub recovery_candidates: LegacyReferenceSet,
    /// External effects without a terminal disposition.
    pub uncertain_effects: LegacyReferenceSet,
    /// Timers, processes, and cleanup obligations.
    pub timers_processes_cleanup: LegacyReferenceSet,
    /// Replay cursors and client-held references.
    pub replay_and_client_cursors: LegacyReferenceSet,
    /// Audit and retention references.
    pub audit_and_retention: LegacyReferenceSet,
    /// Artifacts that preserve a rollback path.
    pub rollback_artifacts: LegacyReferenceSet,
    /// Credentials, packages, and runtime processes.
    pub credentials_packages_processes: LegacyReferenceSet,
}

impl LegacyReferenceInventory {
    /// Verify that every category has a non-zero exact-identity digest.
    pub fn has_valid_identity(&self) -> bool {
        self.reference_sets()
            .into_iter()
            .all(|set| set.identity_digest.as_bytes() != &[0; 32])
    }

    /// Return true only when every blocking count is zero and disposed explicitly.
    pub fn is_retirement_clear(&self) -> bool {
        self.has_valid_identity()
            && self
                .reference_sets()
                .into_iter()
                .all(LegacyReferenceSet::is_retirement_clear)
    }

    /// Compute a canonical domain-separated digest over every category.
    pub fn digest(&self) -> ArtifactDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"gocode-legacy-reference-inventory\x01");
        for (tag, reference_set) in self.reference_sets().into_iter().enumerate() {
            hasher.update([u8::try_from(tag + 1).unwrap_or(u8::MAX)]);
            hasher.update(reference_set.blocking_count.to_be_bytes());
            hasher.update(reference_set.identity_digest.as_bytes());
            hasher.update([match reference_set.disposition {
                LegacyReferenceDisposition::Unresolved => 0,
                LegacyReferenceDisposition::Resolved => 1,
                LegacyReferenceDisposition::RetainedByPolicy => 2,
            }]);
        }
        ArtifactDigest::from_bytes(hasher.finalize().into())
    }

    fn reference_sets(&self) -> [&LegacyReferenceSet; 8] {
        [
            &self.active_and_in_flight,
            &self.recovery_candidates,
            &self.uncertain_effects,
            &self.timers_processes_cleanup,
            &self.replay_and_client_cursors,
            &self.audit_and_retention,
            &self.rollback_artifacts,
            &self.credentials_packages_processes,
        ]
    }
}

/// Independently testable Stage 8 exit conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetirementRequirement {
    /// No runtime reference remains unresolved.
    ReferenceInventoryClear,
    /// Stage 7 closed every new legacy binding.
    LegacyAdmissionClosed,
    /// Replacement was verified on every claimed platform tuple.
    ReplacementPlatformsVerified,
    /// Forward migration support window is closed.
    MigrationWindowClosed,
    /// Rollback support window is closed.
    RollbackWindowClosed,
    /// Legacy credentials are disabled.
    CredentialsDisabled,
    /// Legacy runtime processes are disabled.
    ProcessesDisabled,
    /// Legacy packages are disabled.
    PackagesDisabled,
    /// Removal passed security and compatibility suites.
    RemovalSuitesPassed,
    /// Final retirement audit was accepted.
    FinalAuditAccepted,
}

impl RetirementRequirement {
    /// Canonical complete requirement inventory.
    pub const ALL: [Self; 10] = [
        Self::ReferenceInventoryClear,
        Self::LegacyAdmissionClosed,
        Self::ReplacementPlatformsVerified,
        Self::MigrationWindowClosed,
        Self::RollbackWindowClosed,
        Self::CredentialsDisabled,
        Self::ProcessesDisabled,
        Self::PackagesDisabled,
        Self::RemovalSuitesPassed,
        Self::FinalAuditAccepted,
    ];
}

/// Evaluated Stage 8 readiness over exact immutable evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetirementReadiness {
    /// Exact categorized legacy-reference inventory.
    pub reference_inventory: LegacyReferenceInventory,
    /// New Source bindings are durably closed.
    pub legacy_admission_closed: bool,
    /// Candidate replacement is verified on every claimed platform.
    pub replacement_platforms_verified: bool,
    /// Forward migration window is closed.
    pub migration_window_closed: bool,
    /// Rollback window is closed.
    pub rollback_window_closed: bool,
    /// Legacy credentials are disabled.
    pub credentials_disabled: bool,
    /// Legacy processes are disabled.
    pub processes_disabled: bool,
    /// Legacy packages are disabled.
    pub packages_disabled: bool,
    /// Security and compatibility removal suites passed.
    pub removal_suites_passed: bool,
    /// Final audit was accepted.
    pub final_audit_accepted: bool,
}

impl RetirementReadiness {
    /// Return the first unsatisfied exit condition, if any.
    pub fn first_missing(&self) -> Option<RetirementRequirement> {
        RetirementRequirement::ALL
            .into_iter()
            .find(|requirement| !self.satisfies(*requirement))
    }

    /// Return true only when every Stage 8 exit condition is satisfied.
    pub fn is_ready(&self) -> bool {
        self.first_missing().is_none()
    }

    fn satisfies(&self, requirement: RetirementRequirement) -> bool {
        match requirement {
            RetirementRequirement::ReferenceInventoryClear => {
                self.reference_inventory.is_retirement_clear()
            }
            RetirementRequirement::LegacyAdmissionClosed => self.legacy_admission_closed,
            RetirementRequirement::ReplacementPlatformsVerified => {
                self.replacement_platforms_verified
            }
            RetirementRequirement::MigrationWindowClosed => self.migration_window_closed,
            RetirementRequirement::RollbackWindowClosed => self.rollback_window_closed,
            RetirementRequirement::CredentialsDisabled => self.credentials_disabled,
            RetirementRequirement::ProcessesDisabled => self.processes_disabled,
            RetirementRequirement::PackagesDisabled => self.packages_disabled,
            RetirementRequirement::RemovalSuitesPassed => self.removal_suites_passed,
            RetirementRequirement::FinalAuditAccepted => self.final_audit_accepted,
        }
    }
}

/// Explicit policy for selecting Source before any candidate dispatch is attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreDispatchFallbackPolicy {
    /// Candidate incompatibility rejects admission.
    Disabled,
    /// An exact unsupported candidate profile may bind directly to Source.
    ExplicitSourceBeforeAcceptance {
        /// Exact feature profile authorized for Source execution.
        source_profile: FeatureProfileRef,
    },
}

impl PreDispatchFallbackPolicy {
    /// Require any explicit fallback profile to match the routing unit exactly.
    pub fn validate_routing_unit(&self, unit: &RoutingUnit) -> Result<(), MigrationError> {
        match self {
            Self::Disabled => Ok(()),
            Self::ExplicitSourceBeforeAcceptance { source_profile }
                if source_profile == &unit.feature_profile =>
            {
                Ok(())
            }
            Self::ExplicitSourceBeforeAcceptance { .. } => Err(MigrationError::RoutingUnitMismatch),
        }
    }
}
