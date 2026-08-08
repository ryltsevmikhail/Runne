//! Pure, non-authoritative qualification consistency model for Task 8.
//!
//! This module is deliberately unwired to enforcement. It performs no I/O,
//! mutation, time, or randomness and cannot create authority.

mod mapping;

pub use mapping::{rejection_from_canonical_provider_error, rejection_from_launch_authority_error};

/// Requested provider execution mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationMode {
    /// Runtime-owned protected provider execution.
    Bundled,
    /// Explicitly selected owner-private provider execution.
    External,
}

/// Supported provider contract versions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderContractVersion {
    V1,
    V2,
}

/// Role seeking qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeRole {
    Production,
    DeterministicCompatibility,
}

/// Trust class of qualification evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceClass {
    Fixture,
    Production,
}

/// Exact-match result for an identity axis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityMatch {
    Match,
    Mismatch,
}

/// Bundled-process ownership evidence, which cannot prove external provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundledProcessOwnership {
    Proven,
    Unproven,
}

/// External owner-private provenance, which cannot prove bundled ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalOwnerPrivateProvenance {
    Verified,
    Unverified,
}

/// Evidence bound to exactly one provider execution mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModeEvidence {
    /// Evidence for a runtime-owned protected process.
    Bundled {
        process_ownership: BundledProcessOwnership,
    },
    /// Evidence for explicit owner-private execution.
    External {
        explicit_selection: bool,
        provenance: ExternalOwnerPrivateProvenance,
    },
}

/// Provider credential admission result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialGate {
    Configured,
    NotConfigured,
}

/// Complete typed input to the pure qualification decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationInput {
    pub mode: QualificationMode,
    pub contract_version: ProviderContractVersion,
    pub role: RuntimeRole,
    pub evidence_class: EvidenceClass,
    pub mode_evidence: ModeEvidence,
    pub deterministic_inputs_only: bool,
    pub bundle_hash_match: bool,
    pub capability_set_match: bool,
    pub credential_gate: CredentialGate,
    pub authority: IdentityMatch,
    pub principal: IdentityMatch,
    pub lineage: IdentityMatch,
    pub session: IdentityMatch,
    pub generation: IdentityMatch,
}

/// Non-mutating qualification result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationDisposition {
    VerifiedProtectedV2,
    VerifiedExternalOwnerPrivate,
    DeterministicCompatibilityV1,
    FixtureQualified,
    Rejected(QualificationRejection),
}

/// Fail-closed reasons for qualification rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationRejection {
    ProtectedV2Required,
    MissingExplicitExternalSelection,
    ContractVersionDeniedForRole,
    ModeMismatch,
    ProfileDigestMismatch,
    AuthorityMismatch,
    PrincipalMismatch,
    LineageMismatch,
    SessionMismatch,
    GenerationMismatch,
    CapabilitySetMismatch,
    BlockedCredentials,
    OwnershipNotProven,
    ExternalProvenanceUnverified,
}

/// Qualifies a fully typed input without I/O, mutation, time, or randomness.
#[must_use]
pub fn qualify(input: &QualificationInput) -> QualificationDisposition {
    if !evidence_matches_mode(input) {
        return rejected(QualificationRejection::ModeMismatch);
    }
    if external_selection_is_missing(input) {
        return rejected(QualificationRejection::MissingExplicitExternalSelection);
    }
    if let Some(rejection) = version_rejection(input) {
        return rejected(rejection);
    }
    if let Some(rejection) = common_rejection(input) {
        return rejected(rejection);
    }
    if let Some(rejection) = evidence_rejection(input) {
        return rejected(rejection);
    }
    accepted_disposition(input)
}

fn rejected(rejection: QualificationRejection) -> QualificationDisposition {
    QualificationDisposition::Rejected(rejection)
}

fn evidence_matches_mode(input: &QualificationInput) -> bool {
    matches!(
        (input.mode, input.mode_evidence),
        (QualificationMode::Bundled, ModeEvidence::Bundled { .. })
            | (QualificationMode::External, ModeEvidence::External { .. })
    )
}

fn external_selection_is_missing(input: &QualificationInput) -> bool {
    matches!(
        input.mode_evidence,
        ModeEvidence::External {
            explicit_selection: false,
            ..
        }
    )
}

fn version_rejection(input: &QualificationInput) -> Option<QualificationRejection> {
    match (input.contract_version, input.role) {
        (ProviderContractVersion::V1, RuntimeRole::Production) => Some(match input.mode {
            QualificationMode::Bundled => QualificationRejection::ProtectedV2Required,
            QualificationMode::External => QualificationRejection::ContractVersionDeniedForRole,
        }),
        (ProviderContractVersion::V1, RuntimeRole::DeterministicCompatibility)
            if !input.deterministic_inputs_only =>
        {
            Some(QualificationRejection::ContractVersionDeniedForRole)
        }
        (ProviderContractVersion::V2, RuntimeRole::DeterministicCompatibility) => {
            Some(QualificationRejection::ContractVersionDeniedForRole)
        }
        _ => None,
    }
}

fn common_rejection(input: &QualificationInput) -> Option<QualificationRejection> {
    for (axis, rejection) in [
        (input.authority, QualificationRejection::AuthorityMismatch),
        (input.principal, QualificationRejection::PrincipalMismatch),
        (input.lineage, QualificationRejection::LineageMismatch),
        (input.session, QualificationRejection::SessionMismatch),
        (input.generation, QualificationRejection::GenerationMismatch),
    ] {
        if axis == IdentityMatch::Mismatch {
            return Some(rejection);
        }
    }
    if !input.bundle_hash_match {
        return Some(QualificationRejection::ProfileDigestMismatch);
    }
    if !input.capability_set_match {
        return Some(QualificationRejection::CapabilitySetMismatch);
    }
    (input.credential_gate != CredentialGate::Configured)
        .then_some(QualificationRejection::BlockedCredentials)
}

fn evidence_rejection(input: &QualificationInput) -> Option<QualificationRejection> {
    match input.mode_evidence {
        ModeEvidence::Bundled {
            process_ownership: BundledProcessOwnership::Unproven,
        } => Some(QualificationRejection::OwnershipNotProven),
        ModeEvidence::External {
            provenance: ExternalOwnerPrivateProvenance::Unverified,
            ..
        } => Some(QualificationRejection::ExternalProvenanceUnverified),
        _ => None,
    }
}

fn accepted_disposition(input: &QualificationInput) -> QualificationDisposition {
    match input.contract_version {
        ProviderContractVersion::V1 => QualificationDisposition::DeterministicCompatibilityV1,
        ProviderContractVersion::V2 if input.evidence_class == EvidenceClass::Fixture => {
            QualificationDisposition::FixtureQualified
        }
        ProviderContractVersion::V2 => match input.mode {
            QualificationMode::Bundled => QualificationDisposition::VerifiedProtectedV2,
            QualificationMode::External => QualificationDisposition::VerifiedExternalOwnerPrivate,
        },
    }
}
