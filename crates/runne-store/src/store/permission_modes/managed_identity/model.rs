use runne_application::{
    permission_modes::ModeSelection, project_trust::ProjectTrustEffectPolicySnapshot,
};
use runne_domain::id::IntegrityDigest;

/// V1 managed record identity retained for selections written before V67.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyRecordIdentityV1 {
    /// Project identifier already bound by the selection's workspace.
    pub project_id: [u8; 16],
    /// Managed record revision stored by the legacy selection.
    pub managed_policy_version: u64,
    /// Original V1 record digest stored by the legacy selection.
    pub managed_policy_digest: IntegrityDigest,
}

/// Exact V2 six-rule identity from one held T1 snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedRulesManagedIdentityV2 {
    /// Project identifier whose rules and record were captured.
    pub project_id: [u8; 16],
    /// Current project version, checked when a challenge is consumed.
    pub project_version: u64,
    /// The exact record and six closed decisions from the same T1 fence.
    pub snapshot: ProjectTrustEffectPolicySnapshot,
    /// Canonical application-owned six-rule digest.
    pub canonical_digest: IntegrityDigest,
    /// Challenge-only legacy digest and envelope, absent for a live default.
    pub challenge_binding: Option<ManagedIdentityChallengeBindingV2>,
}

/// Envelope inputs stored with an issued native challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedIdentityChallengeBindingV2 {
    /// Byte-exact V66 challenge issued digest retained as a component.
    pub legacy_issued_digest: IntegrityDigest,
    /// V67 envelope that binds the V66 digest, rules, and project version.
    pub envelope_digest: IntegrityDigest,
}

/// Explicit version selected when reading durable managed identity metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedIdentityMetadata {
    /// A selection without a V67 extension remains a V1 record identity.
    LegacyRecordV1(LegacyRecordIdentityV1),
    /// A V67 selection references its exact immutable six-rule snapshot.
    ClosedRulesV2(ClosedRulesManagedIdentityV2),
}

/// Selected permission mode paired with its exact managed identity version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionModeSelectionManagedIdentity {
    /// Current selection, or AskAlways at revision zero when absent.
    pub selection: ModeSelection,
    /// Explicit V1 legacy or V2 closed-rule identity.
    pub identity: ManagedIdentityMetadata,
}
