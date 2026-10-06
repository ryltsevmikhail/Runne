//! Stable permission-mode, command, and projection types.

use runne_api::ApiPrincipalId;
use runne_domain::id::{ApprovalId, CommandId, IdempotencyKey, IntegrityDigest, WorkspaceId};

use super::{
    command_digest::mode_intent_digest, composite::ContainmentStrategy,
    history::PermissionModeHistoryProjection, readiness::EffectiveModeState,
};

/// Versioned runtime permission preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PermissionMode {
    /// Ask for exact human approval before each effect invocation.
    AskAlways,
    /// Automatically admit only frozen deterministic low-risk effects.
    RiskBased,
    /// Admit effects only inside an explicitly admitted same-user scope.
    FullAccess,
}

/// Version of the deterministic rule set used by a preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PresetVersion(u16);

impl PresetVersion {
    /// Frozen initial permission-mode preset version.
    pub const V1: Self = Self(1);

    /// Numeric version for persistence and projection.
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// Authority, authenticated principal, and workspace boundary for selection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PermissionScope {
    /// Runtime authority owning this mode selection.
    pub runtime_authority_id: crate::ports::RuntimeAuthorityId,
    /// Principal derived by authenticated ingress.
    pub principal_id: ApiPrincipalId,
    /// Workspace whose task effects are governed.
    pub workspace_id: WorkspaceId,
}

/// Durable selected mode observation. Missing rows are ask-always at revision 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeSelection {
    /// Scope of the durable selection.
    pub scope: PermissionScope,
    /// User-selected mode.
    pub selected_mode: PermissionMode,
    /// Version of the selected preset.
    pub preset_version: PresetVersion,
    /// Monotonic authorization revision; absence is revision zero.
    pub authorization_revision: u64,
    /// Optional finite lifetime for the selected mode grant.
    pub expires_at_unix_ms: Option<i64>,
}

impl ModeSelection {
    /// Conservative value used when no durable selection exists.
    pub fn missing(scope: PermissionScope) -> Self {
        Self {
            scope,
            selected_mode: PermissionMode::AskAlways,
            preset_version: PresetVersion::V1,
            authorization_revision: 0,
            expires_at_unix_ms: None,
        }
    }
}

/// Opaque proof accepted by the native verifier but not yet consumed durably.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedNativeChallengeProof {
    binding_digest: IntegrityDigest,
    challenge_identifier: IntegrityDigest,
}

impl VerifiedNativeChallengeProof {
    pub(super) fn verified(
        binding_digest: IntegrityDigest,
        challenge_identifier: IntegrityDigest,
    ) -> Self {
        Self {
            binding_digest,
            challenge_identifier,
        }
    }

    /// Immutable issued challenge ID the Store consumes in the mode-change transaction.
    pub const fn proof_identifier(self) -> IntegrityDigest {
        self.challenge_identifier
    }

    pub(crate) const fn binding_digest(self) -> IntegrityDigest {
        self.binding_digest
    }
}

/// Compare-and-set command for changing a scoped permission mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetPermissionModeCommand {
    /// Canonical command identity used by the durable receipt.
    pub command_id: CommandId,
    /// Selection scope; ingress must construct its principal from auth.
    pub scope: PermissionScope,
    /// Revision that the caller observed.
    pub expected_authorization_revision: u64,
    /// Requested preset.
    pub requested_mode: PermissionMode,
    /// Versioned risk and admission rules.
    pub preset_version: PresetVersion,
    /// Requested semantic intent digest, checked by the command owner.
    pub intent_digest: IntegrityDigest,
    /// Idempotency identity for durable command receipt lookup.
    pub idempotency_key: IdempotencyKey,
    /// Optional expiry included in semantic intent.
    pub expires_at_unix_ms: Option<i64>,
    /// Managed policy generation observed by the command owner.
    pub managed_policy_version: u64,
    /// Exact managed-policy snapshot digest observed by the command owner.
    pub managed_policy_digest: IntegrityDigest,
    /// Opaque challenge identity/purpose binding included in the intent digest.
    pub challenge_binding_digest: Option<IntegrityDigest>,
    /// Short finite challenge expiry; distinct from the selected mode lifetime.
    pub challenge_expires_at_unix_ms: Option<i64>,
    /// Verified proof awaiting atomic one-use consumption by the mode owner.
    pub verified_native_challenge: Option<VerifiedNativeChallengeProof>,
}

impl SetPermissionModeCommand {
    /// Computes the canonical semantic digest used for idempotency and CAS.
    pub fn computed_intent_digest(&self) -> IntegrityDigest {
        mode_intent_digest(self)
    }
}

/// Honest public projection of mode selection and enforcement availability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionModeProjection {
    /// Runtime-owned selected mode.
    pub selected_mode: PermissionMode,
    /// Effective mode or an explicit not-ready reason.
    pub effective: EffectiveModeState,
    /// Current durable authorization revision.
    pub authorization_revision: u64,
    /// Selected preset generation.
    pub preset_version: PresetVersion,
    /// Managed policy generation observed for this projection.
    pub managed_policy_version: u64,
    /// Pending exact approval identifiers projected by the runtime owner.
    pub pending_approval_ids: Vec<ApprovalId>,
    /// Scope strategy used by current enforcement, if admitted.
    pub containment: Option<ContainmentStrategy>,
    /// Honest current egress posture.
    pub network_state: NetworkState,
    /// Optional mode expiry in Unix milliseconds.
    pub expires_at_unix_ms: Option<i64>,
}

/// Durable idempotent result of one permission-mode compare-and-set command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionModeChangeReceipt {
    /// Command identity supplied to the durable owner.
    pub command_id: CommandId,
    /// Idempotency key used for duplicate receipt lookup.
    pub idempotency_key: IdempotencyKey,
    /// Canonical semantic intent digest.
    pub intent_digest: IntegrityDigest,
    /// Selected mode and revision committed by the owner.
    pub selection: ModeSelection,
    /// Honest effective enforcement projection at commit time.
    pub projection: PermissionModeHistoryProjection,
}

/// Network posture exposed to CLI and Desktop projections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkState {
    /// No admitted network effect scope.
    Unavailable,
    /// Network effects use an explicit managed broker policy.
    Brokered,
    /// Broad same-user network access is inside the admitted namespace scope.
    BroadSameUser,
}
