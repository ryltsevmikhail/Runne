//! Frozen, pure permission-mode contract and deterministic preset compiler.

pub use runne_domain::id::IntegrityDigest;

mod admission;
mod attenuation;
mod binding;
mod command_digest;
mod compiler;
mod compiler_rules;
mod composite;
mod composite_digest;
mod confirmation_v2;
mod errors;
mod history;
mod local_command_binding;
mod local_command_digest;
mod local_command_limits;
mod local_command_validation;
mod managed_digest;
mod model;
mod readiness;
mod resource;
mod retained;
mod scope_error;

pub use retained::*;

pub use admission::{
    FullAccessChallengeBinding, NativeAdmissionError, NativeChallengeError,
    NativeChallengeVerifier, NativeScopeAdmissionPort,
};
pub use binding::{ApprovalBinding, InvocationIdentity};
pub use compiler::{
    ApprovalReason, ApprovalUnit, DenyReason, InvocationPolicyRequest, ManagedDisposition,
    ManagedPolicyEvaluation, PermissionPolicyCompiler, PolicyDecision, PolicyEvaluationInput,
};
pub use composite::{
    ChildDelegationScope, ClosedManagedCoverageV1, CompositeEffectScope, CompositeScopeDigest,
    ContainmentStrategy, EffectBudget, FilesystemPermission, FilesystemPosture, FilesystemRoot,
    FilesystemScope, ManagedPolicyCoverage, NetworkScope,
};
pub use confirmation_v2::{
    NativeModeConfirmationBindingV2, NativeModeConfirmationError, NativeModeConfirmationVerifierV2,
    VerifiedNativeModeConfirmationV2, native_mode_public_request_digest_v2,
    verify_native_mode_confirmation_v2,
};
pub use errors::PermissionModeError;
pub use history::{EffectiveModeHistoryState, PermissionModeHistoryProjection};
pub use local_command_binding::{
    LOCAL_COMMAND_PERMISSION_BINDING_COMPILER_VERSION,
    LOCAL_COMMAND_PERMISSION_BINDING_SCHEMA_VERSION, LocalCommandPermissionBindingInputV1,
    LocalCommandPermissionBindingV1,
};
pub use local_command_limits::{
    LocalInvocationLimitsError, LocalInvocationLimitsV1, MAX_LOCAL_COMMAND_CAPTURE_BYTES,
};
pub use local_command_validation::LocalCommandPermissionBindingError;
pub use managed_digest::managed_policy_semantics_digest;
pub use model::{
    ModeSelection, NetworkState, PermissionMode, PermissionModeChangeReceipt,
    PermissionModeProjection, PermissionScope, PresetVersion, SetPermissionModeCommand,
    VerifiedNativeChallengeProof,
};
pub use readiness::{
    EffectiveModeReady, EffectiveModeState, ModeReadinessReceipt, NativeScopeAdmissionReceipt,
    NotReadyReason,
};
pub use resource::{
    ObjectKind, PermissionAction, ResolutionState, ResourceFacts, Sensitivity, SizeBound,
    TargetState, WorkspaceRelation,
};
pub use scope_error::ScopeError;

/// Ask the runtime's native admission port for an effective mode bound to `scope`.
///
/// The returned digest is an opaque platform admission handle. The platform
/// owner retains its real native token and held descriptors; this projection
/// does not recreate, serialize, or authorize those resources.
pub fn admit_effective_mode(
    mode: PermissionMode,
    preset_version: PresetVersion,
    scope: &CompositeEffectScope,
    admission: &dyn NativeScopeAdmissionPort,
) -> Result<EffectiveModeState, NativeAdmissionError> {
    scope
        .validate()
        .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
    let legacy_full_access = scope.containment == ContainmentStrategy::SameUserCompositeV1;
    let partial_fs_full_access = scope.containment == ContainmentStrategy::SameUserCompositeV2;
    if mode == PermissionMode::FullAccess && !(legacy_full_access || partial_fs_full_access) {
        return Err(NativeAdmissionError::CompositePolicyUnenforceable);
    }
    if mode == PermissionMode::FullAccess {
        let v2_policy_supported = partial_fs_full_access
            && scope.managed_policy.supports_scope_shape(scope)
            && scope.managed_policy.scope_minimum_disposition(scope)
                != Some(crate::project_trust::ManagedEffectDecision::Deny);
        let closed_policy_supported = if partial_fs_full_access {
            v2_policy_supported
        } else {
            scope.managed_policy.supports_closed_scope(scope)
        };
        let closed_network_supported = scope.managed_policy.is_closed()
            && matches!(
                scope.network,
                NetworkScope::None | NetworkScope::BroadSameUser
            )
            && closed_policy_supported;
        let legacy_network_supported = legacy_full_access
            && !scope.managed_policy.is_closed()
            && scope.network == NetworkScope::BroadSameUser;
        let filesystem_rights_supported = if partial_fs_full_access {
            !scope
                .filesystem
                .permissions
                .contains(&FilesystemPermission::Create)
                || scope
                    .filesystem
                    .permissions
                    .contains(&FilesystemPermission::Write)
        } else {
            [
                FilesystemPermission::Read,
                FilesystemPermission::Create,
                FilesystemPermission::Write,
                FilesystemPermission::Delete,
            ]
            .iter()
            .all(|permission| scope.filesystem.permissions.contains(permission))
        };
        if !matches!(scope.filesystem.posture, FilesystemPosture::BroadSameUser)
            || !(closed_network_supported || legacy_network_supported)
            || !filesystem_rights_supported
        {
            return Err(NativeAdmissionError::CompositePolicyUnenforceable);
        }
    }
    let handle_id = admission.admit_mode_readiness(mode, scope)?;
    if handle_id.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(NativeAdmissionError::EnforcementUnavailable);
    }
    let scope_digest = scope
        .digest()
        .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
    let receipt = ModeReadinessReceipt::checked(
        handle_id,
        scope_digest,
        scope.managed_policy.policy_digest(),
        scope.containment,
    );
    Ok(EffectiveModeState::Ready(EffectiveModeReady::admitted(
        mode,
        preset_version,
        receipt,
    )))
}

/// Admit the exact immutable scope for one invocation after the runtime has
/// resolved its resource and managed-policy snapshot.
pub fn admit_invocation_scope(
    scope: &CompositeEffectScope,
    admission: &dyn NativeScopeAdmissionPort,
) -> Result<NativeScopeAdmissionReceipt, NativeAdmissionError> {
    scope
        .validate()
        .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
    let handle_id = admission.admit_scope(scope)?;
    if handle_id.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(NativeAdmissionError::EnforcementUnavailable);
    }
    let scope_digest = scope
        .digest()
        .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
    Ok(NativeScopeAdmissionReceipt::admitted(
        handle_id,
        scope_digest,
        scope.managed_policy.policy_digest(),
        scope.containment,
    ))
}

/// Verify fresh full-access proof bytes and return an opaque pending proof.
///
/// This verifies the proof's cryptographic identity and exact command binding.
/// It does not select a mode or consume a nonce. The Store mode-change owner
/// consumes `proof_identifier()` in the same transaction as revision change,
/// managed-policy checks, and idempotency receipt persistence.
pub fn verify_full_access_challenge(
    binding: &FullAccessChallengeBinding,
    proof_bytes: &[u8],
    now_unix_ms: i64,
    verifier: &dyn NativeChallengeVerifier,
) -> Result<VerifiedNativeChallengeProof, NativeChallengeError> {
    if binding.requested_mode != PermissionMode::FullAccess {
        return Err(NativeChallengeError::WrongMode);
    }
    if binding.challenge_expires_at_unix_ms <= 0
        || binding.challenge_expires_at_unix_ms <= now_unix_ms
    {
        return Err(NativeChallengeError::Rejected);
    }
    let challenge_identifier = verifier.verify(binding, proof_bytes)?;
    if challenge_identifier != binding.challenge_binding_digest
        || challenge_identifier
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(NativeChallengeError::InvalidProofReceipt);
    }
    Ok(VerifiedNativeChallengeProof::verified(
        binding.digest(),
        challenge_identifier,
    ))
}

/// Validate immutable mode-command semantics before the Store owner starts its transaction.
pub fn validate_mode_change_command(
    command: &SetPermissionModeCommand,
) -> Result<(), PermissionModeError> {
    if command.preset_version != PresetVersion::V1 {
        return Err(PermissionModeError::UnsupportedPresetVersion);
    }
    if command.computed_intent_digest() != command.intent_digest {
        return Err(PermissionModeError::InvalidIntentDigest);
    }
    match command.requested_mode {
        PermissionMode::FullAccess => {
            let Some(challenge_binding_digest) = command.challenge_binding_digest else {
                return Err(PermissionModeError::ReauthenticationRequired);
            };
            let Some(verified) = command.verified_native_challenge else {
                return Err(PermissionModeError::ReauthenticationRequired);
            };
            let binding = FullAccessChallengeBinding {
                command_id: command.command_id,
                idempotency_key: command.idempotency_key.clone(),
                scope: command.scope.clone(),
                expected_authorization_revision: command.expected_authorization_revision,
                requested_mode: command.requested_mode,
                preset_version: command.preset_version,
                managed_policy_version: command.managed_policy_version,
                managed_policy_digest: command.managed_policy_digest,
                intent_digest: command.intent_digest,
                challenge_binding_digest,
                expires_at_unix_ms: command.expires_at_unix_ms,
                challenge_expires_at_unix_ms: command
                    .challenge_expires_at_unix_ms
                    .ok_or(PermissionModeError::ReauthenticationRequired)?,
            };
            if verified.binding_digest() != binding.digest() {
                return Err(PermissionModeError::ReauthenticationRequired);
            }
        }
        _ if command.challenge_binding_digest.is_some()
            || command.challenge_expires_at_unix_ms.is_some()
            || command.verified_native_challenge.is_some() =>
        {
            return Err(PermissionModeError::UnexpectedReauthenticationProof);
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "permission_modes/closed_coverage/tests_support.rs"]
mod closed_coverage_test_support;

#[cfg(test)]
#[path = "permission_modes/tests_containment_v2.rs"]
mod tests_containment_v2;

#[cfg(test)]
#[path = "permission_modes/local_command_tests.rs"]
mod local_command_tests;
