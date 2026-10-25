use super::fixture::{Fixture, command_id, key, now};
use crate::store::{
    NativeModeConfirmationRequestV2, PermissionModeAuthorityContext, PermissionModeCeremonyStatusV2,
};
use runne_application::permission_modes::*;
use runne_application::project_trust::ProjectTrustPersistence;
use runne_domain::id::IntegrityDigest;

pub(super) fn commit(f: &Fixture, mode: PermissionMode, revision: u64) {
    assert_ne!(
        mode,
        PermissionMode::FullAccess,
        "fixture has no real re-authentication"
    );
    let lease = f.trust.acquire_effect_lease(f.trust_id()).unwrap();
    let authority = PermissionModeAuthorityContext::new(
        &f.principal,
        f.trust_id(),
        lease.as_ref(),
        Some(&f.launch),
    );
    let request = NativeModeConfirmationRequestV2 {
        command_id: command_id(),
        idempotency_key: key(&format!("mode-{revision}")),
        scope: f.scope.clone(),
        expected_authorization_revision: revision,
        requested_mode: mode,
        preset_version: PresetVersion::V1,
        expires_at_unix_ms: None,
    };
    let PermissionModeCeremonyStatusV2::Pending(issued) = f
        .store
        .begin_permission_mode_confirmation_v2(request.clone(), &authority)
        .unwrap()
    else {
        panic!("fresh ceremony")
    };
    let mut command = SetPermissionModeCommand {
        command_id: request.command_id,
        scope: request.scope,
        expected_authorization_revision: revision,
        requested_mode: mode,
        preset_version: request.preset_version,
        intent_digest: IntegrityDigest::from_bytes([0; 32]),
        idempotency_key: request.idempotency_key,
        expires_at_unix_ms: None,
        managed_policy_version: issued.binding().managed_policy_version,
        managed_policy_digest: issued.binding().managed_policy_digest,
        challenge_binding_digest: None,
        challenge_expires_at_unix_ms: None,
        verified_native_challenge: None,
    };
    command.intent_digest = command.computed_intent_digest();
    let proof = verify_native_mode_confirmation_v2(
        issued.binding(),
        b"test-only confirmation echo",
        now(),
        &MockConfirmationEcho,
    )
    .unwrap();
    let history = PermissionModeHistoryProjection {
        selected_mode: mode,
        effective: EffectiveModeHistoryState::NotReady(NotReadyReason::NativeContainment),
        authorization_revision: revision + 1,
        preset_version: command.preset_version,
        managed_policy_version: command.managed_policy_version,
        containment: None,
        network_state: NetworkState::Unavailable,
        expires_at_unix_ms: None,
    };
    let receipt = f
        .store
        .commit_confirmed_permission_mode_v2(command, proof, &authority, history)
        .unwrap();
    assert_eq!(receipt.selection.authorization_revision, revision + 1);
    assert_eq!(receipt.selection.selected_mode, mode);
    let selected = f
        .store
        .load_permission_mode_selection(&f.scope, &f.principal)
        .unwrap();
    assert_eq!(selected.authorization_revision, revision + 1);
    // The scoped sidecar lease is dropped before target capture reacquires it.
}

pub(super) fn assert_same_policy(f: &Fixture, binding: &LocalCommandPermissionBindingV1) {
    let lease = f.trust.acquire_effect_lease(f.trust_id()).unwrap();
    let authority =
        PermissionModeAuthorityContext::new(&f.principal, f.trust_id(), lease.as_ref(), None);
    let current = f
        .store
        .load_permission_mode_selection_with_managed_identity(&f.scope, &f.principal, &authority)
        .unwrap();
    let crate::store::ManagedIdentityMetadata::ClosedRulesV2(managed) = current.identity else {
        panic!("current closed policy")
    };
    assert_eq!(managed.snapshot, binding.closed_rules_snapshot());
    assert_eq!(managed.canonical_digest, binding.closed_rules_digest());
    assert_eq!(managed.project_version, binding.project_version());
    let coverage =
        ManagedPolicyCoverage::from_closed_snapshot(f.trust_id(), &managed.snapshot).unwrap();
    assert_eq!(coverage, binding.scope().managed_policy);
}

// Test-only confirmation authority. This is not a human/native proof verifier.
struct MockConfirmationEcho;
impl NativeModeConfirmationVerifierV2 for MockConfirmationEcho {
    fn verify(
        &self,
        binding: &NativeModeConfirmationBindingV2,
        _: &[u8],
    ) -> Result<IntegrityDigest, NativeModeConfirmationError> {
        Ok(binding.challenge_binding_digest)
    }
}
