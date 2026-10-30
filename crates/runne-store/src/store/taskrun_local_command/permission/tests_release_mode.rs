use super::fixture::{Fixture, command_id, key, now};
use crate::store::{
    NativeModeConfirmationRequestV2, PermissionModeAuthorityContext, PermissionModeCeremonyStatusV2,
};
use runne_application::permission_modes::*;
use runne_application::project_trust::ProjectTrustEffectLease;
use runne_domain::id::IntegrityDigest;

pub(super) fn commit(
    f: &Fixture,
    mode: PermissionMode,
    revision: u64,
    lease: &dyn ProjectTrustEffectLease,
) {
    commit_with_expiry(f, mode, revision, lease, None);
}

// A real trusted receipt with a changed expiry is intentionally incompatible.
pub(super) fn commit_expiring(
    f: &Fixture,
    mode: PermissionMode,
    revision: u64,
    lease: &dyn ProjectTrustEffectLease,
) {
    commit_with_expiry(f, mode, revision, lease, Some(now() + 60_000));
}

fn commit_with_expiry(
    f: &Fixture,
    mode: PermissionMode,
    revision: u64,
    lease: &dyn ProjectTrustEffectLease,
    expires_at_unix_ms: Option<i64>,
) {
    assert_ne!(
        mode,
        PermissionMode::FullAccess,
        "fixture has no real re-authentication"
    );
    let authority =
        PermissionModeAuthorityContext::new(&f.principal, f.trust_id(), lease, Some(&f.launch));
    let request = NativeModeConfirmationRequestV2 {
        command_id: command_id(),
        idempotency_key: key(&format!("mode-{revision}")),
        scope: f.scope.clone(),
        expected_authorization_revision: revision,
        requested_mode: mode,
        preset_version: PresetVersion::V1,
        expires_at_unix_ms,
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
        expires_at_unix_ms,
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
        expires_at_unix_ms,
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
    // Caller retains the SAME genuine lease; no nested sidecar acquisition.
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
