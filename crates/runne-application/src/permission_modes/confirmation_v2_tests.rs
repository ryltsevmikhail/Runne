use runne_domain::id::{CommandId, IdempotencyKey, IntegrityDigest, WorkspaceId};

use super::*;

struct EchoVerifier;

impl NativeModeConfirmationVerifierV2 for EchoVerifier {
    fn verify(
        &self,
        binding: &NativeModeConfirmationBindingV2,
        _proof_bytes: &[u8],
    ) -> Result<IntegrityDigest, NativeModeConfirmationError> {
        Ok(binding.challenge_binding_digest)
    }
}

#[test]
fn public_request_v2_digest_separates_fields_mode_and_expiry_option() {
    let base = binding(PermissionMode::AskAlways, None);
    let mut shifted_fields = base.clone();
    shifted_fields.scope.runtime_authority_id = crate::ports::RuntimeAuthorityId("ab".into());
    shifted_fields.scope.principal_id = runne_api::ApiPrincipalId::new("c").unwrap();
    assert_ne!(
        base.computed_public_request_digest(),
        shifted_fields.computed_public_request_digest()
    );

    let explicit_zero = binding(PermissionMode::AskAlways, Some(0));
    assert_ne!(
        base.computed_public_request_digest(),
        explicit_zero.computed_public_request_digest()
    );
    let different_mode = binding(PermissionMode::RiskBased, None);
    assert_ne!(
        base.computed_public_request_digest(),
        different_mode.computed_public_request_digest()
    );
}

#[test]
fn v2_native_confirmation_verifies_all_modes_and_returns_opaque_proof() {
    for mode in [
        PermissionMode::AskAlways,
        PermissionMode::RiskBased,
        PermissionMode::FullAccess,
    ] {
        let binding = binding(mode, Some(900));
        let proof = verify_native_mode_confirmation_v2(
            &binding,
            b"opaque-native-proof",
            100,
            &EchoVerifier,
        )
        .unwrap();
        assert_eq!(proof.binding_digest(), binding.digest());
        assert_eq!(proof.proof_identifier(), binding.challenge_binding_digest);
    }
}

#[test]
fn v2_confirmation_rejects_expiry_boundary_and_changed_request_fields() {
    let binding = binding(PermissionMode::AskAlways, None);
    assert_eq!(
        verify_native_mode_confirmation_v2(&binding, b"proof", 500, &EchoVerifier),
        Err(NativeModeConfirmationError::Rejected)
    );

    let mut changed = binding.clone();
    changed.requested_mode = PermissionMode::RiskBased;
    assert_eq!(
        verify_native_mode_confirmation_v2(&changed, b"proof", 100, &EchoVerifier),
        Err(NativeModeConfirmationError::Rejected)
    );
}

#[test]
fn v2_issued_binding_changes_with_session_while_public_request_stays_stable() {
    let binding = binding(PermissionMode::AskAlways, None);
    let proof = verify_native_mode_confirmation_v2(&binding, b"proof", 100, &EchoVerifier).unwrap();
    let mut rotated = binding.clone();
    rotated.protected_session_id[15] ^= 1;

    assert_eq!(
        rotated.computed_public_request_digest(),
        binding.computed_public_request_digest()
    );
    assert_ne!(rotated.digest(), binding.digest());
    assert_ne!(proof.binding_digest(), rotated.digest());

    let mut malformed = binding;
    malformed.protected_session_id = [0; 16];
    assert_eq!(
        verify_native_mode_confirmation_v2(&malformed, b"proof", 100, &EchoVerifier),
        Err(NativeModeConfirmationError::Rejected)
    );
}

fn binding(
    requested_mode: PermissionMode,
    expires_at_unix_ms: Option<i64>,
) -> NativeModeConfirmationBindingV2 {
    let command_id = CommandId::from_bytes([1; 16]);
    let idempotency_key = IdempotencyKey::new("mode-change-1").unwrap();
    let scope = PermissionScope {
        runtime_authority_id: crate::ports::RuntimeAuthorityId("authority".into()),
        principal_id: runne_api::ApiPrincipalId::new("principal").unwrap(),
        workspace_id: WorkspaceId::from_bytes([2; 16]),
    };
    let expected_authorization_revision = 7;
    let preset_version = PresetVersion::V1;
    let public_request_digest = native_mode_public_request_digest_v2(
        command_id,
        &idempotency_key,
        &scope,
        expected_authorization_revision,
        requested_mode,
        preset_version,
        expires_at_unix_ms,
    );
    NativeModeConfirmationBindingV2 {
        command_id,
        idempotency_key,
        scope,
        expected_authorization_revision,
        requested_mode,
        preset_version,
        public_request_digest,
        managed_policy_version: 1,
        managed_policy_digest: IntegrityDigest::from_bytes([0x41; 32]),
        challenge_binding_digest: IntegrityDigest::from_bytes([3; 32]),
        protected_session_id: [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ],
        expires_at_unix_ms,
        challenge_expires_at_unix_ms: 500,
        native_warning_version: 1,
    }
}
