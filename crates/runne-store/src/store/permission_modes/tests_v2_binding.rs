use runne_application::permission_modes::{
    EffectiveModeHistoryState, FullAccessChallengeBinding, NativeChallengeError,
    NativeChallengeVerifier, NativeModeConfirmationBindingV2, NativeModeConfirmationError,
    NativeModeConfirmationVerifierV2, NetworkState, NotReadyReason, PermissionMode,
    PermissionModeError, PermissionModeHistoryProjection, SetPermissionModeCommand,
    VerifiedNativeModeConfirmationV2, verify_full_access_challenge,
    verify_native_mode_confirmation_v2,
};
use runne_domain::id::IntegrityDigest;

use super::begin;
use super::support::{Fixture, Storage};
use crate::store::permission_modes::model::{
    IssuedNativeModeConfirmationV2, NativeModeConfirmationRequestV2,
    PermissionModeCeremonyStatusV2, PermissionModeStoreError, ProtectedNativeLaunchContext,
};

const ROTATED_SESSION: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52,
];

pub(super) fn verified_v2(
    issued: &IssuedNativeModeConfirmationV2,
) -> VerifiedNativeModeConfirmationV2 {
    verify_native_mode_confirmation_v2(
        issued.binding(),
        b"fixture native proof",
        unix_ms(),
        &EchoV2,
    )
    .unwrap()
}

pub(super) fn command_and_proof(
    request: &NativeModeConfirmationRequestV2,
    issued: &IssuedNativeModeConfirmationV2,
) -> (SetPermissionModeCommand, VerifiedNativeModeConfirmationV2) {
    let full_access = request.requested_mode == PermissionMode::FullAccess;
    let mut command = SetPermissionModeCommand {
        command_id: request.command_id,
        scope: request.scope.clone(),
        expected_authorization_revision: request.expected_authorization_revision,
        requested_mode: request.requested_mode,
        preset_version: request.preset_version,
        intent_digest: IntegrityDigest::from_bytes([0; 32]),
        idempotency_key: request.idempotency_key.clone(),
        expires_at_unix_ms: request.expires_at_unix_ms,
        managed_policy_version: issued.binding().managed_policy_version,
        managed_policy_digest: issued.binding().managed_policy_digest,
        challenge_binding_digest: full_access.then_some(issued.binding().challenge_binding_digest),
        challenge_expires_at_unix_ms: full_access
            .then_some(issued.binding().challenge_expires_at_unix_ms),
        verified_native_challenge: None,
    };
    command.intent_digest = command.computed_intent_digest();
    if full_access {
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
            challenge_binding_digest: command.challenge_binding_digest.unwrap(),
            expires_at_unix_ms: command.expires_at_unix_ms,
            challenge_expires_at_unix_ms: command.challenge_expires_at_unix_ms.unwrap(),
        };
        command.verified_native_challenge = Some(
            verify_full_access_challenge(&binding, b"fixture legacy proof", unix_ms(), &EchoLegacy)
                .unwrap(),
        );
    }
    (command, verified_v2(issued))
}

pub(super) fn history(command: &SetPermissionModeCommand) -> PermissionModeHistoryProjection {
    PermissionModeHistoryProjection {
        selected_mode: command.requested_mode,
        effective: EffectiveModeHistoryState::NotReady(NotReadyReason::NativeContainment),
        authorization_revision: command.expected_authorization_revision + 1,
        preset_version: command.preset_version,
        managed_policy_version: command.managed_policy_version,
        containment: None,
        network_state: NetworkState::Unavailable,
        expires_at_unix_ms: command.expires_at_unix_ms,
    }
}

#[test]
fn session_rotation_changes_only_the_issued_proof_binding() {
    let fixture = Fixture::new(super::support::Storage::Memory);
    let request = fixture.request(PermissionMode::RiskBased, "session-digest");
    let issued = begin(&fixture, request.clone());
    let mut rotated = issued.binding().clone();
    rotated.protected_session_id = ROTATED_SESSION;
    assert_eq!(
        rotated.public_request_digest,
        request.public_request_digest()
    );
    assert_eq!(
        rotated.computed_public_request_digest(),
        request.public_request_digest()
    );
    assert_ne!(rotated.digest(), issued.binding().digest());

    let original_proof = verified_v2(&issued);
    let rotated_proof =
        verify_native_mode_confirmation_v2(&rotated, b"fixture native proof", unix_ms(), &EchoV2)
            .unwrap();
    assert_ne!(
        original_proof.binding_digest(),
        rotated_proof.binding_digest()
    );
    rotated.protected_session_id = [0; 16];
    assert!(
        verify_native_mode_confirmation_v2(&rotated, b"fixture native proof", unix_ms(), &EchoV2,)
            .is_err()
    );
}

#[test]
fn semantic_conflicts_and_wrong_principal_or_scope_fail_closed() {
    let fixture = Fixture::new(Storage::Memory);
    let request = fixture.request(PermissionMode::RiskBased, "semantic-conflict");
    let issued = begin(&fixture, request.clone());
    let conflicts = [
        NativeModeConfirmationRequestV2 {
            idempotency_key: runne_domain::id::IdempotencyKey::new("changed-key").unwrap(),
            ..request.clone()
        },
        NativeModeConfirmationRequestV2 {
            requested_mode: PermissionMode::AskAlways,
            ..request.clone()
        },
        NativeModeConfirmationRequestV2 {
            expected_authorization_revision: 1,
            ..request.clone()
        },
        NativeModeConfirmationRequestV2 {
            expires_at_unix_ms: Some(unix_ms() + 1000),
            ..request.clone()
        },
        NativeModeConfirmationRequestV2 {
            scope: runne_application::permission_modes::PermissionScope {
                workspace_id: "018f2e3a-7000-7000-8000-000000000043".parse().unwrap(),
                ..request.scope.clone()
            },
            ..request.clone()
        },
        NativeModeConfirmationRequestV2 {
            command_id: runne_domain::id::CommandId::from_bytes(uuid::Uuid::now_v7().into_bytes()),
            ..request.clone()
        },
    ];
    for changed in conflicts {
        assert!(matches!(
            fixture
                .store()
                .begin_permission_mode_confirmation_v2(changed, &fixture.authority()),
            Err(PermissionModeStoreError::Command(
                PermissionModeError::IdempotencyConflict
            ))
        ));
    }
    assert_eq!(
        fixture
            .store()
            .begin_permission_mode_confirmation_v2(request, &fixture.authority())
            .unwrap(),
        PermissionModeCeremonyStatusV2::Pending(issued.clone()),
    );
    let wrong_principal = runne_api::ApiPrincipalId::new("other-principal").unwrap();
    let scope = runne_application::permission_modes::PermissionScope {
        principal_id: wrong_principal.clone(),
        ..fixture.scope.clone()
    };
    assert!(matches!(
        fixture.store().load_permission_mode_confirmation_status_v2(
            &scope,
            &wrong_principal,
            issued.binding().command_id,
        ),
        Err(PermissionModeStoreError::AuthorityMismatch)
    ));
    let workspace: runne_domain::id::WorkspaceId =
        "018f2e3a-7000-7000-8000-000000000043".parse().unwrap();
    let scope = runne_application::permission_modes::PermissionScope {
        workspace_id: workspace,
        ..fixture.scope.clone()
    };
    assert!(matches!(
        fixture.store().load_permission_mode_confirmation_status_v2(
            &scope,
            &fixture.principal,
            issued.binding().command_id,
        ),
        Err(PermissionModeStoreError::AuthorityMismatch)
    ));
}

#[test]
fn v2_issue_requires_explicit_session_but_legacy_constructor_stays_sessionless() {
    let fixture = Fixture::new(Storage::Memory);
    let legacy =
        ProtectedNativeLaunchContext::new([0x61; 16], [0x62; 16], [0x63; 16], 7, 9).unwrap();
    assert_eq!(legacy.protected_session_id(), None);
    assert!(matches!(
        fixture.store().begin_permission_mode_confirmation_v2(
            fixture.request(PermissionMode::RiskBased, "missing-session"),
            &fixture.authority_with(Some(&legacy)),
        ),
        Err(PermissionModeStoreError::ReauthenticationUnavailable)
    ));
}

#[test]
fn issued_confirmation_debug_redacts_the_native_nonce() {
    let fixture = Fixture::new(Storage::Memory);
    let request = fixture.request(PermissionMode::RiskBased, "nonce-redaction");
    let issued = begin(&fixture, request);
    let rendered = format!("{issued:?}");
    assert!(rendered.contains("nonce: \"<redacted>\""));
    assert!(!rendered.contains(&super::hex(issued.nonce_for_native_signing())));
}

// Test-only verifier fixtures, not production proof authorities.
struct EchoV2;
impl NativeModeConfirmationVerifierV2 for EchoV2 {
    fn verify(
        &self,
        binding: &NativeModeConfirmationBindingV2,
        _: &[u8],
    ) -> Result<IntegrityDigest, NativeModeConfirmationError> {
        Ok(binding.challenge_binding_digest)
    }
}

// Test-only verifier fixtures, not production proof authorities.
struct EchoLegacy;
impl NativeChallengeVerifier for EchoLegacy {
    fn verify(
        &self,
        binding: &FullAccessChallengeBinding,
        _: &[u8],
    ) -> Result<IntegrityDigest, NativeChallengeError> {
        Ok(binding.challenge_binding_digest)
    }
}

fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

impl Fixture {
    pub(super) fn reopen(&mut self) {
        assert_ne!(self.db_path, std::path::PathBuf::from(":memory:"));
        drop(self.store.take());
        self.store = Some(
            crate::store::StoreTransaction::open(
                self.db_path.to_str().unwrap(),
                self.scope.runtime_authority_id.clone(),
                std::sync::Arc::new(runne_security::SecretBroker::new().prohibited_content_guard()),
            )
            .unwrap(),
        );
    }
}
