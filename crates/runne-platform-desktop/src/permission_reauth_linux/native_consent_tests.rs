use super::*;
use runne_api::PermissionModeSelectionV1;

fn fixture(expiry: u64) -> (PermissionControlModeChallengeV1, PermissionControlContextV1) {
    let context = PermissionControlContextV1 {
        runtime_authority: "runtime".to_owned(),
        store_lineage_id: [1; 16],
        stable_subject_digest: [2; 32],
        protected_launch_authority_id: [3; 16],
        desktop_authority_id: [4; 16],
        daemon_instance_id: [5; 16],
        protected_session_id: [6; 16],
        launch_generation: 7,
        native_key_epoch: 8,
        command_id: [9; 16],
        idempotency_key: "mode-change".to_owned(),
        public_request_digest: [10; 32],
        predecessor_transcript_digest: [11; 32],
        issued_at_unix_ms: 100,
        expires_at_unix_ms: expiry,
    };
    let challenge = PermissionControlModeChallengeV1 {
        principal: "principal".to_owned(),
        workspace_id: [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 12],
        workspace_label: "Shared workspace".to_owned(),
        expected_authorization_revision: 1,
        requested_mode: PermissionModeSelectionV1::RiskBased,
        preset_version: 1,
        mode_expires_at_unix_ms: None,
        managed_policy_revision: 2,
        managed_policy_digest: [13; 32],
        issued_challenge_binding_digest: [14; 32],
        ceremony_expires_at_unix_ms: expiry,
        native_warning_version: 1,
        challenge_id: [15; 16],
        nonce: [16; 32],
    };
    (challenge, context)
}

#[test]
fn only_current_native_continue_creates_a_mode_bound_one_use_token() {
    let (challenge, context) = fixture(900);
    let digest = native_confirmation_binding_digest(&context, &challenge).unwrap();
    let token = confirmation_for_response(
        gtk::ResponseType::Accept,
        &challenge,
        &context,
        digest,
        Some(200),
    )
    .expect("Continue before expiry creates the opaque token");
    assert!(token.matches_exchange(&context, &challenge, digest, 201));
    assert!(!token.matches_exchange(&context, &challenge, [21; 32], 201));
    let mut other_session = context.clone();
    other_session.protected_session_id[0] ^= 1;
    let other_digest = native_confirmation_binding_digest(&other_session, &challenge).unwrap();
    assert!(!token.matches_exchange(&other_session, &challenge, other_digest, 201));
    let mut other_challenge = challenge.clone();
    other_challenge.challenge_id[0] ^= 1;
    assert!(!token.matches_exchange(&context, &other_challenge, digest, 201));
    let mut altered = challenge;
    altered.requested_mode = PermissionModeSelectionV1::FullAccess;
    assert!(!token.matches_exchange(&context, &altered, digest, 201));
}

#[test]
fn cancel_close_and_expired_continue_create_no_token() {
    let (challenge, context) = fixture(900);
    for response in [gtk::ResponseType::Cancel, gtk::ResponseType::DeleteEvent] {
        assert!(
            confirmation_for_response(response, &challenge, &context, [20; 32], Some(200))
                .is_none()
        );
    }
    assert!(
        confirmation_for_response(
            gtk::ResponseType::Accept,
            &challenge,
            &context,
            [20; 32],
            Some(900),
        )
        .is_none()
    );
}

#[test]
fn warning_subject_displays_the_verified_challenge_identity_and_expiry() {
    let (challenge, _) = fixture(900);
    let message = warning_message(&challenge);

    assert!(message.contains("Workspace: Shared workspace"));
    assert!(message.contains(&format!(
        "Workspace ID: {}",
        uuid::Uuid::from_bytes(challenge.workspace_id)
    )));
    assert!(message.contains("Principal: principal"));
    assert!(message.contains("Requested mode: Risk-based"));
    assert!(message.contains("Mode expiry: never"));
}

#[test]
fn warning_subject_changes_with_workspace_id_principal_and_mode_expiry() {
    let (challenge, _) = fixture(900);
    let baseline = warning_message(&challenge);

    let mut same_label_other_workspace = challenge.clone();
    same_label_other_workspace.workspace_id[15] ^= 1;
    assert_eq!(
        same_label_other_workspace.workspace_label,
        challenge.workspace_label
    );
    assert_ne!(warning_message(&same_label_other_workspace), baseline);

    let mut other_principal = challenge.clone();
    other_principal.principal = "other-principal".to_owned();
    assert_ne!(warning_message(&other_principal), baseline);

    let mut other_mode = challenge.clone();
    other_mode.requested_mode = PermissionModeSelectionV1::AskAlways;
    assert_ne!(warning_message(&other_mode), baseline);

    let mut expiring_mode = challenge;
    expiring_mode.mode_expires_at_unix_ms = Some(1_234);
    let expiring_message = warning_message(&expiring_mode);
    assert!(expiring_message.contains("Mode expiry: 1970-01-01 00:00:01.234 UTC"));
    assert_ne!(expiring_message, baseline);
}

#[test]
fn warning_subject_sanitizes_control_characters_as_plain_text() {
    let (mut challenge, _) = fixture(900);
    challenge.workspace_label = "Shared\u{001b}<b> workspace</b>".to_owned();
    challenge.principal = "principal\u{202e}".to_owned();
    let message = warning_message(&challenge);

    assert!(!message.contains('\u{001b}'));
    assert!(!message.contains('\u{202e}'));
    assert!(message.contains("Workspace: Shared <b> workspace</b>"));
}

struct DropTask;

impl NativePermissionWarningMainThreadScheduler for DropTask {
    fn schedule(&self, task: NativePermissionWarningUiTask) -> Result<(), ()> {
        drop(task);
        Ok(())
    }
}

struct CancelTask;

impl NativePermissionWarningMainThreadScheduler for CancelTask {
    fn schedule(&self, task: NativePermissionWarningUiTask) -> Result<(), ()> {
        task.cancel();
        Ok(())
    }
}

#[test]
fn dropped_or_cancelled_dispatch_never_returns_confirmation() {
    let (challenge, context) = fixture(unix_millis().unwrap() + 2_000);
    assert!(matches!(
        request_native_permission_warning(&challenge, &context, &DropTask),
        Err(LinuxReauthenticationError::NativeWarningRejected)
    ));
    assert!(matches!(
        request_native_permission_warning(&challenge, &context, &CancelTask),
        Err(LinuxReauthenticationError::NativeWarningRejected)
    ));
}

#[test]
fn already_expired_warning_is_rejected_before_dispatch() {
    let (challenge, context) = fixture(0);
    assert!(matches!(
        request_native_permission_warning(&challenge, &context, &CancelTask),
        Err(LinuxReauthenticationError::Expired)
    ));
}
