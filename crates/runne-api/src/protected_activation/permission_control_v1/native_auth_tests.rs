use super::*;

fn context() -> PermissionControlContextV1 {
    let mut context =
        super::super::tests_support::context(super::super::PermissionControlPhaseV1::Consent);
    context.native_key_epoch = 1;
    context
}

fn consent() -> PermissionControlModeConsentV1 {
    PermissionControlModeConsentV1 {
        challenge_id: [15; 16],
        public_request_digest: [10; 32],
        issued_challenge_binding_digest: [14; 32],
        native_warning_version: 1,
        requested_mode: super::super::PermissionModeSelectionV1::FullAccess,
        confirmed_binding_digest: [12; 32],
        warning_attestation: [0; 32],
        os_attestation: super::super::ModeOsAttestationV1::Fresh {
            qualified_fingerprint: [13; 32],
            authenticated_at_unix_ms: 1_500,
        },
    }
}

#[test]
fn fixed_purpose_authenticator_binds_full_transcript_and_key_owner() {
    let first = crate::LaunchSecret::from_bytes([31; 32])
        .unwrap()
        .derive_keys();
    let same = crate::LaunchSecret::from_bytes([31; 32])
        .unwrap()
        .derive_keys();
    let rotated = crate::LaunchSecret::from_bytes([32; 32])
        .unwrap()
        .derive_keys();
    let signer = first.permission_control_native_authenticator();
    let verifier = same.permission_control_native_authenticator();
    let replacement = rotated.permission_control_native_authenticator();
    assert!(signer.has_same_key_identity(&verifier));
    assert!(!signer.has_same_key_identity(&replacement));

    let context = context();
    let mut consent = consent();
    consent.warning_attestation = signer
        .authenticate_mode_consent(&context, &consent)
        .unwrap();
    assert!(verifier.verify_mode_consent(&context, &consent).is_ok());
    assert!(replacement.verify_mode_consent(&context, &consent).is_err());
    let mut other_epoch = context.clone();
    other_epoch.native_key_epoch += 1;
    assert!(
        verifier
            .verify_mode_consent(&other_epoch, &consent)
            .is_err()
    );
    assert_eq!(
        format!("{signer:?}"),
        "PermissionControlNativeAuthenticatorV1(<redacted>)"
    );
}

#[test]
fn fixed_purpose_authenticator_rejects_missing_full_access_pam_facts() {
    let keys = crate::LaunchSecret::from_bytes([41; 32])
        .unwrap()
        .derive_keys();
    let authenticator = keys.permission_control_native_authenticator();
    let mut consent = consent();
    consent.os_attestation = super::super::ModeOsAttestationV1::NotRequired;
    assert!(
        authenticator
            .authenticate_mode_consent(&context(), &consent)
            .is_err()
    );
}

#[test]
fn verified_key_replacement_advances_epoch_even_when_fingerprint_repeats() {
    let previous = crate::LaunchSecret::from_bytes([51; 32])
        .unwrap()
        .derive_keys();
    let mut replacement = crate::LaunchSecret::from_bytes([52; 32])
        .unwrap()
        .derive_keys();
    assert_eq!(
        previous
            .permission_control_native_authenticator()
            .native_key_epoch(),
        1
    );
    assert_eq!(
        replacement
            .permission_control_native_authenticator()
            .native_key_epoch(),
        1
    );

    replacement
        .advance_native_key_epoch_from(&previous)
        .unwrap();
    let replacement_auth = replacement.permission_control_native_authenticator();
    assert_eq!(replacement_auth.native_key_epoch(), 2);
    let mut stale_context = context();
    assert!(
        replacement_auth
            .authenticate_mode_consent(&stale_context, &consent())
            .is_err()
    );
    stale_context.native_key_epoch = replacement_auth.native_key_epoch();
    assert!(
        replacement_auth
            .authenticate_mode_consent(&stale_context, &consent())
            .is_ok()
    );
    assert_eq!(
        previous
            .permission_control_native_authenticator()
            .native_key_epoch(),
        1
    );

    let mut same_key = crate::LaunchSecret::from_bytes([51; 32])
        .unwrap()
        .derive_keys();
    same_key.advance_native_key_epoch_from(&previous).unwrap();
    let same_key_auth = same_key.permission_control_native_authenticator();
    assert_eq!(same_key_auth.native_key_epoch(), 2);
    assert!(
        same_key_auth
            .authenticate_mode_consent(&context(), &consent())
            .is_err()
    );
}
