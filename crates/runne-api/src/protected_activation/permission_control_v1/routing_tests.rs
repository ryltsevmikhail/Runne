use super::tests_support::*;
use super::*;

#[test]
fn mode_routing_hint_requires_mac_and_returns_only_the_command_address() {
    let auth = PermissionControlAuthenticatorV1::from_protected_activation(
        &super::super::LaunchSecret::from_bytes([31; 32])
            .unwrap()
            .derive_keys(),
        PermissionControlPurposeV1::ModeControl,
    );
    let expected = context(PermissionControlPhaseV1::Request);
    let frame = auth
        .issue_frame(
            expected.clone(),
            7,
            PermissionControlDirectionV1::DesktopToDaemon,
            PermissionControlPayloadV1::ModeRequest(PermissionControlModeRequestV1),
        )
        .unwrap();
    let hint = auth.mode_request_routing_hint(&frame, 6, 1_500).unwrap();
    assert_eq!(hint.command_id().as_bytes(), &expected.command_id);

    let mut tampered = frame;
    tampered[20] ^= 1;
    assert_eq!(
        auth.mode_request_routing_hint(&tampered, 6, 1_500),
        Err(PermissionControlErrorV1::AuthenticationFailed)
    );
}

#[test]
fn routing_hint_rejects_non_request_phases_and_stale_or_replayed_sequences() {
    let auth = PermissionControlAuthenticatorV1::from_protected_activation(
        &super::super::LaunchSecret::from_bytes([32; 32])
            .unwrap()
            .derive_keys(),
        PermissionControlPurposeV1::ModeControl,
    );
    let frame = auth
        .issue_frame(
            context(PermissionControlPhaseV1::Challenge),
            99,
            PermissionControlDirectionV1::DaemonToDesktop,
            PermissionControlPayloadV1::ModeChallenge(mode_challenge()),
        )
        .unwrap();
    assert_eq!(
        auth.mode_request_routing_hint(&frame, 0, 1_500),
        Err(PermissionControlErrorV1::PhaseMismatch)
    );

    let request = auth
        .issue_frame(
            context(PermissionControlPhaseV1::Request),
            7,
            PermissionControlDirectionV1::DesktopToDaemon,
            PermissionControlPayloadV1::ModeRequest(PermissionControlModeRequestV1),
        )
        .unwrap();
    assert_eq!(
        auth.mode_request_routing_hint(&request, 5, 1_500),
        Err(PermissionControlErrorV1::SequenceMismatch)
    );
    assert_eq!(
        auth.mode_request_routing_hint(&request, 7, 1_500),
        Err(PermissionControlErrorV1::SequenceMismatch)
    );
    assert!(auth.mode_request_routing_hint(&request, 6, 1_500).is_ok());
}

#[test]
fn consent_and_cancel_routing_hints_require_the_next_mac_verified_mode_sequence() {
    let auth = PermissionControlAuthenticatorV1::from_protected_activation(
        &super::super::LaunchSecret::from_bytes([33; 32])
            .unwrap()
            .derive_keys(),
        PermissionControlPurposeV1::ModeControl,
    );
    let consent_context = context(PermissionControlPhaseV1::Consent);
    let consent = auth
        .issue_frame(
            consent_context.clone(),
            12,
            PermissionControlDirectionV1::DesktopToDaemon,
            PermissionControlPayloadV1::ModeConsent(PermissionControlModeConsentV1 {
                challenge_id: [34; 16],
                public_request_digest: consent_context.public_request_digest,
                issued_challenge_binding_digest: [35; 32],
                native_warning_version: 1,
                requested_mode: PermissionModeSelectionV1::FullAccess,
                confirmed_binding_digest: [36; 32],
                warning_attestation: [37; 32],
                os_attestation: ModeOsAttestationV1::Fresh {
                    qualified_fingerprint: [38; 32],
                    authenticated_at_unix_ms: 1_500,
                },
            }),
        )
        .unwrap();
    assert_eq!(
        auth.mode_consent_routing_hint(&consent, 11, 1_600)
            .unwrap()
            .command_id()
            .as_bytes(),
        &consent_context.command_id
    );
    assert_eq!(
        auth.mode_consent_routing_hint(&consent, 10, 1_600),
        Err(PermissionControlErrorV1::SequenceMismatch)
    );

    let cancel_context = context(PermissionControlPhaseV1::Cancel);
    let cancel = auth
        .issue_frame(
            cancel_context.clone(),
            12,
            PermissionControlDirectionV1::DesktopToDaemon,
            PermissionControlPayloadV1::Cancel,
        )
        .unwrap();
    assert_eq!(
        auth.mode_cancel_routing_hint(&cancel, 11, 1_600)
            .unwrap()
            .command_id()
            .as_bytes(),
        &cancel_context.command_id
    );
    assert_eq!(
        auth.mode_request_routing_hint(&cancel, 11, 1_600),
        Err(PermissionControlErrorV1::PhaseMismatch)
    );
}
