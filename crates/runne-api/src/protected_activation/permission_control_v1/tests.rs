use super::tests_support::*;
use super::*;

fn check(purpose: PermissionControlPurposeV1, payload: PermissionControlPayloadV1) {
    let ctx = context(payload.phase());
    let auth = PermissionControlAuthenticatorV1::from_protected_activation(
        &super::super::LaunchSecret::from_bytes([31; 32])
            .unwrap()
            .derive_keys(),
        purpose,
    );
    let direction = payload.direction();
    let frame = auth
        .issue_frame(ctx.clone(), 7, direction, payload.clone())
        .unwrap();
    let decoded = auth
        .authenticate_frame(&frame, &ctx, purpose, payload.phase(), direction, 6, 1_500)
        .unwrap();
    assert!(decoded.payload() == &payload);
    assert!(decoded.sequence() == 7);
    assert!(decoded.purpose() == purpose);
}

#[test]
fn round_trips_every_closed_payload_variant() {
    check(
        PermissionControlPurposeV1::ModeControl,
        PermissionControlPayloadV1::ModeRequest(PermissionControlModeRequestV1),
    );
    check(
        PermissionControlPurposeV1::ModeControl,
        PermissionControlPayloadV1::ModeChallenge(mode_challenge()),
    );
    let mode_consent = PermissionControlModeConsentV1 {
        challenge_id: [41; 16],
        public_request_digest: [10; 32],
        issued_challenge_binding_digest: [42; 32],
        native_warning_version: 1,
        requested_mode: PermissionModeSelectionV1::FullAccess,
        confirmed_binding_digest: [43; 32],
        warning_attestation: [0; 32],
        os_attestation: ModeOsAttestationV1::Fresh {
            qualified_fingerprint: [0; 32],
            authenticated_at_unix_ms: 1_500,
        },
    };
    check(
        PermissionControlPurposeV1::ModeControl,
        PermissionControlPayloadV1::ModeConsent(mode_consent),
    );
    check(
        PermissionControlPurposeV1::ManagedPolicyControl,
        PermissionControlPayloadV1::ManagedRequest(PermissionControlManagedRequestV1),
    );
    check(
        PermissionControlPurposeV1::ManagedPolicyControl,
        PermissionControlPayloadV1::ManagedChallenge(managed_challenge()),
    );
    let managed_context = context(PermissionControlPhaseV1::Consent);
    let managed_consent = PermissionControlManagedConsentV1 {
        challenge_id: [44; 16],
        public_request_digest: managed_context.public_request_digest,
        issued_challenge_binding_digest: [45; 32],
        native_warning_version: 1,
        confirmed_binding_digest: [46; 32],
        warning_attestation: [0xa5; 32],
        qualified_fingerprint: [0x5a; 32],
        authenticated_at_unix_ms: 1_500,
    };
    check(
        PermissionControlPurposeV1::ManagedPolicyControl,
        PermissionControlPayloadV1::ManagedConsent(managed_consent),
    );
    check(
        PermissionControlPurposeV1::ModeControl,
        PermissionControlPayloadV1::Cancel,
    );
    let result_context = context(PermissionControlPhaseV1::Result);
    check(
        PermissionControlPurposeV1::ModeControl,
        PermissionControlPayloadV1::Result(result(&result_context)),
    );
}

#[test]
fn zero_native_attestations_are_only_transport_authenticated() {
    let purpose = PermissionControlPurposeV1::ModeControl;
    let auth = PermissionControlAuthenticatorV1::from_protected_activation(
        &super::super::LaunchSecret::from_bytes([32; 32])
            .unwrap()
            .derive_keys(),
        purpose,
    );
    let ctx = context(PermissionControlPhaseV1::Consent);
    let consent = PermissionControlModeConsentV1 {
        challenge_id: [51; 16],
        public_request_digest: ctx.public_request_digest,
        issued_challenge_binding_digest: [52; 32],
        native_warning_version: 1,
        requested_mode: PermissionModeSelectionV1::FullAccess,
        confirmed_binding_digest: [53; 32],
        warning_attestation: [0; 32],
        os_attestation: ModeOsAttestationV1::Fresh {
            qualified_fingerprint: [0; 32],
            authenticated_at_unix_ms: 1_500,
        },
    };
    let payload = PermissionControlPayloadV1::ModeConsent(consent);
    let frame = auth
        .issue_frame(ctx.clone(), 1, payload.direction(), payload.clone())
        .unwrap();
    let received = auth
        .authenticate_frame(
            &frame,
            &ctx,
            purpose,
            PermissionControlPhaseV1::Consent,
            PermissionControlDirectionV1::DesktopToDaemon,
            0,
            1_500,
        )
        .unwrap();
    assert!(
        matches!(received.payload(), PermissionControlPayloadV1::ModeConsent(value)
        if value.warning_attestation == [0; 32]
            && matches!(&value.os_attestation, ModeOsAttestationV1::Fresh { qualified_fingerprint, .. }
                if *qualified_fingerprint == [0; 32]))
    );
    assert!(format!("{received:?}").contains("not native-verified"));
}

#[test]
fn request_refers_to_preexisting_command_and_result_echoes_identity() {
    let ctx = context(PermissionControlPhaseV1::Result);
    let value = result(&ctx);
    assert!(value.command_id == ctx.command_id);
    assert!(value.public_request_digest == ctx.public_request_digest);
    assert!(
        PermissionControlPayloadV1::ModeRequest(PermissionControlModeRequestV1).phase()
            == PermissionControlPhaseV1::Request
    );
}

#[test]
fn rejects_invalid_ids_and_nonfinite_or_extended_ttls_at_issue() {
    let endpoint = PermissionControlAuthenticatorV1::from_protected_activation(
        &super::super::LaunchSecret::from_bytes([63; 32])
            .unwrap()
            .derive_keys(),
        PermissionControlPurposeV1::ModeControl,
    );
    let payload = PermissionControlPayloadV1::ModeRequest(PermissionControlModeRequestV1);
    let mut ctx = context(PermissionControlPhaseV1::Request);
    ctx.store_lineage_id = [0; 16];
    assert!(matches!(
        endpoint.issue_frame(
            ctx,
            1,
            PermissionControlDirectionV1::DesktopToDaemon,
            payload.clone()
        ),
        Err(PermissionControlErrorV1::InvalidContract)
    ));
    let mut ctx = context(PermissionControlPhaseV1::Request);
    ctx.expires_at_unix_ms = u64::MAX;
    assert!(matches!(
        endpoint.issue_frame(
            ctx,
            1,
            PermissionControlDirectionV1::DesktopToDaemon,
            payload.clone()
        ),
        Err(PermissionControlErrorV1::InvalidContract)
    ));
    let mut ctx = context(PermissionControlPhaseV1::Request);
    ctx.expires_at_unix_ms += 120_001;
    assert!(matches!(
        endpoint.issue_frame(
            ctx,
            1,
            PermissionControlDirectionV1::DesktopToDaemon,
            payload
        ),
        Err(PermissionControlErrorV1::InvalidContract)
    ));
    let mut challenge = mode_challenge();
    challenge.challenge_id = [0; 16];
    assert!(matches!(
        endpoint.issue_frame(
            context(PermissionControlPhaseV1::Challenge),
            1,
            PermissionControlDirectionV1::DaemonToDesktop,
            PermissionControlPayloadV1::ModeChallenge(challenge)
        ),
        Err(PermissionControlErrorV1::InvalidContract)
    ));
}

#[test]
fn rejects_before_issued_and_at_exact_expiry_boundary() {
    let auth = PermissionControlAuthenticatorV1::from_protected_activation(
        &super::super::LaunchSecret::from_bytes([66; 32])
            .unwrap()
            .derive_keys(),
        PermissionControlPurposeV1::ModeControl,
    );
    let ctx = context(PermissionControlPhaseV1::Request);
    let payload = PermissionControlPayloadV1::ModeRequest(PermissionControlModeRequestV1);
    let frame = auth
        .issue_frame(ctx.clone(), 1, payload.direction(), payload)
        .unwrap();
    for now in [999, 2_000] {
        assert!(matches!(
            auth.authenticate_frame(
                &frame,
                &ctx,
                auth.purpose(),
                PermissionControlPhaseV1::Request,
                PermissionControlDirectionV1::DesktopToDaemon,
                0,
                now
            ),
            Err(PermissionControlErrorV1::Expired)
        ));
    }
}

#[test]
fn mode_and_managed_consents_are_key_purpose_separated() {
    let keys = super::super::LaunchSecret::from_bytes([67; 32])
        .unwrap()
        .derive_keys();
    let mode = PermissionControlAuthenticatorV1::from_protected_activation(
        &keys,
        PermissionControlPurposeV1::ModeControl,
    );
    let managed = PermissionControlAuthenticatorV1::from_protected_activation(
        &keys,
        PermissionControlPurposeV1::ManagedPolicyControl,
    );
    let ctx = context(PermissionControlPhaseV1::Consent);
    let consent = PermissionControlModeConsentV1 {
        challenge_id: [71; 16],
        public_request_digest: ctx.public_request_digest,
        issued_challenge_binding_digest: [72; 32],
        native_warning_version: 1,
        requested_mode: PermissionModeSelectionV1::AskAlways,
        confirmed_binding_digest: [73; 32],
        warning_attestation: [74; 32],
        os_attestation: ModeOsAttestationV1::NotRequired,
    };
    let frame = mode
        .issue_frame(
            ctx.clone(),
            1,
            PermissionControlDirectionV1::DesktopToDaemon,
            PermissionControlPayloadV1::ModeConsent(consent),
        )
        .unwrap();
    assert!(matches!(
        managed.authenticate_frame(
            &frame,
            &ctx,
            managed.purpose(),
            PermissionControlPhaseV1::Consent,
            PermissionControlDirectionV1::DesktopToDaemon,
            0,
            1_500
        ),
        Err(PermissionControlErrorV1::AuthenticationFailed)
    ));
}

#[test]
fn bounds_authority_and_idempotency_utf8_lengths_at_256_bytes() {
    let auth = PermissionControlAuthenticatorV1::from_protected_activation(
        &super::super::LaunchSecret::from_bytes([69; 32])
            .unwrap()
            .derive_keys(),
        PermissionControlPurposeV1::ModeControl,
    );
    for length in [256, 257] {
        let mut ctx = context(PermissionControlPhaseV1::Request);
        ctx.runtime_authority = "a".repeat(length);
        let payload = PermissionControlPayloadV1::ModeRequest(PermissionControlModeRequestV1);
        let result = auth.issue_frame(ctx.clone(), 1, payload.direction(), payload.clone());
        assert_eq!(result.is_ok(), length == 256);
        ctx = context(PermissionControlPhaseV1::Request);
        ctx.idempotency_key = "k".repeat(length);
        let result = auth.issue_frame(ctx, 1, payload.direction(), payload);
        assert_eq!(result.is_ok(), length == 256);
    }
}
