use super::tests_support::*;
use super::*;

fn auth(seed: u8, purpose: PermissionControlPurposeV1) -> PermissionControlAuthenticatorV1 {
    PermissionControlAuthenticatorV1::from_protected_activation(
        &super::super::LaunchSecret::from_bytes([seed; 32])
            .unwrap()
            .derive_keys(),
        purpose,
    )
}
fn request_frame(auth: &PermissionControlAuthenticatorV1) -> (PermissionControlContextV1, Vec<u8>) {
    let ctx = context(PermissionControlPhaseV1::Request);
    let payload = PermissionControlPayloadV1::ModeRequest(PermissionControlModeRequestV1);
    let frame = auth
        .issue_frame(
            ctx.clone(),
            1,
            PermissionControlDirectionV1::DesktopToDaemon,
            payload,
        )
        .unwrap();
    (ctx, frame)
}
#[allow(clippy::too_many_arguments)]
fn expect_error(
    frame: &[u8],
    auth: &PermissionControlAuthenticatorV1,
    ctx: &PermissionControlContextV1,
    phase: PermissionControlPhaseV1,
    direction: PermissionControlDirectionV1,
    prev: u64,
    now: u64,
    error: PermissionControlErrorV1,
) {
    let result = auth.authenticate_frame(frame, ctx, auth.purpose(), phase, direction, prev, now);
    assert!(matches!(result, Err(actual) if actual == error));
}

#[test]
fn bounds_prefix_truncation_and_oversize_before_decode() {
    let endpoint = auth(61, PermissionControlPurposeV1::ModeControl);
    let (ctx, frame) = request_frame(&endpoint);
    let decode = |input: &[u8]| {
        endpoint.authenticate_frame(
            input,
            &ctx,
            endpoint.purpose(),
            PermissionControlPhaseV1::Request,
            PermissionControlDirectionV1::DesktopToDaemon,
            0,
            1_500,
        )
    };
    assert!(matches!(
        decode(&frame[..frame.len() - 1]),
        Err(PermissionControlErrorV1::MalformedFrame)
    ));
    let mut bad_prefix = frame.clone();
    bad_prefix[3] = bad_prefix[3].wrapping_add(1);
    assert!(matches!(
        decode(&bad_prefix),
        Err(PermissionControlErrorV1::MalformedFrame)
    ));
    assert!(matches!(
        decode(&vec![0; 8_193]),
        Err(PermissionControlErrorV1::MalformedFrame)
    ));
}

#[test]
fn rejects_noncanonical_utf8_tags_versions_options_and_trailing_bytes() {
    let endpoint = auth(62, PermissionControlPurposeV1::ModeControl);
    let (ctx, original) = request_frame(&endpoint);
    let mut invalid_utf8 = original.clone();
    invalid_utf8[25] = 0xff;
    resign(&endpoint, &mut invalid_utf8);
    expect_error(
        &invalid_utf8,
        &endpoint,
        &ctx,
        PermissionControlPhaseV1::Request,
        PermissionControlDirectionV1::DesktopToDaemon,
        0,
        1_500,
        PermissionControlErrorV1::MalformedFrame,
    );
    let mut bad_version = original.clone();
    bad_version[12] = 2;
    resign(&endpoint, &mut bad_version);
    expect_error(
        &bad_version,
        &endpoint,
        &ctx,
        PermissionControlPhaseV1::Request,
        PermissionControlDirectionV1::DesktopToDaemon,
        0,
        1_500,
        PermissionControlErrorV1::MalformedFrame,
    );
    let mut bad_tag = original.clone();
    bad_tag[payload_tag_offset(&ctx)] = 0xfe;
    resign(&endpoint, &mut bad_tag);
    expect_error(
        &bad_tag,
        &endpoint,
        &ctx,
        PermissionControlPhaseV1::Request,
        PermissionControlDirectionV1::DesktopToDaemon,
        0,
        1_500,
        PermissionControlErrorV1::MalformedFrame,
    );
    let mut trailing = original.clone();
    let mac_at = trailing.len() - 32;
    trailing.insert(mac_at, 0);
    let len = trailing.len() as u32;
    trailing[..4].copy_from_slice(&len.to_be_bytes());
    resign(&endpoint, &mut trailing);
    expect_error(
        &trailing,
        &endpoint,
        &ctx,
        PermissionControlPhaseV1::Request,
        PermissionControlDirectionV1::DesktopToDaemon,
        0,
        1_500,
        PermissionControlErrorV1::MalformedFrame,
    );

    let challenge = PermissionControlPayloadV1::ModeChallenge(mode_challenge());
    let challenge_ctx = context(PermissionControlPhaseV1::Challenge);
    let mut challenge_frame = endpoint
        .issue_frame(challenge_ctx.clone(), 2, challenge.direction(), challenge)
        .unwrap();
    let tag = payload_tag_offset(&challenge_ctx);
    let mode_tag = tag + 1 + 2 + "local-user".len() + 16 + 2 + "Example workspace".len() + 8;
    challenge_frame[mode_tag] = 9;
    resign(&endpoint, &mut challenge_frame);
    expect_error(
        &challenge_frame,
        &endpoint,
        &challenge_ctx,
        PermissionControlPhaseV1::Challenge,
        PermissionControlDirectionV1::DaemonToDesktop,
        1,
        1_500,
        PermissionControlErrorV1::MalformedFrame,
    );
    let challenge = PermissionControlPayloadV1::ModeChallenge(mode_challenge());
    let mut option_frame = endpoint
        .issue_frame(challenge_ctx.clone(), 2, challenge.direction(), challenge)
        .unwrap();
    option_frame[mode_tag + 3] = 2;
    resign(&endpoint, &mut option_frame);
    expect_error(
        &option_frame,
        &endpoint,
        &challenge_ctx,
        PermissionControlPhaseV1::Challenge,
        PermissionControlDirectionV1::DaemonToDesktop,
        1,
        1_500,
        PermissionControlErrorV1::MalformedFrame,
    );
}

#[test]
fn binds_context_purpose_phase_direction_key_and_strict_shared_sequence() {
    let endpoint = auth(64, PermissionControlPurposeV1::ModeControl);
    let (ctx, frame) = request_frame(&endpoint);
    let mut wrong_context = ctx.clone();
    wrong_context.stable_subject_digest = [88; 32];
    let check = |receiver: &PermissionControlAuthenticatorV1,
                 expected: &PermissionControlContextV1,
                 phase,
                 direction,
                 previous,
                 error| {
        expect_error(
            &frame, receiver, expected, phase, direction, previous, 1_500, error,
        )
    };
    use PermissionControlDirectionV1::{DaemonToDesktop as D2D, DesktopToDaemon as D2M};
    use PermissionControlErrorV1::{
        AuthenticationFailed, ContextMismatch, DirectionMismatch, PhaseMismatch, SequenceMismatch,
    };
    check(
        &endpoint,
        &wrong_context,
        PermissionControlPhaseV1::Request,
        D2M,
        0,
        ContextMismatch,
    );
    check(
        &endpoint,
        &ctx,
        PermissionControlPhaseV1::Challenge,
        D2M,
        0,
        PhaseMismatch,
    );
    check(
        &endpoint,
        &ctx,
        PermissionControlPhaseV1::Request,
        D2D,
        0,
        DirectionMismatch,
    );
    check(
        &endpoint,
        &ctx,
        PermissionControlPhaseV1::Request,
        D2M,
        1,
        SequenceMismatch,
    );
    check(
        &endpoint,
        &ctx,
        PermissionControlPhaseV1::Request,
        D2M,
        u64::MAX,
        SequenceMismatch,
    );
    let other_key = auth(65, PermissionControlPurposeV1::ModeControl);
    check(
        &other_key,
        &ctx,
        PermissionControlPhaseV1::Request,
        D2M,
        0,
        AuthenticationFailed,
    );
    let managed_key = auth(64, PermissionControlPurposeV1::ManagedPolicyControl);
    check(
        &managed_key,
        &ctx,
        PermissionControlPhaseV1::Request,
        D2M,
        0,
        AuthenticationFailed,
    );
}

#[test]
fn result_tags_roundtrip_with_closed_receipt_coherence() {
    let endpoint = auth(68, PermissionControlPurposeV1::ModeControl);
    for (sequence, code) in [
        PermissionControlResultCodeV1::Pending,
        PermissionControlResultCodeV1::Committed,
        PermissionControlResultCodeV1::Cancelled,
        PermissionControlResultCodeV1::Expired,
        PermissionControlResultCodeV1::Invalidated,
        PermissionControlResultCodeV1::Denied,
    ]
    .into_iter()
    .enumerate()
    {
        let ctx = context(PermissionControlPhaseV1::Result);
        let value = if code == PermissionControlResultCodeV1::Committed {
            result(&ctx)
        } else {
            PermissionControlResultV1 {
                code,
                command_id: ctx.command_id,
                public_request_digest: ctx.public_request_digest,
                receipt_digest: None,
                authorization_revision: None,
                managed_policy_revision: None,
            }
        };
        let payload = PermissionControlPayloadV1::Result(value);
        let frame = endpoint
            .issue_frame(
                ctx.clone(),
                sequence as u64 + 1,
                payload.direction(),
                payload.clone(),
            )
            .unwrap();
        let decoded = endpoint
            .authenticate_frame(
                &frame,
                &ctx,
                endpoint.purpose(),
                PermissionControlPhaseV1::Result,
                PermissionControlDirectionV1::DaemonToDesktop,
                sequence as u64,
                1_500,
            )
            .unwrap();
        assert!(decoded.payload() == &payload);
    }
}
