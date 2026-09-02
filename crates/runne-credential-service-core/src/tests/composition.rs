use runne_provider::{
    CredentialOperationAction, CredentialServiceDisposition, CredentialServiceEndpointRole,
    CredentialServiceProtocolCodec, CredentialServiceReply, CredentialServiceRequest,
};

use super::super::{
    CredentialRuntimeReadObservation, CredentialServiceCore, CredentialServiceIngressFailure,
};
use super::support::{
    EPOCH, OWNER, arm_frame_for_owner, auth, binding, binding_for_owner, issue_challenge_at,
    mutation_frames, register, replay_register, replay_register_at, runtime_reply,
};

#[test]
fn desktop_challenge_is_service_issued_context_bound_and_blocks_idle() {
    let mut core = CredentialServiceCore::with_test_epoch(EPOCH).unwrap();
    let request = CredentialServiceRequest::RegistrationChallenge;
    let context = request.context();
    let frame = CredentialServiceProtocolCodec::encode_request(request).unwrap();
    let mut request_bytes = Vec::new();
    frame
        .send(|bytes| {
            request_bytes.extend_from_slice(bytes);
            Ok::<(), ()>(())
        })
        .unwrap();
    let reply = core
        .challenge_with_test_nonce(
            CredentialServiceEndpointRole::Desktop,
            &request_bytes,
            10,
            [7; 16],
        )
        .unwrap();
    let mut reply_bytes = Vec::new();
    reply
        .send(|bytes| {
            reply_bytes.extend_from_slice(bytes);
            Ok::<(), ()>(())
        })
        .unwrap();
    let decoded =
        CredentialServiceProtocolCodec::decode_desktop_reply(&reply_bytes, context).unwrap();
    assert!(matches!(
        decoded,
        CredentialServiceReply::RegistrationChallenge { nonce, .. } if nonce == [7; 16]
    ));
    let active = core.poll(10);
    assert!(active.prevents_idle());
    assert_eq!(active.next_deadline_unix_millis(), Some(5_010));
    assert!(!core.poll(5_010).prevents_idle());
}

#[test]
fn constructor_entropy_failure_is_typed() {
    assert!(CredentialServiceCore::with_test_entropy(|_| Err(())).is_err());
    let mut core = CredentialServiceCore::with_test_epoch(EPOCH).unwrap();
    let (request, context) = challenge_request();
    let reply = core
        .challenge_with_test_entropy(CredentialServiceEndpointRole::Desktop, &request, 10, |_| {
            Err(())
        })
        .unwrap();
    assert!(matches!(
        decode_desktop(reply, context),
        CredentialServiceReply::Rejected(CredentialServiceDisposition::Unavailable)
    ));
    assert!(!core.poll(10).prevents_idle());
}

#[test]
fn challenge_is_one_use_for_non_idempotent_registration_and_expires_exclusively() {
    let mut core = CredentialServiceCore::with_test_epoch(EPOCH).unwrap();
    let first = binding(2, 12, 14, 6_000);
    assert_eq!(
        replay_register(
            &mut core,
            7,
            first.clone(),
            CredentialServiceEndpointRole::Desktop
        )
        .unwrap_err(),
        CredentialServiceDisposition::Denied
    );
    issue_challenge_at(&mut core, *first.challenge_nonce(), 10);
    replay_register(
        &mut core,
        7,
        first.clone(),
        CredentialServiceEndpointRole::Desktop,
    )
    .unwrap();
    let other = binding_for_owner([8; 32], *first.challenge_nonce(), 2, 12, 14, 6_000);
    assert_eq!(
        replay_register(&mut core, 7, other, CredentialServiceEndpointRole::Desktop).unwrap_err(),
        CredentialServiceDisposition::Denied
    );
    assert!(replay_register(&mut core, 7, first, CredentialServiceEndpointRole::Desktop).is_ok());

    let mut expired = CredentialServiceCore::with_test_epoch(EPOCH).unwrap();
    let stale = binding_for_owner(OWNER, [9; 16], 2, 12, 14, 6_000);
    issue_challenge_at(&mut expired, [9; 16], 10);
    assert_eq!(
        replay_register_at(
            &mut expired,
            7,
            stale,
            CredentialServiceEndpointRole::Desktop,
            5_010,
        )
        .unwrap_err(),
        CredentialServiceDisposition::Denied
    );
}

#[test]
fn challenge_capacity_rejects_sixty_fifth_without_evicting_live_entries() {
    let mut core = CredentialServiceCore::with_test_epoch(EPOCH).unwrap();
    let (request, context) = challenge_request();
    for value in 1..=64 {
        let reply = core
            .challenge_with_test_nonce(
                CredentialServiceEndpointRole::Desktop,
                &request,
                10,
                [value; 16],
            )
            .unwrap();
        assert!(matches!(
            decode_desktop(reply, context),
            CredentialServiceReply::RegistrationChallenge { .. }
        ));
    }
    let full = core
        .challenge_with_test_nonce(
            CredentialServiceEndpointRole::Desktop,
            &request,
            10,
            [65; 16],
        )
        .unwrap();
    assert!(matches!(
        decode_desktop(full, context),
        CredentialServiceReply::Rejected(CredentialServiceDisposition::Unavailable)
    ));
    assert!(core.poll(10).prevents_idle());
}

#[test]
fn runtime_reply_is_mac_authenticated_and_bound_to_the_exact_request_context() {
    let mut core = registered_core();
    let first = arm_frame_for_owner(OWNER, OWNER, 1, 7);
    let other = arm_frame_for_owner(OWNER, OWNER, 2, 7);
    let first_context = runtime_context(&first, 7);
    let other_context = runtime_context(&other, 7);
    let envelope = core
        .handle_runtime(CredentialServiceEndpointRole::Runtime, &first, 10, |_| {
            panic!("arm must not call read backend")
        })
        .unwrap();
    let mut outer = Vec::new();
    envelope
        .send(|bytes| {
            outer.extend_from_slice(bytes);
            Ok::<(), ()>(())
        })
        .unwrap();
    let mut exact = false;
    auth(7)
        .verify_runtime_reply(OWNER, &outer)
        .unwrap()
        .consume(|payload| {
            exact = matches!(
                CredentialServiceProtocolCodec::decode_runtime_reply(payload, first_context),
                Ok(CredentialServiceReply::Armed)
            );
            assert!(
                CredentialServiceProtocolCodec::decode_runtime_reply(payload, other_context)
                    .is_err()
            );
        });
    assert!(exact);
}

#[test]
fn bad_pre_context_ingress_invalidates_without_effect_and_owner_mismatch_does_not_advance() {
    let mut core = registered_core();
    let mut bad_mac = arm_frame_for_owner(OWNER, OWNER, 1, 7);
    *bad_mac.last_mut().unwrap() ^= 1;
    let mut called = false;
    assert!(matches!(
        core.handle_runtime(CredentialServiceEndpointRole::Runtime, &bad_mac, 10, |_| {
            called = true;
            CredentialRuntimeReadObservation::Metadata(
                super::super::CredentialBackendResult::Unavailable,
            )
        },),
        Err(CredentialServiceIngressFailure::Invalidate)
    ));
    assert!(!called);

    let mismatch = arm_frame_for_owner([8; 32], OWNER, 1, 7);
    assert!(matches!(
        runtime_reply(&mut core, &mismatch, 7, 10, |_| panic!()),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Denied
        ))
    ));
    let valid = arm_frame_for_owner(OWNER, OWNER, 1, 7);
    assert!(matches!(
        runtime_reply(&mut core, &valid, 7, 10, |_| panic!()),
        Ok(CredentialServiceReply::Armed)
    ));
}

#[test]
fn writer_without_live_session_invalidates_without_reply_or_native_effect() {
    let mut core = CredentialServiceCore::with_test_epoch(EPOCH).unwrap();
    let (_, writer, _) = mutation_frames(1, 1, 7, CredentialOperationAction::Pair);
    let mut called = false;
    assert!(matches!(
        core.handle_writer(CredentialServiceEndpointRole::Writer, &writer, 10, |_| {
            called = true;
            super::super::CredentialBackendResult::Observed(())
        },),
        Err(CredentialServiceIngressFailure::Invalidate)
    ));
    assert!(!called);
}

#[test]
fn poll_purges_session_admissions_and_receipts_at_exclusive_expiry() {
    let mut core = registered_core();
    let arm = arm_frame_for_owner(OWNER, OWNER, 1, 7);
    assert!(matches!(
        runtime_reply(&mut core, &arm, 7, 10, |_| panic!()),
        Ok(CredentialServiceReply::Armed)
    ));
    let active = core.poll(20);
    assert!(active.prevents_idle());
    assert_eq!(active.next_deadline_unix_millis(), Some(100));
    assert!(!core.poll(100).prevents_idle());
}

fn registered_core() -> CredentialServiceCore {
    let mut core = CredentialServiceCore::with_test_epoch(EPOCH).unwrap();
    register(
        &mut core,
        7,
        binding(2, 12, 14, 100),
        CredentialServiceEndpointRole::Desktop,
    )
    .unwrap();
    core
}

fn challenge_request() -> (Vec<u8>, runne_provider::CredentialServiceRequestContext) {
    let request = CredentialServiceRequest::RegistrationChallenge;
    let context = request.context();
    let frame = CredentialServiceProtocolCodec::encode_request(request).unwrap();
    let mut bytes = Vec::new();
    frame
        .send(|frame| {
            bytes.extend_from_slice(frame);
            Ok::<(), ()>(())
        })
        .unwrap();
    (bytes, context)
}

fn decode_desktop(
    reply: runne_provider::CredentialServiceReplyFrame,
    context: runne_provider::CredentialServiceRequestContext,
) -> CredentialServiceReply {
    let mut bytes = Vec::new();
    reply
        .send(|frame| {
            bytes.extend_from_slice(frame);
            Ok::<(), ()>(())
        })
        .unwrap();
    CredentialServiceProtocolCodec::decode_desktop_reply(&bytes, context).unwrap()
}

fn runtime_context(bytes: &[u8], key: u8) -> runne_provider::CredentialServiceRequestContext {
    let mut context = None;
    auth(key)
        .verify_runtime_request(OWNER, bytes)
        .unwrap()
        .consume(|payload| {
            context = Some(
                CredentialServiceProtocolCodec::decode_runtime_request(payload)
                    .unwrap()
                    .context(),
            );
        });
    context.unwrap()
}
