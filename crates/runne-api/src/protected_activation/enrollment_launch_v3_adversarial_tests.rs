use super::*;

fn lifecycle() -> (
    ProtectedCredentialEnrollmentLaunchRequestV3,
    ProtectedCredentialEnrollmentReadyV3,
    ProtectedActivationKeys,
    ProtectedCredentialEnrollmentRenewRequestV3,
    ProtectedCredentialEnrollmentRenewTicketV3,
    ProtectedCredentialEnrollmentOwnedLaunchV3,
) {
    let (launch, ready, keys) = enrollment_launch_v3_tests::fixture();
    let owned = ready.owned_launch();
    let mut renew =
        ProtectedCredentialEnrollmentRenewRequestV3::new(owned.clone(), 1, [21; 32]).unwrap();
    renew.sign(&keys);
    let mut ticket = ProtectedCredentialEnrollmentRenewTicketV3::new(
        &renew,
        enrollment_launch_v3_tests::id(22),
        [23; 32],
        100,
        200,
    )
    .unwrap();
    ticket.sign(&keys);
    (launch, ready, keys, renew, ticket, owned)
}

#[test]
fn enrollment_v3_proofs_and_each_control_field_fail_closed() {
    let (_, _, keys, renew, ticket, owned) = lifecycle();
    let mut tampered_renew = renew.clone();
    tampered_renew.proof[0] ^= 1;
    assert!(tampered_renew.verify_exact(&owned, 0, &keys).is_err());
    let mut sequence = renew.clone();
    sequence.sequence = 2;
    assert!(sequence.verify_exact(&owned, 0, &keys).is_err());
    let mut nonce = renew.clone();
    nonce.nonce[0] ^= 1;
    assert!(nonce.verify_exact(&owned, 0, &keys).is_err());

    let mut ticket_proof = ticket;
    ticket_proof.proof[0] ^= 1;
    assert!(ticket_proof.verify_exact_at(&renew, 100, &keys).is_err());
    let (_, _, keys, renew, ticket, _) = lifecycle();
    let mut ticket_sequence = ticket;
    ticket_sequence.sequence = 2;
    assert!(ticket_sequence.verify_exact_at(&renew, 100, &keys).is_err());
    let (_, _, keys, renew, ticket, _) = lifecycle();
    let mut ticket_nonce = ticket;
    ticket_nonce.nonce[0] ^= 1;
    assert!(ticket_nonce.verify_exact_at(&renew, 100, &keys).is_err());
    let (_, _, keys, renew, ticket, _) = lifecycle();
    let mut ticket_session = ticket;
    ticket_session.next_session[0] ^= 1;
    assert!(ticket_session.verify_exact_at(&renew, 100, &keys).is_err());
    let (_, _, keys, renew, ticket, _) = lifecycle();
    let mut ticket_bootstrap = ticket;
    ticket_bootstrap.bootstrap_ticket[0] ^= 1;
    assert!(
        ticket_bootstrap
            .verify_exact_at(&renew, 100, &keys)
            .is_err()
    );
    let (_, _, keys, renew, ticket, _) = lifecycle();
    let mut ticket_times = ticket;
    ticket_times.issued = 101;
    assert!(ticket_times.verify_exact_at(&renew, 101, &keys).is_err());
    let (_, _, keys, renew, ticket, _) = lifecycle();
    let mut ticket_expiry = ticket;
    ticket_expiry.expires = 199;
    assert!(ticket_expiry.verify_exact_at(&renew, 100, &keys).is_err());

    let (_, ready, keys, _, _, owned) = lifecycle();
    let mut shutdown = ProtectedCredentialEnrollmentShutdownV3::new(owned.clone());
    shutdown.sign(&keys);
    let mut proof = shutdown.clone();
    proof.proof[0] ^= 1;
    assert!(proof.verify_exact(&owned, &keys).is_err());
    let mut wrong_owned = shutdown;
    wrong_owned.owned.core.session_id = enrollment_launch_v3_tests::id(24);
    assert!(wrong_owned.verify_exact(&owned, &keys).is_err());
    let mut ack = ProtectedCredentialEnrollmentShutdownAckV3::new(ready.owned_launch(), true);
    ack.sign(&keys);
    let mut ack_proof = ack.clone();
    ack_proof.proof[0] ^= 1;
    assert!(ack_proof.verify_exact(ack.owned_launch(), &keys).is_err());
    let mut graceful = ack.clone();
    graceful.graceful = false;
    assert!(graceful.verify_exact(ack.owned_launch(), &keys).is_err());
    ack.owned.core.session_id = enrollment_launch_v3_tests::id(25);
    assert!(ack.verify_exact(&owned, &keys).is_err());
}

#[test]
fn enrollment_v3_ready_binds_every_launch_request_field() {
    let (launch, ready, keys) = enrollment_launch_v3_tests::fixture();
    let mut authority = launch.clone();
    authority.core.authority_id = enrollment_launch_v3_tests::id(31);
    assert!(ready.verify_exact(&authority, &keys).is_err());
    let mut desktop = launch.clone();
    desktop.core.desktop_id = enrollment_launch_v3_tests::id(32);
    assert!(ready.verify_exact(&desktop, &keys).is_err());
    let mut secret = launch.clone();
    secret.core.secret = LaunchSecret::from_bytes([0x42; 32]).unwrap();
    assert!(ready.verify_exact(&secret, &secret.derive_keys()).is_err());
    let mut issued = launch.clone();
    issued.core.issued += 1;
    assert!(ready.verify_exact(&issued, &keys).is_err());
    let mut expires = launch.clone();
    expires.core.expires -= 1;
    assert!(ready.verify_exact(&expires, &keys).is_err());
    let mut principal = launch.clone();
    principal.core.principal = "substituted-principal".to_owned();
    assert!(ready.verify_exact(&principal, &keys).is_err());
    let mut profile = launch.clone();
    profile.core.profile = ProtectedRuntimeProfileV1::new(
        profile.core.profile.transport_profile_id(),
        profile.core.profile.runtime_profile_schema_version(),
        profile.core.profile.profile_id(),
        [0x61; 32],
        *profile.core.profile.capability_digest(),
    )
    .unwrap();
    assert!(ready.verify_exact(&profile, &keys).is_err());
    let mut executable = launch.clone();
    executable.core.executable = ExecutableIdentityV1::new(
        [0x62; 32],
        *executable.core.executable.canonical_path_sha256(),
        executable.core.executable.byte_length(),
    )
    .unwrap();
    assert!(ready.verify_exact(&executable, &keys).is_err());
    let mut runtime_root = launch.clone();
    runtime_root.core.runtime_root = PathBuf::from("/tmp/substituted-runtime");
    assert!(ready.verify_exact(&runtime_root, &keys).is_err());
    let mut disposition = launch.clone();
    disposition.core.disposition =
        ActivationDispositionV1::Existing(Box::new(ready.core.stable.clone()));
    assert!(ready.verify_exact(&disposition, &keys).is_err());
    let mut provider = launch.clone();
    provider.provider = ProviderActivationBindingV1::deepseek_responses_text_v1();
    assert!(ready.verify_exact(&provider, &keys).is_err());
    let mut enrollment = launch;
    enrollment.enrollment.release_tuple_digest[0] ^= 1;
    assert!(ready.verify_exact(&enrollment, &keys).is_err());
}

#[test]
fn enrollment_v3_frames_cross_reject_v1_and_v2_for_every_phase() {
    let frames = enrollment_launch_v3_tests::signed_frames();
    assert!(ProtectedLaunchRequestV1::decode_frame(&frames[0]).is_err());
    assert!(ProtectedLaunchRequestV2::decode_frame(&frames[0]).is_err());
    assert!(ProtectedReadyV1::decode_frame(&frames[1]).is_err());
    assert!(ProtectedReadyV2::decode_frame(&frames[1]).is_err());
    assert!(ProtectedRenewRequestV1::decode_frame(&frames[2]).is_err());
    assert!(ProtectedRenewRequestV2::decode_frame(&frames[2]).is_err());
    assert!(ProtectedRenewTicketV1::decode_frame(&frames[3]).is_err());
    assert!(ProtectedRenewTicketV2::decode_frame(&frames[3]).is_err());
    assert!(ProtectedShutdownV1::decode_frame(&frames[4]).is_err());
    assert!(ProtectedShutdownV2::decode_frame(&frames[4]).is_err());
    assert!(ProtectedShutdownAckV1::decode_frame(&frames[5]).is_err());
    assert!(ProtectedShutdownAckV2::decode_frame(&frames[5]).is_err());
}
