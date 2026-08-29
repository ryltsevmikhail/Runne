use super::*;

pub(super) fn id(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}

fn profile() -> ProtectedRuntimeProfileV1 {
    ProtectedRuntimeProfileV1::new(
        PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
        1,
        "gocode-test/1",
        [1; 32],
        [2; 32],
    )
    .unwrap()
}

pub(super) fn fixture() -> (
    ProtectedCredentialEnrollmentLaunchRequestV3,
    ProtectedCredentialEnrollmentReadyV3,
    ProtectedActivationKeys,
) {
    let request = ProtectedLaunchRequestV1::new(
        id(1),
        id(2),
        LaunchSecret::from_bytes([3; 32]).unwrap(),
        10,
        20,
        "principal",
        profile(),
        ExecutableIdentityV1::new([4; 32], [5; 32], 1).unwrap(),
        PathBuf::from("/tmp/runtime"),
        ActivationDispositionV1::FirstActivation,
    )
    .unwrap();
    let keys = request.derive_keys();
    let commitment = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys)
        .enrollment_launch_commitment(request.launch_authority_id());
    let binding = ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
        [6; 32], [7; 32], [8; 32], [9; 32], 1, commitment,
    )
    .unwrap();
    let launch = ProtectedCredentialEnrollmentLaunchRequestV3::new(
        request.clone(),
        ProviderActivationBindingV1::openai_responses_text_v1(),
        binding.clone(),
    )
    .unwrap();
    let stable = StableRuntimeBindingV1::new(
        id(10),
        "principal",
        id(11),
        "gocode-test/1",
        [1; 32],
        [2; 32],
    )
    .unwrap();
    let ready = ProtectedReadyV1::new(
        id(1),
        id(2),
        request.executable().clone(),
        profile(),
        stable,
        id(12),
        1,
        id(13),
        "https://127.0.0.1",
        [14; 32],
        vec![15; 32],
        vec!["provider.enroll".to_owned()],
    )
    .unwrap();
    let mut ready = ProtectedCredentialEnrollmentReadyV3::new(
        ready,
        ProviderActivationBindingV1::openai_responses_text_v1(),
        binding,
        ProviderActivationReadinessV1::CredentialMissing,
    )
    .unwrap();
    ready.sign(&launch, &keys).unwrap();
    (launch, ready, keys)
}

#[test]
fn enrollment_v3_direct_lifecycle_roundtrips_and_binds_every_phase() {
    let (launch, ready, keys) = fixture();
    let decoded_launch =
        ProtectedCredentialEnrollmentLaunchRequestV3::decode_frame(&launch.encode_frame().unwrap())
            .unwrap();
    let decoded_ready =
        ProtectedCredentialEnrollmentReadyV3::decode_frame(&ready.encode_frame().unwrap()).unwrap();
    decoded_ready.verify_exact(&decoded_launch, &keys).unwrap();
    let owned = decoded_ready.owned_launch();
    let mut renew =
        ProtectedCredentialEnrollmentRenewRequestV3::new(owned.clone(), 1, [16; 32]).unwrap();
    renew.sign(&keys);
    let renew =
        ProtectedCredentialEnrollmentRenewRequestV3::decode_frame(&renew.encode_frame().unwrap())
            .unwrap();
    renew.verify_exact(&owned, 0, &keys).unwrap();
    let mut ticket =
        ProtectedCredentialEnrollmentRenewTicketV3::new(&renew, id(17), [18; 32], 100, 200)
            .unwrap();
    ticket.sign(&keys);
    let ticket =
        ProtectedCredentialEnrollmentRenewTicketV3::decode_frame(&ticket.encode_frame().unwrap())
            .unwrap();
    assert!(ticket.verify_exact_at(&renew, 99, &keys).is_err());
    assert!(ticket.verify_exact_at(&renew, 200, &keys).is_ok());
    assert!(ticket.verify_exact_at(&renew, 201, &keys).is_err());
    let ticket = ticket.verify_exact_at(&renew, 100, &keys).unwrap();
    let next = ticket.next_owned_launch();
    let mut shutdown = ProtectedCredentialEnrollmentShutdownV3::new(next.clone());
    shutdown.sign(&keys);
    let shutdown =
        ProtectedCredentialEnrollmentShutdownV3::decode_frame(&shutdown.encode_frame().unwrap())
            .unwrap();
    shutdown.verify_exact(&next, &keys).unwrap();
    let mut ack = ProtectedCredentialEnrollmentShutdownAckV3::new(next.clone(), true);
    ack.sign(&keys);
    let ack =
        ProtectedCredentialEnrollmentShutdownAckV3::decode_frame(&ack.encode_frame().unwrap())
            .unwrap();
    ack.verify_exact(&next, &keys).unwrap();
    assert!(ack.graceful());
}

#[test]
fn enrollment_v3_proof_and_cross_decoder_are_fail_closed() {
    let (launch, ready, keys) = fixture();
    let mut frame = ready.encode_frame().unwrap();
    *frame.last_mut().unwrap() ^= 1;
    let tampered = ProtectedCredentialEnrollmentReadyV3::decode_frame(&frame).unwrap();
    assert_eq!(
        tampered.verify_exact(&launch, &keys),
        Err(LaunchAuthorityError::ReadinessProofMismatch)
    );
    assert!(ProtectedLaunchRequestV2::decode_frame(&launch.encode_frame().unwrap()).is_err());
    assert!(
        ProtectedCredentialEnrollmentRenewRequestV3::decode_frame(&ready.encode_frame().unwrap())
            .is_err()
    );
}

#[test]
fn enrollment_v3_launch_exposes_exact_freshness_without_a_lower_projection() {
    let (launch, _, _) = fixture();
    assert_eq!(
        launch.validate_freshness(9),
        Err(LaunchAuthorityError::StaleLaunchAuthority)
    );
    assert_eq!(launch.validate_freshness(10), Ok(()));
    assert_eq!(launch.validate_freshness(20), Ok(()));
    assert_eq!(
        launch.validate_freshness(21),
        Err(LaunchAuthorityError::StaleLaunchAuthority)
    );
}

#[test]
fn enrollment_v3_ready_covers_nonsecret_launch_fields_not_owned_by_ready() {
    let (launch, ready, keys) = fixture();
    let mut changed_root = launch.clone();
    changed_root.core.runtime_root = PathBuf::from("/tmp/substituted-runtime");
    assert!(ready.verify_exact(&changed_root, &keys).is_err());
    let mut changed_disposition = launch;
    changed_disposition.core.disposition =
        ActivationDispositionV1::Existing(Box::new(ready.core.stable.clone()));
    assert!(ready.verify_exact(&changed_disposition, &keys).is_err());
}

pub(super) fn signed_frames() -> [Vec<u8>; 6] {
    let (launch, ready, keys) = fixture();
    let owned = ready.owned_launch();
    let mut renew =
        ProtectedCredentialEnrollmentRenewRequestV3::new(owned.clone(), 1, [16; 32]).unwrap();
    renew.sign(&keys);
    let mut ticket =
        ProtectedCredentialEnrollmentRenewTicketV3::new(&renew, id(17), [18; 32], 100, 200)
            .unwrap();
    ticket.sign(&keys);
    let next = ticket
        .verify_exact_at(&renew, 100, &keys)
        .unwrap()
        .next_owned_launch();
    let mut shutdown = ProtectedCredentialEnrollmentShutdownV3::new(next.clone());
    shutdown.sign(&keys);
    let mut ack = ProtectedCredentialEnrollmentShutdownAckV3::new(next, true);
    ack.sign(&keys);
    [
        launch.encode_frame().unwrap(),
        ready.encode_frame().unwrap(),
        renew.encode_frame().unwrap(),
        ticket.encode_frame().unwrap(),
        shutdown.encode_frame().unwrap(),
        ack.encode_frame().unwrap(),
    ]
}

#[test]
fn enrollment_v3_wire_ids_and_decoders_are_strict_for_each_phase() {
    assert_eq!(
        [
            ProtectedCredentialEnrollmentLaunchRequestV3::MESSAGE_TYPE_ID,
            ProtectedCredentialEnrollmentReadyV3::MESSAGE_TYPE_ID,
            ProtectedCredentialEnrollmentRenewRequestV3::MESSAGE_TYPE_ID,
            ProtectedCredentialEnrollmentRenewTicketV3::MESSAGE_TYPE_ID,
            ProtectedCredentialEnrollmentShutdownV3::MESSAGE_TYPE_ID,
            ProtectedCredentialEnrollmentShutdownAckV3::MESSAGE_TYPE_ID,
        ],
        [27, 28, 29, 30, 31, 32]
    );
    for (index, frame) in signed_frames().into_iter().enumerate() {
        let mut trailing = frame.clone();
        trailing.push(0);
        let mut truncated = frame;
        truncated.pop();
        let rejected = match index {
            0 => {
                ProtectedCredentialEnrollmentLaunchRequestV3::decode_frame(&trailing).is_err()
                    && ProtectedCredentialEnrollmentLaunchRequestV3::decode_frame(&truncated)
                        .is_err()
            }
            1 => {
                ProtectedCredentialEnrollmentReadyV3::decode_frame(&trailing).is_err()
                    && ProtectedCredentialEnrollmentReadyV3::decode_frame(&truncated).is_err()
            }
            2 => {
                ProtectedCredentialEnrollmentRenewRequestV3::decode_frame(&trailing).is_err()
                    && ProtectedCredentialEnrollmentRenewRequestV3::decode_frame(&truncated)
                        .is_err()
            }
            3 => {
                ProtectedCredentialEnrollmentRenewTicketV3::decode_frame(&trailing).is_err()
                    && ProtectedCredentialEnrollmentRenewTicketV3::decode_frame(&truncated).is_err()
            }
            4 => {
                ProtectedCredentialEnrollmentShutdownV3::decode_frame(&trailing).is_err()
                    && ProtectedCredentialEnrollmentShutdownV3::decode_frame(&truncated).is_err()
            }
            _ => {
                ProtectedCredentialEnrollmentShutdownAckV3::decode_frame(&trailing).is_err()
                    && ProtectedCredentialEnrollmentShutdownAckV3::decode_frame(&truncated).is_err()
            }
        };
        assert!(rejected, "phase {index} accepted malformed frame");
    }
}

#[test]
fn enrollment_v3_fixed_wire_goldens_are_stable() {
    use sha2::{Digest, Sha256};
    let expected = [
        "ca9c472b7a1300f2c643163a0b1a4f7543ec17effb0a00bc41ef8fd9504c7452",
        "d236c8c62958150e2f9fb42d1038bf1b58c0f4f85a9a0bcf0f2756c7a535a7da",
        "6e81d998b3c5eacf118945296f10bb45d522a72124e2549dbeabcb682d7b8d20",
        "a2eed47ba96eb832c0fd843b40ee8e4d9eaadc6e8b24449a6ef3ab5e8b128a75",
        "6ad4bd62777b54ff9b722d9829aa82d36ad79b4086bf2153642f3387add40533",
        "ac595add91827a3a6ebd151fb056b5e54ae1c7988754e6a9fc83b72a671c54f6",
    ];
    for (frame, expected) in signed_frames().into_iter().zip(expected) {
        assert_eq!(format!("{:x}", Sha256::digest(frame)), expected);
    }
}
