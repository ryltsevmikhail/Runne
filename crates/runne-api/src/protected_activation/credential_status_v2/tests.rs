#[test]
fn credential_status_v2_binds_verified_native_facts_to_the_exact_request() {
    let (prepare, _, owned, keys) = fixture();
    let request = ProtectedCredentialStatusRequestV2::new(prepare, &keys).unwrap();
    let verified_request = request.verify_exact_view(&owned, 0, &keys).unwrap();
    let native =
        ProtectedCredentialStatusNativeClaimsV2::new([31; 32], [23; 32], [24; 32], [25; 32], 1, 2)
            .unwrap();
    let mut ack = ProtectedCredentialStatusAckV2::new(&verified_request, native).unwrap();
    ack.sign(&keys);

    assert_eq!(
        request.encode_frame().unwrap(),
        request.encode_frame().unwrap()
    );
    assert_eq!(ack.encode_frame().unwrap(), ack.encode_frame().unwrap());
    let request =
        ProtectedCredentialStatusRequestV2::decode_frame(&request.encode_frame().unwrap()).unwrap();
    let ack = ProtectedCredentialStatusAckV2::decode_frame(&ack.encode_frame().unwrap()).unwrap();
    let verified = ack.verify_exact_view(&request, &keys).unwrap();
    assert_eq!(verified.installation_identity(), [31; 32]);
    assert_eq!(verified.release_tuple_digest(), [23; 32]);
    assert_eq!(verified.qualification_binding_digest(), [24; 32]);
    assert_eq!(verified.desktop_peer_binding_digest(), [25; 32]);
    assert_eq!(verified.desktop_supervisor_generation(), 1);
    assert_eq!(verified.installed_generation(), 2);
}

#[test]
fn credential_status_v2_accepts_a_shared_allocator_gap_after_zero() {
    let (_, _, owned, keys) = fixture();
    let mut prepare = ProtectedCredentialEnrollmentPrepareV2::new(
        owned.clone(),
        6,
        [41; 32],
        [23; 32],
        [24; 32],
        [25; 32],
        1,
    )
    .unwrap();
    prepare.sign(&keys);

    let request = ProtectedCredentialStatusRequestV2::new(prepare, &keys).unwrap();
    assert_eq!(request.sequence(), 6);
    assert!(request.verify_exact_view(&owned, 0, &keys).is_ok());
    assert!(request.verify_exact_view(&owned, 6, &keys).is_err());
}

#[test]
fn credential_status_v2_rejects_frame_kind_sequence_claim_and_ack_substitution() {
    let (prepare, _, owned, keys) = fixture();
    let unsigned = ProtectedCredentialEnrollmentPrepareV2::new(
        owned.clone(),
        1,
        [21; 32],
        [23; 32],
        [24; 32],
        [25; 32],
        1,
    )
    .unwrap();
    assert!(ProtectedCredentialStatusRequestV2::new(unsigned, &keys).is_err());
    let request = ProtectedCredentialStatusRequestV2::new(prepare, &keys).unwrap();
    assert!(request.verify_exact_view(&owned, 1, &keys).is_err());
    let claims = request.verify_exact_view(&owned, 0, &keys).unwrap();
    assert!(
        ProtectedCredentialStatusNativeClaimsV2::new([31; 32], [24; 32], [24; 32], [25; 32], 1, 2,)
            .is_ok()
    );
    assert!(
        ProtectedCredentialStatusAckV2::new(
            &claims,
            ProtectedCredentialStatusNativeClaimsV2::new(
                [31; 32], [24; 32], [24; 32], [25; 32], 1, 2
            )
            .unwrap(),
        )
        .is_err()
    );

    let native =
        ProtectedCredentialStatusNativeClaimsV2::new([31; 32], [23; 32], [24; 32], [25; 32], 1, 2)
            .unwrap();
    let mut ack = ProtectedCredentialStatusAckV2::new(&claims, native).unwrap();
    ack.sign(&keys);
    let mut changed_request = request.clone();
    changed_request.release_tuple_digest[0] ^= 1;
    assert!(ack.verify_exact(&changed_request, &keys).is_err());
    ack.native.installation_identity[0] ^= 1;
    assert!(ack.verify_exact(&request, &keys).is_err());
    assert!(
        ProtectedCredentialEnrollmentPrepareV2::decode_frame(&request.encode_frame().unwrap())
            .is_err()
    );
}
