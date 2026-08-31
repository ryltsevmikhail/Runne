#[test]
fn enrollment_request_round_trips_canonical_intent_claim_digests() {
    let authenticator = authenticator(13);
    let (action_provider_revision, command_identity) = credential_claims(
        ProviderCredentialEnrollmentActionV2::Revoke,
        ProviderCredentialProviderV2::DeepSeek,
        11,
        "018f8d23-7f90-7c00-8000-000000000002",
        "idempotency-b",
    );
    let binding = request_binding_with_claims(
        [4; 32],
        2,
        [5; 32],
        [6; 32],
        [7; 32],
        action_provider_revision,
        command_identity,
        100,
        200,
    );
    let frame = ProtectedCredentialEnrollmentControlFrame::Request(
        authenticator.issue_request(binding.clone(), 1).unwrap(),
    )
    .encode_frame();

    let verified = authenticator
        .decode_request(&frame, &binding, 0, 150)
        .unwrap();
    assert_eq!(
        verified.action_provider_revision_binding(),
        action_provider_revision
    );
    assert_eq!(verified.command_identity_binding(), command_identity);
}

#[test]
fn enrollment_request_rejects_tampered_or_substituted_intent_claims() {
    let authenticator = authenticator(14);
    let (action_provider_revision, command_identity) = credential_claims(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        7,
        "018f8d23-7f90-7c00-8000-000000000001",
        "idempotency-a",
    );
    let binding = request_binding_with_claims(
        [4; 32],
        2,
        [5; 32],
        [6; 32],
        [7; 32],
        action_provider_revision,
        command_identity,
        100,
        200,
    );
    let frame = ProtectedCredentialEnrollmentControlFrame::Request(
        authenticator.issue_request(binding.clone(), 1).unwrap(),
    )
    .encode_frame();
    for index in [221, 253] {
        let mut tampered = frame.clone();
        tampered[index] ^= 1;
        assert!(
            authenticator
                .decode_request(&tampered, &binding, 0, 150)
                .is_err()
        );
    }

    for (other_action_provider_revision, other_command_identity) in [
        credential_claims(
            ProviderCredentialEnrollmentActionV2::Revoke,
            ProviderCredentialProviderV2::OpenAi,
            7,
            "018f8d23-7f90-7c00-8000-000000000001",
            "idempotency-a",
        ),
        credential_claims(
            ProviderCredentialEnrollmentActionV2::Pair,
            ProviderCredentialProviderV2::DeepSeek,
            7,
            "018f8d23-7f90-7c00-8000-000000000001",
            "idempotency-a",
        ),
        credential_claims(
            ProviderCredentialEnrollmentActionV2::Pair,
            ProviderCredentialProviderV2::OpenAi,
            8,
            "018f8d23-7f90-7c00-8000-000000000001",
            "idempotency-a",
        ),
        credential_claims(
            ProviderCredentialEnrollmentActionV2::Pair,
            ProviderCredentialProviderV2::OpenAi,
            7,
            "018f8d23-7f90-7c00-8000-000000000002",
            "idempotency-a",
        ),
    ] {
        let expected = request_binding_with_claims(
            [4; 32],
            2,
            [5; 32],
            [6; 32],
            [7; 32],
            other_action_provider_revision,
            other_command_identity,
            100,
            200,
        );
        assert!(
            authenticator
                .decode_request(&frame, &expected, 0, 150)
                .is_err()
        );
    }
}
