fn transfer_authority(
    issuer: &ProviderCredentialRequestAuthorityIssuer,
    secret: [u8; 32],
    protected_session: [u8; 32],
) -> (
    runne_api::ProviderCredentialBrokerTransferAuthority,
    CredentialBrokerTransferAuthenticator,
) {
    use runne_api::{
        ProtectedCredentialEnrollmentAdmissionBinding,
        ProtectedCredentialEnrollmentAuthenticator, ProtectedCredentialEnrollmentControlFrame,
        ProtectedCredentialEnrollmentRequestBinding,
    };

    let keys = LaunchSecret::from_bytes(secret).unwrap().derive_keys();
    let enrollment =
        ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(&keys);
    let transfer = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let request_binding = ProtectedCredentialEnrollmentRequestBinding::new(
        uuid(1),
        uuid(2),
        uuid(3),
        1,
        1,
        uuid(4),
        [7; 32],
        [5; 32],
        [9; 32],
        [10; 32],
        [11; 32],
        [12; 32],
        [13; 32],
        100_000,
        120_000,
    )
    .unwrap();
    let request_frame = ProtectedCredentialEnrollmentControlFrame::Request(
        enrollment
            .issue_request(request_binding.clone(), 1)
            .unwrap(),
    )
    .encode_frame();
    let request = enrollment
        .decode_request(&request_frame, &request_binding, 0, 110_000)
        .unwrap();
    let admission_binding = ProtectedCredentialEnrollmentAdmissionBinding::new(
        [3; 32],
        [7; 32],
        protected_session,
        1,
        [6; 32],
        1,
        [5; 32],
        [9; 32],
        [10; 32],
        uuid(5),
        120_000,
    )
    .unwrap();
    let admission_frame = ProtectedCredentialEnrollmentControlFrame::Admission(
        enrollment
            .issue_admission(&request, admission_binding.clone(), 2)
            .unwrap(),
    )
    .encode_frame();
    let admission = enrollment
        .decode_admission(
            &admission_frame,
            &request,
            &admission_binding,
            1,
            110_000,
        )
        .unwrap();
    let admission = keys.bind_credential_broker_transfer(admission).unwrap();
    let (_, _, transfer_authority) = issuer
        .issue_from_verified_enrollment_with_broker_transfer(request, admission)
        .unwrap();
    (transfer_authority, transfer)
}

const fn uuid(value: u8) -> [u8; 16] {
    [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, value]
}
