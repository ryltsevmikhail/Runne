use super::super::ProviderCredentialRequestAuthorityPair;

#[test]
fn authority_issuer_consumes_verified_enrollment_claims_once_by_value() {
    let (request, admission) = verified_enrollment_claims();
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let (authority, proof) = issuer
        .issue_from_verified_enrollment(request, admission)
        .expect("verified envelope claims");

    assert!(verifier.verify_base(&authority).is_ok());
    assert!(verifier.verify_intent_proof(&proof).is_ok());
    assert_eq!(authority.installation_identity(), &[8; 32]);
    assert_eq!(authority.release_tuple_digest(), &[4; 32]);
    assert_eq!(authority.protected_session_id(), &[9; 32]);
    assert_eq!(authority.desktop_supervisor_generation(), 2);
    assert_eq!(authority.daemon_authority_id(), &[10; 32]);
    assert_eq!(authority.database_generation(), 4);
    assert_eq!(authority.authenticated_tauri_peer_process(), &[5; 32]);
    assert_ne!(proof.proof_digest(), &[0; 32]);
}

#[test]
fn authority_issuer_rejects_claims_from_different_enrollment_requests() {
    let (request, _) = verified_enrollment_claims();
    let (_, admission) = verified_enrollment_claims_with_request_id(2);
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();

    assert!(matches!(
        issuer.issue_from_verified_enrollment(request, admission),
        Err(crate::ProviderCredentialEnrollmentHostError::AccessDenied)
    ));
}

fn verified_enrollment_claims() -> (
    crate::VerifiedProtectedCredentialEnrollmentRequest,
    crate::VerifiedProtectedCredentialEnrollmentAdmission,
) {
    verified_enrollment_claims_with_request_id(1)
}

fn verified_enrollment_claims_with_request_id(
    request_id: u8,
) -> (
    crate::VerifiedProtectedCredentialEnrollmentRequest,
    crate::VerifiedProtectedCredentialEnrollmentAdmission,
) {
    let keys = crate::LaunchSecret::from_bytes([31; 32])
        .unwrap()
        .derive_keys();
    let authenticator =
        crate::ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(&keys);
    let binding = crate::ProtectedCredentialEnrollmentRequestBinding::new(
        uuid(request_id),
        uuid(2),
        uuid(3),
        3,
        2,
        uuid(4),
        [4; 32],
        [5; 32],
        [6; 32],
        [7; 32],
        [8; 32],
        [9; 32],
        100,
        200,
    )
    .unwrap();
    let request_frame = crate::ProtectedCredentialEnrollmentControlFrame::Request(
        authenticator.issue_request(binding.clone(), 1).unwrap(),
    )
    .encode_frame();
    let request = authenticator
        .decode_request(&request_frame, &binding, 0, 150)
        .unwrap();
    let admission_binding = crate::ProtectedCredentialEnrollmentAdmissionBinding::new(
        [8; 32],
        [4; 32],
        [9; 32],
        2,
        [10; 32],
        4,
        [5; 32],
        [6; 32],
        [7; 32],
        uuid(5),
        200,
    )
    .unwrap();
    let admission = authenticator
        .issue_admission(&request, admission_binding.clone(), 2)
        .unwrap();
    let admission_frame =
        crate::ProtectedCredentialEnrollmentControlFrame::Admission(admission).encode_frame();
    let admission = authenticator
        .decode_admission(&admission_frame, &request, &admission_binding, 1, 150)
        .unwrap();
    (request, admission)
}

fn uuid(value: u8) -> [u8; 16] {
    [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, value]
}
