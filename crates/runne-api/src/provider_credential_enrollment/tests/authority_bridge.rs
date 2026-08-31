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
    let (_, admission) = verified_enrollment_claims_with([31; 32], 2);
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();

    assert!(matches!(
        issuer.issue_from_verified_enrollment(request, admission),
        Err(crate::ProviderCredentialEnrollmentHostError::AccessDenied)
    ));
}

#[test]
fn authority_issuer_rejects_admission_from_another_authenticator_domain() {
    let (request, _) = verified_enrollment_claims_with([31; 32], 1);
    let (_, admission) = verified_enrollment_claims_with([32; 32], 1);
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();

    assert!(matches!(
        issuer.issue_from_verified_enrollment(request, admission),
        Err(crate::ProviderCredentialEnrollmentHostError::AccessDenied)
    ));
}

#[test]
fn authority_intent_expiry_uses_store_seconds_without_rounding_up() {
    for (expires_at_unix_millis, expected_seconds) in [(1_020_000, 1_020), (1_020_999, 1_020)] {
        let (request, admission) = verified_enrollment_claims_at(
            expires_at_unix_millis - 20_000,
            expires_at_unix_millis,
            expires_at_unix_millis - 10_000,
            [31; 32],
            1,
        );
        let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
        let (_, proof) = issuer
            .issue_from_verified_enrollment(request, admission)
            .expect("live verified enrollment claims");

        assert_eq!(proof.expires_at_high_water(), expected_seconds);
        assert!(proof.expires_at_high_water() > 0);
    }
}

#[test]
fn authority_intent_expiry_rejects_sub_second_store_expiry() {
    let (request, admission) = verified_enrollment_claims_at(1, 500, 250, [31; 32], 1);
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();

    assert_eq!(
        issuer
            .issue_from_verified_enrollment(request, admission)
            .unwrap_err(),
        crate::ProviderCredentialEnrollmentHostError::AccessDenied
    );
}

fn verified_enrollment_claims() -> (
    crate::VerifiedProtectedCredentialEnrollmentRequest,
    crate::VerifiedProtectedCredentialEnrollmentAdmission,
) {
    verified_enrollment_claims_at(1_000_000, 1_020_000, 1_010_000, [31; 32], 1)
}

fn verified_enrollment_claims_with(
    key: [u8; 32],
    request_id: u8,
) -> (
    crate::VerifiedProtectedCredentialEnrollmentRequest,
    crate::VerifiedProtectedCredentialEnrollmentAdmission,
) {
    verified_enrollment_claims_at(1_000_000, 1_020_000, 1_010_000, key, request_id)
}

fn verified_enrollment_claims_at(
    issued_at_unix_millis: u64,
    expires_at_unix_millis: u64,
    now_unix_millis: u64,
    key: [u8; 32],
    request_id: u8,
) -> (
    crate::VerifiedProtectedCredentialEnrollmentRequest,
    crate::VerifiedProtectedCredentialEnrollmentAdmission,
) {
    let keys = crate::LaunchSecret::from_bytes(key).unwrap().derive_keys();
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
        [10; 32],
        issued_at_unix_millis,
        expires_at_unix_millis,
    )
    .unwrap();
    let request_frame = crate::ProtectedCredentialEnrollmentControlFrame::Request(
        authenticator.issue_request(binding.clone(), 1).unwrap(),
    )
    .encode_frame();
    let request = authenticator
        .decode_request(&request_frame, &binding, 0, now_unix_millis)
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
        expires_at_unix_millis,
    )
    .unwrap();
    let admission = authenticator
        .issue_admission(&request, admission_binding.clone(), 2)
        .unwrap();
    let admission_frame =
        crate::ProtectedCredentialEnrollmentControlFrame::Admission(admission).encode_frame();
    let admission = authenticator
        .decode_admission(
            &admission_frame,
            &request,
            &admission_binding,
            1,
            now_unix_millis,
        )
        .unwrap();
    (request, admission)
}

fn uuid(value: u8) -> [u8; 16] {
    [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, value]
}
