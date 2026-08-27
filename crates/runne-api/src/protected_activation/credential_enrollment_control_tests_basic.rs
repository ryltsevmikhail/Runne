#[test]
fn enrollment_frames_round_trip_only_for_the_exact_current_binding() {
    let authenticator = authenticator(1);
    let (request_binding, request_frame) = request_frame(&authenticator);
    let request = authenticator
        .decode_request(&request_frame, &request_binding, 0, 150)
        .unwrap();
    let admission_binding = admission_binding();
    let admission = authenticator
        .issue_admission(&request, admission_binding.clone(), 2)
        .unwrap();
    let admission_frame =
        ProtectedCredentialEnrollmentControlFrame::Admission(admission).encode_frame();
    let verified = authenticator
        .decode_admission(&admission_frame, &request, &admission_binding, 1, 150)
        .unwrap();
    assert_eq!(verified.request_digest(), request.request_digest());
    assert_eq!(verified.admission_id(), uuid(5));
    assert_eq!(verified.request_id(), uuid(4));
    assert_eq!(verified.installation_identity(), [8; 32]);
    assert_eq!(verified.release_tuple_digest(), [4; 32]);
    assert_eq!(verified.protected_session_binding(), [9; 32]);
    assert_eq!(verified.desktop_supervisor_generation(), 2);
    assert_eq!(verified.daemon_authority_binding(), [10; 32]);
    assert_eq!(verified.database_generation(), 4);
    assert_eq!(verified.authenticated_tauri_peer_binding(), [5; 32]);
    assert_eq!(verified.native_confirmation_digest(), [6; 32]);
    assert_eq!(verified.broker_process_evidence_digest(), [7; 32]);
    assert_eq!(verified.sequence(), 2);
}

#[test]
fn enrollment_frames_have_the_exact_fixed_width_contract() {
    let authenticator = authenticator(7);
    let (binding, request_frame) = request_frame(&authenticator);
    assert_eq!(request_frame.len(), 4 + 305 + 32);
    let request = authenticator
        .decode_request(&request_frame, &binding, 0, 150)
        .unwrap();
    let admission = authenticator
        .issue_admission(&request, admission_binding(), 2)
        .unwrap();
    let admission_frame =
        ProtectedCredentialEnrollmentControlFrame::Admission(admission).encode_frame();
    assert_eq!(admission_frame.len(), 4 + 313 + 32);
}

#[test]
fn enrollment_request_cannot_splice_admissions_between_authenticators() {
    let authenticator_a = authenticator(10);
    let authenticator_b = authenticator(11);
    let (binding, request_frame) = request_frame(&authenticator_a);
    let request = authenticator_a
        .decode_request(&request_frame, &binding, 0, 150)
        .unwrap();
    let admission_binding = admission_binding();
    let admission = authenticator_a
        .issue_admission(&request, admission_binding.clone(), 2)
        .unwrap();
    let admission_frame =
        ProtectedCredentialEnrollmentControlFrame::Admission(admission).encode_frame();
    assert!(
        authenticator_a
            .decode_admission(&admission_frame, &request, &admission_binding, 1, 150)
            .is_ok()
    );
    assert!(
        authenticator_b
            .issue_admission(&request, admission_binding.clone(), 2)
            .is_err()
    );
    assert!(
        authenticator_b
            .decode_admission(&admission_frame, &request, &admission_binding, 1, 150)
            .is_err()
    );
}

#[test]
fn verified_enrollment_request_redacts_its_private_authenticator_context() {
    let authenticator = authenticator(12);
    let (binding, request_frame) = request_frame(&authenticator);
    let request = authenticator
        .decode_request(&request_frame, &binding, 0, 150)
        .unwrap();
    assert_eq!(
        format!("{request:?}"),
        "VerifiedProtectedCredentialEnrollmentRequest(<authenticated>)"
    );
}

#[test]
fn enrollment_admission_is_a_redacted_non_authority_candidate() {
    let authenticator = authenticator(6);
    let (binding, frame) = request_frame(&authenticator);
    let request = authenticator
        .decode_request(&frame, &binding, 0, 150)
        .unwrap();
    let binding = admission_binding();
    let admission = authenticator
        .issue_admission(&request, binding.clone(), 2)
        .unwrap();
    let verified = authenticator
        .decode_admission(
            &ProtectedCredentialEnrollmentControlFrame::Admission(admission).encode_frame(),
            &request,
            &binding,
            1,
            150,
        )
        .unwrap();
    assert_eq!(
        format!("{verified:?}"),
        "VerifiedProtectedCredentialEnrollmentAdmission(<candidate>)"
    );
}
