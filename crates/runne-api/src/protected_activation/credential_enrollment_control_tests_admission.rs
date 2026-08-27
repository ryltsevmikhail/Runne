#[test]
fn enrollment_admission_rejects_every_mixed_request_tuple_claim_at_issue_and_decode() {
    let authenticator = authenticator(8);
    let (binding_a, frame_a) = request_frame(&authenticator);
    let request_a = authenticator
        .decode_request(&frame_a, &binding_a, 0, 150)
        .unwrap();
    for (release, supervisor, peer, confirmation, broker) in [
        ([11; 32], 2, [5; 32], [6; 32], [7; 32]),
        ([4; 32], 3, [5; 32], [6; 32], [7; 32]),
        ([4; 32], 2, [12; 32], [6; 32], [7; 32]),
        ([4; 32], 2, [5; 32], [13; 32], [7; 32]),
        ([4; 32], 2, [5; 32], [6; 32], [14; 32]),
    ] {
        let binding_b =
            request_binding_with(release, supervisor, peer, confirmation, broker, 100, 200);
        let frame_b = ProtectedCredentialEnrollmentControlFrame::Request(
            authenticator.issue_request(binding_b.clone(), 1).unwrap(),
        )
        .encode_frame();
        let request_b = authenticator
            .decode_request(&frame_b, &binding_b, 0, 150)
            .unwrap();
        let admission_b =
            admission_binding_with(release, supervisor, peer, confirmation, broker, 200);
        assert!(
            authenticator
                .issue_admission(&request_a, admission_b.clone(), 2)
                .is_err()
        );
        let frame = ProtectedCredentialEnrollmentControlFrame::Admission(
            authenticator
                .issue_admission(&request_b, admission_b.clone(), 2)
                .unwrap(),
        )
        .encode_frame();
        assert!(
            authenticator
                .decode_admission(&frame, &request_a, &admission_b, 1, 150)
                .is_err()
        );
    }
}

#[test]
fn enrollment_admission_cannot_extend_or_revive_the_request_window() {
    let authenticator = authenticator(9);
    let binding = request_binding_with([4; 32], 2, [5; 32], [6; 32], [7; 32], 100, 200);
    let request_frame = ProtectedCredentialEnrollmentControlFrame::Request(
        authenticator.issue_request(binding.clone(), 1).unwrap(),
    )
    .encode_frame();
    let request = authenticator
        .decode_request(&request_frame, &binding, 0, 150)
        .unwrap();
    assert!(
        authenticator
            .issue_admission(
                &request,
                admission_binding_with([4; 32], 2, [5; 32], [6; 32], [7; 32], 201),
                2,
            )
            .is_err()
    );
    assert!(
        ProtectedCredentialEnrollmentAdmissionBinding::new(
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
            u64::MAX,
        )
        .is_err()
    );
    let admission = authenticator
        .issue_admission(&request, admission_binding(), 2)
        .unwrap();
    let frame = ProtectedCredentialEnrollmentControlFrame::Admission(admission).encode_frame();
    assert!(
        authenticator
            .decode_admission(&frame, &request, &admission_binding(), 1, 99)
            .is_err()
    );
    assert!(
        authenticator
            .decode_admission(&frame, &request, &admission_binding(), 1, 201)
            .is_err()
    );
}
