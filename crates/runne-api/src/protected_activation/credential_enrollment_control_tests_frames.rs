#[test]
fn enrollment_frames_reject_each_authenticated_security_binding_tamper() {
    let authenticator = authenticator(2);
    let (binding, request_frame) = request_frame(&authenticator);
    for index in [13, 29, 45, 61, 69, 77, 93, 125, 157, 189, 221, 229, 237] {
        let mut altered = request_frame.clone();
        altered[index] ^= 1;
        assert!(
            authenticator
                .decode_request(&altered, &binding, 0, 150)
                .is_err(),
            "request byte {index}"
        );
    }
    let request = authenticator
        .decode_request(&request_frame, &binding, 0, 150)
        .unwrap();
    let admission_binding = admission_binding();
    let admission = authenticator
        .issue_admission(&request, admission_binding.clone(), 2)
        .unwrap();
    let admission_frame =
        ProtectedCredentialEnrollmentControlFrame::Admission(admission).encode_frame();
    for index in [13, 45, 77, 109, 141, 149, 181, 189, 221, 253, 285, 301, 309] {
        let mut altered = admission_frame.clone();
        altered[index] ^= 1;
        assert!(
            authenticator
                .decode_admission(&altered, &request, &admission_binding, 1, 150)
                .is_err(),
            "admission byte {index}"
        );
    }
}

#[test]
fn enrollment_frames_close_key_window_sequence_and_tuple_substitution() {
    let authenticator = authenticator(3);
    let (binding, frame) = request_frame(&authenticator);
    assert!(
        crate::ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(
            &LaunchSecret::from_bytes([4; 32]).unwrap().derive_keys(),
        )
        .decode_request(&frame, &binding, 0, 150)
        .is_err()
    );
    assert!(
        authenticator
            .decode_request(&frame, &binding, 0, 99)
            .is_err()
    );
    assert!(
        authenticator
            .decode_request(&frame, &binding, 0, 201)
            .is_err()
    );
    assert!(
        authenticator
            .decode_request(&frame, &binding, 1, 150)
            .is_err()
    );
    for expected in [
        request_binding(uuid(9), uuid(3), 2, uuid(4)),
        request_binding(uuid(2), uuid(9), 2, uuid(4)),
        request_binding(uuid(2), uuid(3), 9, uuid(4)),
    ] {
        assert!(
            authenticator
                .decode_request(&frame, &expected, 0, 150)
                .is_err()
        );
    }
    let request = authenticator
        .decode_request(&frame, &binding, 0, 150)
        .unwrap();
    let admission_binding = admission_binding();
    let admission = authenticator
        .issue_admission(&request, admission_binding.clone(), 2)
        .unwrap();
    let admission_frame =
        ProtectedCredentialEnrollmentControlFrame::Admission(admission).encode_frame();
    let other_binding = request_binding(uuid(2), uuid(3), 2, uuid(9));
    let other_frame = ProtectedCredentialEnrollmentControlFrame::Request(
        authenticator
            .issue_request(other_binding.clone(), 1)
            .unwrap(),
    )
    .encode_frame();
    let other_request = authenticator
        .decode_request(&other_frame, &other_binding, 0, 150)
        .unwrap();
    assert!(
        authenticator
            .decode_admission(&admission_frame, &other_request, &admission_binding, 1, 150)
            .is_err()
    );
}

#[test]
fn enrollment_frames_reject_malformed_prefix_magic_phase_length_and_trailing_data() {
    let authenticator = authenticator(5);
    let (binding, frame) = request_frame(&authenticator);
    for mut altered in [
        {
            let mut value = frame.clone();
            value[..4].copy_from_slice(&1_u32.to_be_bytes());
            value
        },
        {
            let mut value = frame.clone();
            value[4..12].copy_from_slice(b"GCRHCTL3");
            value
        },
        {
            let mut value = frame.clone();
            value[12] = 9;
            value
        },
        {
            let mut value = frame.clone();
            value.push(0);
            value
        },
        frame[..frame.len() - 1].to_vec(),
    ] {
        assert!(
            authenticator
                .decode_request(&altered, &binding, 0, 150)
                .is_err()
        );
        altered.clear();
    }
}
