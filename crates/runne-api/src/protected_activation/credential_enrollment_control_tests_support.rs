fn uuid(value: u8) -> [u8; 16] {
    [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, value]
}

fn request_binding(
    session_id: [u8; 16],
    daemon_instance_id: [u8; 16],
    supervisor_generation: u64,
    request_id: [u8; 16],
) -> ProtectedCredentialEnrollmentRequestBinding {
    ProtectedCredentialEnrollmentRequestBinding::new(
        uuid(1),
        session_id,
        daemon_instance_id,
        3,
        supervisor_generation,
        request_id,
        [4; 32],
        [5; 32],
        [6; 32],
        [7; 32],
        100,
        200,
    )
    .unwrap()
}

fn request_binding_with(
    release: [u8; 32],
    supervisor: u64,
    peer: [u8; 32],
    confirmation: [u8; 32],
    broker: [u8; 32],
    issued: u64,
    expiry: u64,
) -> ProtectedCredentialEnrollmentRequestBinding {
    ProtectedCredentialEnrollmentRequestBinding::new(
        uuid(1),
        uuid(2),
        uuid(3),
        3,
        supervisor,
        uuid(4),
        release,
        peer,
        confirmation,
        broker,
        issued,
        expiry,
    )
    .unwrap()
}

fn admission_binding() -> ProtectedCredentialEnrollmentAdmissionBinding {
    admission_binding_with([4; 32], 2, [5; 32], [6; 32], [7; 32], 200)
}

fn admission_binding_with(
    release: [u8; 32],
    supervisor: u64,
    peer: [u8; 32],
    confirmation: [u8; 32],
    broker: [u8; 32],
    expiry: u64,
) -> ProtectedCredentialEnrollmentAdmissionBinding {
    ProtectedCredentialEnrollmentAdmissionBinding::new(
        [8; 32],
        release,
        [9; 32],
        supervisor,
        [10; 32],
        4,
        peer,
        confirmation,
        broker,
        uuid(5),
        expiry,
    )
    .unwrap()
}

fn authenticator(byte: u8) -> ProtectedCredentialEnrollmentAuthenticator {
    let keys = LaunchSecret::from_bytes([byte; 32]).unwrap().derive_keys();
    ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(&keys)
}

fn request_frame(
    authenticator: &ProtectedCredentialEnrollmentAuthenticator,
) -> (ProtectedCredentialEnrollmentRequestBinding, Vec<u8>) {
    let binding = request_binding(uuid(2), uuid(3), 2, uuid(4));
    let request = authenticator.issue_request(binding.clone(), 1).unwrap();
    (
        binding,
        ProtectedCredentialEnrollmentControlFrame::Request(request).encode_frame(),
    )
}
