#[test]
fn enrollment_bindings_reject_zero_and_noncanonical_security_values() {
    assert!(
        ProtectedCredentialEnrollmentRequestBinding::new(
            [0; 16],
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
            100,
            200,
        )
        .is_err()
    );
    assert!(
        ProtectedCredentialEnrollmentRequestBinding::new(
            uuid(1),
            uuid(2),
            uuid(3),
            3,
            2,
            uuid(4),
            [4; 32],
            [5; 32],
            [6; 32],
            [7; 32],
            [0; 32],
            [9; 32],
            [10; 32],
            100,
            200,
        )
        .is_err()
    );
    assert!(
        ProtectedCredentialEnrollmentRequestBinding::new(
            [1; 16],
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
            100,
            200,
        )
        .is_err()
    );
    assert!(
        ProtectedCredentialEnrollmentAdmissionBinding::new(
            [0; 32],
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
        .is_err()
    );
}
