use super::*;

fn id(byte: u8) -> [u8; 16] {
    let mut id = [byte; 16];
    id[6] = 0x70;
    id[8] = 0x80;
    id
}

#[test]
fn linux_arm64_prelude_roundtrips_without_macos_relabeling() {
    let prelude = DaemonEnrollmentLaunchPreludeV1::linux_arm64(
        id(1),
        id(2),
        [3; 32],
        [4; 32],
        [5; 32],
        [6; 32],
        [7; 32],
        1,
        10,
        20,
    )
    .unwrap();
    assert_eq!(
        DaemonEnrollmentLaunchPreludeV1::decode_frame(&prelude.encode_frame().unwrap()).unwrap(),
        prelude
    );
}

#[test]
fn linux_arm64_binding_roundtrips_without_macos_relabeling() {
    let binding = ProtectedCredentialEnrollmentLaunchBindingV1::linux_arm64(
        [1; 32],
        [2; 32],
        [3; 32],
        [4; 32],
        1,
        CredentialBrokerTransferCommitment::from_authenticated_bytes([5; 32]),
    )
    .unwrap();
    let mut encoder = CborEncoder::new();
    encode_enrollment_binding(&mut encoder, &binding);
    let bytes = encoder.into_bytes();
    let mut decoder = CborDecoder::new(&bytes);
    assert_eq!(decode_enrollment_binding(&mut decoder).unwrap(), binding);
}

#[test]
fn linux_x86_64_roundtrips_with_distinct_authenticated_target() {
    let prelude = DaemonEnrollmentLaunchPreludeV1::linux_x86_64(
        id(1),
        id(2),
        [3; 32],
        [4; 32],
        [5; 32],
        [6; 32],
        [7; 32],
        1,
        10,
        20,
    )
    .unwrap();
    assert_eq!((prelude.platform(), prelude.architecture()), (2, 3));
    let decoded =
        DaemonEnrollmentLaunchPreludeV1::decode_frame(&prelude.encode_frame().unwrap()).unwrap();
    assert_eq!(decoded, prelude);
    let binding = ProtectedCredentialEnrollmentLaunchBindingV1::linux_x86_64(
        [1; 32],
        [2; 32],
        [3; 32],
        [4; 32],
        1,
        CredentialBrokerTransferCommitment::from_authenticated_bytes([5; 32]),
    )
    .unwrap();
    let mut encoder = CborEncoder::new();
    encode_enrollment_binding(&mut encoder, &binding);
    let bytes = encoder.into_bytes();
    assert_eq!(
        decode_enrollment_binding(&mut CborDecoder::new(&bytes)).unwrap(),
        binding
    );
    let mut other = prelude.clone();
    other.architecture = 2;
    let keys = enrollment_launch_v3_tests::fixture().2;
    let auth = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    assert_ne!(
        auth.enrollment_launch_commitment(&prelude),
        auth.enrollment_launch_commitment(&other)
    );
}

#[test]
fn mixed_and_unknown_targets_are_rejected_without_normalization() {
    for (platform, architecture) in [(1, 2), (1, 3), (2, 1), (0, 0), (3, 3), (2, 4)] {
        let mut prelude = DaemonEnrollmentLaunchPreludeV1::macos_arm64(
            id(1),
            id(2),
            [3; 32],
            [4; 32],
            [5; 32],
            [6; 32],
            [7; 32],
            1,
            10,
            20,
        )
        .unwrap();
        prelude.platform = platform;
        prelude.architecture = architecture;
        assert!(
            DaemonEnrollmentLaunchPreludeV1::decode_frame(&prelude.encode_frame().unwrap())
                .is_err()
        );
    }
    for architecture in [
        EnrollmentArchitectureV1::Arm64,
        EnrollmentArchitectureV1::X86_64,
    ] {
        let mut binding = ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            1,
            CredentialBrokerTransferCommitment::from_authenticated_bytes([5; 32]),
        )
        .unwrap();
        binding.architecture = architecture;
        let mut encoder = CborEncoder::new();
        encode_enrollment_binding(&mut encoder, &binding);
        let bytes = encoder.into_bytes();
        assert!(decode_enrollment_binding(&mut CborDecoder::new(&bytes)).is_err());
    }
}
