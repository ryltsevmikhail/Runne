use super::*;

#[test]
fn enrollment_transition_v3_resource_locator_is_required_bounded_and_mac_covered() {
    let (_, _, owned, keys) = fixture();
    let mut request = ProtectedCredentialEnrollmentPrepareV2::new(
        owned.clone(),
        1,
        [31; 32],
        [32; 32],
        [33; 32],
        [34; 32],
        1,
    )
    .unwrap()
    .with_resource_directory_hint("/opt/runne/resources")
    .unwrap();
    request.sign(&keys);
    let frame = request.encode_frame().unwrap();
    let decoded = ProtectedCredentialEnrollmentPrepareV2::decode_frame(&frame).unwrap();
    assert_eq!(
        decoded.resource_directory_hint(),
        Some("/opt/runne/resources")
    );
    decoded.verify_exact(&owned, 0, &keys).unwrap();
    let view = decoded.verify_exact_view(&owned, 0, &keys).unwrap();
    assert_eq!(view.resource_directory_hint(), Some("/opt/runne/resources"));

    let mut changed = decoded.clone();
    changed.resource_directory_hint = Some("/opt/other/resources".to_owned());
    assert!(changed.verify_exact(&owned, 0, &keys).is_err());

    let mut downgraded = decoded.clone();
    downgraded.schema_version = PROTOCOL_SCHEMA_VERSION_V2;
    assert!(
        ProtectedCredentialEnrollmentPrepareV2::decode_frame(&downgraded.encode_frame().unwrap())
            .is_err()
    );
    assert!(
        ProtectedCredentialEnrollmentPrepareV2::new(
            owned.clone(),
            1,
            [31; 32],
            [32; 32],
            [33; 32],
            [34; 32],
            1,
        )
        .unwrap()
        .with_resource_directory_hint("relative/resources")
        .is_err()
    );
    assert!(
        ProtectedCredentialEnrollmentPrepareV2::new(
            owned, 1, [31; 32], [32; 32], [33; 32], [34; 32], 1,
        )
        .unwrap()
        .with_resource_directory_hint(&format!("/{}", "x".repeat(MAX_TEXT_BYTES)))
        .is_err()
    );
}
