use super::NativeEnrollmentQualificationRowV1;

#[test]
fn qualified_v3_metadata_produces_only_the_v3_release_candidate() {
    let (mut metadata, trust, _) = super::tests::pinned_test_facts();
    metadata.targets.target.native_enrollment_tuple = None;
    let tuple = super::tuple_v3_tests::tuple(&metadata.targets.target);
    let row = NativeEnrollmentQualificationRowV1::new_v3(
        &metadata.targets.target,
        &tuple,
        "a".repeat(64),
        90,
        200,
    )
    .unwrap();
    metadata.targets.target.native_enrollment_tuple_v3 = Some(
        tuple
            .with_qualification(&metadata.targets.target, row)
            .unwrap(),
    );
    super::tuple_v3_tests::resign_targets(&mut metadata);

    let verified = super::verify_signed_update_metadata_v2(&metadata, &trust, 100).unwrap();
    assert!(verified.qualified_release_candidate().is_none());
    let candidate = verified.qualified_release_candidate_v3().unwrap();
    assert_ne!(candidate.release_binding_digest(), [0; 32]);
    assert_eq!(
        candidate.native_enrollment_tuple().tuple_digest(),
        verified
            .native_enrollment_tuple_v3()
            .unwrap()
            .tuple_digest(),
    );
}

#[test]
fn exact_installed_release_preserves_the_qualified_v3_tuple_for_writer_admission() {
    let (mut metadata, trust, _) = super::tests::pinned_test_facts();
    metadata.targets.target.native_enrollment_tuple = None;
    let tuple = super::tuple_v3_tests::tuple(&metadata.targets.target);
    let row = NativeEnrollmentQualificationRowV1::new_v3(
        &metadata.targets.target,
        &tuple,
        "a".repeat(64),
        90,
        200,
    )
    .unwrap();
    metadata.targets.target.native_enrollment_tuple_v3 = Some(
        tuple
            .with_qualification(&metadata.targets.target, row)
            .unwrap(),
    );
    super::tuple_v3_tests::resign_targets(&mut metadata);
    let verified = super::verify_signed_update_metadata_v2(&metadata, &trust, 100).unwrap();
    let expected_release = verified
        .qualified_release_candidate_v3()
        .unwrap()
        .release_binding_digest();
    let canonical = serde_json::to_vec(&metadata).unwrap();

    let exact =
        super::verify_exact_signed_installed_release_v2(&canonical, &trust, expected_release, 100)
            .unwrap();

    let exact_tuple = exact.native_enrollment_tuple_v3().unwrap();
    assert_eq!(
        exact_tuple.credential_service_digest(),
        [u8::from_str_radix("44", 16).unwrap(); 32]
    );
    assert_eq!(exact_tuple.writer_identity().identifier(), "runne");
}
