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
