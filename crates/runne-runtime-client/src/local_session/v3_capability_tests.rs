#[test]
fn v3_ready_profile_accepts_the_exact_enrollment_qualified_capability_profile() {
    let capabilities = crate::ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES
        .iter()
        .map(|capability| (*capability).to_owned())
        .collect();
    let (launch, ready, keys) = v3_fixture_with_capabilities(false, 6, capabilities);

    assert!(ProtectedBundledRuntimeProfile::from_ready_v3(&ready, &launch, 1_000, &keys).is_ok());
}

#[test]
fn v3_ready_profile_rejects_arbitrary_or_mixed_capability_profiles() {
    let mut mixed = crate::ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES
        .iter()
        .map(|capability| (*capability).to_owned())
        .collect::<Vec<_>>();
    mixed.push("arbitrary.capability.v1".to_owned());
    for capabilities in [vec!["arbitrary.capability.v1".to_owned()], mixed] {
        let (launch, ready, keys) = v3_fixture_with_capabilities(false, 6, capabilities);
        assert!(matches!(
            ProtectedBundledRuntimeProfile::from_ready_v3(&ready, &launch, 1_000, &keys),
            Err(runne_api::LaunchAuthorityError::ProfileHashMismatch)
        ));
    }
}
