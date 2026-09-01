#[test]
fn installed_enrollment_confirmation_requires_a_ready_supervisor() {
    let fixture = crate::tests::OwnerPrivateBundledRuntimeFixture::new();
    let spec = ProtectedBundledRuntimeLaunchSpec::new(fixture.daemon(), &fixture.runtime_root())
        .expect("trusted launch spec");
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);

    let error = supervisor
        .confirm_installed_native_enrollment(
            crate::PreparedInstalledNativeEnrollment::test_only_for_state_rejection(),
        )
        .expect_err("an absent supervisor must not mint enrollment evidence");

    assert_eq!(error, ProtectedBundledRuntimeError::InvalidState);
}

#[test]
fn installed_enrollment_evidence_has_no_copyable_or_serializable_surface() {
    let source = include_str!("../updater_metadata/enrollment_tuple/live_daemon.rs");
    for forbidden in [
        "derive(Clone",
        "impl Clone for PreparedInstalledNativeEnrollment",
        "impl Clone for ConfirmedInstalledNativeEnrollment",
        "impl Serialize for",
        "pub fn session",
        "pub fn daemon",
        "pub fn release_tuple",
    ] {
        assert!(!source.contains(forbidden), "forbidden evidence surface: {forbidden}");
    }
}

#[test]
fn enrollment_transition_queues_v3_profile_before_any_writer_handoff_surface() {
    let source = include_str!("native_enrollment.rs");
    assert!(!source.contains("begin_credential_enrollment_handoff"));
    let transition = source
        .find("begin_credential_enrollment_transition")
        .expect("split transition entry point");
    let queued = source[transition..]
        .find("self.pending_profile = Some(profile)")
        .expect("transitioned profile retained by supervisor");
    let handoff = source
        .find("pub fn run_credential_writer_handoff")
        .expect("separate post-Begin handoff entry point");
    assert!(transition + queued < handoff);
}
