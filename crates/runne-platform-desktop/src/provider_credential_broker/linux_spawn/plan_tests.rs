//! Plan seam tests, split from `plan.rs` so the plan surface and its tests
//! each stay within the file line budget. Content and assertions are
//! unchanged from their previous inline forms.

#[cfg(all(test, feature = "linux-native-enrollment-qualification"))]
#[test]
fn qualification_plan_forwards_only_the_validated_private_fixture_root() {
    use super::super::SessionBusAddress;
    use runne_platform_ports::provider_credential_broker::{
        VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
    };
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    let parent = tempfile::tempdir().unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = parent.path().join("fixture");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let bus_path = parent.path().join("bus");
    let _bus = UnixListener::bind(&bus_path).unwrap();
    let address = SessionBusAddress::for_tests(&bus_path).unwrap();
    let spec = VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new("/bundle/runne".into(), [1; 32], [2; 32]).unwrap(),
    );

    let with_fixture = super::build_plan(&spec, &address, 10, 11, 12, None, Some(&root)).unwrap();
    assert_eq!(with_fixture.environment.len(), 2);
    assert!(with_fixture.environment.iter().any(|value| {
        value.to_bytes().starts_with(
            format!("{}=", crate::provider_credential_broker::linux_native_enrollment_qualification::FIXTURE_ROOT_ENV).as_bytes(),
        )
    }));
    let default = super::build_plan(&spec, &address, 10, 11, 12, None, None).unwrap();
    assert_eq!(default.environment.len(), 1);
}

#[cfg(all(
    test,
    not(any(
        feature = "test-support",
        feature = "linux-native-enrollment-qualification"
    ))
))]
#[test]
fn default_plan_rejects_qualification_fixture_forwarding() {
    use super::super::SessionBusAddress;
    use runne_platform_ports::provider_credential_broker::{
        VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
    };
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    let parent = tempfile::tempdir().unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = parent.path().join("fixture");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let bus_path = parent.path().join("bus");
    let _bus = UnixListener::bind(&bus_path).unwrap();
    let address = SessionBusAddress::for_tests(&bus_path).unwrap();
    let spec = VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new("/bundle/runne".into(), [1; 32], [2; 32]).unwrap(),
    );
    assert!(super::build_plan(&spec, &address, 10, 11, 12, None, Some(&root)).is_err());
    assert_eq!(
        super::build_plan(&spec, &address, 10, 11, 12, None, None)
            .unwrap()
            .environment
            .len(),
        1
    );
}
