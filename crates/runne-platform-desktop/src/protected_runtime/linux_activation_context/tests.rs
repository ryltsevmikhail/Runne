use super::*;
use crate::protected_runtime::{
    DesktopLaunchRequest, DesktopReady, DevelopmentBundledRuntimeLauncher,
    ProtectedBundledRuntimeLaunchSpec, v3_fixture,
};

#[test]
fn live_authority_is_preserved_for_v3() {
    let (request, ready, _, _) = v3_fixture();
    let expected = *ready.stable().authority_id();
    let activation = DesktopReady::V3(ready)
        .into_process_activation(DesktopLaunchRequest::V3(request))
        .unwrap();
    assert_eq!(activation_binding(&activation).unwrap().1, expected);
}

#[test]
fn absent_supervisor_cannot_supply_activation_facts() {
    let fixture = crate::tests::OwnerPrivateBundledRuntimeFixture::new();
    let spec =
        ProtectedBundledRuntimeLaunchSpec::new(fixture.daemon(), &fixture.runtime_root()).unwrap();
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
    assert_eq!(
        supervisor.linux_activation_context(),
        Err(ProtectedBundledRuntimeError::InvalidState)
    );
}

#[test]
fn measurement_requires_the_daemon_admitted_by_the_transcript() {
    use sha2::{Digest, Sha256};
    let root = tempfile::tempdir().unwrap();
    let artifact = root.path().join("artifact");
    std::fs::write(&artifact, b"measured fixture").unwrap();
    let layout = LinuxInstallationLayout {
        runtime_root: root.path(),
        desktop_image: &artifact,
        writer_image: &artifact,
        daemon_image: &artifact,
        machine_id_path: &artifact,
    };
    let expected = Sha256::digest(b"measured fixture").into();
    assert_eq!(
        measure(&layout, [7; 16], expected)
            .unwrap()
            .runtime_authority_id,
        [7; 16]
    );
    std::fs::write(&artifact, b"substituted image").unwrap();
    assert!(measure(&layout, [7; 16], expected).is_err());
}
