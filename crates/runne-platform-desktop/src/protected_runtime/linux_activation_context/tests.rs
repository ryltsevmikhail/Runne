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

#[test]
fn activation_writer_comes_from_desktop_package_when_daemon_is_staged() {
    let directory = tempfile::tempdir().unwrap();
    let package = directory.path().join("package/MacOS");
    let stage = directory
        .path()
        .join("runtime/.desktop-protected-activation/executables-v1");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::create_dir_all(&stage).unwrap();
    let desktop = package.join("runne-desktop");
    let packaged_writer = package.join("runne");
    let staged_daemon = stage.join("signed-daemon.runned");
    let staged_writer = stage.join("staged-writer.runned");
    std::fs::write(&desktop, b"desktop").unwrap();
    std::fs::write(&packaged_writer, b"signed package writer").unwrap();
    std::fs::write(&staged_daemon, b"daemon").unwrap();
    std::fs::write(&staged_writer, b"different writer").unwrap();
    std::os::unix::fs::symlink(&staged_writer, stage.join("runne")).unwrap();

    assert_eq!(
        super::package_writer_for_desktop(&desktop),
        Some(packaged_writer)
    );
    assert!(super::package_writer_for_desktop(&staged_daemon).is_none());
    std::fs::remove_file(package.join("runne")).unwrap();
    assert!(super::package_writer_for_desktop(&desktop).is_none());
}
