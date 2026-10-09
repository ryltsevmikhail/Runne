use super::support;
use runne_application::permission_modes::{
    FilesystemPermission, NetworkScope, admit_invocation_scope,
};
use runne_application::project_trust::ManagedEffectClass;
use runne_platform::local_command_linux::{
    LinuxCommandContainmentV2, LinuxCommandExecutable, LinuxCommandSpec, SealedExecutableSnapshot,
};
use std::ffi::OsString;

#[test]
fn read_deny_does_not_grant_dynamic_loader_reads() {
    eprintln!("RUN: read_deny_does_not_grant_dynamic_loader_reads");
    let Some(fixture) = support::fixture(
        NetworkScope::None,
        [FilesystemPermission::Create, FilesystemPermission::Write],
        Some(ManagedEffectClass::FsRead),
    ) else {
        return;
    };
    assert_eq!(support::run_python(&fixture, "pass", &[]), 127);
    fixture.cleanup();
}

#[test]
#[cfg(target_arch = "x86_64")]
fn read_deny_allows_a_static_sealed_executable() {
    eprintln!("RUN: read_deny_allows_a_static_sealed_executable");
    let Some(fixture) = support::fixture(
        NetworkScope::None,
        [FilesystemPermission::Create, FilesystemPermission::Write],
        Some(ManagedEffectClass::FsRead),
    ) else {
        return;
    };
    let (_dir, sealed): (tempfile::TempDir, SealedExecutableSnapshot) =
        support::static_exit_snapshot();
    let receipt = admit_invocation_scope(&fixture.scope, &fixture.admission)
        .expect("ReadDeny native receipt");
    let command = LinuxCommandSpec {
        executable: LinuxCommandExecutable::SealedSnapshot(&sealed),
        workspace: &fixture.workspace_fd,
        cwd: &fixture.cwd,
        argv: vec![OsString::from("sealed-static-exit")],
        env: Vec::new(),
    };
    let containment = LinuxCommandContainmentV2::SameUserCompositeV2 {
        scope: &fixture.scope,
        receipt,
        admission: &fixture.admission,
    };
    command
        .preflight_with_containment_v2(containment)
        .expect("static profile preflight");
    let mut child = command
        .spawn_gated_with_containment_v2(&fixture.area, containment)
        .expect("stopped static child");
    child.release().expect("GO");
    assert_eq!(child.wait(std::time::Duration::from_secs(5)).unwrap(), 0);
    let proof = fixture.area.prove_empty().expect("area empty");
    proof.revalidate().unwrap();
    fixture.cleanup();
}
