#![cfg(all(target_os = "linux", feature = "test-support"))]

use std::fs;

use runne_platform_desktop::{
    RootHandleBrokerError, VerifiedRootHandle, launcher_spawn_attempt_count,
};

#[test]
fn allowed_file_is_validated_but_editor_remains_unavailable_without_spawn() {
    let workspace = tempfile::tempdir().unwrap();
    fs::write(workspace.path().join("notes.md"), "safe").unwrap();
    let canonical = fs::canonicalize(workspace.path()).unwrap();
    let root = VerifiedRootHandle::open(&canonical).unwrap();
    let attempts = launcher_spawn_attempt_count();

    assert!(matches!(
        root.launch_system_default_editor("notes.md"),
        Err(RootHandleBrokerError::Unavailable)
    ));
    assert_eq!(launcher_spawn_attempt_count(), attempts);
}

#[test]
fn replaced_allowed_name_with_outside_symlink_is_rejected_without_spawn() {
    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(workspace.path().join("notes.md"), "safe").unwrap();
    fs::write(outside.path().join("secret.txt"), "outside").unwrap();
    let canonical = fs::canonicalize(workspace.path()).unwrap();
    let root = VerifiedRootHandle::open(&canonical).unwrap();

    fs::remove_file(workspace.path().join("notes.md")).unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("secret.txt"),
        workspace.path().join("notes.md"),
    )
    .unwrap();
    let attempts = launcher_spawn_attempt_count();

    assert!(matches!(
        root.launch_system_default_editor("notes.md"),
        Err(RootHandleBrokerError::Rejected)
    ));
    assert_eq!(launcher_spawn_attempt_count(), attempts);
}
