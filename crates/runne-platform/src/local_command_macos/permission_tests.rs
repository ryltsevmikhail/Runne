use super::*;
use runne_domain::task_run::TaskRunExecutable;
use std::os::unix::fs::PermissionsExt;

fn command() -> TaskRunLocalCommand {
    TaskRunLocalCommand::new(
        TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
        ".".into(),
        vec!["bin/tool".into(), "--check".into()],
        vec![("A".into(), "1".into())],
    )
    .unwrap()
}

fn sealed() -> SealedExecutableSnapshot {
    let source = File::open("/bin/echo").unwrap();
    SealedExecutableSnapshot::from_held_file(&source).unwrap()
}

#[test]
fn preparation_records_the_same_facts_as_the_shared_digest() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("work")).unwrap();
    let workspace = File::open(directory.path()).unwrap();
    let cwd = File::open(directory.path().join("work")).unwrap();
    let owner = MacOsPermissionOwnerV1::new().unwrap();
    let prepared = owner
        .preparation()
        .prepare_target(command(), &workspace, &cwd, sealed())
        .unwrap();
    let observation = prepared.observation();
    assert_eq!(observation.owner_generation(), 1);
    assert_eq!(observation.target_version(), 1);
    assert_eq!(
        observation.workspace_identity(),
        &digest::descriptor_identity(&workspace).unwrap()
    );
    assert_eq!(
        observation.cwd_identity(),
        &digest::descriptor_identity(&cwd).unwrap()
    );
    assert_eq!(
        observation.executable_digest(),
        prepared.snapshot().digest()
    );
    assert_eq!(
        observation.environment_digest(),
        &digest::environment_digest(&command()).unwrap()
    );
    assert_eq!(observation.schema_digest(), &digest::schema_digest());
    assert_eq!(
        observation.normalized_arguments_digest(),
        &command().intent_digest()
    );
    prepared.verify_held().unwrap();
}

#[test]
fn identical_bytes_in_distinct_sealed_objects_have_distinct_targets() {
    let directory = tempfile::tempdir().unwrap();
    let workspace = File::open(directory.path()).unwrap();
    let preparation = MacOsPermissionOwnerV1::new().unwrap().preparation();
    let first = preparation
        .prepare_target(command(), &workspace, &workspace, sealed())
        .unwrap();
    let second = preparation
        .prepare_target(command(), &workspace, &workspace, sealed())
        .unwrap();
    assert_eq!(
        first.observation().workspace_identity(),
        second.observation().workspace_identity()
    );
    assert_ne!(
        first.observation().target_identity(),
        second.observation().target_identity()
    );
}

#[test]
fn a_different_cwd_changes_both_identities() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("work")).unwrap();
    let workspace = File::open(directory.path()).unwrap();
    let work = File::open(directory.path().join("work")).unwrap();
    let preparation = MacOsPermissionOwnerV1::new().unwrap().preparation();
    let at_root = preparation
        .prepare_target(command(), &workspace, &workspace, sealed())
        .unwrap();
    let at_work = preparation
        .prepare_target(command(), &workspace, &work, sealed())
        .unwrap();
    assert_ne!(
        at_root.observation().cwd_identity(),
        at_work.observation().cwd_identity()
    );
    assert_ne!(
        at_root.observation().target_identity(),
        at_work.observation().target_identity()
    );
}

#[test]
fn rejects_a_regular_file_as_workspace_or_cwd() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("notes.txt");
    std::fs::write(&path, b"not a directory").unwrap();
    let workspace = File::open(directory.path()).unwrap();
    let file = File::open(&path).unwrap();
    let preparation = MacOsPermissionOwnerV1::new().unwrap().preparation();
    assert_eq!(
        preparation
            .prepare_target(command(), &file, &workspace, sealed())
            .err(),
        Some(CommandError::Invalid)
    );
    assert_eq!(
        preparation
            .prepare_target(command(), &workspace, &file, sealed())
            .err(),
        Some(CommandError::Invalid)
    );
}

#[test]
fn verify_held_rejects_a_tampered_sealed_image() {
    let directory = tempfile::tempdir().unwrap();
    let workspace = File::open(directory.path()).unwrap();
    let prepared = MacOsPermissionOwnerV1::new()
        .unwrap()
        .preparation()
        .prepare_target(command(), &workspace, &workspace, sealed())
        .unwrap();
    let path = prepared.snapshot().path().to_path_buf();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, b"tampered executable").unwrap();
    assert_eq!(prepared.verify_held(), Err(CommandError::Unverified));
    assert_eq!(
        prepared.snapshot().validate_seals(),
        Err(CommandError::Unverified)
    );
}

#[test]
fn verify_held_rejects_a_replaced_image_at_the_private_path() {
    let directory = tempfile::tempdir().unwrap();
    let workspace = File::open(directory.path()).unwrap();
    let prepared = MacOsPermissionOwnerV1::new()
        .unwrap()
        .preparation()
        .prepare_target(command(), &workspace, &workspace, sealed())
        .unwrap();
    let path = prepared.snapshot().path().to_path_buf();
    let held = path.with_extension("held");
    std::fs::rename(&path, &held).unwrap();
    std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
    assert_eq!(prepared.snapshot().validate_seals(), Ok(()));
    assert_eq!(prepared.verify_held(), Err(CommandError::Unverified));
}

#[test]
fn verify_held_rejects_a_symlink_at_the_private_path() {
    let directory = tempfile::tempdir().unwrap();
    let workspace = File::open(directory.path()).unwrap();
    let prepared = MacOsPermissionOwnerV1::new()
        .unwrap()
        .preparation()
        .prepare_target(command(), &workspace, &workspace, sealed())
        .unwrap();
    let path = prepared.snapshot().path().to_path_buf();
    std::fs::rename(&path, path.with_extension("held")).unwrap();
    std::os::unix::fs::symlink("/bin/echo", &path).unwrap();
    assert_eq!(prepared.verify_held(), Err(CommandError::Unverified));
}

#[test]
fn preparation_view_keeps_the_owner_identity_alive() {
    let directory = tempfile::tempdir().unwrap();
    let workspace = File::open(directory.path()).unwrap();
    let first_owner = MacOsPermissionOwnerV1::new().unwrap();
    let second_owner = MacOsPermissionOwnerV1::new().unwrap();
    let first = first_owner.preparation();
    let second = second_owner.preparation();
    drop(first_owner);
    let prepared = first
        .prepare_target(command(), &workspace, &workspace, sealed())
        .unwrap();
    let other = second
        .prepare_target(command(), &workspace, &workspace, sealed())
        .unwrap();
    assert_ne!(
        prepared.observation().owner_id(),
        other.observation().owner_id()
    );
    assert_eq!(prepared.observation().owner_generation(), 1);
    assert_eq!(
        prepared.observation().owner_id(),
        first
            .prepare_target(command(), &workspace, &workspace, sealed())
            .unwrap()
            .observation()
            .owner_id()
    );
}
