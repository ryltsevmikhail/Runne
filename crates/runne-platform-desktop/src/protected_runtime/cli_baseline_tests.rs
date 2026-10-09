use std::os::unix::fs::symlink;

fn make_private(path: &std::path::Path) {
    std::fs::create_dir_all(path).expect("create private fixture directory");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("set private fixture mode");
}

fn rejected_with_container(name: &str, create: impl FnOnce(&std::path::Path)) {
    let parent = tempfile::tempdir().expect("private fixture parent");
    make_private(parent.path());
    create(&parent.path().join(name));
    let root = parent.path().join("runtime");
    assert_eq!(
        require_linux_cli_baseline_root(&root),
        Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable)
    );
}

fn rejected_with_runtime_update(create: impl FnOnce(&std::path::Path)) {
    let parent = tempfile::tempdir().expect("private fixture parent");
    make_private(parent.path());
    let root = parent.path().join("runtime");
    make_private(&root);
    create(&root.join("updates"));
    assert_eq!(
        require_linux_cli_baseline_root(&root),
        Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable)
    );
}

#[test]
fn allows_missing_legacy_containers_without_creating_runtime_state() {
    let parent = tempfile::tempdir().expect("private fixture parent");
    make_private(parent.path());
    let root = parent.path().join("runtime");

    require_linux_cli_baseline_root(&root).expect("absent legacy containers allow baseline");

    assert!(!root.exists());
    assert!(!parent.path().join("updates").exists());
    assert!(!parent.path().join(".runne-native-enrollment").exists());
}

#[test]
fn permits_existing_private_runtime_root_for_reopen_without_changing_it() {
    let parent = tempfile::tempdir().expect("private fixture parent");
    make_private(parent.path());
    let root = parent.path().join("runtime");
    make_private(&root);
    let sentinel = root.join("stable-state");
    std::fs::write(&sentinel, b"existing baseline state").expect("write sentinel");
    let mode = std::fs::symlink_metadata(&root)
        .expect("root metadata")
        .permissions()
        .mode();

    require_linux_cli_baseline_root(&root).expect("existing private baseline root is reusable");

    assert_eq!(
        std::fs::read(&sentinel).expect("read sentinel"),
        b"existing baseline state"
    );
    assert_eq!(
        std::fs::symlink_metadata(&root)
            .expect("root metadata after guard")
            .permissions()
            .mode(),
        mode
    );
}

#[test]
fn rejects_each_existing_legacy_container_shape() {
    for name in ["updates", ".runne-native-enrollment"] {
        rejected_with_container(name, |path| {
            std::fs::write(path, b"legacy file").expect("legacy file");
        });
        rejected_with_container(name, |path| {
            symlink(path.with_extension("missing-target"), path).expect("legacy symlink");
        });
    }
}

#[test]
fn rejects_updates_inside_existing_runtime_root() {
    rejected_with_runtime_update(|path| {
        std::fs::write(path, b"runtime update state").expect("updates file");
    });
    rejected_with_runtime_update(|path| {
        std::fs::create_dir(path).expect("updates directory");
    });
    rejected_with_runtime_update(|path| {
        symlink(path.with_extension("missing-target"), path).expect("updates symlink");
    });
}

#[test]
fn permits_existing_empty_private_native_enrollment_directory_read_only() {
    let parent = tempfile::tempdir().expect("private fixture parent");
    make_private(parent.path());
    let root = parent.path().join("runtime");
    let enrollment = parent.path().join(".runne-native-enrollment");
    make_private(&enrollment);

    require_linux_cli_baseline_root(&root).expect("empty private container is desktop baseline");

    assert!(enrollment.is_dir());
    assert_eq!(
        std::fs::read_dir(enrollment)
            .expect("read container")
            .count(),
        0
    );
    assert!(!root.exists());
    assert!(!parent.path().join("updates").exists());
}

#[test]
fn rejects_numbered_native_journal_and_corrupt_container_mode() {
    rejected_with_container(".runne-native-enrollment", |path| {
        std::fs::create_dir(path).expect("native enrollment container");
        std::fs::write(path.join("journal-0007.json"), b"journal")
            .expect("numbered native journal");
    });
    rejected_with_container(".runne-native-enrollment", |path| {
        std::fs::create_dir(path).expect("native enrollment container");
        std::fs::write(path.join("temporary"), b"unknown artifact")
            .expect("unknown enrollment artifact");
    });
    rejected_with_container(".runne-native-enrollment", |path| {
        std::fs::create_dir(path).expect("native enrollment container");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o750))
            .expect("insecure enrollment container mode");
    });
    rejected_with_container("updates", |path| {
        std::fs::create_dir(path).expect("updates container");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777))
            .expect("corrupt container mode");
    });
}

#[test]
fn rejects_relative_malformed_and_insecure_parent_paths() {
    assert_eq!(
        require_linux_cli_baseline_root(std::path::Path::new("relative/runtime")),
        Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable)
    );
    assert_eq!(
        require_linux_cli_baseline_root(std::path::Path::new("/")),
        Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable)
    );

    let parent = tempfile::tempdir().expect("private fixture parent");
    make_private(parent.path());
    let missing_parent = parent.path().join("missing/runtime");
    assert_eq!(
        require_linux_cli_baseline_root(&missing_parent),
        Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable)
    );

    let parent_file = parent.path().join("parent-file");
    std::fs::write(&parent_file, b"not a directory").expect("malformed parent fixture");
    assert_eq!(
        require_linux_cli_baseline_root(&parent_file.join("runtime")),
        Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable)
    );

    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o755))
        .expect("make parent insecure");
    let insecure_root = parent.path().join("runtime");
    assert_eq!(
        require_linux_cli_baseline_root(&insecure_root),
        Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable)
    );
}

#[test]
fn rejects_symlink_parent_and_existing_root_with_corrupt_mode() {
    let outer = tempfile::tempdir().expect("outer fixture");
    make_private(outer.path());
    let target = outer.path().join("target");
    make_private(&target);
    let alias = outer.path().join("alias");
    symlink(&target, &alias).expect("symlink parent");
    assert_eq!(
        require_linux_cli_baseline_root(&alias.join("runtime")),
        Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable)
    );

    let parent = tempfile::tempdir().expect("private fixture parent");
    make_private(parent.path());
    let root = parent.path().join("runtime");
    make_private(&root);
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
        .expect("corrupt runtime-root mode");
    assert_eq!(
        require_linux_cli_baseline_root(&root),
        Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable)
    );
}
