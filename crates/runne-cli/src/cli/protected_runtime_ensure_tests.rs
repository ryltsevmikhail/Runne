use super::*;
use std::path::PathBuf;

fn private_dir(path: &Path) {
    fs::create_dir_all(path).expect("create fixture directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("make fixture directory private");
}

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let parent = tempfile::tempdir().expect("private fixture parent");
    let runtime_root = parent.path().join("runtime");
    let project_root = parent.path().join("project");
    private_dir(&runtime_root);
    private_dir(&project_root);
    (parent, runtime_root, project_root)
}

fn usage_error(result: &Result<(), super::super::super::CliError>) -> bool {
    matches!(result, Err(super::super::super::CliError::Usage))
}

fn runtime_error(result: &Result<(), super::super::super::CliError>) -> bool {
    matches!(result, Err(super::super::super::CliError::Runtime))
}

#[test]
fn rebind_accepts_existing_absolute_private_directory_outside_runtime_root() {
    let (parent, runtime_root, project_root) = fixture();
    assert!(
        validate_rebind_root(&runtime_root, &project_root).is_ok(),
        "0700 owner-only project root under a 0700 parent rebinds"
    );
    drop(parent);
}

#[test]
fn rebind_rejects_argument_shaped_paths_with_usage() {
    let (parent, runtime_root, project_root) = fixture();
    assert!(
        usage_error(&validate_rebind_root(
            &runtime_root,
            Path::new("relative/project")
        )),
        "relative project root is an argument error"
    );
    assert!(
        usage_error(&validate_rebind_root(
            &runtime_root,
            &project_root.join("..").join("escape")
        )),
        "parent-directory components are argument errors"
    );
    assert!(
        usage_error(&validate_rebind_root(
            &runtime_root,
            &parent.path().join("missing")
        )),
        "missing target is an argument error"
    );
    let file = parent.path().join("file");
    fs::write(&file, b"not a directory").expect("create regular file");
    assert!(
        usage_error(&validate_rebind_root(&runtime_root, &file)),
        "non-directory target is an argument error"
    );
    drop(parent);
}

#[test]
fn rebind_rejects_cur_dir_segments_with_usage() {
    let (parent, runtime_root, project_root) = fixture();
    let inner = project_root.join("inner");
    private_dir(&inner);
    assert!(
        usage_error(&validate_rebind_root(
            &runtime_root,
            &project_root.join(".")
        )),
        "trailing /. is an argument error"
    );
    assert!(
        usage_error(&validate_rebind_root(
            &runtime_root,
            &project_root.join(".").join("inner")
        )),
        "embedded /./ is an argument error"
    );
    assert!(
        usage_error(&validate_rebind_root(
            &runtime_root,
            &inner.join(".").join("leaf")
        )),
        "interior dot segment is an argument error even when the target is absent"
    );
    drop(parent);
}

#[test]
fn rebind_fails_closed_inside_runtime_root() {
    let (parent, runtime_root, _project_root) = fixture();
    let inside = runtime_root.join("inner");
    private_dir(&inside);
    assert!(
        runtime_error(&validate_rebind_root(&runtime_root, &inside)),
        "a project root inside the protected runtime root never rebinds"
    );
    assert!(
        runtime_error(&validate_rebind_root(&runtime_root, &runtime_root)),
        "a project root equal to the protected runtime root never rebinds"
    );
    drop(parent);
}

#[test]
fn rebind_fails_closed_when_runtime_root_is_inside_project_root() {
    let (parent, _runtime_root, project_root) = fixture();
    let nested_runtime_root = project_root.join("runtime");
    private_dir(&nested_runtime_root);
    assert!(
        runtime_error(&validate_rebind_root(&nested_runtime_root, &project_root)),
        "a protected runtime root inside the project root never rebinds"
    );
    drop(parent);
}

#[test]
fn rebind_checks_the_parent_of_the_canonical_target() {
    let (parent, runtime_root, _project_root) = fixture();
    let canonical_parent = parent.path().join("real");
    let canonical_project = canonical_parent.join("project");
    private_dir(&canonical_project);
    private_dir(&canonical_parent);
    let link = parent.path().join("link");
    std::os::unix::fs::symlink(&canonical_project, &link).expect("symlink to project root");
    fs::set_permissions(&canonical_parent, fs::Permissions::from_mode(0o755))
        .expect("make the canonical parent non-private");
    assert!(
        runtime_error(&validate_rebind_root(&runtime_root, &link)),
        "the mode of the canonical parent is checked, not of the argument's textual parent"
    );
    drop(parent);
}

#[test]
fn rebind_fails_closed_on_shared_directory_modes() {
    let (parent, runtime_root, project_root) = fixture();
    fs::set_permissions(&project_root, fs::Permissions::from_mode(0o770))
        .expect("make project root group-writable");
    assert!(
        runtime_error(&validate_rebind_root(&runtime_root, &project_root)),
        "group-writable project root fails closed"
    );
    fs::set_permissions(&project_root, fs::Permissions::from_mode(0o700))
        .expect("restore project root mode");
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o755))
        .expect("make parent world-readable");
    assert!(
        runtime_error(&validate_rebind_root(&runtime_root, &project_root)),
        "parent that is not 0700-compatible fails closed"
    );
    drop(parent);
}
