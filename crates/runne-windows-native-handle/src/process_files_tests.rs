use std::fs;
use std::path::Path;

use tempfile::tempdir;

use crate::{DirectoryHandle, NativeHandleError};

#[test]
fn opens_handle_relative_process_material_and_measures_identity() {
    let root = tempdir().expect("temporary root");
    fs::create_dir(root.path().join("bin")).expect("bin");
    fs::create_dir(root.path().join("workspace")).expect("workspace");
    fs::write(root.path().join("bin/tool.exe"), b"native tool").expect("tool");
    let handle = DirectoryHandle::open(root.path()).expect("root handle");

    let files = handle
        .open_process_files(Path::new("bin/tool.exe"), Path::new("workspace"))
        .expect("process material");

    assert!(files.executable_path().is_absolute());
    assert!(files.cwd_path().is_absolute());
    assert_ne!(files.executable_content_digest(), [0; 32]);
    assert_ne!(files.executable_identity_digest(), [0; 32]);
    assert_ne!(files.cwd_identity_digest(), [0; 32]);
}

#[test]
fn rejects_traversal_before_opening_process_material() {
    let root = tempdir().expect("temporary root");
    fs::create_dir(root.path().join("workspace")).expect("workspace");
    let handle = DirectoryHandle::open(root.path()).expect("root handle");

    assert!(matches!(
        handle.open_process_files(Path::new("../tool.exe"), Path::new("workspace")),
        Err(NativeHandleError::Rejected)
    ));
}
