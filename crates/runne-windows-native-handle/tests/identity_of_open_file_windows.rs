#![cfg(windows)]

//! Windows regressions for the borrowed-handle identity publication:
//! `identity_of_open_file` must answer a stable `FILE_ID_INFO` identity for
//! an open regular file without disturbing the caller's handle, and must
//! fail closed for objects the audited boundary does not admit (directories,
//! reparse material) instead of returning a vacuous identity.

use std::fs::File;
use std::io::Read;
use std::os::windows::fs::OpenOptionsExt;

use runne_windows_native_handle::identity_of_open_file;

#[test]
fn regular_file_identity_is_stable_and_keeps_the_borrowed_handle_usable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("measured");
    std::fs::write(&path, b"payload").unwrap();
    let mut file = File::open(&path).unwrap();
    let first = identity_of_open_file(&file).unwrap();
    let second = identity_of_open_file(&file).unwrap();
    assert_eq!(first, second);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"payload");
}

#[test]
fn distinct_files_carry_distinct_identities() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first");
    let second = directory.path().join("second");
    std::fs::write(&first, b"first").unwrap();
    std::fs::write(&second, b"second").unwrap();
    let first = identity_of_open_file(&File::open(first).unwrap()).unwrap();
    let second = identity_of_open_file(&File::open(second).unwrap()).unwrap();
    assert_ne!(first, second);
}

#[test]
fn directory_handles_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x0200_0000) // FILE_FLAG_BACKUP_SEMANTICS: open the directory itself
        .open(directory.path())
        .unwrap();
    assert!(identity_of_open_file(&handle).is_err());
}
