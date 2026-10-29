use super::*;
use crate::local_command_macos::MacOsCommandError;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;

#[test]
fn copies_exact_executable_bytes_and_proves_identity() {
    let source = File::open("/bin/echo").unwrap();
    let snapshot = SealedExecutableSnapshot::from_held_file(&source).unwrap();
    assert!(snapshot.path().is_file());
    assert_eq!(
        std::fs::metadata(snapshot.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o500
    );
    let mut bytes = Vec::new();
    File::open("/bin/echo")
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(snapshot.digest(), Sha256::digest(&bytes).as_slice());
    assert_eq!(
        std::fs::metadata(snapshot.path()).unwrap().len(),
        bytes.len() as u64
    );
}

#[test]
fn rejects_a_non_executable_source() {
    let source = File::open("/etc/hosts").unwrap();
    assert_eq!(
        SealedExecutableSnapshot::from_held_file(&source).unwrap_err(),
        MacOsCommandError::Invalid
    );
}

#[test]
fn drop_removes_the_private_image_directory() {
    let source = File::open("/bin/echo").unwrap();
    let snapshot = SealedExecutableSnapshot::from_held_file(&source).unwrap();
    let path = snapshot.path().to_path_buf();
    let directory = path.parent().unwrap().to_path_buf();
    drop(snapshot);
    assert!(!path.exists());
    assert!(!directory.exists());
}

#[test]
fn every_snapshot_has_its_own_private_directory() {
    let source = File::open("/bin/echo").unwrap();
    let first = SealedExecutableSnapshot::from_held_file(&source).unwrap();
    let second = SealedExecutableSnapshot::from_held_file(&source).unwrap();
    assert_ne!(first.path(), second.path());
    assert_ne!(first.object_id(), second.object_id());
}
