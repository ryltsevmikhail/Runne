#![cfg(unix)]

use std::fs;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use gocode_api::{LaunchSecret, RootHandleTransferAuthenticator};
use gocode_platform_desktop::{RootHandleBroker, VerifiedRootHandle};
use tempfile::tempdir;

fn authenticator_with_secret(secret: u8) -> RootHandleTransferAuthenticator {
    let keys = LaunchSecret::from_bytes([secret; 32])
        .unwrap()
        .derive_keys();
    RootHandleTransferAuthenticator::from_protected_activation(&keys)
}

fn authenticator() -> RootHandleTransferAuthenticator {
    authenticator_with_secret(9)
}

fn open(path: &Path) -> VerifiedRootHandle {
    VerifiedRootHandle::open(path).unwrap()
}

#[test]
fn opens_a_directory_handle_without_retaining_or_debugging_its_path() {
    let directory = tempdir().unwrap();
    let root = open(directory.path());

    assert!(root.open_relative_directory(Path::new(".")).is_ok());
    let debug = format!("{root:?}");
    assert!(!debug.contains(&directory.path().display().to_string()));
    assert!(debug.contains("redacted"));
}

#[test]
fn rejects_final_symlinks_and_parent_traversal() {
    let directory = tempdir().unwrap();
    let target = directory.path().join("target");
    let link = directory.path().join("link");
    let nested = target.join("nested");
    let nested_link = directory.path().join("nested-link");
    fs::create_dir(&target).unwrap();
    fs::create_dir(&nested).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    std::os::unix::fs::symlink(&nested, &nested_link).unwrap();

    assert!(VerifiedRootHandle::open(&link).is_err());
    assert!(VerifiedRootHandle::open(&directory.path().join("target/../target")).is_err());
    assert!(
        open(directory.path())
            .open_relative_directory(Path::new("nested-link/child"))
            .is_err()
    );
}

#[test]
fn authenticated_rights_transfer_rejects_wrong_proof_and_replay() {
    let directory = tempdir().unwrap();
    let root = open(directory.path());
    let (sender, receiver) = UnixStream::pair().unwrap();
    let broker = RootHandleBroker::new(authenticator());

    let nonce = [4; 32];
    broker.send_with_nonce(&sender, &root, nonce).unwrap();
    let transferred = broker.receive(&receiver).unwrap();
    assert!(transferred.same_filesystem_object(&root));
    assert_eq!(
        transferred.filesystem_identity_digest(),
        root.filesystem_identity_digest()
    );

    broker.send_with_nonce(&sender, &root, nonce).unwrap();
    assert!(broker.receive(&receiver).is_err());
    RootHandleBroker::new(authenticator_with_secret(10))
        .send(&sender, &root)
        .unwrap();
    assert!(broker.receive(&receiver).is_err());
}

#[test]
fn transferred_handle_resists_path_replacement_after_open() {
    let directory = tempdir().unwrap();
    let selected = directory.path().join("selected");
    let replacement = directory.path().join("replacement");
    fs::create_dir(&selected).unwrap();
    let root = open(&selected);
    fs::rename(&selected, &replacement).unwrap();
    fs::create_dir(&selected).unwrap();

    let (sender, receiver) = UnixStream::pair().unwrap();
    let broker = RootHandleBroker::new(authenticator());
    broker.send(&sender, &root).unwrap();
    let transferred = broker.receive(&receiver).unwrap();

    assert!(transferred.same_filesystem_object(&root));
    assert!(!transferred.same_filesystem_object(&open(&selected)));
}

#[test]
fn real_child_process_receives_authenticated_rights() {
    if let Ok(socket_path) = std::env::var("GOCODE_ROOT_HANDLE_CHILD_SOCKET") {
        let listener = std::os::unix::net::UnixListener::bind(socket_path).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let root = RootHandleBroker::new(authenticator())
            .receive(&stream)
            .unwrap();
        assert!(root.open_relative_directory(Path::new(".")).is_ok());
        println!("child-root-identity-verified");
        return;
    }

    let directory = tempdir().unwrap();
    let root = open(directory.path());
    let socket_path = directory.path().join("child.sock");
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "real_child_process_receives_authenticated_rights",
            "--nocapture",
        ])
        .env("GOCODE_ROOT_HANDLE_CHILD_SOCKET", &socket_path)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let sender = connect_to_child(&socket_path);
    RootHandleBroker::new(authenticator())
        .send(&sender, &root)
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("child-root-identity-verified")
    );
}

fn connect_to_child(path: &Path) -> UnixStream {
    for _ in 0..50 {
        if let Ok(stream) = UnixStream::connect(path) {
            return stream;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("child receiver did not bind its socket");
}
