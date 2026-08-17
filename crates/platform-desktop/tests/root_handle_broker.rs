#![cfg(all(unix, feature = "test-support"))]

use std::fs;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use gocode_api::{LaunchSecret, RootHandleTransferAuthenticator};
use gocode_platform_desktop::{
    RootHandleTransferBinding, VerifiedRootHandle, test_transfer_pair, test_transfer_receiver,
    test_transfer_sender,
};
use tempfile::tempdir;

fn authenticator(secret: u8) -> RootHandleTransferAuthenticator {
    let keys = LaunchSecret::from_bytes([secret; 32])
        .unwrap()
        .derive_keys();
    RootHandleTransferAuthenticator::from_protected_activation(&keys)
}

fn binding() -> RootHandleTransferBinding {
    RootHandleTransferBinding::test_binding(
        [7; 16],
        1,
        std::process::id(),
        std::process::id(),
        rustix::process::getuid().as_raw() as u32,
    )
    .unwrap()
}

fn open(path: &Path) -> VerifiedRootHandle {
    let canonical = std::fs::canonicalize(path).unwrap();
    VerifiedRootHandle::open(&canonical).unwrap()
}

#[test]
fn opens_a_directory_handle_without_retaining_or_debugging_its_path() {
    let directory = tempdir().unwrap();
    let root = open(directory.path());
    assert!(root.open_relative_directory(Path::new(".")).is_ok());
    assert!(!format!("{root:?}").contains(&directory.path().display().to_string()));
}

#[test]
fn rejects_relative_and_intermediate_symlink_paths() {
    let directory = tempdir().unwrap();
    let target = directory.path().join("target");
    let link = directory.path().join("link");
    fs::create_dir(&target).unwrap();
    fs::create_dir(target.join("nested")).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(VerifiedRootHandle::open(Path::new("relative-directory")).is_err());
    assert!(VerifiedRootHandle::open(&link).is_err());
    assert!(VerifiedRootHandle::open(&link.join("nested")).is_err());
}

#[test]
fn receiver_challenge_authenticates_one_real_fd_transfer() {
    let directory = tempdir().unwrap();
    let root = open(directory.path());
    let (sender, receiver) =
        test_transfer_pair(authenticator(9), authenticator(9), binding()).unwrap();
    let receiver_thread = std::thread::spawn(move || receiver.receive());
    sender.transfer(&root).unwrap();
    let transferred = receiver_thread.join().unwrap().unwrap();
    assert_eq!(
        transferred.filesystem_identity_digest(),
        root.filesystem_identity_digest()
    );
}

#[test]
fn sender_rejects_a_wrong_receiver_pid_before_the_challenge() {
    let directory = tempdir().unwrap();
    let root = open(directory.path());
    let binding = RootHandleTransferBinding::test_binding(
        [7; 16],
        1,
        std::process::id(),
        std::process::id() + 1,
        rustix::process::getuid().as_raw() as u32,
    )
    .unwrap();
    let (stream, _peer) = UnixStream::pair().unwrap();
    let started = Instant::now();
    assert!(
        test_transfer_sender(stream, authenticator(9), binding)
            .transfer(&root)
            .is_err()
    );
    assert!(started.elapsed() < Duration::from_millis(200));
}

#[test]
fn receiver_rejects_a_wrong_sender_pid_before_the_challenge() {
    let binding = RootHandleTransferBinding::test_binding(
        [7; 16],
        1,
        std::process::id() + 1,
        std::process::id(),
        rustix::process::getuid().as_raw() as u32,
    )
    .unwrap();
    let (_peer, stream) = UnixStream::pair().unwrap();
    let started = Instant::now();
    assert!(
        test_transfer_receiver(stream, authenticator(9), binding)
            .receive()
            .is_err()
    );
    assert!(started.elapsed() < Duration::from_millis(200));
}

#[test]
fn sender_rejects_a_wrong_effective_uid_before_the_challenge() {
    let directory = tempdir().unwrap();
    let root = open(directory.path());
    let uid = rustix::process::getuid().as_raw() as u32;
    let wrong_uid = uid.checked_add(1).unwrap_or(uid - 1);
    let binding = RootHandleTransferBinding::test_binding(
        [7; 16],
        1,
        std::process::id(),
        std::process::id(),
        wrong_uid,
    )
    .unwrap();
    let (stream, _peer) = UnixStream::pair().unwrap();
    let started = Instant::now();
    assert!(
        test_transfer_sender(stream, authenticator(9), binding)
            .transfer(&root)
            .is_err()
    );
    assert!(started.elapsed() < Duration::from_millis(200));
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn unix_without_exact_peer_credentials_rejects_the_transfer() {
    let directory = tempdir().unwrap();
    let root = open(directory.path());
    let (sender, receiver) =
        test_transfer_pair(authenticator(9), authenticator(9), binding()).unwrap();
    let receiver_thread = std::thread::spawn(move || receiver.receive());
    assert!(sender.transfer(&root).is_err());
    assert!(receiver_thread.join().unwrap().is_err());
}

#[test]
fn mismatched_receiver_key_rejects_before_descriptor_adoption() {
    let directory = tempdir().unwrap();
    let root = open(directory.path());
    let (sender, receiver) =
        test_transfer_pair(authenticator(9), authenticator(10), binding()).unwrap();
    let receiver_thread = std::thread::spawn(move || receiver.receive());
    assert!(sender.transfer(&root).is_err());
    assert!(receiver_thread.join().unwrap().is_err());
}

#[test]
fn replacement_after_open_cannot_change_the_transferred_identity() {
    let directory = tempdir().unwrap();
    let selected = directory.path().join("selected");
    let replacement = directory.path().join("replacement");
    fs::create_dir(&selected).unwrap();
    let root = open(&selected);
    fs::rename(&selected, &replacement).unwrap();
    fs::create_dir(&selected).unwrap();
    let (sender, receiver) =
        test_transfer_pair(authenticator(9), authenticator(9), binding()).unwrap();
    let receiver_thread = std::thread::spawn(move || receiver.receive());
    sender.transfer(&root).unwrap();
    let transferred = receiver_thread.join().unwrap().unwrap();
    assert!(transferred.same_filesystem_object(&root));
    assert!(!transferred.same_filesystem_object(&open(&selected)));
}

#[test]
fn real_child_process_receives_a_receiver_authenticated_transfer() {
    if let Ok(socket_path) = std::env::var("GOCODE_ROOT_HANDLE_CHILD_SOCKET") {
        let parent_pid = std::env::var("GOCODE_ROOT_HANDLE_PARENT_PID")
            .unwrap()
            .parse()
            .unwrap();
        let listener = UnixListener::bind(socket_path).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let binding = RootHandleTransferBinding::test_binding(
            [8; 16],
            1,
            parent_pid,
            std::process::id(),
            rustix::process::getuid().as_raw() as u32,
        )
        .unwrap();
        let transferred = test_transfer_receiver(stream, authenticator(9), binding)
            .receive()
            .unwrap();
        println!(
            "child-root-transfer-digest={}",
            hex::encode(transferred.filesystem_identity_digest())
        );
        return;
    }
    let directory = tempdir().unwrap();
    let root = open(directory.path());
    let socket_path = directory.path().join("child.sock");
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "real_child_process_receives_a_receiver_authenticated_transfer",
            "--nocapture",
        ])
        .env("GOCODE_ROOT_HANDLE_CHILD_SOCKET", &socket_path)
        .env(
            "GOCODE_ROOT_HANDLE_PARENT_PID",
            std::process::id().to_string(),
        )
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stream = connect_to_child(&socket_path);
    let binding = RootHandleTransferBinding::test_binding(
        [8; 16],
        1,
        std::process::id(),
        child.id(),
        rustix::process::getuid().as_raw() as u32,
    )
    .unwrap();
    test_transfer_sender(stream, authenticator(9), binding)
        .transfer(&root)
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains(&format!(
        "child-root-transfer-digest={}",
        hex::encode(root.filesystem_identity_digest())
    )));
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
