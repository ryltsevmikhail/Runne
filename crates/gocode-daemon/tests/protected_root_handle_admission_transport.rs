#![cfg(all(unix, feature = "desktop-protected", feature = "test-support"))]

use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use gocode_api::{
    ExecutableIdentityV1, LaunchSecret, ProtectedOwnedLaunchV1, ProtectedReadyV1,
    ProtectedRuntimeProfileV1, StableRuntimeBindingV1,
};
use gocode_daemon::protected_activation::test_support::run_inherited_root_admission_fixture;
use gocode_domain::id::WorkspaceId;
use gocode_platform_desktop::{
    BundledRuntimeProcessStatus, ProtectedBundledRuntimeProcess, VerifiedRootHandle,
};
use gocode_runtime_client::ProtectedRootAdmission;

const AUTHORITY: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];
const LINEAGE: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 2];
const DAEMON: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 3];
const SESSION: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 4];
const WORKSPACE: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 6];

#[test]
fn inherited_child_binds_the_exact_admission_once() {
    if let Some(path) = std::env::var_os("GOCODE_B1B_TOKEN_PATH") {
        run_inherited_root_admission_fixture(path.as_os_str());
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let token_path = directory.path().join("admission.token");
    let root = VerifiedRootHandle::open(directory.path()).unwrap();
    let (parent, child_channel) = UnixStream::pair().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "inherited_child_binds_the_exact_admission_once"])
        .env("GOCODE_B1B_TOKEN_PATH", &token_path)
        .stdin(Stdio::from(OwnedFd::from(child_channel)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let (keys, owned) = fixture();
    let mut process =
        ProtectedBundledRuntimeProcess::test_root_transport_process(child, parent, keys, owned);
    let admission = process
        .prepare_root_admission(&root, workspace(), 1)
        .unwrap();
    let admission = ProtectedRootAdmission::from_verified(admission).unwrap();
    let admission_digest = admission.admission_digest();
    let digest_path = token_path.with_extension("admission-digest");
    publish_exact(&digest_path, &admission_digest);
    wait_for_exact_file(&digest_path, &admission_digest);
    wait_for_exact_file(
        &token_path.with_extension("outcome"),
        b"durably_recorded_root_bound",
    );
    assert_eq!(admission.admission_digest(), admission_digest);
    let _ = process
        .prepare_root_admission(&root, workspace(), 1)
        .unwrap();
    process.request_graceful_stop().unwrap();
    assert_eq!(
        process.wait_for_exit(Duration::from_secs(5)).unwrap(),
        BundledRuntimeProcessStatus::Exited
    );
}

fn publish_exact(path: &std::path::Path, bytes: &[u8]) {
    let temporary_path = path.with_extension("tmp");
    let mut temporary = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)
        .unwrap();
    temporary.write_all(bytes).unwrap();
    temporary.sync_all().unwrap();
    drop(temporary);
    std::fs::rename(temporary_path, path).unwrap();
}

fn wait_for_exact_file(path: &std::path::Path, expected: &[u8]) {
    for _ in 0..100 {
        if std::fs::read(path).is_ok_and(|bytes| bytes == expected) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("exact cross-process witness was not published")
}

const fn workspace() -> WorkspaceId {
    WorkspaceId::from_bytes(WORKSPACE)
}

fn fixture() -> (gocode_api::ProtectedActivationKeys, ProtectedOwnedLaunchV1) {
    let keys = LaunchSecret::from_bytes([9; 32]).unwrap().derive_keys();
    let executable = ExecutableIdentityV1::new([1; 32], [2; 32], 1).unwrap();
    let profile =
        ProtectedRuntimeProfileV1::new("fixture", 1, "fixture", [3; 32], [4; 32]).unwrap();
    let stable = StableRuntimeBindingV1::new(
        AUTHORITY,
        "local-owner",
        LINEAGE,
        "fixture",
        [3; 32],
        [4; 32],
    )
    .unwrap();
    let ready = ProtectedReadyV1::new(
        AUTHORITY,
        AUTHORITY,
        executable,
        profile,
        stable,
        DAEMON,
        1,
        SESSION,
        "https://127.0.0.1",
        [5; 32],
        vec![1],
        vec!["fixture".into()],
    )
    .unwrap();
    (keys, ready.owned_launch())
}
