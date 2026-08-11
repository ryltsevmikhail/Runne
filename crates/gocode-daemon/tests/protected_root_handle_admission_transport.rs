#![cfg(all(unix, feature = "desktop-protected", feature = "test-support"))]

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
    BundledRuntimeProcessStatus, ProtectedBundledRuntimeError, ProtectedBundledRuntimeProcess,
    VerifiedRootHandle,
};

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
    assert_eq!(
        admission.encode_token().unwrap(),
        std::fs::read_to_string(&token_path).unwrap()
    );
    assert!(matches!(
        process.prepare_root_admission(&root, workspace(), 1),
        Err(ProtectedBundledRuntimeError::OwnershipMismatch)
    ));
    process.request_graceful_stop().unwrap();
    assert_eq!(
        process.wait_for_exit(Duration::from_secs(5)).unwrap(),
        BundledRuntimeProcessStatus::Exited
    );
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
