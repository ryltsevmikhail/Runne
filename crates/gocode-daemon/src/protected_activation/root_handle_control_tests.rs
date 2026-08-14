use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::protected_activation::ProtectedActivationChannel;
use crate::protected_activation::test_support::{
    dispatch_without_admission, run_without_admission,
};
use gocode_api::{
    ApiPrincipalId, ExecutableIdentityV1, LaunchSecret, ProtectedActivationKeys,
    ProtectedOwnedLaunchV1, ProtectedReadyV1, ProtectedRuntimeProfileV1, RuntimeSessionBinding,
    StableRuntimeBinding, StableRuntimeBindingV1,
};
use gocode_application::local_session::LocalSessionService;
use gocode_domain::{
    event::Sensitivity,
    id::{DaemonInstanceId, EventLogLineageId, WorkspaceId},
};
use gocode_platform_desktop::{
    BundledRuntimeProcessStatus, ProtectedBundledRuntimeError, ProtectedBundledRuntimeProcess,
    VerifiedRootHandle,
};

const AUTHORITY: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];
const HOST: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2];
const LINEAGE: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 3];
const DAEMON: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 4];
const SESSION: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 5];

fn fixture() -> (ProtectedActivationKeys, ProtectedOwnedLaunchV1) {
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
        HOST,
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

#[test]
fn inherited_stdin_child_runs_production_root_dispatcher_for_sequential_rejections() {
    if std::env::var_os("GOCODE_B1A_ROOT_CHILD").is_some() {
        let mut channel = ProtectedActivationChannel::from_inherited_stdin()
            .unwrap()
            .unwrap();
        let (keys, owned) = fixture();
        let mut used = std::collections::VecDeque::new();
        let mut sequence = 0;
        for _ in 0..2 {
            let frame = channel.read_control_frame().unwrap();
            sequence = dispatch_without_admission(
                &mut channel,
                &frame,
                &keys,
                &owned,
                &mut used,
                sequence,
                unix_millis(),
            )
            .unwrap()
            .unwrap();
        }
        run_without_admission(
            channel,
            keys,
            owned,
            Arc::new(Mutex::new(session_service())),
            Arc::new(|| Duration::from_secs(1)),
        )
        .unwrap();
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let root = VerifiedRootHandle::open(directory.path()).unwrap();
    let (parent, child_channel) = UnixStream::pair().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "protected_activation::root_handle_control_tests::inherited_stdin_child_runs_production_root_dispatcher_for_sequential_rejections",
        ])
        .env("GOCODE_B1A_ROOT_CHILD", "1")
        .stdin(Stdio::from(OwnedFd::from(child_channel)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let (keys, owned) = fixture();
    let mut process =
        ProtectedBundledRuntimeProcess::test_root_transport_process(child, parent, keys, owned);
    let workspace = WorkspaceId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 6]);
    assert_eq!(
        process.prepare_root_handle(&root, workspace, 1),
        Err(ProtectedBundledRuntimeError::OwnershipMismatch)
    );
    std::thread::sleep(Duration::from_millis(1_100));
    assert_eq!(
        process.prepare_root_handle(&root, workspace, 2),
        Err(ProtectedBundledRuntimeError::OwnershipMismatch)
    );
    process.request_graceful_stop().unwrap();
    assert_eq!(
        process.wait_for_exit(Duration::from_secs(5)).unwrap(),
        BundledRuntimeProcessStatus::Exited
    );
}

fn session_service() -> LocalSessionService {
    let stable = StableRuntimeBinding::new(
        AUTHORITY,
        ApiPrincipalId::new("local-owner").unwrap(),
        EventLogLineageId::from_bytes(LINEAGE),
        "fixture",
        [3; 32],
        [4; 32],
    )
    .unwrap();
    let binding = RuntimeSessionBinding::new(
        stable,
        DaemonInstanceId::from_bytes(DAEMON),
        1,
        SESSION,
        0,
        Sensitivity::Public,
        [5; 32],
    )
    .unwrap();
    LocalSessionService::new(binding, [7; 32])
}

#[test]
fn peer_close_after_offer_poison_reaps_the_exact_child() {
    if std::env::var_os("GOCODE_B1A_PARTIAL_CHILD").is_some() {
        let mut byte = [0; 1];
        std::io::stdin().read_exact(&mut byte).unwrap();
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let root = VerifiedRootHandle::open(directory.path()).unwrap();
    let (parent, child_channel) = UnixStream::pair().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "protected_activation::root_handle_control_tests::peer_close_after_offer_poison_reaps_the_exact_child",
        ])
        .env("GOCODE_B1A_PARTIAL_CHILD", "1")
        .stdin(Stdio::from(OwnedFd::from(child_channel)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let (keys, owned) = fixture();
    let mut process =
        ProtectedBundledRuntimeProcess::test_root_transport_process(child, parent, keys, owned);
    let workspace = WorkspaceId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 6]);
    assert_eq!(
        process.prepare_root_handle(&root, workspace, 1),
        Err(ProtectedBundledRuntimeError::ProtectedChannelUnavailable)
    );
    assert_eq!(
        process.status().unwrap(),
        BundledRuntimeProcessStatus::Exited
    );
}

#[test]
fn invalid_preflight_keeps_the_inherited_channel_healthy() {
    if std::env::var_os("GOCODE_B1A_PREFLIGHT_CHILD").is_some() {
        let mut channel = ProtectedActivationChannel::from_inherited_stdin()
            .unwrap()
            .unwrap();
        let (keys, owned) = fixture();
        let mut used = std::collections::VecDeque::new();
        let frame = channel.read_control_frame().unwrap();
        dispatch_without_admission(
            &mut channel,
            &frame,
            &keys,
            &owned,
            &mut used,
            0,
            unix_millis(),
        )
        .unwrap()
        .unwrap();
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let root = VerifiedRootHandle::open(directory.path()).unwrap();
    let (parent, child_channel) = UnixStream::pair().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "protected_activation::root_handle_control_tests::invalid_preflight_keeps_the_inherited_channel_healthy",
        ])
        .env("GOCODE_B1A_PREFLIGHT_CHILD", "1")
        .stdin(Stdio::from(OwnedFd::from(child_channel)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let (keys, owned) = fixture();
    let mut process =
        ProtectedBundledRuntimeProcess::test_root_transport_process(child, parent, keys, owned);
    let workspace = WorkspaceId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 6]);
    assert!(process.prepare_root_handle(&root, workspace, 0).is_err());
    assert_eq!(
        process.status().unwrap(),
        BundledRuntimeProcessStatus::Running
    );
    assert_eq!(
        process.prepare_root_handle(&root, workspace, 1),
        Err(ProtectedBundledRuntimeError::OwnershipMismatch)
    );
    assert_eq!(
        process.wait_for_exit(Duration::from_secs(5)).unwrap(),
        BundledRuntimeProcessStatus::Exited
    );
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}
