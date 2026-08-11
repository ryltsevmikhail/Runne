#![cfg(all(unix, feature = "test-support"))]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use gocode_api::{
    ActivationDispositionV1, ExecutableIdentityV1, LaunchAuthorityError, LaunchSecret,
    ProtectedFirstActivationCommitV1, ProtectedFirstActivationPreparedV1, ProtectedLaunchRequestV1,
    ProtectedReadyV1, ProtectedRenewRequestV1, ProtectedRenewTicketV1, ProtectedRuntimeProfileV1,
    ProtectedShutdownAckV1, ProtectedShutdownV1,
};
use gocode_daemon::application::workspace_internal::{self, ProtectedProviderDependencyCapsule};
use gocode_daemon::error::DaemonError;
use gocode_daemon::protected_activation::test_support::run_without_admission;
use gocode_daemon::protected_activation::{ProtectedActivationChannel, ProtectedDaemonLaunch};

fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    let payload = u32::from_be_bytes(prefix) as usize;
    let mut frame = vec![0; payload + 4];
    frame[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut frame[4..]).unwrap();
    frame
}

#[test]
fn delayed_first_activation_commit_cannot_outlive_launch_authority_ttl() {
    let runtime_root = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(runtime_root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let canonical_runtime_root = std::fs::canonicalize(runtime_root.path()).unwrap();
    let executable_path = std::env::current_exe().unwrap();
    let executable = ExecutableIdentityV1::measure(&executable_path).unwrap();
    let profile_hash: [u8; 32] = hex::decode(gocode_runtime::bundle::PUBLISHED_BUNDLE_HASH)
        .unwrap()
        .try_into()
        .unwrap();
    let profile = ProtectedRuntimeProfileV1::new(
        "gocode-bundled-runtime/1",
        1,
        gocode_runtime::bundle::BUNDLE_ID,
        profile_hash,
        gocode_http::runtime_profile::ordered_capability_digest(
            gocode_runtime::bundle::PUBLISHED_RUNTIME_CAPABILITIES,
        ),
    )
    .unwrap();
    let secret = LaunchSecret::from_bytes([0xa5; 32]).unwrap();
    let keys = secret.derive_keys();
    let request = ProtectedLaunchRequestV1::new(
        *uuid::Uuid::now_v7().as_bytes(),
        *uuid::Uuid::now_v7().as_bytes(),
        secret,
        1_000,
        31_000,
        "local-owner",
        profile,
        executable,
        canonical_runtime_root.clone(),
        ActivationDispositionV1::FirstActivation,
    )
    .unwrap();
    let request_for_client = request.clone();
    let (mut client, server) = UnixStream::pair().unwrap();
    let times = Arc::new(Mutex::new(std::collections::VecDeque::from([
        1_001_u64, 31_001_u64,
    ])));
    let server_times = Arc::clone(&times);
    let server_thread = std::thread::spawn(move || {
        let mut channel = ProtectedActivationChannel::new(server).unwrap();
        ProtectedDaemonLaunch::accept(&mut channel, &executable_path, move || {
            server_times
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(LaunchAuthorityError::StaleLaunchAuthority)
        })
        .err()
        .expect("expired commit must not produce a launch")
    });

    client.write_all(&request.encode_frame().unwrap()).unwrap();
    let prepared =
        ProtectedFirstActivationPreparedV1::decode_frame(&read_frame(&mut client)).unwrap();
    prepared.verify_exact(&request_for_client, &keys).unwrap();
    let mut commit = ProtectedFirstActivationCommitV1::new(
        request_for_client.launch_authority_id(),
        request_for_client.desktop_host_instance_id(),
        prepared.pending().clone(),
    );
    commit.sign(&keys);
    client.write_all(&commit.encode_frame().unwrap()).unwrap();

    assert_eq!(
        server_thread.join().unwrap(),
        LaunchAuthorityError::StaleLaunchAuthority
    );
    assert!(
        !canonical_runtime_root
            .join("gocode-daemon/event-log.db")
            .exists()
    );
}

#[test]
fn inherited_socket_commits_first_activation_before_bootstrap() {
    let runtime_root = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(runtime_root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let canonical_runtime_root = std::fs::canonicalize(runtime_root.path()).unwrap();
    let executable_path = std::env::current_exe().unwrap();
    let executable = ExecutableIdentityV1::measure(&executable_path).unwrap();
    let profile_hash: [u8; 32] = hex::decode(gocode_runtime::bundle::PUBLISHED_BUNDLE_HASH)
        .unwrap()
        .try_into()
        .unwrap();
    let profile = ProtectedRuntimeProfileV1::new(
        "gocode-bundled-runtime/1",
        1,
        gocode_runtime::bundle::BUNDLE_ID,
        profile_hash,
        gocode_http::runtime_profile::ordered_capability_digest(
            gocode_runtime::bundle::PUBLISHED_RUNTIME_CAPABILITIES,
        ),
    )
    .unwrap();
    let secret = LaunchSecret::from_bytes([0xa5; 32]).unwrap();
    let keys = secret.derive_keys();
    let request = ProtectedLaunchRequestV1::new(
        *uuid::Uuid::now_v7().as_bytes(),
        *uuid::Uuid::now_v7().as_bytes(),
        secret,
        1_000,
        31_000,
        "local-owner",
        profile,
        executable,
        canonical_runtime_root.clone(),
        ActivationDispositionV1::FirstActivation,
    )
    .unwrap();
    let request_for_client = request.clone();
    let request_frame = request.encode_frame().unwrap();
    let (mut client, server) = UnixStream::pair().unwrap();
    let server_path = executable_path.clone();
    let server_thread = std::thread::spawn(move || {
        let mut channel = ProtectedActivationChannel::new(server).unwrap();
        let mut launch =
            ProtectedDaemonLaunch::accept(&mut channel, &server_path, || Ok(1_001)).unwrap();
        let start = launch
            .bootstrap_runtime_start_for_test(|| Ok(1_001))
            .unwrap();
        let profile_directory = std::path::Path::new(&launch.config().replay_integrity_key_path)
            .parent()
            .unwrap()
            .to_path_buf();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let application = workspace_internal::start_from_verified_protected_launch(
                start,
                ProtectedProviderDependencyCapsule::production(),
            )
            .await
            .unwrap();
            let ready = application
                .protected_ready(launch.request(), launch.keys())
                .unwrap();
            let owned_launch = ready.owned_launch();
            let control_keys = launch.keys().clone();
            let local_session_service = application.protected_session_service().unwrap();
            let session_clock = application.protected_session_clock().unwrap();
            let observed_session_service = local_session_service.clone();
            channel
                .write_control_frame(&ready.encode_frame().unwrap())
                .unwrap();
            let control_loop = tokio::task::spawn_blocking(move || {
                run_without_admission(
                    channel,
                    control_keys,
                    owned_launch,
                    local_session_service,
                    session_clock,
                )
            });
            application
                .run(async move {
                    control_loop
                        .await
                        .map_err(|_| DaemonError::Bootstrap("control task failed".into()))?
                        .map_err(|_| DaemonError::Bootstrap("control channel failed".into()))
                })
                .await
                .unwrap();
            let rotated_session_id = *observed_session_service
                .lock()
                .unwrap()
                .current_binding()
                .ephemeral()
                .session_id();
            (profile_directory, rotated_session_id)
        })
    });

    client.write_all(&request_frame).unwrap();
    let prepared =
        ProtectedFirstActivationPreparedV1::decode_frame(&read_frame(&mut client)).unwrap();
    prepared
        .verify_exact(&request_for_client, &keys)
        .expect("authenticated preparation");
    assert!(
        !canonical_runtime_root
            .join("gocode-daemon/event-log.db")
            .exists(),
        "Event Log must not exist before desktop commit"
    );
    let mut commit = ProtectedFirstActivationCommitV1::new(
        request_for_client.launch_authority_id(),
        request_for_client.desktop_host_instance_id(),
        prepared.pending().clone(),
    );
    commit.sign(&keys);
    client.write_all(&commit.encode_frame().unwrap()).unwrap();

    let ready = ProtectedReadyV1::decode_frame(&read_frame(&mut client)).unwrap();
    ready
        .verify_exact(&request_for_client, &keys)
        .expect("exact protected readiness");
    let mut renewal = ProtectedRenewRequestV1::new(ready.owned_launch(), 1, [0xb7; 32]).unwrap();
    renewal.sign(&keys);
    client.write_all(&renewal.encode_frame().unwrap()).unwrap();
    let ticket = ProtectedRenewTicketV1::decode_frame(&read_frame(&mut client)).unwrap();
    ticket
        .verify_exact(&renewal, &keys)
        .expect("exact protected renewal ticket");
    let rotated_session_id = *ticket.next_session_id();
    let next_owned_launch = ticket.next_owned_launch();
    let mut shutdown = ProtectedShutdownV1::new(next_owned_launch.clone());
    shutdown.sign(&keys);
    client.write_all(&shutdown.encode_frame().unwrap()).unwrap();
    let acknowledgement = ProtectedShutdownAckV1::decode_frame(&read_frame(&mut client)).unwrap();
    acknowledgement
        .verify_exact(&next_owned_launch, &keys)
        .expect("exact protected shutdown acknowledgement");
    assert!(acknowledgement.graceful());

    let (profile_directory, daemon_session_id) = server_thread.join().unwrap();
    assert_eq!(daemon_session_id, rotated_session_id);
    assert!(!profile_directory.join("client-profile.json").exists());
    assert!(
        std::fs::read_dir(profile_directory)
            .unwrap()
            .flatten()
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with("bootstrap-"))
    );
}
